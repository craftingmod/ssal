#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/vfs.h>
#include <unistd.h>

/* Loaded before Zygote forks: setters do no allocation or file I/O. */
/* shortcut: at most 8191 types; grow this table when a larger GSI needs it. */
static struct { char original[256], mapped[256]; } types[8192];
static size_t count;

static const char *mapped_context(const char *context, char *out, size_t size) {
    if (!context) return NULL;
    const char *role = strchr(context, ':');
    const char *type = role ? strchr(role + 1, ':') : NULL;
    const char *level = type ? strchr(type + 1, ':') : NULL;
    if (!level) { errno = EINVAL; return NULL; }
    size_t length = (size_t)(level - type - 1);
    for (size_t i = 0; i < count; i++) {
        if (strlen(types[i].mapped) == length && !memcmp(type + 1, types[i].mapped, length)) return context;
        if (strlen(types[i].original) != length || memcmp(type + 1, types[i].original, length)) continue;
        int n = snprintf(out, size, "%.*s%s%s", (int)(type - context + 1), context, types[i].mapped, level);
        if (n < 0 || (size_t)n >= size) { errno = EOVERFLOW; return NULL; }
        return out;
    }
    errno = EINVAL;
    return NULL;
}

#ifndef SSAL_CONTEXT_MAP_TEST
static int (*real_setcon)(const char *);
static int (*real_setexeccon)(const char *);
static int (*real_setfscreatecon)(const char *);
static int (*real_getcon)(char **);
static int (*real_check_access)(const char *, const char *, const char *, const char *, void *);
static int (*real_avc_reset)(void);
static void *libselinux_handle;

static int set_context_via_procattr(const char *context) {
    dprintf(2, "SSAL_PROCATTR_OPEN_BEGIN path=/proc/thread-self/attr/current\n");
    errno = 0;
    int fd = open("/proc/thread-self/attr/current", O_WRONLY | O_CLOEXEC);
    int open_error = errno;
    dprintf(2, "SSAL_PROCATTR_OPEN_RESULT fd=%d errno=%d\n", fd, open_error);
    if (fd < 0) {
        errno = open_error;
        return -1;
    }
    size_t length = strlen(context);
    ssize_t written;
    dprintf(2, "SSAL_PROCATTR_WRITE_BEGIN length=%zu\n", length);
    errno = 0;
    do written = write(fd, context, length); while (written < 0 && errno == EINTR);
    int error = errno;
    static const char returned[] = "SSAL_PROCATTR_WRITE_RETURN\n";
    (void)write(2, returned, sizeof(returned) - 1);
    close(fd);
    if (written != (ssize_t)length) {
        errno = written < 0 ? error : EIO;
        return -1;
    }
    errno = error;
    return 0;
}

__attribute__((constructor)) static void load_map(void) {
    FILE *file = fopen("/run/ssal/selinux-types", "re");
    if (!file) _Exit(126);
    while (count < sizeof(types) / sizeof(types[0]) &&
           fscanf(file, "%255s %255s", types[count].original, types[count].mapped) == 2) count++;
    if (!feof(file) || ferror(file) || !count) _Exit(126);
    fclose(file);
    real_setcon = dlsym(RTLD_NEXT, "setcon");
    real_setexeccon = dlsym(RTLD_NEXT, "setexeccon");
    real_setfscreatecon = dlsym(RTLD_NEXT, "setfscreatecon");
    real_getcon = dlsym(RTLD_NEXT, "getcon");
    real_check_access = dlsym(RTLD_NEXT, "selinux_check_access");
    real_avc_reset = dlsym(RTLD_NEXT, "avc_reset");
    if (!real_avc_reset) real_avc_reset = dlsym(RTLD_DEFAULT, "avc_reset");
    if (!real_avc_reset) {
        libselinux_handle = dlopen("libselinux.so", RTLD_NOW | RTLD_NOLOAD);
        if (libselinux_handle) real_avc_reset = dlsym(libselinux_handle, "avc_reset");
    }
    /* libselinux ignores RO selinuxfs; register the real Guest view explicitly. */
    struct statfs fs;
    void (*set_mount)(const char *) = dlsym(RTLD_NEXT, "set_selinuxmnt");
    int (*enabled)(void) = dlsym(RTLD_NEXT, "is_selinux_enabled");
    int (*enforcing)(void) = dlsym(RTLD_NEXT, "security_getenforce");
    if (!enabled) return; /* Helpers without libselinux have no discovery to repair. */
    if (!set_mount || !enabled || !enforcing ||
        statfs("/sys/fs/selinux", &fs) || (unsigned long)fs.f_type != 0xf97cff8cUL) _Exit(126);
    if (enabled() != 1) set_mount("/sys/fs/selinux");
    if (enabled() != 1 || enforcing() != 1) _Exit(126);
}

#define SETTER(name) \
    int name(const char *context) { \
        char out[1024]; \
        const char *mapped = mapped_context(context, out, sizeof(out)); \
        int incoming = errno; \
        int inspect = context && strstr(context, "system_server"); \
        if (context && !mapped) { \
            int error = errno; \
            dprintf(2, "SSAL_CONTEXT_MAP_FAIL setter=%s raw=%s mapped=NULL result=-1 errno=%d\n", #name, context, error); \
            errno = error; \
            return -1; \
        } \
        if (!real_##name) { errno = ENOSYS; return -1; } \
        char *source = NULL; \
        int got = -2, get_error = 0, avc_reset = -2, avc_error = 0, dyntransition = -2, dyn_error = 0, setcurrent = -2, current_error = 0; \
        if (inspect && real_getcon) { \
            errno = 0; \
            got = real_getcon(&source); \
            get_error = errno; \
        } \
        if (inspect && getenv("SSAL_CONTEXT_MAP_AVC_RESET") && !strcmp(getenv("SSAL_CONTEXT_MAP_AVC_RESET"), "1")) { \
            dprintf(2, "SSAL_CONTEXT_MAP_AVC_RESET_BEGIN setter=%s source=%s mapped=%s\n", #name, source ? source : "NULL", mapped ? mapped : "NULL"); \
            if (real_avc_reset) { errno = 0; avc_reset = real_avc_reset(); avc_error = errno; } \
            else { avc_reset = -1; avc_error = ENOSYS; } \
        } \
        if (inspect && got == 0 && source && real_check_access) { \
            errno = 0; \
            dyntransition = real_check_access(source, mapped, "process", "dyntransition", NULL); \
            dyn_error = errno; \
            errno = 0; \
            setcurrent = real_check_access(source, source, "process", "setcurrent", NULL); \
            current_error = errno; \
        } \
        if (inspect) dprintf(2, "SSAL_CONTEXT_MAP_PRE setter=%s raw=%s mapped=%s source=%s getcon=%d getcon_errno=%d avc_reset=%d avc_errno=%d dyntransition=%d dyn_errno=%d setcurrent=%d current_errno=%d\n", #name, context, mapped ? mapped : "NULL", source ? source : "NULL", got, get_error, avc_reset, avc_error, dyntransition, dyn_error, setcurrent, current_error); \
        errno = incoming; \
        int direct = !strcmp(#name, "setcon") && getenv("SSAL_CONTEXT_MAP_RAW_SETCON") && !strcmp(getenv("SSAL_CONTEXT_MAP_RAW_SETCON"), "1"); \
        if (direct && inspect) dprintf(2, "SSAL_CONTEXT_MAP_RAW_SETCON_BEGIN mapped=%s path=/proc/thread-self/attr/current\n", mapped); \
        /* Avoid stdio/allocator locks inherited across the Zygote fork after the SID changes. */ \
        if (direct) { \
            free(source); \
            int raw_result = set_context_via_procattr(mapped); \
            int raw_error = errno; \
            if (raw_result != 0) dprintf(2, "SSAL_CONTEXT_MAP_FAIL setter=%s raw=%s mapped=%s result=%d errno=%d\n", #name, context ? context : "NULL", mapped ? mapped : "NULL", raw_result, raw_error); \
            errno = raw_error; \
            return raw_result; \
        } \
        int result = real_##name(mapped), error = errno; \
        if (result != 0 && !inspect) dprintf(2, "SSAL_CONTEXT_MAP_FAIL setter=%s raw=%s mapped=%s result=%d errno=%d\n", #name, context ? context : "NULL", mapped ? mapped : "NULL", result, error); \
        if (inspect) dprintf(2, "SSAL_CONTEXT_MAP setter=%s raw=%s mapped=%s source=%s getcon=%d getcon_errno=%d dyntransition=%d dyn_errno=%d setcurrent=%d current_errno=%d result=%d errno=%d\n", #name, context, mapped ? mapped : "NULL", source ? source : "NULL", got, get_error, dyntransition, dyn_error, setcurrent, current_error, result, error); \
        free(source); \
        errno = error; \
        return result; \
    }
SETTER(setcon)
SETTER(setexeccon)
SETTER(setfscreatecon)

#else
#include <assert.h>
int main(void) {
    strcpy(types[0].original, "system_server");
    strcpy(types[0].mapped, "ssal_p0001_system_server");
    count = 1;
    char out[1024];
    assert(!strcmp(mapped_context("u:r:system_server:s0:c12,c34", out, sizeof(out)),
                   "u:r:ssal_p0001_system_server:s0:c12,c34"));
    assert(!strcmp(mapped_context("u:r:ssal_p0001_system_server:s0", out, sizeof(out)),
                   "u:r:ssal_p0001_system_server:s0"));
    assert(!mapped_context("u:r:init:s0", out, sizeof(out)) && errno == EINVAL);
    assert(!mapped_context("u:r:system_server:s0", out, 5) && errno == EOVERFLOW);
    assert(!mapped_context("invalid", out, sizeof(out)));
    assert(!mapped_context(NULL, out, sizeof(out)));
}
#endif
