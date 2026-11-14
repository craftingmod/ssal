#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/vfs.h>

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
        if (context && !mapped) return -1; \
        if (!real_##name) { errno = ENOSYS; return -1; } \
        return real_##name(mapped); \
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
