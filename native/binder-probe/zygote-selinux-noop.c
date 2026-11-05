#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

static void sid(char *buffer, size_t size) {
    int fd = open("/proc/thread-self/attr/current", O_RDONLY | O_CLOEXEC);
    ssize_t n = fd < 0 ? -1 : read(fd, buffer, size - 1);
    int error = errno;
    if (fd >= 0) close(fd);
    if (n > 0) {
        buffer[n] = 0;
        if (buffer[n - 1] == '\n') buffer[n - 1] = 0;
    } else {
        snprintf(buffer, size, "UNAVAILABLE(errno=%d)", error);
    }
}

static void record(const char *api, const char *before, int result, int error) {
    char after[512];
    struct timespec now = {0};
    sid(after, sizeof(after));
    clock_gettime(CLOCK_REALTIME, &now);
    dprintf(2, "SSAL_SELINUX_NOOP api=%s pid=%d uid=%d gid=%d unix_s=%lld.%09ld result=%d errno=%d before=%s after=%s\n",
            api, getpid(), getuid(), getgid(), (long long)now.tv_sec, now.tv_nsec,
            result, error, before, after);
}

int selinux_android_setcontext(uid_t uid, bool server, const char *seinfo, const char *name) {
    int incoming = errno;
    int (*original)(uid_t, bool, const char *, const char *) = dlsym(RTLD_NEXT, "selinux_android_setcontext");
    char before[512];
    sid(before, sizeof(before));
    dprintf(2, "SSAL_SELINUX_ARGS api=setcontext pid=%d uid=%u server=%d seinfo=%s name=%s incoming_errno=%d resolved=%d\n",
            getpid(), uid, server, seinfo ? seinfo : "NULL", name ? name : "NULL", incoming, original != NULL);
    // Missing symbols must fail visibly; never manufacture transition success.
    errno = original ? incoming : ENOSYS;
    int result = original ? original(uid, server, seinfo, name) : -1;
    int error = errno;
    record("setcontext", before, result, error);
    errno = error;
    return result;
}

int selinux_android_setcon(const char *context) {
    int incoming = errno;
    int (*original)(const char *) = dlsym(RTLD_NEXT, "selinux_android_setcon");
    char before[512];
    sid(before, sizeof(before));
    dprintf(2, "SSAL_SELINUX_ARGS api=setcon pid=%d context=%s incoming_errno=%d resolved=%d\n",
            getpid(), context ? context : "NULL", incoming, original != NULL);
    errno = original ? incoming : ENOSYS;
    int result = original ? original(context) : -1;
    int error = errno;
    record("setcon", before, result, error);
    errno = error;
    return result;
}

__attribute__((constructor)) static void loaded(void) {
    int incoming = errno;
    dprintf(2, "SSAL_SELINUX_NOOP_LOADED pid=%d\n", getpid());
    // Fork children retain the mapping; subsequent exec must not inherit diagnostics.
    unsetenv("LD_PRELOAD");
    errno = incoming;
}
