#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    if (getuid() != 1000 || getgid() != 1000) return 2;
    void *library = dlopen("libselinux.so", RTLD_NOW | RTLD_GLOBAL);
    if (!library) { dprintf(2, "SSAL_STARTUP_DLOPEN error=%s\n", dlerror()); return 2; }
    int (*startup)(uid_t, bool, const char *, const char *) = dlsym(RTLD_DEFAULT, "selinux_android_setcontext");
    int (*final)(const char *) = dlsym(RTLD_DEFAULT, "selinux_android_setcon");
    if (!startup || !final) {
        dprintf(2, "SSAL_STARTUP_SYMBOLS startup=%d final=%d\n", startup != NULL, final != NULL);
        return 2;
    }
    const char *context = "u:r:system_server_startup:s0";
    errno = 0;
    int fd = open("/sys/fs/selinux/context", O_RDWR | O_CLOEXEC);
    int valid = fd < 0 ? -1 : (int)write(fd, context, strlen(context));
    int error = errno;
    if (fd >= 0) close(fd);
    dprintf(2, "SSAL_STARTUP_CONTEXT_CHECK context=%s result=%d errno=%d\n", context, valid, error);
    errno = 0;
    int result = startup(1000, true, NULL, NULL);
    error = errno;
    dprintf(2, "SSAL_STARTUP_PROBE result=%d errno=%d final_reached=%d SystemServer_main=never\n", result, error, result == 0);
    if (result == 0) {
        errno = 0;
        result = final("u:r:system_server:s0");
        error = errno;
        dprintf(2, "SSAL_FINAL_PROBE result=%d errno=%d\n", result, error);
    }
    return 0;
}
