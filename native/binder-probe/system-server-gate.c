#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* This is a terminal gate, never a launcher for the wrapper's trailing argv. */
__attribute__((noreturn)) static void stop(int code, const char *reason) {
    dprintf(2, "SSAL_SS_GATE pid=%d reason=%s SystemServer_main=never\n", getpid(), reason);
    _exit(code);
}

#ifdef SSAL_GATE_WRAPPER
int main(void) { stop(80, "wrapper"); }
#else
int ssal_system_server_gate_version(void) { return 1; }

int selinux_android_setcontext(uid_t uid, bool server, const char *seinfo, const char *name) {
    /* Unexpected startup calls must not return to Java either. */
    if (server) stop(81, "startup-call-blocked-preflight-only");
    int (*original)(uid_t, bool, const char *, const char *) =
        dlsym(RTLD_NEXT, "selinux_android_setcontext");
    if (!original) { errno = ENOSYS; return -1; }
    return original(uid, server, seinfo, name);
}

int selinux_android_setcon(const char *context) {
    if (context && !strcmp(context, "u:r:system_server:s0")) {
        /* No transition in 4B-1. A future post-setter gate needs binary proof. */
        stop(82, "final-call-blocked-preflight-only");
    }
    int (*original)(const char *) = dlsym(RTLD_NEXT, "selinux_android_setcon");
    if (!original) { errno = ENOSYS; return -1; }
    return original(context);
}
#endif
