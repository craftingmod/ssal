#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/system_properties.h>
#include <unistd.h>

/* No JVM, forkSystemServer, class loading or production entrypoint in this harness. */
int main(int argc, char **argv) {
    if (argc != 2) return 2;
    const char *mode = argv[1];
    if (!strcmp(mode, "timeout")) { for (;;) pause(); }
    if (!strcmp(mode, "early-exit")) return 86;
    const char *path = !strcmp(mode, "hook-missing") ? "/ssal-missing-hook.so" :
        !strcmp(mode, "hook-wrong") ? "libm.so" : "/run/ssal/ssal-system-server-gate.so";
    void *gate = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    int (*version)(void) = gate ? dlsym(gate, "ssal_system_server_gate_version") : NULL;
    if (!version || version() != 1) return 83;
    if (!strcmp(mode, "wrapper")) {
        char property[PROP_VALUE_MAX];
        if (__system_property_get("wrap.system_server", property) <= 0 ||
            strcmp(property, "/run/ssal/ssal-system-server-wrapper")) return 87;
        execl(property, "ssal-system-server-wrapper", "ignored", NULL);
        _exit(84);
    }
    if (!strcmp(mode, "exec-failure")) {
        execl("/ssal-nonexistent-wrapper", "missing", NULL);
        _exit(84);
    }
    if (!strcmp(mode, "wrapper-failure")) {
        execl("/system/bin/false", "false", NULL);
        _exit(84);
    }
    if (!strcmp(mode, "property-missing") || !strcmp(mode, "control-disconnected")) {
        char property[PROP_VALUE_MAX];
        if (__system_property_get("wrap.system_server", property) > 0) return 87;
        if (!strcmp(mode, "control-disconnected")) close(STDERR_FILENO);
        int (*final)(const char *) = dlsym(gate, "selinux_android_setcon");
        if (!final) return 83;
        final("u:r:system_server:s0");
    } else if (!strcmp(mode, "startup")) {
        int (*startup)(uid_t, bool, const char *, const char *) = dlsym(gate, "selinux_android_setcontext");
        if (!startup) return 83;
        startup(1000, true, NULL, NULL);
    } else return 2;
    dprintf(2, "SSAL_SS_GATE_RETURNED_UNSAFE\n");
    return 99;
}
