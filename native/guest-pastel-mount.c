#define _GNU_SOURCE
#include <limits.h>
#include <sched.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <unistd.h>

static int fail(const char *operation) {
    perror(operation);
    return 2;
}

static int report_ipc_boundary(const char *side) {
    char mnt[64], net[64], sid[256];
    ssize_t mnt_len = readlink("/proc/self/ns/mnt", mnt, sizeof mnt - 1);
    ssize_t net_len = readlink("/proc/self/ns/net", net, sizeof net - 1);
    if (mnt_len < 0 || net_len < 0)
        return fail("read mount/network namespace");
    FILE *context = fopen("/proc/self/attr/current", "r");
    if (!context)
        return fail("open current SELinux context");
    bool read_context = fgets(sid, sizeof sid, context) != NULL;
    fclose(context);
    if (!read_context) {
        fputs("read current SELinux context failed\n", stderr);
        return 2;
    }
    printf("%s pid=%ld mount=%.*s network=%.*s sid=%s\n", side, (long)getpid(),
           (int)mnt_len, mnt, (int)net_len, net, sid);
    fflush(stdout);
    return 0;
}

int main(int argc, char **argv) {
    const char prefix[] = "/data/local/tmp/ssal-vulkan-b02.";
    bool frame_transfer = argc == 4 && !strcmp(argv[2], "angle-p01");
    if ((argc != 3 && !frame_transfer) || strncmp(argv[1], prefix, sizeof prefix - 1) ||
        !argv[1][sizeof prefix - 1] || strchr(argv[1] + sizeof prefix - 1, '/')) {
        fputs("usage: guest-pastel-mount /data/local/tmp/ssal-vulkan-b02.SUFFIX "
              "vulkan|angle|angle-swiftshader|angle-p01 FD\n",
              stderr);
        return 2;
    }
    const char *probe = "/system/bin/ssal-angle-b0";
    const char *option = "vulkan";
    if (!strcmp(argv[2], "vulkan")) {
        probe = "/system/bin/ssal-vulkan-b01";
        option = "--pastel-device";
    } else if (!strcmp(argv[2], "angle-swiftshader")) {
        option = "swiftshader";
    } else if (frame_transfer) {
        probe = "/system/bin/ssal-angle-p01";
    } else if (strcmp(argv[2], "angle")) {
        fputs("unknown probe mode\n", stderr);
        return 2;
    }

    char root[PATH_MAX], source[PATH_MAX], target[PATH_MAX], resolved[PATH_MAX];
    if (snprintf(root, sizeof root, "%s/root", argv[1]) >= (int)sizeof root ||
        snprintf(source, sizeof source, "%s/pastel", argv[1]) >= (int)sizeof source ||
        snprintf(target, sizeof target, "%s/vendor", root) >= (int)sizeof target)
        return 2;
    if (!realpath(source, resolved) || strcmp(source, resolved) ||
        !realpath(target, resolved) || strcmp(target, resolved)) {
        fputs("staging paths must resolve inside the named Guest staging directory\n", stderr);
        return 2;
    }

    if (frame_transfer && report_ipc_boundary("Launcher before unshare"))
        return 2;
    if (unshare(CLONE_NEWNS | CLONE_NEWNET))
        return fail("unshare mount/network");
    if (frame_transfer && report_ipc_boundary("Launcher after unshare"))
        return 2;
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL))
        return fail("make mount namespace private");
    if (mount(source, target, NULL, MS_BIND, NULL))
        return fail("bind Guest vendor");
    if (mount(NULL, target, NULL, MS_BIND | MS_REMOUNT | MS_RDONLY | MS_NODEV | MS_NOSUID, NULL))
        return fail("remount Guest vendor read-only");
    printf("Guest-only vendor bind: %s -> %s (ro,nodev,nosuid)\n", source, target);
    fflush(stdout);
    if (chroot(root) || chdir("/"))
        return fail("chroot Guest");
    if (clearenv() || setenv("LD_LIBRARY_PATH", "/apex/com.android.runtime/lib64/bionic", 1))
        return fail("set Guest linker environment");
    const char *linker = "/apex/com.android.runtime/bin/linker64";
    execl(linker, linker, probe, option, frame_transfer ? argv[3] : NULL, (char *)NULL);
    return fail("exec GSI linker");
}
