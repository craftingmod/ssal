#define _GNU_SOURCE
#include "guest-frame-p01.h"

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if ((argc != 3 && (argc != 4 || strcmp(argv[3], "--presenter-test"))) ||
        argv[1][0] != '/' || geteuid() != 0) {
        fprintf(stderr, "usage: %s ABSOLUTE_BRIDGE_ROOT GUEST_SID [--presenter-test]\n", argv[0]);
        return 2;
    }
    int attr = open("/proc/self/attr/exec", O_WRONLY | O_CLOEXEC);
    if (attr < 0 || write(attr, SSAL_P02_BRIDGE_SID, sizeof SSAL_P02_BRIDGE_SID - 1) !=
                        sizeof SSAL_P02_BRIDGE_SID - 1) {
        perror("set bridge exec context");
        return 1;
    }
    close(attr);
    if (chdir(argv[1]) || chroot(".") || chdir("/")) {
        perror("enter bridge root");
        return 1;
    }
    for (int capability = 0; capability < 64; ++capability) {
        if (prctl(PR_CAPBSET_DROP, capability, 0, 0, 0)) {
            if (errno == EINVAL)
                break;
            perror("drop bridge capability");
            return 1;
        }
    }
    if (setgroups(0, NULL) || setresgid(2000, 2000, 2000) || setresuid(2000, 2000, 2000) ||
        syscall(SYS_close_range, 3, ~0U, 0)) {
        perror("set bridge credentials and close inherited descriptors");
        return 1;
    }
    execl("/state/receiver", "host-frame-p02", argc == 4 ? "--bridge-test" : "--bridge",
          argv[2], (char *)NULL);
    perror("exec frame bridge");
    return 1;
}
