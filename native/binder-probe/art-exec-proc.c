// Phase 2 only: ask the supervisor for this compiler's own proc view, then run stock art_exec.
#define _GNU_SOURCE
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <linux/capability.h>
#include <sched.h>
#include <stdio.h>
#include <unistd.h>

int main(int argc, char** argv) {
    if (argc < 2 || unshare(CLONE_NEWNS) != 0) { perror("phase2 compiler unshare"); return 120; }
    pid_t pid = getpid();
    char ack = 0;
    if (send(198, &pid, sizeof(pid), MSG_NOSIGNAL) != sizeof(pid) || recv(198, &ack, 1, 0) != 1 || ack != 1) return 121;
    struct __user_cap_header_struct header = {_LINUX_CAPABILITY_VERSION_3, 0};
    struct __user_cap_data_struct caps[2] = {{0}};
    if (syscall(SYS_capget, &header, caps) != 0) return 122;
    unsigned bit = 1U << CAP_SYS_ADMIN;
    caps[0].effective &= ~bit;
    caps[0].permitted &= ~bit;
    caps[0].inheritable &= ~bit;
    if (syscall(SYS_capset, &header, caps) != 0 || prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_LOWER, CAP_SYS_ADMIN, 0, 0) != 0) return 123;
    if (send(198, &pid, sizeof(pid), MSG_NOSIGNAL) != sizeof(pid) || recv(198, &ack, 1, 0) != 1 || ack != 2 || close(198) != 0) return 125;
    // NNP remains set; the compiler cannot regain the dropped mount capability.
    argv[0] = "/run/ssal/phase2-real-art-exec";
    execv(argv[0], argv);
    perror("phase2 stock art_exec");
    return 124;
}
