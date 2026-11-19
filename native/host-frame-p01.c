#define _GNU_SOURCE
#include "guest-frame-p01.h"

#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

static int validate_frame(const unsigned char *frame, ssize_t size) {
    if (size != SSAL_P01_HEADER + SSAL_P01_PIXELS) {
        fprintf(stderr, "Host FAIL: recv size=%zd expected=%d%s\n", size,
                SSAL_P01_HEADER + SSAL_P01_PIXELS, size == 0 ? " (peer closed or empty record)" : "");
        return 1;
    }
    printf("Host recv packet=%zd payload=%d width=%u height=%u stride=%u format=%u\n",
           size, SSAL_P01_PIXELS, frame[4], frame[5], frame[6], frame[7]);
    if (memcmp(frame, SSAL_P01_MAGIC, 4) || frame[4] != SSAL_P01_WIDTH ||
        frame[5] != SSAL_P01_HEIGHT || frame[6] != SSAL_P01_STRIDE ||
        frame[7] != SSAL_P01_RGBA8) {
        fputs("Host FAIL: invalid SSAL frame header\n", stderr);
        return 1;
    }
    const unsigned char red[] = {255, 0, 0, 255};
    unsigned matches = 0;
    for (size_t i = SSAL_P01_HEADER; i < (size_t)size; i += sizeof red)
        matches += memcmp(frame + i, red, sizeof red) == 0;
    printf("Host RED=%u/16\n", matches);
    return matches != 16;
}

static int receive_frame(int fd) {
    unsigned char frame[SSAL_P01_HEADER + SSAL_P01_PIXELS];
    ssize_t size = recv(fd, frame, sizeof frame, MSG_TRUNC);
    if (size < 0) {
        perror("Host recv");
        return 1;
    }
    return validate_frame(frame, size);
}

static int listen_for_guest(const char *path, const char *expected_sid, bool bridge) {
    struct sockaddr_un address = { .sun_family = AF_UNIX };
    if ((!bridge && path[0] != '/') || strlen(path) >= sizeof address.sun_path) {
        fputs("Host requires an absolute Unix socket path of at most 107 bytes\n", stderr);
        return 2;
    }
    strcpy(address.sun_path, path);
    int listener = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (listener < 0) {
        perror("Host socket");
        return 1;
    }
    umask(bridge ? 0177 : 077);
    if (bind(listener, (struct sockaddr *)&address, sizeof address)) {
        perror("Host bind");
        return 1;
    }
    if ((!bridge && (chown(path, 2000, 2000) || chmod(path, 0600))) || listen(listener, 1)) {
        perror("Host configure socket");
        if (!bridge)
            unlink(path);
        return 1;
    }
    printf("Host listening pid=%ld uid=%u gid=%u socket=%s mode=0600 owner=2000:2000\n",
           (long)getpid(), getuid(), getgid(), path);
    int peer = accept(listener, NULL, NULL);
    if (peer < 0)
        perror("Host accept");
    int failed = peer < 0 || ssal_frame_peer(peer, 2000, 2000, expected_sid) || receive_frame(peer);
    if (peer >= 0)
        close(peer);
    if (!bridge)
        unlink(path);
    return failed;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc == 4 && !strcmp(argv[1], "--listen"))
        return listen_for_guest(argv[2], argv[3], false);
    if (argc == 3 && !strcmp(argv[1], "--bridge")) {
        if (getuid() != 2000 || geteuid() != 2000 || getgid() != 2000 || getegid() != 2000)
            return 2;
        int log = open("state/receiver.txt", O_WRONLY | O_APPEND | O_CLOEXEC | O_NOFOLLOW);
        if (log < 0 || dup2(log, STDOUT_FILENO) < 0 || dup2(log, STDERR_FILENO) < 0)
            return 1;
        if (log > STDERR_FILENO)
            close(log);
        return listen_for_guest("frame", argv[2], true);
    }
    if (argc != 3) {
        fprintf(stderr, "usage: %s guest-pastel-mount STAGE | --listen SOCKET_PATH GUEST_SID | --bridge GUEST_SID\n",
                argv[0]);
        return 2;
    }
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, pair)) {
        perror("Host socketpair(AF_UNIX, SOCK_SEQPACKET)");
        return 1;
    }
    printf("Host pid=%ld created private AF_UNIX SOCK_SEQPACKET pair\n", (long)getpid());
    pid_t child = fork();
    if (child < 0) {
        perror("Host fork");
        return 1;
    }
    if (child == 0) {
        close(pair[0]);
        char fd[32];
        snprintf(fd, sizeof fd, "%d", pair[1]);
        execl(argv[1], argv[1], argv[2], "angle-p01", fd, (char *)NULL);
        perror("exec Guest launcher");
        _exit(127);
    }
    close(pair[1]);
    int invalid = receive_frame(pair[0]);
    close(pair[0]);

    int status;
    if (waitpid(child, &status, 0) < 0) {
        perror("Host waitpid");
        return 1;
    }
    if (WIFEXITED(status))
        printf("Guest exit=%d\n", WEXITSTATUS(status));
    else if (WIFSIGNALED(status))
        printf("Guest signal=%d\n", WTERMSIG(status));
    int failed = invalid || !WIFEXITED(status) || WEXITSTATUS(status) != 0;
    puts(failed ? "SSAL P0.1 FAIL" : "SSAL P0.1 PASS");
    return failed;
}
