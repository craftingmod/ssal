#ifndef SSAL_GUEST_FRAME_P01_H
#define SSAL_GUEST_FRAME_P01_H

enum {
    SSAL_P01_WIDTH = 4,
    SSAL_P01_HEIGHT = 4,
    SSAL_P01_STRIDE = SSAL_P01_WIDTH * 4,
    SSAL_P01_RGBA8 = 1,
    SSAL_P01_HEADER = 8,
    SSAL_P01_PIXELS = SSAL_P01_HEIGHT * SSAL_P01_STRIDE,
};

// One SOCK_SEQPACKET record: magic, width, height, byte stride, format, pixels.
#define SSAL_P01_MAGIC "SSAL"
#define SSAL_P02_BRIDGE_SID "u:r:ssal_p0001_p02_frame_bridge:s0"

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

static inline int ssal_frame_peer(int fd, uid_t uid, gid_t gid, const char *sid) {
    struct ucred peer;
    socklen_t size = sizeof peer;
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &peer, &size)) {
        perror("SO_PEERCRED");
        return 1;
    }
    char context[256] = {0};
    size = sizeof context - 1;
    if (getsockopt(fd, SOL_SOCKET, SO_PEERSEC, context, &size)) {
        perror("SO_PEERSEC");
        return 1;
    }
    printf("Unix peer pid=%d uid=%u gid=%u sid=%s\n", peer.pid, peer.uid, peer.gid, context);
    if (peer.uid != uid || peer.gid != gid || strcmp(context, sid)) {
        fputs("Wrong Unix peer identity\n", stderr);
        return 1;
    }
    return 0;
}

#endif
