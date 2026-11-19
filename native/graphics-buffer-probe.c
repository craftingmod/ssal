#define _GNU_SOURCE
#include "guest-frame-p01.h"

#include <EGL/egl.h>
#include <EGL/eglext.h>
#include <GLES3/gl3.h>
#include <GLES2/gl2ext.h>
#include <android/hardware_buffer.h>
#include <errno.h>
#include <limits.h>
#include <linux/sync_file.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

enum { edge = 16, frame_count = 8 };
static const unsigned char colors[][4] = {{255, 0, 0, 255}, {0, 255, 0, 255}};

static int fail(const char *stage) {
    fprintf(stderr, "FAIL: %s\n", stage);
    return 1;
}

static int open_peer(const char *path, bool host) {
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    if (path[0] != '/' || strlen(path) >= sizeof address.sun_path) {
        errno = EINVAL;
        return -1;
    }
    strcpy(address.sun_path, path);
    int fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;
    if (!host) {
        if (!connect(fd, (struct sockaddr *)&address, sizeof address))
            return fd;
    } else {
        umask(0177);
        if (!bind(fd, (struct sockaddr *)&address, sizeof address)) {
            int peer = -1;
            if (!listen(fd, 1)) {
                puts("Host buffer probe ready");
                struct pollfd ready = {.fd = fd, .events = POLLIN};
                if (poll(&ready, 1, 15000) > 0)
                    peer = accept4(fd, NULL, NULL, SOCK_CLOEXEC);
                else
                    errno = ETIMEDOUT;
            }
            int error = errno;
            unlink(path);
            close(fd);
            errno = error;
            return peer;
        }
    }
    int error = errno;
    close(fd);
    errno = error;
    return -1;
}

static int send_fence(int socket_fd, unsigned char frame, int fence) {
    union { struct cmsghdr align; unsigned char bytes[CMSG_SPACE(sizeof(int))]; } control = {0};
    struct iovec data = {.iov_base = &frame, .iov_len = 1};
    struct msghdr msg = {.msg_iov = &data, .msg_iovlen = 1,
                         .msg_control = control.bytes, .msg_controllen = sizeof control.bytes};
    struct cmsghdr *header = CMSG_FIRSTHDR(&msg);
    header->cmsg_level = SOL_SOCKET;
    header->cmsg_type = SCM_RIGHTS;
    header->cmsg_len = CMSG_LEN(sizeof fence);
    memcpy(CMSG_DATA(header), &fence, sizeof fence);
    return sendmsg(socket_fd, &msg, MSG_NOSIGNAL) == 1 ? 0 : -1;
}

static int wait_fence(int socket_fd, unsigned char expected_frame) {
    unsigned char frame;
    union { struct cmsghdr align; unsigned char bytes[CMSG_SPACE(sizeof(int))]; } control = {0};
    struct iovec data = {.iov_base = &frame, .iov_len = 1};
    struct msghdr msg = {.msg_iov = &data, .msg_iovlen = 1,
                         .msg_control = control.bytes, .msg_controllen = sizeof control.bytes};
    ssize_t size = recvmsg(socket_fd, &msg, MSG_CMSG_CLOEXEC);
    if (size < 0)
        return -1;
    int fence = -1;
    for (struct cmsghdr *header = CMSG_FIRSTHDR(&msg); header; header = CMSG_NXTHDR(&msg, header)) {
        if (header->cmsg_level != SOL_SOCKET || header->cmsg_type != SCM_RIGHTS)
            continue;
        size_t count = (header->cmsg_len - CMSG_LEN(0)) / sizeof(int);
        for (size_t i = 0; i < count; ++i) {
            int fd;
            memcpy(&fd, CMSG_DATA(header) + i * sizeof fd, sizeof fd);
            if (count == 1 && fence < 0)
                fence = fd;
            else
                close(fd);
        }
    }
    if (fence < 0)
        return -1;
    struct pollfd ready = {.fd = fence, .events = POLLIN};
    struct sync_file_info info = {0};
    bool signaled = size == 1 && frame == expected_frame &&
        !(msg.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) &&
        poll(&ready, 1, 5000) == 1 && ready.revents == POLLIN &&
        !ioctl(fence, SYNC_IOC_FILE_INFO, &info) && info.status == 1;
    if (!signaled)
        fprintf(stderr, "frame=%u fence revents=0x%x status=%d errno=%d\n",
                expected_frame, ready.revents, info.status, errno);
    close(fence);
    return signaled ? 0 : -1;
}

static int run_probe(int fd, bool host, bool host_allocates, uint64_t usage) {
    const EGLint config_attrs[] = {EGL_SURFACE_TYPE, EGL_PBUFFER_BIT, EGL_RENDERABLE_TYPE,
        EGL_OPENGL_ES3_BIT, EGL_RED_SIZE, 8, EGL_GREEN_SIZE, 8, EGL_BLUE_SIZE, 8,
        EGL_ALPHA_SIZE, 8, EGL_NONE};
    const EGLint context_attrs[] = {EGL_CONTEXT_CLIENT_VERSION, 3, EGL_NONE};
    const EGLint surface_attrs[] = {EGL_WIDTH, SSAL_P01_WIDTH, EGL_HEIGHT, SSAL_P01_HEIGHT, EGL_NONE};
    EGLDisplay display = eglGetDisplay(EGL_DEFAULT_DISPLAY);
    EGLConfig config;
    EGLint configs;
    if (display == EGL_NO_DISPLAY || !eglInitialize(display, NULL, NULL) ||
        !eglChooseConfig(display, config_attrs, &config, 1, &configs) || configs != 1)
        return fail("EGL display/config");
    EGLContext context = eglCreateContext(display, config, EGL_NO_CONTEXT, context_attrs);
    EGLSurface surface = eglCreatePbufferSurface(display, config, surface_attrs);
    if (context == EGL_NO_CONTEXT || surface == EGL_NO_SURFACE ||
        !eglMakeCurrent(display, surface, surface, context))
        return fail("EGL context/pbuffer");
    printf("EGL vendor=%s GLES vendor=%s renderer=%s\n", eglQueryString(display, EGL_VENDOR),
           glGetString(GL_VENDOR), glGetString(GL_RENDERER));

    if (!strstr(eglQueryString(display, EGL_EXTENSIONS), "EGL_ANDROID_native_fence_sync"))
        return fail("EGL_ANDROID_native_fence_sync unavailable");
    PFNEGLGETNATIVECLIENTBUFFERANDROIDPROC native_client =
        (PFNEGLGETNATIVECLIENTBUFFERANDROIDPROC)eglGetProcAddress("eglGetNativeClientBufferANDROID");
    PFNGLEGLIMAGETARGETTEXTURE2DOESPROC bind_image =
        (PFNGLEGLIMAGETARGETTEXTURE2DOESPROC)eglGetProcAddress("glEGLImageTargetTexture2DOES");
    PFNEGLDUPNATIVEFENCEFDANDROIDPROC dup_fence =
        (PFNEGLDUPNATIVEFENCEFDANDROIDPROC)eglGetProcAddress("eglDupNativeFenceFDANDROID");
    if (!native_client || !bind_image || !dup_fence)
        return fail("EGLImage/fence entry points");

    AHardwareBuffer *buffer = NULL;
    AHardwareBuffer_Desc desc = {.width = edge, .height = edge, .layers = 1,
        .format = AHARDWAREBUFFER_FORMAT_R8G8B8A8_UNORM, .usage = usage};
    if (fd < 0 || host == host_allocates) {
        int rc = AHardwareBuffer_allocate(&desc, &buffer);
        if (rc) {
            fprintf(stderr, "AHardwareBuffer_allocate usage=0x%llx rc=%d\n",
                    (unsigned long long)usage, rc);
            return 1;
        }
        if (fd >= 0 && AHardwareBuffer_sendHandleToUnixSocket(buffer, fd))
            return fail("send native buffer");
    } else if (AHardwareBuffer_recvHandleFromUnixSocket(fd, &buffer) || !buffer) {
        return fail("receive/import native buffer");
    }
    AHardwareBuffer_describe(buffer, &desc);
    if (desc.width != edge || desc.height != edge || desc.layers != 1 ||
        desc.format != AHARDWAREBUFFER_FORMAT_R8G8B8A8_UNORM || desc.usage != usage)
        return fail("unexpected native buffer geometry, format, or usage");
    printf("RGBA8 %ux%u stride=%u usage=0x%llx allocation=%s\n", desc.width, desc.height,
           desc.stride, (unsigned long long)desc.usage,
           fd < 0 ? "local" : host_allocates ? "host" : "producer");

    EGLClientBuffer client_buffer = native_client(buffer);
    const EGLAttrib image_attrs[] = {EGL_IMAGE_PRESERVED_KHR, EGL_TRUE, EGL_NONE};
    EGLImage image = eglCreateImage(display, EGL_NO_CONTEXT, EGL_NATIVE_BUFFER_ANDROID,
                                    client_buffer, image_attrs);
    if (image == EGL_NO_IMAGE)
        return fail("EGLImage import");
    GLuint texture, framebuffer;
    glGenTextures(1, &texture);
    glBindTexture(GL_TEXTURE_2D, texture);
    bind_image(GL_TEXTURE_2D, image);
    glGenFramebuffers(1, &framebuffer);
    glBindFramebuffer(GL_FRAMEBUFFER, framebuffer);
    glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D, texture, 0);
    if (glGetError() || glCheckFramebufferStatus(GL_FRAMEBUFFER) != GL_FRAMEBUFFER_COMPLETE)
        return fail("EGLImage framebuffer attachment");

    for (unsigned char frame = 0; fd >= 0 && frame < frame_count; ++frame) {
        const unsigned char *color = colors[frame % 2];
        if (host) {
            if (wait_fence(fd, frame))
                return fail("acquire fence");
            unsigned char record[SSAL_P01_HEADER + SSAL_P01_PIXELS] = {
                'S', 'S', 'A', 'L', SSAL_P01_WIDTH, SSAL_P01_HEIGHT, SSAL_P01_STRIDE, SSAL_P01_RGBA8,
            };
            unsigned char *pixels = record + SSAL_P01_HEADER;
            glBindFramebuffer(GL_READ_FRAMEBUFFER, framebuffer);
            glBindFramebuffer(GL_DRAW_FRAMEBUFFER, 0);
            glBlitFramebuffer(0, 0, edge, edge, 0, 0, SSAL_P01_WIDTH, SSAL_P01_HEIGHT,
                              GL_COLOR_BUFFER_BIT, GL_NEAREST);
            glBindFramebuffer(GL_READ_FRAMEBUFFER, 0);
            glReadPixels(0, 0, SSAL_P01_WIDTH, SSAL_P01_HEIGHT, GL_RGBA, GL_UNSIGNED_BYTE, pixels);
            if (glGetError())
                return fail("Host blit/readback");
            for (size_t i = 0; i < SSAL_P01_PIXELS; i += 4) {
                if (memcmp(pixels + i, color, 4))
                    return fail("Host pixel mismatch on reused buffer");
            }
            // Readback completes the blit before the producer may overwrite the buffer.
            if (send(fd, &frame, 1, MSG_NOSIGNAL) != 1)
                return fail("send read-complete acknowledgement");
            printf("frame=%u RGBA=%u,%u,%u,%u pixels=%u\n", frame, color[0], color[1],
                   color[2], color[3], SSAL_P01_WIDTH * SSAL_P01_HEIGHT);
            if (frame == frame_count - 1) {
                fputs("SSAL_PRESENTER_FRAME=", stdout);
                for (size_t i = 0; i < sizeof record; ++i)
                    printf("%02x", record[i]);
                putchar('\n');
            }
        } else {
            glClearColor(color[0] / 255.0f, color[1] / 255.0f, 0, 1);
            glClear(GL_COLOR_BUFFER_BIT);
            EGLSync sync = eglCreateSync(display, EGL_SYNC_NATIVE_FENCE_ANDROID, NULL);
            if (glGetError() || sync == EGL_NO_SYNC)
                return fail("create acquire fence");
            glFlush();
            int fence = dup_fence(display, sync);
            eglDestroySync(display, sync);
            if (fence < 0)
                return fail("export acquire fence");
            int sent = send_fence(fd, frame, fence);
            close(fence);
            unsigned char ack;
            if (sent || recv(fd, &ack, 1, MSG_TRUNC) != 1 || ack != frame)
                return fail("wait for Host read-complete acknowledgement");
        }
    }
    glDeleteFramebuffers(1, &framebuffer);
    glDeleteTextures(1, &texture);
    eglDestroyImage(display, image);
    AHardwareBuffer_release(buffer);
    eglMakeCurrent(display, EGL_NO_SURFACE, EGL_NO_SURFACE, EGL_NO_CONTEXT);
    eglDestroySurface(display, surface);
    eglDestroyContext(display, context);
    eglTerminate(display);
    puts(fd < 0 ? "PASS: local allocation and EGLImage FBO"
                : "PASS: native buffer, acquire fence, and ordered reuse");
    return 0;
}

static bool parse_id(const char *arg, unsigned *id) {
    char *end;
    errno = 0;
    unsigned long value = strtoul(arg, &end, 10);
    if (arg[0] < '0' || arg[0] > '9' || *end || errno || value >= UINT_MAX)
        return false;
    *id = (unsigned)value;
    return true;
}

int main(int argc, char **argv) {
    bool check = argc == 3 && !strcmp(argv[1], "check");
    const char *usage_name = check ? argv[2] : argc == 8 ? argv[3] : "";
    uint64_t usage = AHARDWAREBUFFER_USAGE_GPU_FRAMEBUFFER | AHARDWAREBUFFER_USAGE_GPU_SAMPLED_IMAGE;
    if (!strcmp(usage_name, "client-target"))
        usage |= AHARDWAREBUFFER_USAGE_COMPOSER_OVERLAY | (1ULL << 12); // COMPOSER_CLIENT_TARGET
    else if (strcmp(usage_name, "app"))
        check = false;
    setvbuf(stdout, NULL, _IONBF, 0);
    if (check)
        return run_probe(-1, false, false, usage);

    unsigned uid, gid;
    if (argc != 8 || (strcmp(argv[1], "host") && strcmp(argv[1], "producer")) ||
        (strcmp(argv[2], "host-alloc") && strcmp(argv[2], "producer-alloc")) ||
        (strcmp(argv[3], "app") && strcmp(argv[3], "client-target")) ||
        !parse_id(argv[5], &uid) || !parse_id(argv[6], &gid)) {
        fprintf(stderr, "usage: %s check app|client-target\n"
                "       %s host|producer host-alloc|producer-alloc app|client-target "
                "SOCKET PEER_UID PEER_GID PEER_SID\n", argv[0], argv[0]);
        return 2;
    }
    bool host = !strcmp(argv[1], "host");
    int fd = open_peer(argv[4], host);
    if (fd < 0) {
        perror("buffer probe socket");
        return 1;
    }
    struct timeval timeout = {.tv_sec = 10};
    int failed = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout) ||
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof timeout) ||
        ssal_frame_peer(fd, uid, gid, argv[7]) || run_probe(fd, host, !strcmp(argv[2], "host-alloc"), usage);
    close(fd);
    return failed;
}
