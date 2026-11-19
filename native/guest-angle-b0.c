#define _GNU_SOURCE
#include <EGL/egl.h>
#include <EGL/eglext.h>
#include <GLES2/gl2.h>
#include <android/log.h>
#include <dlfcn.h>
#include <link.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#ifdef SSAL_FRAME_P01
#ifndef SSAL_B04
#error SSAL_FRAME_P01 requires the B0.4 all-red readback
#endif
#include "guest-frame-p01.h"
#include <limits.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#endif
#ifdef SSAL_MAPPER_TRACE
#include <inttypes.h>
#include <stdatomic.h>
#include <unwind.h>
#endif

/* ANGLE extension tokens absent from the Android NDK headers. */
#define EGL_PLATFORM_ANGLE_ANGLE 0x3202
#define EGL_PLATFORM_ANGLE_TYPE_ANGLE 0x3203
#define EGL_PLATFORM_ANGLE_TYPE_VULKAN_ANGLE 0x3450
#define EGL_PLATFORM_ANGLE_DEVICE_TYPE_ANGLE 0x3209
#define EGL_PLATFORM_ANGLE_DEVICE_TYPE_SWIFTSHADER_ANGLE 0x3487

static int mapped(struct dl_phdr_info *info, size_t size, void *data) {
    (void)size;
    (void)data;
    if (*info->dlpi_name)
        printf("mapped %s\n", info->dlpi_name);
    return 0;
}

#ifdef SSAL_MAPPER_TRACE
static _Unwind_Reason_Code log_frame(struct _Unwind_Context *context, void *state) {
    unsigned *frame = state;
    uintptr_t pc = _Unwind_GetIP(context);
    if (!pc || *frame == 32)
        return _URC_END_OF_STACK;
    Dl_info info;
    if (dladdr((const void *)(pc - 1), &info)) {
        fprintf(stderr, "mapper-frame %02u %s +0x%" PRIxPTR " %s\n", *frame,
                info.dli_fname, pc - 1 - (uintptr_t)info.dli_fbase,
                info.dli_sname ? info.dli_sname : "-");
    }
    ++*frame;
    return _URC_NO_REASON;
}
#endif

static void log_to_stderr(const struct __android_log_message *message) {
    fprintf(stderr, "android[%s/%d] %s\n", message->tag, message->priority, message->message);
#ifdef SSAL_MAPPER_TRACE
    static atomic_bool readiness_traced, mapper_traced;
    atomic_bool *traced = NULL;
    if (!strcmp(message->tag, "libbinder.BackendUnifiedServiceManager") &&
        strstr(message->message, "servicemanager.ready"))
        traced = &readiness_traced;
    if (!strcmp(message->tag, "GraphicBufferMapper") &&
        strstr(message->message, "gralloc-mapper is missing"))
        traced = &mapper_traced;
    if (traced && !atomic_exchange(traced, true)) {
        unsigned frame = 0;
        _Unwind_Backtrace(log_frame, &frame);
    }
#endif
}

static void EGLAPIENTRY egl_debug(EGLenum error, const char *command, EGLint type,
                                  EGLLabelKHR thread, EGLLabelKHR object, const char *message) {
    (void)thread;
    (void)object;
    fprintf(stderr, "EGL_KHR_debug %s type=0x%04x error=0x%04x: %s\n",
            command, type, error, message ? message : "");
}

#define LOAD(handle, type, name) \
    type name = (type)dlsym(handle, #name); \
    if (!name) { fprintf(stderr, "dlsym(%s): %s\n", #name, dlerror()); return 1; }
#define EGL_CHECK(call) \
    if (!(call)) { fprintf(stderr, "%s: EGL error 0x%04x\n", #call, eglGetError()); return 1; }
#define GL_CHECK(call) do { \
    call; \
    GLenum error = glGetError(); \
    if (error != GL_NO_ERROR) { fprintf(stderr, "%s: GL error 0x%04x\n", #call, error); return 1; } \
} while (0)
#define EGL_STAGE(type, value, call, success) \
    puts("begin " #call); \
    type value = call; \
    EGLint value##_error = eglGetError(); \
    printf("%s: return=%p EGL=0x%04x\n", #call, (void *)(uintptr_t)value, value##_error); \
    if (!(success) || value##_error != EGL_SUCCESS) return 1
#define GL_STAGE(call) do { \
    puts("begin " #call); \
    call; \
    GLenum error = glGetError(); \
    printf("%s: return=void GL=0x%04x\n", #call, error); \
    if (error != GL_NO_ERROR) return 1; \
} while (0)

#ifdef SSAL_FRAME_P01
static int connect_frame(const char *path, bool bridge) {
    struct sockaddr_un address = { .sun_family = AF_UNIX };
    if (strlen(path) >= sizeof address.sun_path) {
        fputs("Guest socket path too long\n", stderr);
        return -1;
    }
    strcpy(address.sun_path, path);
    int fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        perror("Guest socket(AF_UNIX, SOCK_SEQPACKET)");
        return -1;
    }
    fprintf(stderr, "Guest connect path=%s pid=%ld uid=%u gid=%u\n",
            path, (long)getpid(), getuid(), getgid());
    if (connect(fd, (struct sockaddr *)&address, sizeof address)) {
        perror("Guest connect");
        close(fd);
        return -1;
    }
    if (ssal_frame_peer(fd, bridge ? 2000 : 0, bridge ? 2000 : 0,
                        bridge ? SSAL_P02_BRIDGE_SID : "u:r:ksu:s0")) {
        close(fd);
        return -1;
    }
    return fd;
}
#endif

int main(int argc, char **argv) {
#ifdef SSAL_FRAME_P01
    bool bridge = argc == 4 && !strcmp(argv[3], "--bridge") && argv[2][0] == '/';
    if ((argc != 3 && !bridge) || strcmp(argv[1], "vulkan")) {
        fprintf(stderr, "usage: %s vulkan FRAME_FD|SOCKET_PATH [--bridge]\n", argv[0]);
        return 2;
    }
    setvbuf(stdout, NULL, _IONBF, 0);
    long frame_fd;
    if (argv[2][0] == '/') {
        frame_fd = connect_frame(argv[2], bridge);
        if (frame_fd < 0)
            return 1;
    } else {
        char *end;
        frame_fd = strtol(argv[2], &end, 10);
        if (*end || frame_fd < 3 || frame_fd > INT_MAX) {
            fputs("Invalid Guest frame descriptor\n", stderr);
            return 2;
        }
    }
#else
    if (argc != 2 || (strcmp(argv[1], "swiftshader") && strcmp(argv[1], "vulkan"))) {
        fprintf(stderr, "usage: %s swiftshader|vulkan\n", argv[0]);
        return 2;
    }
#endif
    bool swiftshader = !strcmp(argv[1], "swiftshader");
#ifndef SSAL_FRAME_P01
    setvbuf(stdout, NULL, _IONBF, 0);
#endif
    __android_log_set_logger(log_to_stderr);
    __android_log_set_minimum_priority(ANDROID_LOG_VERBOSE);
    printf("requested=%s\n", argv[1]);
    void *egl = dlopen("/system/lib64/libEGL_angle.so", RTLD_NOW | RTLD_LOCAL);
    if (!egl) {
        fprintf(stderr, "dlopen(libEGL_angle.so): %s\n", dlerror());
        return 1;
    }
    puts("dlopen(libEGL_angle.so): OK");
    LOAD(egl, PFNEGLGETERRORPROC, eglGetError);
    LOAD(egl, PFNEGLQUERYSTRINGPROC, eglQueryString);
    LOAD(egl, PFNEGLGETPROCADDRESSPROC, eglGetProcAddress);
    LOAD(egl, PFNEGLINITIALIZEPROC, eglInitialize);
    const char *client = eglQueryString(EGL_NO_DISPLAY, EGL_EXTENSIONS);
    EGL_CHECK(client);
    printf("EGL_CLIENT_EXTENSIONS=%s\n", client);
    PFNEGLDEBUGMESSAGECONTROLKHRPROC debug_control =
        (PFNEGLDEBUGMESSAGECONTROLKHRPROC)eglGetProcAddress("eglDebugMessageControlKHR");
    if (strstr(client, "EGL_KHR_debug") && debug_control) {
        EGLint status = debug_control(egl_debug, NULL);
        if (status != EGL_SUCCESS)
            fprintf(stderr, "eglDebugMessageControlKHR: EGL status 0x%04x\n", status);
    }

    PFNEGLGETPLATFORMDISPLAYEXTPROC get_display =
        (PFNEGLGETPLATFORMDISPLAYEXTPROC)eglGetProcAddress("eglGetPlatformDisplayEXT");
    if (!get_display) {
        fprintf(stderr, "eglGetProcAddress(eglGetPlatformDisplayEXT): NULL, EGL error 0x%04x\n",
                eglGetError());
        return 1;
    }
    const EGLint display_attrs[] = {
        EGL_PLATFORM_ANGLE_TYPE_ANGLE, EGL_PLATFORM_ANGLE_TYPE_VULKAN_ANGLE,
        swiftshader ? EGL_PLATFORM_ANGLE_DEVICE_TYPE_ANGLE : EGL_NONE,
        EGL_PLATFORM_ANGLE_DEVICE_TYPE_SWIFTSHADER_ANGLE, EGL_NONE,
    };
    EGLDisplay display = get_display(EGL_PLATFORM_ANGLE_ANGLE, EGL_DEFAULT_DISPLAY, display_attrs);
    if (display == EGL_NO_DISPLAY) {
        fprintf(stderr, "eglGetPlatformDisplayEXT: EGL error 0x%04x\n", eglGetError());
        dl_iterate_phdr(mapped, NULL);
        return 1;
    }
    puts("eglGetPlatformDisplayEXT: OK");
    EGLint major, minor;
    EGL_STAGE(EGLBoolean, initialized, eglInitialize(display, &major, &minor), initialized);
    printf("eglInitialize: EGL %d.%d\n", major, minor);
    dl_iterate_phdr(mapped, NULL);

    const char *vendor = eglQueryString(display, EGL_VENDOR);
    EGL_CHECK(vendor);
    printf("EGL_VENDOR=%s\n", vendor);
    const char *extensions = eglQueryString(display, EGL_EXTENSIONS);
    EGL_CHECK(extensions);
    printf("EGL_DISPLAY_EXTENSIONS=%s\n", extensions);
    LOAD(egl, PFNEGLBINDAPIPROC, eglBindAPI);
    LOAD(egl, PFNEGLCHOOSECONFIGPROC, eglChooseConfig);
    LOAD(egl, PFNEGLCREATEPBUFFERSURFACEPROC, eglCreatePbufferSurface);
    LOAD(egl, PFNEGLCREATECONTEXTPROC, eglCreateContext);
    LOAD(egl, PFNEGLMAKECURRENTPROC, eglMakeCurrent);
    LOAD(egl, PFNEGLDESTROYCONTEXTPROC, eglDestroyContext);
    LOAD(egl, PFNEGLDESTROYSURFACEPROC, eglDestroySurface);
    LOAD(egl, PFNEGLTERMINATEPROC, eglTerminate);
    EGL_CHECK(eglBindAPI(EGL_OPENGL_ES_API));
    const EGLint config_attrs[] = {
        EGL_SURFACE_TYPE, EGL_PBUFFER_BIT, EGL_RENDERABLE_TYPE, EGL_OPENGL_ES2_BIT,
        EGL_RED_SIZE, 8, EGL_GREEN_SIZE, 8, EGL_BLUE_SIZE, 8, EGL_ALPHA_SIZE, 8, EGL_NONE,
    };
    EGLConfig config;
    EGLint count;
    EGL_CHECK(eglChooseConfig(display, config_attrs, &config, 1, &count));
    if (count != 1) {
        fprintf(stderr, "eglChooseConfig: no RGBA pbuffer GLES2 config\n");
        return 1;
    }
#ifdef SSAL_B04
    LOAD(egl, PFNEGLGETCONFIGATTRIBPROC, eglGetConfigAttrib);
    const EGLint channels[] = { EGL_RED_SIZE, EGL_GREEN_SIZE, EGL_BLUE_SIZE, EGL_ALPHA_SIZE };
    EGLint sizes[4];
    for (unsigned i = 0; i < sizeof channels / sizeof channels[0]; ++i)
        EGL_CHECK(eglGetConfigAttrib(display, config, channels[i], &sizes[i]));
    printf("eglChooseConfig: RGBA=%d/%d/%d/%d\n", sizes[0], sizes[1], sizes[2], sizes[3]);
    if (sizes[0] != 8 || sizes[1] != 8 || sizes[2] != 8 || sizes[3] != 8)
        return 1;
#endif
#ifdef SSAL_FRAME_P01
    enum { width = SSAL_P01_WIDTH, height = SSAL_P01_HEIGHT };
#else
    enum { width = 4, height = 4 };
#endif
    const EGLint surface_attrs[] = { EGL_WIDTH, width, EGL_HEIGHT, height, EGL_NONE };
    const EGLint context_attrs[] = { EGL_CONTEXT_CLIENT_VERSION, 2, EGL_NONE };
    EGL_STAGE(EGLSurface, surface, eglCreatePbufferSurface(display, config, surface_attrs),
              surface != EGL_NO_SURFACE);
    EGL_STAGE(EGLContext, context, eglCreateContext(display, config, EGL_NO_CONTEXT, context_attrs),
              context != EGL_NO_CONTEXT);
    EGL_STAGE(EGLBoolean, current, eglMakeCurrent(display, surface, surface, context), current);

    void *gles = dlopen("/system/lib64/libGLESv2_angle.so", RTLD_NOW | RTLD_LOCAL);
    if (!gles) {
        fprintf(stderr, "dlopen(libGLESv2_angle.so): %s\n", dlerror());
        return 1;
    }
    LOAD(gles, PFNGLGETERRORPROC, glGetError);
    LOAD(gles, PFNGLGETSTRINGPROC, glGetString);
    LOAD(gles, PFNGLCLEARCOLORPROC, glClearColor);
    LOAD(gles, PFNGLCLEARPROC, glClear);
    LOAD(gles, PFNGLREADPIXELSPROC, glReadPixels);
    const GLubyte *renderer, *gl_extensions, *version;
    GL_CHECK(renderer = glGetString(GL_RENDERER));
    GL_CHECK(version = glGetString(GL_VERSION));
    GL_CHECK(gl_extensions = glGetString(GL_EXTENSIONS));
    if (!renderer || !version || !gl_extensions) {
        fputs("glGetString: NULL without a GL error\n", stderr);
        return 1;
    }
    printf("GL_RENDERER=%s\nGL_VERSION=%s\nGL_EXTENSIONS=%s\n", renderer, version, gl_extensions);
    dl_iterate_phdr(mapped, NULL);

    GL_STAGE(glClearColor(1, 0, 0, 1));
    GL_STAGE(glClear(GL_COLOR_BUFFER_BIT));
#ifndef SSAL_B04
    LOAD(gles, PFNGLENABLEPROC, glEnable);
    LOAD(gles, PFNGLSCISSORPROC, glScissor);
    GL_CHECK(glEnable(GL_SCISSOR_TEST));
    GL_CHECK(glScissor(width / 2, 0, width / 2, height));
    GL_CHECK(glClearColor(0, 0, 1, 1));
    GL_CHECK(glClear(GL_COLOR_BUFFER_BIT));
#endif
    GLubyte pixels[height][width][4] = {0};
    GL_STAGE(glReadPixels(0, 0, width, height, GL_RGBA, GL_UNSIGNED_BYTE, pixels));
#ifdef SSAL_FRAME_P01
    if (!strstr((const char *)renderer, "SwiftShader")) {
        fputs("Pastel SwiftShader renderer was not selected\n", stderr);
        return 1;
    }
    _Static_assert(sizeof pixels == SSAL_P01_PIXELS, "unexpected readback size");
    unsigned char frame[SSAL_P01_HEADER + sizeof pixels] = SSAL_P01_MAGIC;
    frame[4] = width;
    frame[5] = height;
    frame[6] = sizeof pixels[0];
    frame[7] = SSAL_P01_RGBA8;
    memcpy(frame + SSAL_P01_HEADER, pixels, sizeof pixels);
    printf("Guest begin send fd=%ld packet=%zu payload=%zu\n", frame_fd, sizeof frame, sizeof pixels);
    ssize_t sent = send((int)frame_fd, frame, sizeof frame, MSG_NOSIGNAL | MSG_DONTWAIT);
    if (sent < 0) {
        perror("Guest send");
        return 1;
    }
    printf("Guest send=%zd\n", sent);
    if (sent != sizeof frame)
        return 1;
#else
    printf("pixel(0,0)=%u,%u,%u,%u\n", pixels[0][0][0], pixels[0][0][1],
           pixels[0][0][2], pixels[0][0][3]);
    const GLubyte colors[][4] = {{255, 0, 0, 255}, {0, 0, 255, 255}};
    for (int y = 0; y < height; ++y) {
        for (int x = 0; x < width; ++x) {
#ifdef SSAL_B04
            const GLubyte *expected = colors[0];
#else
            const GLubyte *expected = colors[x >= width / 2];
#endif
            const GLubyte *pixel = pixels[y][x];
            if (memcmp(pixel, expected, sizeof colors[0])) {
                fprintf(stderr, "pixel(%d,%d) got %u,%u,%u,%u expected %u,%u,%u,%u\n",
                        x, y, pixel[0], pixel[1], pixel[2], pixel[3],
                        expected[0], expected[1], expected[2], expected[3]);
                return 1;
            }
        }
    }
    puts("glReadPixels: 16/16 RGBA pixels match");
#endif
    bool swiftshader_selected = strstr((const char *)renderer, "SwiftShader") != NULL;
    EGL_CHECK(eglMakeCurrent(display, EGL_NO_SURFACE, EGL_NO_SURFACE, EGL_NO_CONTEXT));
    EGL_CHECK(eglDestroyContext(display, context));
    EGL_CHECK(eglDestroySurface(display, surface));
    EGL_CHECK(eglTerminate(display));
    if (swiftshader && !swiftshader_selected) {
        fputs("requested SwiftShader renderer was not selected\n", stderr);
        return 1;
    }
    return 0;
}
