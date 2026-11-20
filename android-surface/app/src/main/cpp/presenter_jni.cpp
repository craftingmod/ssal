#include <EGL/egl.h>
#include <EGL/eglext.h>
#include <GLES2/gl2.h>
#include <GLES2/gl2ext.h>
#include <android/hardware_buffer.h>
#include <android/log.h>
#include <android/native_window_jni.h>
#include <dlfcn.h>
#include <errno.h>
#include <jni.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#define LOG_TAG "SsalNativePresenter"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

namespace {

constexpr uint32_t kPacketMagic = 0x5353414C; // 'SSAL'
constexpr uint32_t kPacketVersion = 1;
constexpr uint32_t kTouchMagic = 0x53544348; // 'STCH'
constexpr uint32_t kKeyMagic = 0x534B4559; // 'SKEY'
constexpr uint32_t kTouchVersion = 1;
constexpr uint32_t kMaxTouchPointers = 10;
constexpr size_t kMaxScmFds = 32;
constexpr size_t kMaxInts = 256;
constexpr int32_t kCreateFromHandleMethodRegister = 1;
constexpr int32_t kCreateFromHandleMethodClone = 2;

struct TouchPointer {
    int32_t id;
    float x;
    float y;
    float pressure;
};

struct TouchPacketHeader {
    uint32_t magic;
    uint32_t version;
    int32_t action;
    uint32_t pointer_count;
    int64_t down_time_ms;
    int64_t event_time_ms;
};

static_assert(sizeof(TouchPointer) == 16, "TouchPointer size mismatch");
static_assert(sizeof(TouchPacketHeader) == 32, "TouchPacketHeader size mismatch");

struct PresenterPacketHeader {
    uint32_t magic;
    uint32_t version;
    int32_t slot;
    uint32_t width;
    uint32_t height;
    uint32_t format;
    int32_t dataspace;
    uint32_t num_fds;
    uint32_t num_ints;
    uint32_t has_fence;
};

struct native_handle_t {
    int version;
    int numFds;
    int numInts;
    int data[0];
};

using CreateFromHandleFn = int (*)(const AHardwareBuffer_Desc* desc,
                                   const native_handle_t* handle,
                                   int32_t method,
                                   AHardwareBuffer** outBuffer);

CreateFromHandleFn load_create_from_handle() {
    void* lib = dlopen("libnativewindow.so", RTLD_NOW | RTLD_LOCAL);
    if (!lib) {
        LOGE("dlopen(libnativewindow.so) failed: %s", dlerror());
        return nullptr;
    }
    auto fn = reinterpret_cast<CreateFromHandleFn>(
        dlsym(lib, "AHardwareBuffer_createFromHandle"));
    if (!fn) {
        LOGE("dlsym(AHardwareBuffer_createFromHandle) failed: %s", dlerror());
    }
    return fn;
}

int connect_unix_seqpacket(const std::string& addr) {
    int fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        return -1;
    }

    struct sockaddr_un sun {};
    sun.sun_family = AF_UNIX;
    socklen_t addr_len = 0;

    if (!addr.empty() && addr[0] == '@') {
        const size_t name_len = addr.size() - 1;
        if (name_len + 1 > sizeof(sun.sun_path)) {
            close(fd);
            errno = ENAMETOOLONG;
            return -1;
        }
        sun.sun_path[0] = '\0';
        std::memcpy(sun.sun_path + 1, addr.data() + 1, name_len);
        addr_len = static_cast<socklen_t>(sizeof(sun.sun_family) + 1 + name_len);
    } else {
        if (addr.size() + 1 > sizeof(sun.sun_path)) {
            close(fd);
            errno = ENAMETOOLONG;
            return -1;
        }
        std::memcpy(sun.sun_path, addr.c_str(), addr.size() + 1);
        addr_len = static_cast<socklen_t>(sizeof(sun.sun_family) + addr.size() + 1);
    }

    if (connect(fd, reinterpret_cast<struct sockaddr*>(&sun), addr_len) < 0) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }
    return fd;
}

int bind_unix_seqpacket(const std::string& path) {
    if (path.empty() || path.size() + 1 > sizeof(sockaddr_un::sun_path)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    int fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        return -1;
    }
    unlink(path.c_str());

    struct sockaddr_un sun {};
    sun.sun_family = AF_UNIX;
    std::memcpy(sun.sun_path, path.c_str(), path.size() + 1);
    const auto addr_len = static_cast<socklen_t>(sizeof(sun.sun_family) + path.size() + 1);

    if (bind(fd, reinterpret_cast<struct sockaddr*>(&sun), addr_len) < 0 ||
        listen(fd, 4) < 0) {
        int saved = errno;
        close(fd);
        unlink(path.c_str());
        errno = saved;
        return -1;
    }
    chmod(path.c_str(), 0600);
    return fd;
}

void close_fds(const std::vector<int>& fds) {
    for (int fd : fds) {
        if (fd >= 0) {
            close(fd);
        }
    }
}

struct NativePresenter {
    std::string socket_addr;
    CreateFromHandleFn create_from_handle = nullptr;
    std::atomic<bool> running{true};
    std::atomic<int> active_listener_fd{-1};
    std::atomic<int> active_peer_fd{-1};
    std::atomic<int32_t> pending_key_code{0};
    std::atomic<int64_t> pending_key_time_ms{0};

    std::mutex surface_mutex;
    ANativeWindow* window = nullptr;
    int32_t surface_width = 0;
    int32_t surface_height = 0;

    EGLDisplay egl_display = EGL_NO_DISPLAY;
    EGLConfig egl_config = nullptr;
    EGLContext egl_context = EGL_NO_CONTEXT;
    EGLSurface egl_surface = EGL_NO_SURFACE;
    GLuint gl_program = 0;
    GLuint gl_texture = 0;
    GLint gl_pos_loc = -1;
    GLint gl_uv_loc = -1;
    GLint gl_tex_loc = -1;
    PFNEGLGETNATIVECLIENTBUFFERANDROIDPROC pfn_eglGetNativeClientBufferANDROID = nullptr;
    PFNEGLCREATEIMAGEKHRPROC pfn_eglCreateImageKHR = nullptr;
    PFNEGLDESTROYIMAGEKHRPROC pfn_eglDestroyImageKHR = nullptr;
    PFNGLEGLIMAGETARGETTEXTURE2DOESPROC pfn_glEGLImageTargetTexture2DOES = nullptr;

    std::mutex geom_mutex;
    uint32_t guest_width = 0;
    uint32_t guest_height = 0;
    int32_t dst_x = 0;
    int32_t dst_y = 0;
    int32_t dst_w = 0;
    int32_t dst_h = 0;

    uint32_t probed_width = 0;
    uint32_t probed_height = 0;
    uint32_t probed_format = 0;
    uint32_t probed_stride = 0;

    std::unordered_map<int32_t, AHardwareBuffer*> slot_cache;
    std::thread rx_thread;

    explicit NativePresenter(std::string addr)
        : socket_addr(std::move(addr)),
          create_from_handle(load_create_from_handle()) {
        rx_thread = std::thread(&NativePresenter::run_loop, this);
    }

    ~NativePresenter() {
        running.store(false, std::memory_order_release);
        int listener = active_listener_fd.load(std::memory_order_acquire);
        if (listener >= 0) {
            shutdown(listener, SHUT_RDWR);
        }
        int peer = active_peer_fd.load(std::memory_order_acquire);
        if (peer >= 0) {
            shutdown(peer, SHUT_RDWR);
        }
        if (rx_thread.joinable()) {
            rx_thread.join();
        }
        clear_slot_cache();
        set_surface(nullptr, 0, 0);
        destroy_egl();
    }

    void clear_slot_cache() {
        for (auto& [slot, ahb] : slot_cache) {
            if (ahb) {
                AHardwareBuffer_release(ahb);
            }
        }
        slot_cache.clear();
    }

    static GLuint compile_shader(GLenum type, const char* src) {
        GLuint shader = glCreateShader(type);
        if (!shader) {
            return 0;
        }
        glShaderSource(shader, 1, &src, nullptr);
        glCompileShader(shader);
        GLint ok = 0;
        glGetShaderiv(shader, GL_COMPILE_STATUS, &ok);
        if (!ok) {
            char log[256]{};
            glGetShaderInfoLog(shader, sizeof(log), nullptr, log);
            LOGE("Shader compile failed: %s", log);
            glDeleteShader(shader);
            return 0;
        }
        return shader;
    }

    bool ensure_egl() {
        if (egl_display != EGL_NO_DISPLAY && egl_context != EGL_NO_CONTEXT && gl_program != 0) {
            return true;
        }
        egl_display = eglGetDisplay(EGL_DEFAULT_DISPLAY);
        if (egl_display == EGL_NO_DISPLAY || !eglInitialize(egl_display, nullptr, nullptr)) {
            LOGE("eglInitialize failed: 0x%x", eglGetError());
            egl_display = EGL_NO_DISPLAY;
            return false;
        }
        const EGLint cfg_attrs[] = {
            EGL_RENDERABLE_TYPE, EGL_OPENGL_ES2_BIT,
            EGL_SURFACE_TYPE, EGL_WINDOW_BIT,
            EGL_RED_SIZE, 8,
            EGL_GREEN_SIZE, 8,
            EGL_BLUE_SIZE, 8,
            EGL_ALPHA_SIZE, 8,
            EGL_NONE,
        };
        EGLint num_cfg = 0;
        if (!eglChooseConfig(egl_display, cfg_attrs, &egl_config, 1, &num_cfg) || num_cfg < 1) {
            LOGE("eglChooseConfig failed: 0x%x", eglGetError());
            return false;
        }
        const EGLint ctx_attrs[] = {EGL_CONTEXT_CLIENT_VERSION, 2, EGL_NONE};
        egl_context = eglCreateContext(egl_display, egl_config, EGL_NO_CONTEXT, ctx_attrs);
        if (egl_context == EGL_NO_CONTEXT) {
            LOGE("eglCreateContext failed: 0x%x", eglGetError());
            return false;
        }
        pfn_eglGetNativeClientBufferANDROID =
            reinterpret_cast<PFNEGLGETNATIVECLIENTBUFFERANDROIDPROC>(
                eglGetProcAddress("eglGetNativeClientBufferANDROID"));
        pfn_eglCreateImageKHR =
            reinterpret_cast<PFNEGLCREATEIMAGEKHRPROC>(
                eglGetProcAddress("eglCreateImageKHR"));
        pfn_eglDestroyImageKHR =
            reinterpret_cast<PFNEGLDESTROYIMAGEKHRPROC>(
                eglGetProcAddress("eglDestroyImageKHR"));
        pfn_glEGLImageTargetTexture2DOES =
            reinterpret_cast<PFNGLEGLIMAGETARGETTEXTURE2DOESPROC>(
                eglGetProcAddress("glEGLImageTargetTexture2DOES"));
        if (!pfn_eglGetNativeClientBufferANDROID || !pfn_eglCreateImageKHR ||
            !pfn_eglDestroyImageKHR || !pfn_glEGLImageTargetTexture2DOES) {
            LOGE("Missing required EGL/GLES OES extension functions");
            return false;
        }
        return true;
    }

    bool ensure_gl_resources() {
        if (gl_program != 0 && gl_texture != 0) {
            return true;
        }
        static const char kVertSrc[] =
            "attribute vec2 aPos;\n"
            "attribute vec2 aUv;\n"
            "varying vec2 vUv;\n"
            "void main() {\n"
            "  vUv = aUv;\n"
            "  gl_Position = vec4(aPos, 0.0, 1.0);\n"
            "}\n";
        static const char kFragSrc[] =
            "#extension GL_OES_EGL_image_external : require\n"
            "precision mediump float;\n"
            "varying vec2 vUv;\n"
            "uniform samplerExternalOES uTex;\n"
            "void main() {\n"
            "  gl_FragColor = texture2D(uTex, vUv);\n"
            "}\n";
        GLuint vs = compile_shader(GL_VERTEX_SHADER, kVertSrc);
        GLuint fs = compile_shader(GL_FRAGMENT_SHADER, kFragSrc);
        if (!vs || !fs) {
            if (vs) glDeleteShader(vs);
            if (fs) glDeleteShader(fs);
            return false;
        }
        gl_program = glCreateProgram();
        glAttachShader(gl_program, vs);
        glAttachShader(gl_program, fs);
        glLinkProgram(gl_program);
        glDeleteShader(vs);
        glDeleteShader(fs);
        GLint linked = 0;
        glGetProgramiv(gl_program, GL_LINK_STATUS, &linked);
        if (!linked) {
            LOGE("GL program link failed");
            glDeleteProgram(gl_program);
            gl_program = 0;
            return false;
        }
        gl_pos_loc = glGetAttribLocation(gl_program, "aPos");
        gl_uv_loc = glGetAttribLocation(gl_program, "aUv");
        gl_tex_loc = glGetUniformLocation(gl_program, "uTex");
        glGenTextures(1, &gl_texture);
        glBindTexture(GL_TEXTURE_EXTERNAL_OES, gl_texture);
        glTexParameteri(GL_TEXTURE_EXTERNAL_OES, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
        glTexParameteri(GL_TEXTURE_EXTERNAL_OES, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
        glTexParameteri(GL_TEXTURE_EXTERNAL_OES, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
        glTexParameteri(GL_TEXTURE_EXTERNAL_OES, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
        return true;
    }

    void destroy_egl_surface() {
        if (egl_display != EGL_NO_DISPLAY && egl_surface != EGL_NO_SURFACE) {
            eglMakeCurrent(egl_display, EGL_NO_SURFACE, EGL_NO_SURFACE, EGL_NO_CONTEXT);
            eglDestroySurface(egl_display, egl_surface);
            egl_surface = EGL_NO_SURFACE;
        }
    }

    void destroy_egl() {
        destroy_egl_surface();
        if (egl_display != EGL_NO_DISPLAY) {
            if (egl_context != EGL_NO_CONTEXT) {
                eglDestroyContext(egl_display, egl_context);
                egl_context = EGL_NO_CONTEXT;
            }
            eglTerminate(egl_display);
            egl_display = EGL_NO_DISPLAY;
        }
        gl_program = 0;
        gl_texture = 0;
    }

    void set_surface(ANativeWindow* new_window, int32_t width, int32_t height) {
        std::lock_guard<std::mutex> lock(surface_mutex);
        if (new_window == nullptr || width <= 0 || height <= 0) {
            destroy_egl_surface();
            if (window) {
                ANativeWindow_release(window);
                window = nullptr;
            }
            surface_width = 0;
            surface_height = 0;
            {
                std::lock_guard<std::mutex> geom_lock(geom_mutex);
                dst_x = 0;
                dst_y = 0;
                dst_w = 0;
                dst_h = 0;
            }
            if (new_window) {
                ANativeWindow_release(new_window);
            }
            return;
        }

        if (window != new_window) {
            destroy_egl_surface();
            if (window) {
                ANativeWindow_release(window);
            }
            window = new_window;
            if (ensure_egl()) {
                egl_surface = eglCreateWindowSurface(egl_display, egl_config, window, nullptr);
                if (egl_surface == EGL_NO_SURFACE) {
                    LOGE("eglCreateWindowSurface failed: 0x%x", eglGetError());
                } else {
                    LOGI("Created EGLWindowSurface %dx%d", width, height);
                }
            }
        } else {
            ANativeWindow_release(new_window);
        }
        surface_width = width;
        surface_height = height;
    }

    void handle_packet(const PresenterPacketHeader& hdr,
                       const int32_t* ints,
                       std::vector<int>& fds) {
        if (hdr.num_fds > 0 || hdr.num_ints > 0) {
            if (!create_from_handle) {
                close_fds(fds);
                return;
            }
            const size_t handle_bytes =
                sizeof(native_handle_t) + (hdr.num_fds + hdr.num_ints) * sizeof(int);
            auto* handle = static_cast<native_handle_t*>(std::calloc(1, handle_bytes));
            if (!handle) {
                close_fds(fds);
                return;
            }
            handle->version = sizeof(native_handle_t);
            handle->numFds = static_cast<int>(hdr.num_fds);
            handle->numInts = static_cast<int>(hdr.num_ints);
            for (uint32_t i = 0; i < hdr.num_fds; ++i) {
                handle->data[i] = fds[i];
            }
            for (uint32_t i = 0; i < hdr.num_ints; ++i) {
                handle->data[hdr.num_fds + i] = ints[i];
            }

            uint32_t aligned_stride = hdr.width;
            if (probed_width == hdr.width &&
                probed_height == hdr.height &&
                probed_format == hdr.format &&
                probed_stride > 0) {
                aligned_stride = probed_stride;
            } else {
                AHardwareBuffer_Desc probe_desc{};
                probe_desc.width = hdr.width;
                probe_desc.height = hdr.height;
                probe_desc.layers = 1;
                probe_desc.format = hdr.format;
                probe_desc.usage =
                    AHARDWAREBUFFER_USAGE_GPU_SAMPLED_IMAGE |
                    AHARDWAREBUFFER_USAGE_GPU_FRAMEBUFFER |
                    AHARDWAREBUFFER_USAGE_COMPOSER_OVERLAY |
                    (1ULL << 12);
                AHardwareBuffer* probe_ahb = nullptr;
                if (AHardwareBuffer_allocate(&probe_desc, &probe_ahb) == 0 && probe_ahb) {
                    AHardwareBuffer_describe(probe_ahb, &probe_desc);
                    aligned_stride = probe_desc.stride;
                    probed_width = hdr.width;
                    probed_height = hdr.height;
                    probed_format = hdr.format;
                    probed_stride = aligned_stride;
                    LOGI("Probed allocator %ux%u fmt=%u -> stride=%u",
                         probe_desc.width, probe_desc.height, probe_desc.format, aligned_stride);
                    AHardwareBuffer_release(probe_ahb);
                }
            }

            const uint32_t candidate_strides[] = {
                aligned_stride,
                hdr.width,
                (hdr.width + 31u) & ~31u,
                (hdr.width + 63u) & ~63u,
                (hdr.width + 127u) & ~127u,
            };
            const uint64_t candidate_usages[] = {
                AHARDWAREBUFFER_USAGE_GPU_SAMPLED_IMAGE |
                    AHARDWAREBUFFER_USAGE_GPU_FRAMEBUFFER |
                    AHARDWAREBUFFER_USAGE_COMPOSER_OVERLAY |
                    (1ULL << 12),
                AHARDWAREBUFFER_USAGE_GPU_FRAMEBUFFER |
                    AHARDWAREBUFFER_USAGE_COMPOSER_OVERLAY |
                    (1ULL << 12),
                AHARDWAREBUFFER_USAGE_GPU_SAMPLED_IMAGE |
                    AHARDWAREBUFFER_USAGE_GPU_FRAMEBUFFER |
                    AHARDWAREBUFFER_USAGE_COMPOSER_OVERLAY,
                AHARDWAREBUFFER_USAGE_GPU_SAMPLED_IMAGE |
                    AHARDWAREBUFFER_USAGE_GPU_FRAMEBUFFER,
                0,
            };

            AHardwareBuffer* ahb = nullptr;
            int rc = -22;
            uint32_t used_stride = hdr.width;
            uint64_t used_usage = 0;
            int32_t used_method = kCreateFromHandleMethodClone;
            for (int32_t method : {kCreateFromHandleMethodClone, kCreateFromHandleMethodRegister}) {
                for (uint64_t usage : candidate_usages) {
                    for (uint32_t stride : candidate_strides) {
                        AHardwareBuffer_Desc desc{};
                        desc.width = hdr.width;
                        desc.height = hdr.height;
                        desc.layers = 1;
                        desc.format = hdr.format;
                        desc.usage = usage;
                        desc.stride = stride;
                        rc = create_from_handle(&desc, handle, method, &ahb);
                        if (rc == 0 && ahb) {
                            used_stride = stride;
                            used_usage = usage;
                            used_method = method;
                            break;
                        }
                        ahb = nullptr;
                    }
                    if (ahb) {
                        break;
                    }
                }
                if (ahb) {
                    break;
                }
            }
            if (rc != 0 || !ahb) {
                std::free(handle);
            }
            if (rc != 0 || !ahb || used_method == kCreateFromHandleMethodClone) {
                for (uint32_t i = 0; i < hdr.num_fds; ++i) {
                    close(fds[i]);
                    fds[i] = -1;
                }
            }
            if (rc != 0 || !ahb) {
                AHardwareBuffer_Desc probe_desc{};
                probe_desc.width = hdr.width;
                probe_desc.height = hdr.height;
                probe_desc.layers = 1;
                probe_desc.format = hdr.format;
                probe_desc.usage = AHARDWAREBUFFER_USAGE_GPU_SAMPLED_IMAGE |
                                   AHARDWAREBUFFER_USAGE_GPU_FRAMEBUFFER |
                                   AHARDWAREBUFFER_USAGE_COMPOSER_OVERLAY;
                AHardwareBuffer* probe_ahb = nullptr;
                if (AHardwareBuffer_allocate(&probe_desc, &probe_ahb) == 0 && probe_ahb) {
                    AHardwareBuffer_describe(probe_ahb, &probe_desc);
                    LOGE("Probe allocate %ux%u -> stride=%u usage=0x%llx",
                         probe_desc.width, probe_desc.height, probe_desc.stride,
                         static_cast<unsigned long long>(probe_desc.usage));
                    AHardwareBuffer_release(probe_ahb);
                }
                std::string ints_str;
                for (uint32_t i = 0; i < hdr.num_ints && i < 16; ++i) {
                    char buf[24];
                    snprintf(buf, sizeof(buf), "%s%d", i ? "," : "", ints[i]);
                    ints_str += buf;
                }
                LOGE("AHardwareBuffer_createFromHandle failed: rc=%d slot=%d %ux%u fmt=%u fds=%u ints=%u [%s]",
                     rc, hdr.slot, hdr.width, hdr.height, hdr.format, hdr.num_fds, hdr.num_ints, ints_str.c_str());
                if (hdr.has_fence && !fds.empty() && fds.back() >= 0) {
                    close(fds.back());
                }
                return;
            }

            auto it = slot_cache.find(hdr.slot);
            if (it != slot_cache.end() && it->second) {
                AHardwareBuffer_release(it->second);
            }
            slot_cache[hdr.slot] = ahb;
            LOGI("Imported AHardwareBuffer slot=%d %ux%u stride=%u usage=0x%llx fmt=%u",
                 hdr.slot, hdr.width, hdr.height, used_stride,
                 static_cast<unsigned long long>(used_usage), hdr.format);
        }

        int acquire_fence = (hdr.has_fence && !fds.empty()) ? fds.back() : -1;
        auto it = slot_cache.find(hdr.slot);
        AHardwareBuffer* ahb = (it != slot_cache.end()) ? it->second : nullptr;

        std::lock_guard<std::mutex> lock(surface_mutex);
        if (egl_display == EGL_NO_DISPLAY || egl_surface == EGL_NO_SURFACE ||
            egl_context == EGL_NO_CONTEXT || !ahb ||
            surface_width <= 0 || surface_height <= 0) {
            if (acquire_fence >= 0) {
                close(acquire_fence);
            }
            return;
        }

        static int tx_log_count = 0;
        if (tx_log_count < 5) {
            ++tx_log_count;
            LOGI("Apply egl-blit #%d slot=%d %ux%u -> %dx%d dataspace=%d has_fence=%u fence_fd=%d",
                 tx_log_count, hdr.slot, hdr.width, hdr.height,
                 surface_width, surface_height, hdr.dataspace, hdr.has_fence, acquire_fence);
        }

        if (acquire_fence >= 0) {
            struct pollfd pfd { acquire_fence, POLLIN, 0 };
            poll(&pfd, 1, 16);
            close(acquire_fence);
            acquire_fence = -1;
        }

        int32_t cur_dst_w = surface_width;
        int32_t cur_dst_h = surface_height;
        if (hdr.width > 0 && hdr.height > 0) {
            const int64_t lhs = static_cast<int64_t>(surface_width) * hdr.height;
            const int64_t rhs = static_cast<int64_t>(surface_height) * hdr.width;
            if (lhs > rhs) {
                cur_dst_w = static_cast<int32_t>(rhs / hdr.height);
            } else if (lhs < rhs) {
                cur_dst_h = static_cast<int32_t>(lhs / hdr.width);
            }
        }
        const int32_t cur_dst_x = (surface_width - cur_dst_w) / 2;
        const int32_t cur_dst_y = (surface_height - cur_dst_h) / 2;
        {
            std::lock_guard<std::mutex> geom_lock(geom_mutex);
            guest_width = hdr.width;
            guest_height = hdr.height;
            dst_x = cur_dst_x;
            dst_y = cur_dst_y;
            dst_w = cur_dst_w;
            dst_h = cur_dst_h;
        }

        if (!eglMakeCurrent(egl_display, egl_surface, egl_surface, egl_context)) {
            LOGE("eglMakeCurrent failed: 0x%x", eglGetError());
            return;
        }
        if (!ensure_gl_resources()) {
            eglMakeCurrent(egl_display, EGL_NO_SURFACE, EGL_NO_SURFACE, EGL_NO_CONTEXT);
            return;
        }

        EGLClientBuffer client_buf = pfn_eglGetNativeClientBufferANDROID(ahb);
        if (!client_buf) {
            LOGE("eglGetNativeClientBufferANDROID returned null");
            eglMakeCurrent(egl_display, EGL_NO_SURFACE, EGL_NO_SURFACE, EGL_NO_CONTEXT);
            return;
        }
        const EGLint img_attrs[] = {EGL_IMAGE_PRESERVED_KHR, EGL_TRUE, EGL_NONE};
        EGLImageKHR image = pfn_eglCreateImageKHR(
            egl_display, EGL_NO_CONTEXT, EGL_NATIVE_BUFFER_ANDROID, client_buf, img_attrs);
        if (image == EGL_NO_IMAGE_KHR) {
            LOGE("eglCreateImageKHR failed: 0x%x", eglGetError());
            eglMakeCurrent(egl_display, EGL_NO_SURFACE, EGL_NO_SURFACE, EGL_NO_CONTEXT);
            return;
        }

        glViewport(0, 0, surface_width, surface_height);
        glClearColor(0.0f, 0.0f, 0.0f, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT);

        const int32_t gl_y = surface_height - cur_dst_y - cur_dst_h;
        glViewport(cur_dst_x, gl_y, cur_dst_w, cur_dst_h);

        glUseProgram(gl_program);
        glActiveTexture(GL_TEXTURE0);
        glBindTexture(GL_TEXTURE_EXTERNAL_OES, gl_texture);
        pfn_glEGLImageTargetTexture2DOES(GL_TEXTURE_EXTERNAL_OES, image);
        glUniform1i(gl_tex_loc, 0);

        static const GLfloat kPos[] = {
            -1.0f, -1.0f,
             1.0f, -1.0f,
            -1.0f,  1.0f,
             1.0f,  1.0f,
        };
        static const GLfloat kUv[] = {
            0.0f, 1.0f,
            1.0f, 1.0f,
            0.0f, 0.0f,
            1.0f, 0.0f,
        };
        glEnableVertexAttribArray(static_cast<GLuint>(gl_pos_loc));
        glVertexAttribPointer(static_cast<GLuint>(gl_pos_loc), 2, GL_FLOAT, GL_FALSE, 0, kPos);
        glEnableVertexAttribArray(static_cast<GLuint>(gl_uv_loc));
        glVertexAttribPointer(static_cast<GLuint>(gl_uv_loc), 2, GL_FLOAT, GL_FALSE, 0, kUv);
        glDrawArrays(GL_TRIANGLE_STRIP, 0, 4);
        glDisableVertexAttribArray(static_cast<GLuint>(gl_pos_loc));
        glDisableVertexAttribArray(static_cast<GLuint>(gl_uv_loc));

        if (!eglSwapBuffers(egl_display, egl_surface)) {
            LOGE("eglSwapBuffers failed: 0x%x", eglGetError());
        }
        pfn_eglDestroyImageKHR(egl_display, image);
        eglMakeCurrent(egl_display, EGL_NO_SURFACE, EGL_NO_SURFACE, EGL_NO_CONTEXT);
    }

    void send_touch(int32_t action,
                    int32_t pointer_count,
                    int64_t down_time_ms,
                    int64_t event_time_ms,
                    const int32_t* ids,
                    const float* xs,
                    const float* ys,
                    const float* pressures) {
        int peer = active_peer_fd.load(std::memory_order_acquire);
        if (peer < 0 || pointer_count <= 0) {
            return;
        }
        const uint32_t count = std::min(static_cast<uint32_t>(pointer_count), kMaxTouchPointers);

        uint32_t gw = 0;
        uint32_t gh = 0;
        int32_t dx = 0;
        int32_t dy = 0;
        int32_t dw = 0;
        int32_t dh = 0;
        {
            std::lock_guard<std::mutex> geom_lock(geom_mutex);
            gw = guest_width;
            gh = guest_height;
            dx = dst_x;
            dy = dst_y;
            dw = dst_w;
            dh = dst_h;
        }
        if (gw == 0 || gh == 0 || dw <= 0 || dh <= 0) {
            return;
        }

        uint8_t buf[sizeof(TouchPacketHeader) + kMaxTouchPointers * sizeof(TouchPointer)]{};
        TouchPacketHeader hdr{
            kTouchMagic,
            kTouchVersion,
            action,
            count,
            down_time_ms,
            event_time_ms,
        };
        std::memcpy(buf, &hdr, sizeof(hdr));

        const float fw = static_cast<float>(gw);
        const float fh = static_cast<float>(gh);
        const float scale_x = fw / static_cast<float>(dw);
        const float scale_y = fh / static_cast<float>(dh);

        for (uint32_t i = 0; i < count; ++i) {
            float gx = std::clamp((xs[i] - static_cast<float>(dx)) * scale_x, 0.0f, fw);
            float gy = std::clamp((ys[i] - static_cast<float>(dy)) * scale_y, 0.0f, fh);
            TouchPointer ptr{ids[i], gx, gy, pressures[i]};
            std::memcpy(buf + sizeof(hdr) + i * sizeof(TouchPointer), &ptr, sizeof(ptr));
        }

        const size_t total_bytes = sizeof(hdr) + count * sizeof(TouchPointer);
        send(peer, buf, total_bytes, MSG_DONTWAIT | MSG_NOSIGNAL);
    }

    static void send_key_packets(int peer, int32_t key_code, int64_t event_time_ms) {
        if (peer < 0 || key_code <= 0) {
            return;
        }
        for (int32_t action : {0, 1}) { // ACTION_DOWN, ACTION_UP
            TouchPacketHeader hdr{
                kKeyMagic,
                kTouchVersion,
                action,
                static_cast<uint32_t>(key_code),
                event_time_ms,
                event_time_ms,
            };
            send(peer, &hdr, sizeof(hdr), MSG_DONTWAIT | MSG_NOSIGNAL);
        }
    }

    void send_key(int32_t key_code, int64_t event_time_ms) {
        if (key_code <= 0) {
            return;
        }
        int peer = active_peer_fd.load(std::memory_order_acquire);
        if (peer >= 0) {
            send_key_packets(peer, key_code, event_time_ms);
        } else {
            pending_key_time_ms.store(event_time_ms, std::memory_order_release);
            pending_key_code.store(key_code, std::memory_order_release);
        }
    }

    void receive_from_peer(int sock) {
        struct timeval tv { 0, 250 * 1000 };
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        std::vector<uint8_t> payload(
            sizeof(PresenterPacketHeader) + kMaxInts * sizeof(int32_t));
        std::vector<uint8_t> cmsg_buf(CMSG_SPACE(kMaxScmFds * sizeof(int)));

        while (running.load(std::memory_order_acquire)) {
            struct iovec iov { payload.data(), payload.size() };
            struct msghdr msg {};
            msg.msg_iov = &iov;
            msg.msg_iovlen = 1;
            msg.msg_control = cmsg_buf.data();
            msg.msg_controllen = cmsg_buf.size();

            ssize_t n = recvmsg(sock, &msg, MSG_CMSG_CLOEXEC);
            if (n < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                    continue;
                }
                LOGW("recvmsg failed: errno=%d", errno);
                break;
            }
            if (n == 0) {
                LOGI("Presenter socket closed by peer");
                break;
            }

            std::vector<int> fds;
            for (struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
                 cmsg != nullptr;
                 cmsg = CMSG_NXTHDR(&msg, cmsg)) {
                if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
                    size_t count = (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int);
                    const auto* data = reinterpret_cast<const int*>(CMSG_DATA(cmsg));
                    fds.insert(fds.end(), data, data + count);
                }
            }

            if (static_cast<size_t>(n) < sizeof(PresenterPacketHeader) ||
                (msg.msg_flags & (MSG_TRUNC | MSG_CTRUNC))) {
                close_fds(fds);
                continue;
            }

            PresenterPacketHeader hdr{};
            std::memcpy(&hdr, payload.data(), sizeof(hdr));
            const size_t expected_bytes =
                sizeof(hdr) + static_cast<size_t>(hdr.num_ints) * sizeof(int32_t);
            const size_t expected_fds =
                static_cast<size_t>(hdr.num_fds) + (hdr.has_fence ? 1 : 0);

            if (hdr.magic != kPacketMagic || hdr.version != kPacketVersion ||
                hdr.num_ints > kMaxInts ||
                static_cast<size_t>(n) < expected_bytes ||
                fds.size() != expected_fds) {
                close_fds(fds);
                continue;
            }

            const auto* ints = reinterpret_cast<const int32_t*>(
                payload.data() + sizeof(hdr));
            handle_packet(hdr, ints, fds);
        }
    }

    void run_loop() {
        if (!socket_addr.empty() && socket_addr[0] == '@') {
            while (running.load(std::memory_order_acquire)) {
                int sock = connect_unix_seqpacket(socket_addr);
                if (sock < 0) {
                    usleep(200 * 1000);
                    continue;
                }
                LOGI("Connected to presenter socket: %s", socket_addr.c_str());
                receive_from_peer(sock);
                close(sock);
                clear_slot_cache();
            }
            return;
        }

        int listener = bind_unix_seqpacket(socket_addr);
        if (listener < 0) {
            LOGE("bind_unix_seqpacket(%s) failed: errno=%d", socket_addr.c_str(), errno);
            return;
        }
        LOGI("Listening on presenter socket: %s", socket_addr.c_str());
        active_listener_fd.store(listener, std::memory_order_release);

        while (running.load(std::memory_order_acquire)) {
            struct pollfd pfd { listener, POLLIN, 0 };
            int rc = poll(&pfd, 1, 250);
            if (rc <= 0) {
                continue;
            }
            int peer = accept4(listener, nullptr, nullptr, SOCK_CLOEXEC);
            if (peer < 0) {
                if (errno != EINTR && errno != EAGAIN) {
                    LOGW("accept4 failed: errno=%d", errno);
                }
                continue;
            }
            LOGI("Accepted presenter relay connection");
            active_peer_fd.store(peer, std::memory_order_release);
            int32_t queued_key = pending_key_code.exchange(0, std::memory_order_acq_rel);
            if (queued_key > 0) {
                send_key_packets(
                    peer,
                    queued_key,
                    pending_key_time_ms.load(std::memory_order_acquire));
            }
            receive_from_peer(peer);
            active_peer_fd.store(-1, std::memory_order_release);
            close(peer);
            clear_slot_cache();
        }

        active_listener_fd.store(-1, std::memory_order_release);
        close(listener);
        unlink(socket_addr.c_str());
    }
};

} // namespace

extern "C" {

JNIEXPORT jlong JNICALL
Java_alyac_android_ssalsurface_NativePresenter_nativeCreate(
    JNIEnv* env, jobject /* thiz */, jstring socket_addr) {
    const char* chars = env->GetStringUTFChars(socket_addr, nullptr);
    std::string addr(chars ? chars : "");
    if (chars) {
        env->ReleaseStringUTFChars(socket_addr, chars);
    }
    auto* presenter = new NativePresenter(std::move(addr));
    return reinterpret_cast<jlong>(presenter);
}

JNIEXPORT void JNICALL
Java_alyac_android_ssalsurface_NativePresenter_nativeSetSurface(
    JNIEnv* env, jobject /* thiz */, jlong handle, jobject surface, jint width, jint height) {
    auto* presenter = reinterpret_cast<NativePresenter*>(handle);
    if (!presenter) {
        return;
    }
    ANativeWindow* window = surface ? ANativeWindow_fromSurface(env, surface) : nullptr;
    presenter->set_surface(window, width, height);
}

JNIEXPORT void JNICALL
Java_alyac_android_ssalsurface_NativePresenter_nativeSendTouch(
    JNIEnv* env,
    jobject /* thiz */,
    jlong handle,
    jint action,
    jint pointer_count,
    jlong down_time_ms,
    jlong event_time_ms,
    jintArray ids_arr,
    jfloatArray xs_arr,
    jfloatArray ys_arr,
    jfloatArray pressures_arr) {
    auto* presenter = reinterpret_cast<NativePresenter*>(handle);
    if (!presenter || pointer_count <= 0) {
        return;
    }
    const jsize count = std::min(
        static_cast<jsize>(pointer_count),
        static_cast<jsize>(kMaxTouchPointers));
    if (env->GetArrayLength(ids_arr) < count ||
        env->GetArrayLength(xs_arr) < count ||
        env->GetArrayLength(ys_arr) < count ||
        env->GetArrayLength(pressures_arr) < count) {
        return;
    }
    jint ids[kMaxTouchPointers];
    jfloat xs[kMaxTouchPointers];
    jfloat ys[kMaxTouchPointers];
    jfloat pressures[kMaxTouchPointers];
    env->GetIntArrayRegion(ids_arr, 0, count, ids);
    env->GetFloatArrayRegion(xs_arr, 0, count, xs);
    env->GetFloatArrayRegion(ys_arr, 0, count, ys);
    env->GetFloatArrayRegion(pressures_arr, 0, count, pressures);
    presenter->send_touch(
        action, count, down_time_ms, event_time_ms, ids, xs, ys, pressures);
}

JNIEXPORT void JNICALL
Java_alyac_android_ssalsurface_NativePresenter_nativeSendKey(
    JNIEnv* /* env */, jobject /* thiz */, jlong handle, jint key_code, jlong event_time_ms) {
    auto* presenter = reinterpret_cast<NativePresenter*>(handle);
    if (presenter) {
        presenter->send_key(key_code, event_time_ms);
    }
}

JNIEXPORT void JNICALL
Java_alyac_android_ssalsurface_NativePresenter_nativeDestroy(
    JNIEnv* /* env */, jobject /* thiz */, jlong handle) {
    auto* presenter = reinterpret_cast<NativePresenter*>(handle);
    delete presenter;
}

} // extern "C"
