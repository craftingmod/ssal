#include <android/data_space.h>
#include <android/hardware_buffer.h>
#include <android/log.h>
#include <android/native_window_jni.h>
#include <android/rect.h>
#include <android/surface_control.h>
#include <dlfcn.h>
#include <errno.h>
#include <jni.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <atomic>
#include <cstdint>
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
constexpr size_t kMaxScmFds = 32;
constexpr size_t kMaxInts = 256;
constexpr int32_t kCreateFromHandleMethodRegister = 1;

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

    std::mutex surface_mutex;
    ANativeWindow* window = nullptr;
    ASurfaceControl* surface_control = nullptr;
    int32_t surface_width = 0;
    int32_t surface_height = 0;

    std::unordered_map<int32_t, AHardwareBuffer*> slot_cache;
    std::thread rx_thread;

    explicit NativePresenter(std::string addr)
        : socket_addr(std::move(addr)),
          create_from_handle(load_create_from_handle()) {
        rx_thread = std::thread(&NativePresenter::run_loop, this);
    }

    ~NativePresenter() {
        running.store(false, std::memory_order_release);
        if (rx_thread.joinable()) {
            rx_thread.join();
        }
        clear_slot_cache();
        set_surface(nullptr, 0, 0);
    }

    void clear_slot_cache() {
        for (auto& [slot, ahb] : slot_cache) {
            if (ahb) {
                AHardwareBuffer_release(ahb);
            }
        }
        slot_cache.clear();
    }

    void set_surface(ANativeWindow* new_window, int32_t width, int32_t height) {
        std::lock_guard<std::mutex> lock(surface_mutex);
        if (new_window == nullptr || width <= 0 || height <= 0) {
            if (surface_control) {
                ASurfaceControl_release(surface_control);
                surface_control = nullptr;
            }
            if (window) {
                ANativeWindow_release(window);
                window = nullptr;
            }
            surface_width = 0;
            surface_height = 0;
            if (new_window) {
                ANativeWindow_release(new_window);
            }
            return;
        }

        if (window != new_window) {
            if (surface_control) {
                ASurfaceControl_release(surface_control);
                surface_control = nullptr;
            }
            if (window) {
                ANativeWindow_release(window);
            }
            window = new_window;
            surface_control = ASurfaceControl_createFromWindow(window, "ssal-guest-presenter");
            if (!surface_control) {
                LOGE("ASurfaceControl_createFromWindow failed");
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
            std::vector<uint8_t> handle_buf(handle_bytes, 0);
            auto* handle = reinterpret_cast<native_handle_t*>(handle_buf.data());
            handle->version = sizeof(native_handle_t);
            handle->numFds = static_cast<int>(hdr.num_fds);
            handle->numInts = static_cast<int>(hdr.num_ints);
            for (uint32_t i = 0; i < hdr.num_fds; ++i) {
                handle->data[i] = fds[i];
            }
            for (uint32_t i = 0; i < hdr.num_ints; ++i) {
                handle->data[hdr.num_fds + i] = ints[i];
            }

            AHardwareBuffer_Desc desc{};
            desc.width = hdr.width;
            desc.height = hdr.height;
            desc.layers = 1;
            desc.format = hdr.format;
            desc.usage = AHARDWAREBUFFER_USAGE_GPU_SAMPLED_IMAGE |
                         AHARDWAREBUFFER_USAGE_GPU_FRAMEBUFFER |
                         AHARDWAREBUFFER_USAGE_COMPOSER_OVERLAY;
            desc.stride = hdr.width;

            AHardwareBuffer* ahb = nullptr;
            int rc = create_from_handle(&desc, handle, kCreateFromHandleMethodRegister, &ahb);
            for (uint32_t i = 0; i < hdr.num_fds; ++i) {
                close(fds[i]);
                fds[i] = -1;
            }
            if (rc != 0 || !ahb) {
                LOGE("AHardwareBuffer_createFromHandle failed: rc=%d slot=%d", rc, hdr.slot);
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
            LOGI("Imported AHardwareBuffer slot=%d %ux%u fmt=%u",
                 hdr.slot, hdr.width, hdr.height, hdr.format);
        }

        int acquire_fence = (hdr.has_fence && !fds.empty()) ? fds.back() : -1;
        auto it = slot_cache.find(hdr.slot);
        AHardwareBuffer* ahb = (it != slot_cache.end()) ? it->second : nullptr;

        std::lock_guard<std::mutex> lock(surface_mutex);
        if (!surface_control || !ahb || surface_width <= 0 || surface_height <= 0) {
            if (acquire_fence >= 0) {
                close(acquire_fence);
            }
            return;
        }

        ASurfaceTransaction* tx = ASurfaceTransaction_create();
        ASurfaceTransaction_setVisibility(
            tx, surface_control, ASURFACE_TRANSACTION_VISIBILITY_SHOW);
        ARect src{0, 0, static_cast<int32_t>(hdr.width), static_cast<int32_t>(hdr.height)};
        ARect dst{0, 0, surface_width, surface_height};
        ASurfaceTransaction_setGeometry(tx, surface_control, src, dst, 0);
        ASurfaceTransaction_setBuffer(tx, surface_control, ahb, acquire_fence);
        ASurfaceTransaction_setBufferDataSpace(
            tx, surface_control, static_cast<ADataSpace>(hdr.dataspace));
        ASurfaceTransaction_apply(tx);
        ASurfaceTransaction_delete(tx);
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
            receive_from_peer(peer);
            close(peer);
            clear_slot_cache();
        }

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
Java_alyac_android_ssalsurface_NativePresenter_nativeDestroy(
    JNIEnv* /* env */, jobject /* thiz */, jlong handle) {
    auto* presenter = reinterpret_cast<NativePresenter*>(handle);
    delete presenter;
}

} // extern "C"
