#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#define ORIG_LIBNETD_CLIENT_PATH "/run/ssal/libnetd_client_orig.so"
#define SSAL_SOCK_PATH "/dev/socket/ssal_sock"
#define AID_APP_START 10000

typedef int (*socket_fn_t)(int, int, int);
typedef int (*connect_fn_t)(int, const struct sockaddr*, socklen_t);
typedef int (*accept4_fn_t)(int, struct sockaddr*, socklen_t*, int);
typedef int (*sendmmsg_fn_t)(int, struct mmsghdr*, unsigned int, int);
typedef ssize_t (*sendmsg_fn_t)(int, const struct msghdr*, int);
typedef ssize_t (*sendto_fn_t)(int, const void*, size_t, int, const struct sockaddr*, socklen_t);

static pthread_once_t g_orig_once = PTHREAD_ONCE_INIT;
static void* g_orig_handle = NULL;
static socket_fn_t g_orig_libc_socket = NULL;
static socket_fn_t g_orig_netd_socket = NULL;

static void load_orig_lib(void) {
    g_orig_handle = dlopen(ORIG_LIBNETD_CLIENT_PATH, RTLD_LAZY | RTLD_LOCAL);
}

static void* orig_sym(const char* name) {
    pthread_once(&g_orig_once, load_orig_lib);
    if (!g_orig_handle) {
        return NULL;
    }
    return dlsym(g_orig_handle, name);
}

static int fallback_socket(int domain, int type, int protocol) {
    if (g_orig_netd_socket) {
        return g_orig_netd_socket(domain, type, protocol);
    }
    if (g_orig_libc_socket) {
        return g_orig_libc_socket(domain, type, protocol);
    }
    errno = ENOSYS;
    return -1;
}

static int write_all(int fd, const void* buf, size_t len) {
    const uint8_t* p = (const uint8_t*)buf;
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(fd, p + sent, len - sent, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (n == 0) {
            errno = EIO;
            return -1;
        }
        sent += (size_t)n;
    }
    return 0;
}

static int request_socket_from_netd(int domain, int type, int protocol, int* out_errno) {
    if (!g_orig_libc_socket) {
        *out_errno = ENOSYS;
        return -1;
    }

    int ipc = g_orig_libc_socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (ipc < 0) {
        *out_errno = errno;
        return -2;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SSAL_SOCK_PATH, sizeof(addr.sun_path) - 1);

    int rc;
    do {
        rc = connect(ipc, (const struct sockaddr*)&addr, sizeof(addr));
    } while (rc < 0 && errno == EINTR);
    if (rc < 0) {
        *out_errno = errno;
        close(ipc);
        return -2;
    }

    int32_t req[3] = { (int32_t)domain, (int32_t)type, (int32_t)protocol };
    if (write_all(ipc, req, sizeof(req)) < 0) {
        *out_errno = errno;
        close(ipc);
        return -2;
    }

    int32_t resp_err = 0;
    struct iovec iov = {
        .iov_base = &resp_err,
        .iov_len = sizeof(resp_err),
    };
    union {
        struct cmsghdr align;
        uint8_t buf[CMSG_SPACE(sizeof(int))];
    } cmsg_buf;
    memset(&cmsg_buf, 0, sizeof(cmsg_buf));

    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.buf;
    msg.msg_controllen = sizeof(cmsg_buf.buf);

    int recv_flags = (type & SOCK_CLOEXEC) ? MSG_CMSG_CLOEXEC : 0;
    ssize_t n;
    do {
        n = recvmsg(ipc, &msg, recv_flags);
    } while (n < 0 && errno == EINTR);
    int saved_errno = errno;
    close(ipc);

    if (n != (ssize_t)sizeof(resp_err)) {
        *out_errno = (n < 0) ? saved_errno : EIO;
        return -2;
    }
    if (resp_err < 0) {
        *out_errno = -resp_err;
        return -1;
    }

    int received_fd = -1;
    for (struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL;
         cmsg = CMSG_NXTHDR(&msg, cmsg)) {
        if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS &&
            cmsg->cmsg_len >= CMSG_LEN(sizeof(int))) {
            memcpy(&received_fd, CMSG_DATA(cmsg), sizeof(received_fd));
            break;
        }
    }
    if (received_fd < 0) {
        *out_errno = EIO;
        return -2;
    }
    return received_fd;
}

static int ssal_netd_socket(int domain, int type, int protocol) {
    if ((domain != AF_INET && domain != AF_INET6) || getuid() < AID_APP_START) {
        return fallback_socket(domain, type, protocol);
    }

    int req_errno = 0;
    int fd = request_socket_from_netd(domain, type, protocol, &req_errno);
    if (fd >= 0) {
        return fd;
    }
    if (fd == -1) {
        errno = req_errno ? req_errno : EINVAL;
        return -1;
    }
    return fallback_socket(domain, type, protocol);
}

void netdClientInitSocket(socket_fn_t* function) {
    if (!function || !*function) {
        return;
    }
    g_orig_libc_socket = *function;
    socket_fn_t tmp = *function;
    void (*orig_init)(socket_fn_t*) =
        (void (*)(socket_fn_t*))orig_sym("netdClientInitSocket");
    if (orig_init) {
        orig_init(&tmp);
        g_orig_netd_socket = tmp;
    } else {
        g_orig_netd_socket = g_orig_libc_socket;
    }
    *function = ssal_netd_socket;
}

void netdClientInitConnect(connect_fn_t* function) {
    void (*orig_init)(connect_fn_t*) =
        (void (*)(connect_fn_t*))orig_sym("netdClientInitConnect");
    if (orig_init) {
        orig_init(function);
    }
}

void netdClientInitAccept4(accept4_fn_t* function) {
    void (*orig_init)(accept4_fn_t*) =
        (void (*)(accept4_fn_t*))orig_sym("netdClientInitAccept4");
    if (orig_init) {
        orig_init(function);
    }
}

void netdClientInitSendmmsg(sendmmsg_fn_t* function) {
    void (*orig_init)(sendmmsg_fn_t*) =
        (void (*)(sendmmsg_fn_t*))orig_sym("netdClientInitSendmmsg");
    if (orig_init) {
        orig_init(function);
    }
}

void netdClientInitSendmsg(sendmsg_fn_t* function) {
    void (*orig_init)(sendmsg_fn_t*) =
        (void (*)(sendmsg_fn_t*))orig_sym("netdClientInitSendmsg");
    if (orig_init) {
        orig_init(function);
    }
}

void netdClientInitSendto(sendto_fn_t* function) {
    void (*orig_init)(sendto_fn_t*) =
        (void (*)(sendto_fn_t*))orig_sym("netdClientInitSendto");
    if (orig_init) {
        orig_init(function);
    }
}

int setNetworkForSocket(unsigned netId, int socketFd) {
    int (*fn)(unsigned, int) = (int (*)(unsigned, int))orig_sym("setNetworkForSocket");
    return fn ? fn(netId, socketFd) : 0;
}

int getNetworkForSocket(int socketFd) {
    int (*fn)(int) = (int (*)(int))orig_sym("getNetworkForSocket");
    return fn ? fn(socketFd) : 0;
}

int setNetworkForProcess(unsigned netId) {
    int (*fn)(unsigned) = (int (*)(unsigned))orig_sym("setNetworkForProcess");
    return fn ? fn(netId) : 0;
}

unsigned getNetworkForProcess(void) {
    unsigned (*fn)(void) = (unsigned (*)(void))orig_sym("getNetworkForProcess");
    return fn ? fn() : 0;
}

int setNetworkForResolv(unsigned netId) {
    int (*fn)(unsigned) = (int (*)(unsigned))orig_sym("setNetworkForResolv");
    return fn ? fn(netId) : 0;
}

int setNetworkForUser(uid_t uid, int socketFd) {
    int (*fn)(uid_t, int) = (int (*)(uid_t, int))orig_sym("setNetworkForUser");
    return fn ? fn(uid, socketFd) : 0;
}

int protectFromVpn(int socketFd) {
    int (*fn)(int) = (int (*)(int))orig_sym("protectFromVpn");
    return fn ? fn(socketFd) : 0;
}

int protectFromVpnForUser(uid_t uid, int socketFd) {
    int (*fn)(uid_t, int) = (int (*)(uid_t, int))orig_sym("protectFromVpnForUser");
    return fn ? fn(uid, socketFd) : 0;
}

int queryUserAccess(uid_t uid, unsigned netId) {
    int (*fn)(uid_t, unsigned) = (int (*)(uid_t, unsigned))orig_sym("queryUserAccess");
    return fn ? fn(uid, netId) : 0;
}

int tagSocket(int sockfd, uint32_t tag, uid_t uid) {
    int (*fn)(int, uint32_t, uid_t) = (int (*)(int, uint32_t, uid_t))orig_sym("tagSocket");
    return fn ? fn(sockfd, tag, uid) : 0;
}

int untagSocket(int sockfd) {
    int (*fn)(int) = (int (*)(int))orig_sym("untagSocket");
    return fn ? fn(sockfd) : 0;
}

void netdClientInitNetIdForResolv(void* function) {
    void (*orig_init)(void*) = (void (*)(void*))orig_sym("netdClientInitNetIdForResolv");
    if (orig_init) {
        orig_init(function);
    }
}

void netdClientInitDnsOpenProxy(void* function) {
    void (*orig_init)(void*) = (void (*)(void*))orig_sym("netdClientInitDnsOpenProxy");
    if (orig_init) {
        orig_init(function);
    }
}

int resNetworkQuery(unsigned netId, const char* dname, int ns_class, int ns_type, uint32_t flags) {
    int (*fn)(unsigned, const char*, int, int, uint32_t) =
        (int (*)(unsigned, const char*, int, int, uint32_t))orig_sym("resNetworkQuery");
    return fn ? fn(netId, dname, ns_class, ns_type, flags) : -ENOSYS;
}

int resNetworkSend(unsigned netId, const uint8_t* msg, size_t msglen, uint32_t flags) {
    int (*fn)(unsigned, const uint8_t*, size_t, uint32_t) =
        (int (*)(unsigned, const uint8_t*, size_t, uint32_t))orig_sym("resNetworkSend");
    return fn ? fn(netId, msg, msglen, flags) : -ENOSYS;
}

int resNetworkResult(int fd, int* rcode, uint8_t* answer, size_t anslen) {
    int (*fn)(int, int*, uint8_t*, size_t) =
        (int (*)(int, int*, uint8_t*, size_t))orig_sym("resNetworkResult");
    return fn ? fn(fd, rcode, answer, anslen) : -ENOSYS;
}

int resNetworkCancel(int fd) {
    int (*fn)(int) = (int (*)(int))orig_sym("resNetworkCancel");
    return fn ? fn(fd) : 0;
}

int getAllowNetworkingForProcess(void) {
    int (*fn)(void) = (int (*)(void))orig_sym("getAllowNetworkingForProcess");
    return fn ? fn() : 1;
}

void setAllowNetworkingForProcess(int allow) {
    void (*fn)(int) = (void (*)(int))orig_sym("setAllowNetworkingForProcess");
    if (fn) {
        fn(allow);
    }
}

int getNetworkForDns(unsigned* dnsNetId) {
    int (*fn)(unsigned*) = (int (*)(unsigned*))orig_sym("getNetworkForDns");
    if (fn) {
        return fn(dnsNetId);
    }
    if (dnsNetId) {
        *dnsNetId = 0;
    }
    return 0;
}

int ssal_getNetworkForDnsInternal(int fd, unsigned* dnsNetId)
    __asm__("_Z24getNetworkForDnsInternaliPj");
int ssal_getNetworkForDnsInternal(int fd, unsigned* dnsNetId) {
    int (*fn)(int, unsigned*) =
        (int (*)(int, unsigned*))orig_sym("_Z24getNetworkForDnsInternaliPj");
    if (fn) {
        return fn(fd, dnsNetId);
    }
    if (dnsNetId) {
        *dnsNetId = 0;
    }
    return 0;
}

int ssal_fwmark_should_set(int family)
    __asm__("_ZN12FwmarkClient15shouldSetFwmarkEi");
int ssal_fwmark_should_set(int family) {
    int (*fn)(int) = (int (*)(int))orig_sym("_ZN12FwmarkClient15shouldSetFwmarkEi");
    return fn ? fn(family) : 0;
}

void ssal_fwmark_ctor1(void* self) __asm__("_ZN12FwmarkClientC1Ev");
void ssal_fwmark_ctor1(void* self) {
    void (*fn)(void*) = (void (*)(void*))orig_sym("_ZN12FwmarkClientC1Ev");
    if (fn) {
        fn(self);
    }
}

void ssal_fwmark_ctor2(void* self) __asm__("_ZN12FwmarkClientC2Ev");
void ssal_fwmark_ctor2(void* self) {
    void (*fn)(void*) = (void (*)(void*))orig_sym("_ZN12FwmarkClientC2Ev");
    if (fn) {
        fn(self);
    }
}

void ssal_fwmark_dtor1(void* self) __asm__("_ZN12FwmarkClientD1Ev");
void ssal_fwmark_dtor1(void* self) {
    void (*fn)(void*) = (void (*)(void*))orig_sym("_ZN12FwmarkClientD1Ev");
    if (fn) {
        fn(self);
    }
}

void ssal_fwmark_dtor2(void* self) __asm__("_ZN12FwmarkClientD2Ev");
void ssal_fwmark_dtor2(void* self) {
    void (*fn)(void*) = (void (*)(void*))orig_sym("_ZN12FwmarkClientD2Ev");
    if (fn) {
        fn(self);
    }
}

int ssal_fwmark_send(void* self, void* cmd, int fd, void* info)
    __asm__("_ZN12FwmarkClient4sendEP13FwmarkCommandiP17FwmarkConnectInfo");
int ssal_fwmark_send(void* self, void* cmd, int fd, void* info) {
    int (*fn)(void*, void*, int, void*) =
        (int (*)(void*, void*, int, void*))orig_sym(
            "_ZN12FwmarkClient4sendEP13FwmarkCommandiP17FwmarkConnectInfo");
    return fn ? fn(self, cmd, fd, info) : 0;
}

__attribute__((aligned(4096)))
void __cfi_check(uint64_t call_site_type_id, void* ptr, void* diag_data) {
    (void)call_site_type_id;
    (void)ptr;
    (void)diag_data;
}
