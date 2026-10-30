// AOSP platform libbinder helper; no service registry or HAL access.
#include <binder/Binder.h>
#include <binder/IPCThreadState.h>
#include <binder/Parcel.h>
#include <binder/ProcessState.h>
#include <poll.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <cstdint>
#include <dirent.h>
#include <sys/prctl.h>
#include <dlfcn.h>
#include <sys/resource.h>

using namespace android;
static constexpr uint32_t kEcho = IBinder::FIRST_CALL_TRANSACTION + 73;
static constexpr uint32_t kObjectEcho = kEcho + 1;
static constexpr int32_t kNonce = 0x5353414c;

static void context(const char* role) {
    char value[256] = {};
    int fd = open("/proc/self/attr/current", O_RDONLY | O_CLOEXEC);
    if (fd >= 0) { read(fd, value, sizeof(value) - 1); close(fd); }
    value[strcspn(value, "\n")] = '\0';
    printf("Binder helper %s: pid=%d context=%s; scope=probe_only\n", role, getpid(), value);
}

static sp<ProcessState> driver(const char* path, unsigned expectedMajor, unsigned expectedMinor) {
    // ProcessState can fall back to /dev/binder. Both path and actual FD must
    // match the Rust-created private device; there is no host-driver fallback.
    struct stat before {};
    if (stat(path, &before) || !S_ISCHR(before.st_mode) || major(before.st_rdev) != expectedMajor || minor(before.st_rdev) != expectedMinor) {
        fprintf(stderr, "private driver path identity mismatch\n"); return nullptr;
    }
    struct stat fallback {};
    if (stat("/dev/binder", &fallback) || fallback.st_dev != before.st_dev || fallback.st_ino != before.st_ino || fallback.st_rdev != before.st_rdev) {
        fprintf(stderr, "default fallback is not the intended private driver\n"); return nullptr;
    }
    auto process = ProcessState::initWithDriver(path);
    bool found = false;
    bool unexpected = false;
    // Works with the restrictive empty proc view too. The launcher closes all
    // descriptors outside its explicit observation allowlist before this exec.
    for (int fd = 0; fd < 1024; ++fd) {
            struct stat actual {};
            if (!fstat(fd, &actual) && S_ISCHR(actual.st_mode) && actual.st_rdev == before.st_rdev && actual.st_dev == before.st_dev && actual.st_ino == before.st_ino) found = true;
            if (S_ISCHR(actual.st_mode) && major(actual.st_rdev) == expectedMajor && actual.st_rdev != before.st_rdev) unexpected = true;
    }
    if (strcmp(process->getDriverName().c_str(), path) || !found || unexpected) {
        fprintf(stderr, "libbinder opened an unexpected device\n"); return nullptr;
    }
    printf("{\"event\":\"libbinder_driver\",\"pid\":%d,\"path\":\"%s\",\"dev\":%llu,\"inode\":%llu,\"rdev\":%llu,\"default_private\":true,\"actual_fd_verified\":true}\n", getpid(), path, static_cast<unsigned long long>(before.st_dev), static_cast<unsigned long long>(before.st_ino), static_cast<unsigned long long>(before.st_rdev));
    return process;
}

class Echo final : public BBinder {
    status_t onTransact(uint32_t code, const Parcel& request, Parcel* reply, uint32_t flags) override {
        if (code == kObjectEcho) {
            if (!reply || IPCThreadState::self()->getCallingUid() != getuid()) return BAD_VALUE;
            sp<IBinder> object;
            status_t result = request.readStrongBinder(&object);
            if (result != OK || !object) return BAD_VALUE;
            return reply->writeStrongBinder(object);
        }
        if (code != kEcho) return BBinder::onTransact(code, request, reply, flags);
        int32_t nonce = 0;
        if (!reply || request.readInt32(&nonce) != OK || nonce != kNonce || IPCThreadState::self()->getCallingUid() != getuid()) return BAD_VALUE;
        if (reply->writeInt32(nonce) != OK) return NO_MEMORY;
        return reply->writeInt32(getpid());
    }
};

static void stop(pid_t child) {
    kill(child, SIGTERM);
    for (int i = 0; i < 50; ++i) { if (waitpid(child, nullptr, WNOHANG) == child) return; usleep(10000); }
    kill(child, SIGKILL);
    while (waitpid(child, nullptr, 0) < 0 && errno == EINTR) {}
}

static bool enforcedIdentity(char** argv, const char* target) {
    char current[256] = {}, status[8192] = {}, enforce[8] = {};
    char* buffers[] = {current, status, enforce};
    const size_t sizes[] = {sizeof(current), sizeof(status), sizeof(enforce)};
    for (int i = 0; i < 3; ++i) {
        char* end = nullptr;
        long fd = strtol(argv[5 + i], &end, 10);
        if (!end || *end || fd < 3 || fd >= 1024) return false;
        ssize_t n = read(static_cast<int>(fd), buffers[i], sizes[i] - 1);
        close(static_cast<int>(fd));
        if (n <= 0 || static_cast<size_t>(n) >= sizes[i] - 1) return false;
    }
    current[strcspn(current, "\n")] = '\0';
    gid_t groups[64];
    int count = getgroups(64, groups);
    bool caps = strstr(status, "CapEff:\t0000000000000000") && strstr(status, "CapPrm:\t0000000000000000") && strstr(status, "CapInh:\t0000000000000000") && strstr(status, "CapBnd:\t0000000000000000") && strstr(status, "CapAmb:\t0000000000000000");
    bool clean = true;
    for (int fd = 3; fd < 1024; ++fd) if (fcntl(fd, F_GETFD) >= 0) clean = false;
    bool passed = !strcmp(current, target) && enforce[0] == '1' && getuid() == 1000 && geteuid() == 1000 && getgid() == 1000 && getegid() == 1000 && count == 1 && groups[0] == 3009 && caps && clean && prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1;
    struct stat root {};
    struct rlimit nofile {}, core {};
    passed = passed && !stat("/", &root) && root.st_dev == strtoull(argv[8], nullptr, 10) && root.st_ino == strtoull(argv[9], nullptr, 10) && !getrlimit(RLIMIT_NOFILE, &nofile) && nofile.rlim_cur == 1024 && nofile.rlim_max == 1024 && !getrlimit(RLIMIT_CORE, &core) && core.rlim_cur == 0 && core.rlim_max == 0;
    bool stdioValid = true;
    for (int fd = 0; fd < 3; ++fd) {
        struct stat st {};
        int flags = fcntl(fd, F_GETFL);
        if (fstat(fd, &st) || flags < 0 || (fd == 0 ? (!S_ISCHR(st.st_mode) || st.st_rdev != makedev(1, 3) || (flags & O_ACCMODE) != O_RDONLY) : (!S_ISFIFO(st.st_mode) || (flags & O_ACCMODE) != O_WRONLY))) stdioValid = false;
        if (fcntl(fd, F_SETFD, FD_CLOEXEC)) stdioValid = false;
    }
    size_t envCount = 0;
    while (environ[envCount]) ++envCount;
    bool environment = envCount == 3 && getenv("PATH") && !strcmp(getenv("PATH"), "/system/bin") && getenv("ANDROID_ROOT") && !strcmp(getenv("ANDROID_ROOT"), "/system") && getenv("ANDROID_DATA") && !strcmp(getenv("ANDROID_DATA"), "/data");
    passed = passed && stdioValid && environment;
    printf("{\"event\":\"libbinder_post_exec\",\"context\":\"%s\",\"uid\":%d,\"gid\":%d,\"supplementary_group_count\":%d,\"group0\":%d,\"capabilities_zero\":%s,\"extra_fds_absent\":%s,\"stdio_valid\":%s,\"environment_valid\":%s,\"nofile\":[%llu,%llu],\"core\":[%llu,%llu],\"credentials_valid\":%s,\"no_new_privs\":%d}\n", current, getuid(), getgid(), count, count > 0 ? groups[0] : -1, caps ? "true" : "false", clean ? "true" : "false", stdioValid ? "true" : "false", environment ? "true" : "false", static_cast<unsigned long long>(nofile.rlim_cur), static_cast<unsigned long long>(nofile.rlim_max), static_cast<unsigned long long>(core.rlim_cur), static_cast<unsigned long long>(core.rlim_max), passed ? "true" : "false", prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0));
    return passed;
}

int main(int argc, char** argv) {
    setvbuf(stdout, nullptr, _IONBF, 0);
    setvbuf(stderr, nullptr, _IONBF, 0);
    bool serverOnly = argc == 10 && !strcmp(argv[1], "enforcing-server");
    bool clientOnly = argc == 10 && !strcmp(argv[1], "enforcing-client");
    bool enforcing = argc == 10 && (!strcmp(argv[1], "enforcing-selftest") || serverOnly || clientOnly);
    if (!enforcing && (argc != 5 || strcmp(argv[1], "selftest"))) { fprintf(stderr, "usage: ssal-binder-probe selftest PRIVATE_DRIVER MAJOR MINOR\n"); return 2; }
    if (enforcing && (!enforcedIdentity(argv, clientOnly ? "u:r:shell:s0" : "u:r:servicemanager:s0") || strcmp(argv[2], "/dev/binder"))) return 10;
    Dl_info library {};
    if (!dladdr(reinterpret_cast<void*>(&ProcessState::self), &library) || !library.dli_fname || strcmp(library.dli_fname, "/system/lib64/libbinder.so")) return 12;
    printf("{\"event\":\"libbinder_runtime_library\",\"path\":\"%s\"}\n", library.dli_fname);
    char* end = nullptr;
    unsigned long expectedMajor = strtoul(argv[3], &end, 10);
    if (!end || *end || expectedMajor > UINT32_MAX) return 2;
    unsigned long expectedMinor = strtoul(argv[4], &end, 10);
    if (!end || *end || expectedMinor > UINT32_MAX) return 2;
    if (serverOnly) {
        auto process = driver(argv[2], expectedMajor, expectedMinor);
        if (!process) return 4;
        auto object = sp<Echo>::make();
        IPCThreadState::self()->setTheContextObject(object);
        if (!process->becomeContextManager()) return 5;
        puts("{\"event\":\"private_context_manager\",\"status\":\"passed\",\"engine\":\"libbinder\"}");
        IPCThreadState::self()->joinThreadPool();
        return 13;
    }
    if (clientOnly) {
        auto process = driver(argv[2], expectedMajor, expectedMinor);
        if (!process) return 8;
        auto remote = process->getContextObject(nullptr);
        Parcel request, reply;
        int32_t echoed = 0, sender = 0;
        status_t result = request.writeInt32(kNonce);
        if (result == OK && remote) result = remote->transact(kEcho, request, &reply);
        else result = BAD_VALUE;
        if (result == OK) result = reply.readInt32(&echoed);
        if (result == OK) result = reply.readInt32(&sender);
        bool passed = result == OK && echoed == kNonce && sender > 0 && sender != getpid();
        printf("{\"event\":\"libbinder_transaction\",\"status_t\":%d,\"passed\":%s,\"server_pid\":%d}\n", result, passed ? "true" : "false", sender);
        if (passed) {
            auto local = sp<BBinder>::make();
            Parcel objects, returned;
            sp<IBinder> echoedObject;
            result = objects.writeStrongBinder(local);
            if (result == OK) result = remote->transact(kObjectEcho, objects, &returned);
            if (result == OK) result = returned.readStrongBinder(&echoedObject);
            passed = result == OK && echoedObject == local;
            printf("{\"event\":\"libbinder_object_transfer\",\"status_t\":%d,\"passed\":%s}\n", result, passed ? "true" : "false");
        }
        return passed ? 0 : 9;
    }
    int ready[2];
    if (pipe2(ready, O_CLOEXEC)) return 3;
    // Fork before either process initializes libbinder. Neither child inherits
    // a live ProcessState, Binder descriptor, object or thread pool.
    pid_t parent = getpid();
    pid_t server = fork();
    if (server < 0) return 3;
    if (server == 0) {
        if (prctl(PR_SET_PDEATHSIG, SIGKILL) || getppid() != parent) _exit(11);
        close(ready[0]);
        context("server");
        auto process = driver(argv[2], expectedMajor, expectedMinor);
        if (!process) _exit(4);
        auto object = sp<Echo>::make();
        IPCThreadState::self()->setTheContextObject(object);
        puts("SSAL_BINDER_CONTEXT_MANAGER=attempted");
        if (!process->becomeContextManager()) { fprintf(stderr, "context manager registration failed\n"); _exit(5); }
        puts("SSAL_BINDER_CONTEXT_MANAGER=passed");
        if (write(ready[1], "R", 1) != 1) _exit(6);
        close(ready[1]);
        IPCThreadState::self()->joinThreadPool();
        _exit(0);
    }
    close(ready[1]);
    pollfd item {ready[0], POLLIN, 0};
    char signal = 0;
    if (poll(&item, 1, 5000) <= 0 || read(ready[0], &signal, 1) != 1 || signal != 'R') { close(ready[0]); stop(server); return 7; }
    close(ready[0]);
    context("client");
    auto process = driver(argv[2], expectedMajor, expectedMinor);
    if (!process) { stop(server); return 8; }
    auto remote = process->getContextObject(nullptr);
    Parcel request, reply;
    puts("SSAL_BINDER_IPC=attempted");
    int32_t echoed = 0, sender = 0;
    status_t result = request.writeInt32(kNonce);
    if (result == OK && remote) result = remote->transact(kEcho, request, &reply);
    else result = BAD_VALUE;
    if (result == OK) result = reply.readInt32(&echoed);
    if (result == OK) result = reply.readInt32(&sender);
    bool passed = result == OK && echoed == kNonce && sender == server;
    printf("{\"event\":\"libbinder_transaction\",\"status_t\":%d,\"passed\":%s,\"scope\":\"private driver; no Host registry lookup\"}\n", result, passed ? "true" : "false");
    if (!passed) fprintf(stderr, "Binder echo failed status=%d server_identity_matches=%d\n", result, sender == server);
    stop(server);
    if (passed) puts("SSAL_BINDER_IPC=passed");
    return passed ? 0 : 9;
}
