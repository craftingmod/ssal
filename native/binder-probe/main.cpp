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

using namespace android;
static constexpr uint32_t kEcho = IBinder::FIRST_CALL_TRANSACTION + 73;
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
    auto process = ProcessState::initWithDriver(path);
    bool found = false;
    DIR* descriptors = opendir("/proc/self/fd");
    if (descriptors) {
        while (auto* entry = readdir(descriptors)) {
            char* end = nullptr;
            long fd = strtol(entry->d_name, &end, 10);
            if (!end || *end || fd < 0 || fd > INT32_MAX) continue;
            struct stat actual {};
            if (!fstat(static_cast<int>(fd), &actual) && S_ISCHR(actual.st_mode) && actual.st_rdev == before.st_rdev && actual.st_dev == before.st_dev && actual.st_ino == before.st_ino) found = true;
        }
        closedir(descriptors);
    }
    if (strcmp(process->getDriverName().c_str(), path) || !found) {
        fprintf(stderr, "libbinder opened an unexpected device\n"); return nullptr;
    }
    return process;
}

class Echo final : public BBinder {
    status_t onTransact(uint32_t code, const Parcel& request, Parcel* reply, uint32_t flags) override {
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

int main(int argc, char** argv) {
    setvbuf(stdout, nullptr, _IONBF, 0);
    setvbuf(stderr, nullptr, _IONBF, 0);
    if (argc != 5 || strcmp(argv[1], "selftest")) { fprintf(stderr, "usage: ssal-binder-probe selftest PRIVATE_DRIVER MAJOR MINOR\n"); return 2; }
    char* end = nullptr;
    unsigned long expectedMajor = strtoul(argv[3], &end, 10);
    if (!end || *end || expectedMajor > UINT32_MAX) return 2;
    unsigned long expectedMinor = strtoul(argv[4], &end, 10);
    if (!end || *end || expectedMinor > UINT32_MAX) return 2;
    int ready[2];
    if (pipe2(ready, O_CLOEXEC)) return 3;
    // Fork before either process initializes libbinder. Neither child inherits
    // a live ProcessState, Binder descriptor, object or thread pool.
    pid_t server = fork();
    if (server < 0) return 3;
    if (server == 0) {
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
    if (!passed) fprintf(stderr, "Binder echo failed status=%d server_identity_matches=%d\n", result, sender == server);
    stop(server);
    if (passed) puts("SSAL_BINDER_IPC=passed");
    return passed ? 0 : 9;
}
