// AOSP platform libbinder helper; Test B registry access is explicit and scoped.
#include <binder/Binder.h>
#include <binder/IPCThreadState.h>
#include <binder/Parcel.h>
#include <binder/ProcessState.h>
#include <binder/Status.h>
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
#include <cctype>
#include <cstdint>
#include <dirent.h>
#include <sys/prctl.h>
#include <dlfcn.h>
#include <sys/resource.h>
#include "system_properties/prop_area.h"

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

static int registry(int argc, char** argv) {
    auto unavailable = [](const char* stage) {
        printf("{\"event\":\"registry\",\"result\":\"unavailable\",\"stage\":\"%s\",\"errno\":%d}\n", stage, errno);
        return 5;
    };
    if (argc != 7) return 2;
    Dl_info library {};
    if (!dladdr(reinterpret_cast<void*>(&ProcessState::self), &library) || !library.dli_fname || strcmp(library.dli_fname,"/system/lib64/libbinder.so")) return unavailable("runtime_libbinder");
    printf("{\"event\":\"libbinder_runtime_library\",\"path\":\"%s\"}\n",library.dli_fname);
    const bool server = !strcmp(argv[1], "registry-server");
    const bool echo = !strcmp(argv[1], "registry-echo");
    if (!server && !echo && strcmp(argv[1], "registry-check")) return 2;
    char* end = nullptr;
    unsigned long majorNumber = strtoul(argv[3], &end, 10);
    if (!end || *end || majorNumber > UINT32_MAX) return 2;
    unsigned long minorNumber = strtoul(argv[4], &end, 10);
    if (!end || *end || minorNumber > UINT32_MAX) return 2;
    unsigned long long hostRdev = strtoull(argv[6], &end, 10);
    if (!end || *end) return 2;
    // Registration is forbidden on the Host driver, including accidental aliases.
    struct stat node {};
    if (stat(argv[2], &node) || (server && node.st_rdev == hostRdev)) return 3;
    const char* name = argv[5];
    if (server && strcmp(name, "aidl_lazy_test_1")) return 2;
    for (const char* p = name; *p; ++p) if (!isalnum(static_cast<unsigned char>(*p)) && *p != '.' && *p != '_' && *p != '-') return 2;
    auto process = driver(argv[2], majorNumber, minorNumber);
    if (!process) return 4;
    struct stat root {};
    char namespaceName[128] = {};
    ssize_t namespaceSize = readlink("/proc/self/ns/mnt", namespaceName, sizeof(namespaceName)-1);
    if (namespaceSize > 0) namespaceName[namespaceSize] = '\0';
    if (stat("/", &root)) return 5;
    printf("{\"event\":\"registry_environment\",\"root_dev\":%llu,\"root_inode\":%llu,\"mount_namespace\":\"%s\"}\n", static_cast<unsigned long long>(root.st_dev), static_cast<unsigned long long>(root.st_ino), namespaceName);
    if (!server) {
        void* selinux = dlopen("libselinux.so", RTLD_NOW | RTLD_LOCAL);
        if (!selinux) return unavailable("dlopen_libselinux");
        using Handle = void*;
        auto handle = reinterpret_cast<Handle(*)()>(dlsym(selinux, "selinux_android_service_context_handle"));
        auto lookup = reinterpret_cast<int(*)(Handle,char**,const char*,int)>(dlsym(selinux, "selabel_lookup"));
        auto getcon = reinterpret_cast<int(*)(char**)>(dlsym(selinux, "getcon"));
        auto release = reinterpret_cast<void(*)(char*)>(dlsym(selinux, "freecon"));
        auto access = reinterpret_cast<int(*)(const char*,const char*,const char*,const char*,void*)>(dlsym(selinux, "selinux_check_access"));
        auto enabled = reinterpret_cast<int(*)()>(dlsym(selinux, "is_selinux_enabled"));
        auto statusOpen = reinterpret_cast<int(*)(int)>(dlsym(selinux, "selinux_status_open"));
        auto enforcement = reinterpret_cast<int(*)()>(dlsym(selinux, "security_getenforce"));
        if (!handle || !lookup || !getcon || !release || !access || !enabled || !statusOpen || !enforcement) return unavailable("libselinux_symbols");
        if (enabled() != 1 || statusOpen(1) < 0) return unavailable("effective_selinux_status");
        printf("{\"event\":\"registry_policy_status\",\"enabled\":true,\"enforcing\":%d}\n", enforcement());
        Handle labels = handle();
        char *source = nullptr, *target = nullptr;
        if (!labels) return unavailable("service_context_handle");
        if (getcon(&source)) return unavailable("getcon");
        if (lookup(labels, &target, name, 0)) {
            puts("{\"event\":\"registry\",\"result\":\"name_mapping_absent\"}");
            release(source); return 6;
        }
        bool allowed = access(source, target, "service_manager", "find", nullptr) == 0;
        printf("{\"event\":\"registry_permission\",\"name\":\"%s\",\"uid\":%d,\"sid\":\"%s\",\"target\":\"%s\",\"permission\":\"find\",\"effective_allowed\":%s}\n", name, getuid(), source, target, allowed ? "true" : "false");
        release(source); release(target);
        if (!allowed) {
            puts("{\"event\":\"registry\",\"result\":\"find_denied\"}");
            return 7;
        }
    } else {
        puts("{\"event\":\"registry_policy\",\"source\":\"selinuxfs supervisor query\"}");
    }
    auto manager = process->getContextObject(nullptr);
    if (!manager || manager->pingBinder() != OK) return 8;
    Parcel request, reply;
    status_t result = request.writeInterfaceToken(String16("android.os.IServiceManager"));
    if (result == OK) result = request.writeString16(String16(name));
    sp<Echo> local;
    if (server) {
        local = sp<Echo>::make();
        if (result == OK) result = request.writeStrongBinder(local);
        if (result == OK) result = request.writeBool(false);
        if (result == OK) result = request.writeInt32(8);
    }
    // android-16.0.0_r2 IServiceManager.aidl: legacy checkService=2, addService=4.
    if (result == OK) result = manager->transact(IBinder::FIRST_CALL_TRANSACTION + (server ? 4 : 2), request, &reply);
    binder::Status status;
    if (result == OK) result = status.readFromParcel(reply);
    if (result != OK || !status.isOk()) {
        printf("{\"event\":\"registry\",\"result\":\"transaction_failed\",\"status_t\":%d,\"exception\":%d}\n", result, status.exceptionCode());
        return 8;
    }
    if (server) {
        printf("{\"event\":\"registry\",\"result\":\"registered\",\"pid\":%d}\n", getpid());
        IPCThreadState::self()->joinThreadPool();
        return 9;
    }
    sp<IBinder> remote;
    // A successful nullable read is distinct from malformed/failed transport.
    result = reply.readNullableStrongBinder(&remote);
    if (result != OK || reply.dataAvail() != 0) return 8;
    if (!echo) {
        printf("{\"event\":\"registry\",\"result\":\"%s\",\"name\":\"%s\"}\n", remote ? "present" : "not_registered", name);
        return 0;
    }
    if (!remote) return 8;
    Parcel challenge, response;
    int32_t nonce = 0, pid = 0;
    result = challenge.writeInt32(kNonce);
    if (result == OK) result = remote->transact(kEcho, challenge, &response);
    if (result == OK) result = response.readInt32(&nonce);
    if (result == OK) result = response.readInt32(&pid);
    if (result != OK || nonce != kNonce || pid <= 0) return 8;
    printf("{\"event\":\"registry\",\"result\":\"echo\",\"server_pid\":%d,\"nonce\":%d}\n", pid, nonce);
    return 0;
}

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

// Fixed Android 16 AIDL probe. No caller-supplied package, path or transaction code.
static bool dataCall(const sp<IBinder>& remote, uint32_t code, Parcel& request, Parcel& reply) {
    status_t rc = remote->transact(IBinder::FIRST_CALL_TRANSACTION + code, request, &reply);
    binder::Status status;
    if (rc == OK) rc = status.readFromParcel(reply);
    if (rc != OK || !status.isOk()) {
        printf("{\"event\":\"data_error\",\"transaction\":%u,\"status_t\":%d,\"exception\":%d,\"service_error\":%d,\"detail\":\"", code, rc, status.exceptionCode(), status.serviceSpecificErrorCode());
        const auto detail = status.toString8();
        for (const unsigned char* p = reinterpret_cast<const unsigned char*>(detail.c_str()); *p; ++p) {
            if (*p == '"' || *p == '\\') putchar('\\');
            if (*p >= 32) putchar(*p); else printf("\\u%04x", *p);
        }
        puts("\"}");
        return false;
    }
    return true;
}

template <typename Write> static status_t sized(Parcel& parcel, Write write) {
    size_t start = parcel.dataPosition();
    status_t rc = parcel.writeInt32(0);
    if (rc == OK) rc = write();
    size_t end = parcel.dataPosition();
    parcel.setDataPosition(start);
    if (rc == OK) rc = parcel.writeInt32(static_cast<int32_t>(end - start));
    parcel.setDataPosition(end);
    return rc;
}

static int dataProbe(int argc, char** argv) {
    if (argc != 7) return 2;
    auto process = driver(argv[2], strtoul(argv[3], nullptr, 10), strtoul(argv[4], nullptr, 10));
    struct stat node {};
    if (!process || stat(argv[2], &node) || node.st_rdev == strtoull(argv[6], nullptr, 10)) return 3;
    const bool art = !strcmp(argv[1], "data-artd");
    const bool create = !strcmp(argv[1], "data-installd-create");
    if (!art && !create && strcmp(argv[1], "data-installd-delete")) return 2;
    const char* service = art ? "artd" : "installd";
    const char* descriptor = art ? "com.android.server.art.IArtd" : "android.os.IInstalld";
    auto manager = process->getContextObject(nullptr);
    if (!manager) return 4;
    sp<IBinder> remote;
    for (int attempt = 0; attempt < 100 && !remote; ++attempt) {
        Parcel lookup, found;
        if (lookup.writeInterfaceToken(String16("android.os.IServiceManager")) != OK || lookup.writeString16(String16(service)) != OK || !dataCall(manager, 2, lookup, found)) return 5;
        if (found.readNullableStrongBinder(&remote) != OK || found.dataAvail() != 0) return 6;
        if (!remote) usleep(50000);
    }
    const bool matches = remote && remote->getInterfaceDescriptor() == String16(descriptor);
    printf("{\"event\":\"data_service_lookup\",\"service\":\"%s\",\"present\":%s,\"descriptor_matches\":%s}\n", service, remote ? "true" : "false", matches ? "true" : "false");
    if (!matches) return 6;
    const char* package = "com.android.ssal.phase2";
    const char* dex = "/data/app/com.android.ssal.phase2/base.apk";
    if (!art) {
        Parcel request, reply;
        if (request.writeInterfaceToken(String16(descriptor)) != OK) return 7;
        if (create) {
            // CreateAppDataArgs, non-null parcelable; nullable internal volume UUID.
            if (request.writeInt32(1) != OK || sized(request, [&]() -> status_t {
                if (request.writeInt32(-1) != OK || request.writeString16(String16(package)) != OK) return BAD_VALUE;
                for (int32_t value : {0, 3, 10000, 0}) if (request.writeInt32(value) != OK) return BAD_VALUE;
                if (request.writeString16(String16("default:targetSdkVersion=36")) != OK) return BAD_VALUE;
                return request.writeInt32(36);
            }) != OK || !dataCall(remote, 3, request, reply)) return 8;
            int32_t present = 0, size = 0;
            int64_t ce = 0, de = 0;
            int32_t exception = -1;
            if (reply.readInt32(&present) != OK || present != 1 || reply.readInt32(&size) != OK || size < 24 || reply.readInt64(&ce) != OK || reply.readInt64(&de) != OK || reply.readInt32(&exception) != OK || exception != 0 || ce <= 0 || de <= 0) return 9;
        } else {
            if (request.writeInt32(-1) != OK || request.writeString16(String16(package)) != OK || request.writeInt32(0) != OK || request.writeInt32(3) != OK || request.writeInt64(0) != OK || !dataCall(remote, 9, request, reply) || reply.dataAvail() != 0) return 10;
        }
        printf("{\"event\":\"data_operation\",\"result\":\"%s\",\"private_binder\":true}\n", create ? "installd_created" : "installd_deleted");
        return 0;
    }
    Parcel aliveRequest, aliveReply;
    bool alive = false;
    if (aliveRequest.writeInterfaceToken(String16(descriptor)) != OK || !dataCall(remote, 0, aliveRequest, aliveReply) || aliveReply.readBool(&alive) != OK || !alive || aliveReply.dataAvail() != 0) return 11;
    Parcel cancelRequest, cancelReply;
    sp<IBinder> cancel;
    if (cancelRequest.writeInterfaceToken(String16(descriptor)) != OK || !dataCall(remote, 16, cancelRequest, cancelReply) || cancelReply.readStrongBinder(&cancel) != OK || !cancel || cancelReply.dataAvail() != 0) return 12;
    int loggingFd = open("/data/local/tmp/phase2-dex2oat.log", O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
    if (loggingFd < 0) return 13;
    Parcel request, reply;
    auto text = [&](const char* s) { return request.writeString16(String16(s)); };
    auto permission = [&]() -> status_t { if (request.writeInt32(1) != OK) return BAD_VALUE; return sized(request, [&]() -> status_t {
        for (int32_t value : {1000, 1000, 1, 0}) if (request.writeInt32(value) != OK) return BAD_VALUE;
        return OK;
    }); };
    if (request.writeInterfaceToken(String16(descriptor)) != OK || request.writeInt32(1) != OK || sized(request, [&]() -> status_t {
        if (request.writeInt32(1) != OK || sized(request, [&]() -> status_t {
            if (text(dex) != OK || text("arm64") != OK || request.writeBool(true) != OK) return BAD_VALUE;
            return request.writeBool(false);
        }) != OK) return BAD_VALUE;
        if (request.writeInt32(1) != OK) return BAD_VALUE;
        return sized(request, [&]() -> status_t {
            if (permission() != OK || permission() != OK) return BAD_VALUE;
            return request.writeInt32(0); // no SeContext
        });
    }) != OK || text(dex) != OK || text("arm64") != OK || text("PCL[]") != OK || text("verify") != OK) return 13;
    // Nullable profile, input VDEX and DM; PriorityClass::BOOT (no Host cgroup task profile).
    for (int32_t value : {0, 0, 0, 100}) if (request.writeInt32(value) != OK) return 13;
    if (request.writeInt32(1) != OK || sized(request, [&]() -> status_t {
        if (text("cmdline") != OK || request.writeInt32(36) != OK) return BAD_VALUE;
        for (int i = 0; i < 3; ++i) if (request.writeBool(false) != OK) return BAD_VALUE;
        return text("ssal Phase 2 disposable probe");
    }) != OK || request.writeStrongBinder(cancel) != OK || request.writeInt32(1) != OK || request.writeDupParcelFileDescriptor(loggingFd) != OK) { close(loggingFd); return 14; }
    close(loggingFd);
    // Android 16 QPR2 adds a nullable trailing loggingFd, scoped to Guest userdata.
    if (!dataCall(remote, 15, request, reply)) return 14;
    // ArtdDexoptResult is a required sized parcelable. Filesystem evidence is checked by the supervisor.
    int32_t present = 0, size = 0;
    bool cancelled = true;
    if (reply.readInt32(&present) != OK || present != 1) return 15;
    size_t start = reply.dataPosition();
    int64_t wall = -1, cpu = -1, bytes = -1, before = -1;
    if (reply.readInt32(&size) != OK || size < 40 || static_cast<size_t>(size) > reply.dataSize() - start || reply.readBool(&cancelled) != OK || cancelled || reply.readInt64(&wall) != OK || reply.readInt64(&cpu) != OK || reply.readInt64(&bytes) != OK || reply.readInt64(&before) != OK || wall < 0 || cpu < 0 || bytes <= 0 || before < 0) return 15;
    reply.setDataPosition(start + size);
    if (reply.dataAvail() != 0) return 15;
    printf("{\"event\":\"data_operation\",\"result\":\"artd_compiled\",\"private_binder\":true,\"compiler_filter\":\"verify\",\"wall_time_ms\":%lld,\"cpu_time_ms\":%lld,\"output_bytes\":%lld}\n",static_cast<long long>(wall),static_cast<long long>(cpu),static_cast<long long>(bytes));
    return 0;
}

int main(int argc, char** argv) {
    setvbuf(stdout, nullptr, _IONBF, 0);
    setvbuf(stderr, nullptr, _IONBF, 0);
    if (argc == 3 && !strcmp(argv[1], "phase2-properties")) {
        auto area = prop_area::map_prop_area_rw(argv[2], nullptr, nullptr);
        if (!area) return 1;
        const char* compiler = "dalvik.vm.dex2oat64.enabled";
        const char* abi = "ro.product.cpu.abilist64";
        const char* sdk = "ro.build.version.sdk";
        const char* codename = "ro.build.version.codename";
        const bool ok = area->add("servicemanager.ready", 20, "true", 4) && area->add(compiler, strlen(compiler), "true", 4) && area->add(abi, strlen(abi), "arm64-v8a", 9) && area->add(sdk,strlen(sdk),"36",2) && area->add(codename,strlen(codename),"REL",3);
        prop_area::unmap_prop_area(&area);
        return ok ? 0 : 1;
    }
    if (argc > 1 && !strncmp(argv[1], "data-", 5)) return dataProbe(argc, argv);
    if (argc > 1 && !strncmp(argv[1], "registry-", 9)) return registry(argc, argv);
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
