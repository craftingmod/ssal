// Guest Private HwBinder / HIDL verification client using the NDK-only ssal HwBinder transport.
#include "../hwbinder/hwbinder.h"
#include <fcntl.h>
#include <linux/android/binder.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

using ssal::OK;
using ssal::DEAD_OBJECT;
using ssal::sp;
using ssal::status_t;
using ssal::hardware::hidl_memory;
using ssal::hardware::hidl_string;
using ssal::hardware::IBinder;
using ssal::hardware::Parcel;
using ssal::hardware::ProcessState;
using ssal::hardware::readEmbeddedFromParcel;
using ssal::hardware::readFromParcel;
using ssal::hardware::Status;
using ssal::hardware::writeEmbeddedToParcel;

static bool parseMajorMinor(const char* arg, unsigned* majorOut, unsigned* minorOut) {
    const char* colon = strchr(arg, ':');
    if (!colon || colon == arg || !colon[1]) return false;
    char* end = nullptr;
    unsigned long maj = strtoul(arg, &end, 10);
    if (end != colon || maj > UINT32_MAX) return false;
    unsigned long min = strtoul(colon + 1, &end, 10);
    if (!end || *end || min > UINT32_MAX) return false;
    *majorOut = static_cast<unsigned>(maj);
    *minorOut = static_cast<unsigned>(min);
    return true;
}

static bool verifyPrivateHwBinderDevice(unsigned expectedMajor, unsigned expectedMinor,
                                        struct stat* devStatOut) {
    struct stat st {};
    if (stat("/dev/hwbinder", &st) != 0 || !S_ISCHR(st.st_mode) ||
        major(st.st_rdev) != expectedMajor || minor(st.st_rdev) != expectedMinor) {
        fprintf(stderr, "private /dev/hwbinder identity mismatch (errno=%d)\n", errno);
        return false;
    }
    const char* forbidden[] = {
        "/dev/binder",
        "/dev/vndbinder",
        "/dev/binderfs/hwbinder",
        "/proc/1/root/dev/hwbinder",
    };
    for (const char* path : forbidden) {
        struct stat other {};
        if (lstat(path, &other) == 0) {
            fprintf(stderr, "unexpected endpoint accessible: %s\n", path);
            return false;
        }
    }
    int fd = open("/dev/hwbinder", O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        fprintf(stderr, "open(/dev/hwbinder) failed: errno=%d\n", errno);
        return false;
    }
    struct binder_version version {};
    if (ioctl(fd, BINDER_VERSION, &version) != 0 || version.protocol_version != 8) {
        fprintf(stderr, "BINDER_VERSION failed: proto=%ld errno=%d\n",
                static_cast<long>(version.protocol_version), errno);
        close(fd);
        return false;
    }
    void* mapped = mmap(nullptr, 4096, PROT_READ, MAP_PRIVATE, fd, 0);
    if (mapped == MAP_FAILED) {
        fprintf(stderr, "mmap(/dev/hwbinder) failed: errno=%d\n", errno);
        close(fd);
        return false;
    }
    munmap(mapped, 4096);
    close(fd);
    *devStatOut = st;
    return true;
}

static bool verifyProcessStateFd(const struct stat& expected, unsigned expectedMajor) {
    bool found = false;
    bool unexpected = false;
    for (int fd = 0; fd < 1024; ++fd) {
        struct stat actual {};
        if (fstat(fd, &actual) == 0 && S_ISCHR(actual.st_mode)) {
            if (actual.st_dev == expected.st_dev && actual.st_ino == expected.st_ino &&
                actual.st_rdev == expected.st_rdev) {
                found = true;
            } else if (major(actual.st_rdev) == expectedMajor) {
                unexpected = true;
            }
        }
    }
    if (!found || unexpected) {
        fprintf(stderr, "ssal HwBinder opened unexpected binder fd (found=%d unexpected=%d)\n",
                found ? 1 : 0, unexpected ? 1 : 0);
        return false;
    }
    return true;
}

static status_t lookupService(const sp<IBinder>& sm, const char* fqNameStr, const char* instStr,
                              sp<IBinder>* serviceOut) {
    Parcel req, rep;
    status_t rc = req.writeInterfaceToken("android.hidl.manager@1.0::IServiceManager");
    if (rc != OK) return rc;
    hidl_string fqName(fqNameStr);
    hidl_string inst(instStr);
    size_t h1 = 0, h2 = 0;
    rc = req.writeBuffer(&fqName, sizeof(fqName), &h1);
    if (rc == OK) rc = writeEmbeddedToParcel(fqName, &req, h1, 0);
    if (rc == OK) rc = req.writeBuffer(&inst, sizeof(inst), &h2);
    if (rc == OK) rc = writeEmbeddedToParcel(inst, &req, h2, 0);
    if (rc != OK) return rc;
    rc = sm->transact(IBinder::FIRST_CALL_TRANSACTION /* IServiceManager::get */, req, &rep);
    if (rc != OK) return rc;
    Status status;
    rc = readFromParcel(&status, rep);
    if (rc != OK) return rc;
    if (!status.isOk()) {
        fprintf(stderr, "IServiceManager::get status error: %s\n", status.description().c_str());
        return ssal::UNKNOWN_ERROR;
    }
    return rep.readNullableStrongBinder(serviceOut);
}

static status_t pingHidl(const sp<IBinder>& target) {
    Parcel req, rep;
    status_t rc = req.writeInterfaceToken("android.hidl.base@1.0::IBase");
    if (rc != OK) return rc;
    rc = target->transact(IBinder::HIDL_PING_TRANSACTION, req, &rep);
    if (rc != OK) return rc;
    Status status;
    rc = readFromParcel(&status, rep);
    if (rc != OK) return rc;
    return status.isOk() ? OK : ssal::UNKNOWN_ERROR;
}

static bool testAllocatorTransactions(const sp<IBinder>& svc) {
    if (!svc || svc->localBinder() != nullptr) {
        fprintf(stderr, "allocator service is null or unexpectedly local\n");
        return false;
    }
    // 1. IBase::ping
    {
        status_t rc = pingHidl(svc);
        if (rc != OK) {
            fprintf(stderr, "IBase::ping failed: rc=%d\n", rc);
            return false;
        }
        printf("guest_hwbinder_hidl=PASS service=android.hidl.allocator@1.0::IAllocator/ashmem transaction=IBase::ping\n");
    }
    // 2. IBase::interfaceDescriptor
    {
        Parcel req, rep;
        status_t rc = req.writeInterfaceToken("android.hidl.base@1.0::IBase");
        if (rc == OK) rc = svc->transact(IBinder::HIDL_GET_DESCRIPTOR_TRANSACTION, req, &rep);
        Status status;
        if (rc == OK) rc = readFromParcel(&status, rep);
        const hidl_string* desc = nullptr;
        size_t handle = 0;
        if (rc == OK && status.isOk()) {
            rc = rep.readBuffer(sizeof(hidl_string), &handle,
                                reinterpret_cast<const void**>(&desc));
        }
        if (rc == OK) rc = readEmbeddedFromParcel(*desc, rep, handle, 0);
        if (rc != OK || !status.isOk() || !desc ||
            strcmp(desc->c_str(), "android.hidl.allocator@1.0::IAllocator") != 0) {
            fprintf(stderr, "IBase::interfaceDescriptor failed: rc=%d desc=%s\n", rc,
                    rc == OK && desc ? desc->c_str() : "(invalid)");
            return false;
        }
        printf("guest_hwbinder_hidl=PASS service=android.hidl.allocator@1.0::IAllocator/ashmem transaction=IBase::interfaceDescriptor descriptor=%s\n",
               desc->c_str());
    }
    // 3. IAllocator::allocate(4096)
    {
        Parcel req, rep;
        status_t rc = req.writeInterfaceToken("android.hidl.allocator@1.0::IAllocator");
        if (rc == OK) rc = req.writeUint64(4096);
        if (rc == OK) rc = svc->transact(IBinder::FIRST_CALL_TRANSACTION /* allocate */, req, &rep);
        Status status;
        if (rc == OK) rc = readFromParcel(&status, rep);
        bool success = false;
        if (rc == OK && status.isOk()) rc = rep.readBool(&success);
        const hidl_memory* mem = nullptr;
        size_t memHandle = 0;
        if (rc == OK && status.isOk() && success) {
            rc = rep.readBuffer(sizeof(hidl_memory), &memHandle,
                                reinterpret_cast<const void**>(&mem));
        }
        if (rc == OK && mem) rc = readEmbeddedFromParcel(*mem, rep, memHandle, 0);
        if (rc != OK || !status.isOk() || !success || !mem || mem->size() != 4096 ||
            strcmp(mem->name().c_str(), "ashmem") != 0 || !mem->handle() ||
            mem->handle()->numFds != 1 || mem->handle()->data[0] < 0) {
            fprintf(stderr,
                    "IAllocator::allocate failed: rc=%d status=%s success=%d size=%llu name=%s\n",
                    rc, status.description().c_str(), success ? 1 : 0,
                    mem ? static_cast<unsigned long long>(mem->size()) : 0ULL,
                    rc == OK && mem ? mem->name().c_str() : "(invalid)");
            return false;
        }
        int shmFd = mem->handle()->data[0];
        void* buf = mmap(nullptr, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, shmFd, 0);
        if (buf == MAP_FAILED) {
            fprintf(stderr, "mmap returned hidl_memory fd=%d failed: errno=%d\n", shmFd, errno);
            return false;
        }
        static const char kMagic[] = "SSAL_HWBINDER_HIDL_OK";
        memcpy(buf, kMagic, sizeof(kMagic));
        bool verified = memcmp(buf, kMagic, sizeof(kMagic)) == 0;
        munmap(buf, 4096);
        if (!verified) {
            fprintf(stderr, "shared memory readback verification failed\n");
            return false;
        }
        printf("guest_hwbinder_hidl=PASS service=android.hidl.allocator@1.0::IAllocator/ashmem transaction=IAllocator::allocate size=4096 name=%s fd=%d shm_rw=PASS\n",
               mem->name().c_str(), shmFd);
    }
    return true;
}

int main(int argc, char** argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s MAJOR:MINOR empty|absent|live|dead\n", argv[0]);
        return 2;
    }
    unsigned expectedMajor = 0, expectedMinor = 0;
    if (!parseMajorMinor(argv[1], &expectedMajor, &expectedMinor)) {
        fprintf(stderr, "invalid MAJOR:MINOR: %s\n", argv[1]);
        return 2;
    }
    const char* mode = argv[2];
    const bool isEmpty = strcmp(mode, "empty") == 0;
    const bool isAbsent = strcmp(mode, "absent") == 0;
    const bool isLive = strcmp(mode, "live") == 0;
    const bool isDead = strcmp(mode, "dead") == 0;
    if (!isEmpty && !isAbsent && !isLive && !isDead) {
        fprintf(stderr, "invalid mode: %s\n", mode);
        return 2;
    }

    struct stat devStat {};
    if (!verifyPrivateHwBinderDevice(expectedMajor, expectedMinor, &devStat)) return 3;

    auto ps = ProcessState::self();
    if (!ps || !verifyProcessStateFd(devStat, expectedMajor)) return 4;

    char sid[256] = {};
    int sidFd = open("/proc/self/attr/current", O_RDONLY | O_CLOEXEC);
    if (sidFd >= 0) {
        ssize_t n = read(sidFd, sid, sizeof(sid) - 1);
        close(sidFd);
        if (n > 0) sid[strcspn(sid, "\n")] = '\0';
    }
    printf("guest_hwbinder_client mode=%s rdev=%u:%u uid=%u sid=%s open_mmap_ioctl=PASS\n",
           mode, expectedMajor, expectedMinor, getuid(), sid);

    sp<IBinder> sm = ps->getContextObject(nullptr);
    if (!sm) {
        fprintf(stderr, "getContextObject(nullptr) returned null\n");
        return 5;
    }
    status_t pingRc = pingHidl(sm);
    if (isEmpty || isDead) {
        if (pingRc == OK) {
            fprintf(stderr, "expected handle 0 unavailable in %s mode, but ping returned OK\n",
                    mode);
            return 6;
        }
        printf("guest_hwbinder_context_manager mode=%s status=%s rc=%d\n", mode,
               pingRc == DEAD_OBJECT ? "DEAD_OBJECT" : "UNAVAILABLE", pingRc);
        return 0;
    }
    if (pingRc != OK) {
        fprintf(stderr, "handle 0 ping failed in %s mode: rc=%d\n", mode, pingRc);
        return 7;
    }
    printf("guest_hwbinder_context_manager mode=%s status=ALIVE\n", mode);

    sp<IBinder> svc;
    status_t lookupRc = lookupService(sm, "android.hidl.allocator@1.0::IAllocator", "ashmem", &svc);
    if (lookupRc != OK) {
        fprintf(stderr, "IServiceManager::get failed: rc=%d\n", lookupRc);
        return 8;
    }
    if (isAbsent) {
        if (svc != nullptr) {
            fprintf(stderr, "expected IAllocator/ashmem absent, but service was returned\n");
            return 9;
        }
        printf("guest_hwbinder_service_lookup mode=absent service=android.hidl.allocator@1.0::IAllocator/ashmem present=false\n");
        return 0;
    }
    if (!svc) {
        fprintf(stderr, "IAllocator/ashmem not found in live mode\n");
        return 10;
    }
    printf("guest_hwbinder_service_lookup mode=live service=android.hidl.allocator@1.0::IAllocator/ashmem present=true remote=%d\n",
           svc->localBinder() == nullptr ? 1 : 0);
    if (!testAllocatorTransactions(svc)) return 11;
    return 0;
}
