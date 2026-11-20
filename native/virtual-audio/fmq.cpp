#include "fmq.h"
#include <linux/futex.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <algorithm>
#include <climits>

namespace ssal::audio {
status_t Queue::emptyDescriptor(hardware::Parcel* parcel) {
    uint8_t descriptor[32] = {};
    size_t parent;
    status_t rc = parcel->writeBuffer(descriptor, sizeof(descriptor), &parent);
    if (rc == OK) rc = parcel->writeEmbeddedBuffer(nullptr, 0, nullptr, parent, 0);
    if (rc == OK) rc = parcel->writeEmbeddedNativeHandle(nullptr, parent, 16);
    return rc;
}
Queue::Queue(size_t capacity, uint32_t quantum, bool event)
    : capacity_(capacity), size_(0), eventOffset_((64 + capacity + 3) & ~size_t(3)),
      quantum_(quantum), event_(event) {
    if (!capacity || capacity > 1024 * 1024 || !quantum || capacity % quantum) return;
    size_t page = static_cast<size_t>(sysconf(_SC_PAGESIZE));
    size_ = (eventOffset_ + 4 + page - 1) & ~(page - 1);
    handle_.fd = static_cast<int>(syscall(__NR_memfd_create, "ssal_audio_fmq", MFD_CLOEXEC));
    if (handle_.fd < 0 || ftruncate(handle_.fd, size_) != 0) return;
    void* raw = mmap(nullptr, size_, PROT_READ | PROT_WRITE, MAP_SHARED, handle_.fd, 0);
    if (raw == MAP_FAILED) return;
    memory_ = static_cast<uint8_t*>(raw);
    new (readPtr()) std::atomic<uint64_t>(0);
    new (writePtr()) std::atomic<uint64_t>(0);
    new (eventPtr()) std::atomic<uint32_t>(0);
}
Queue::~Queue() {
    if (memory_) munmap(memory_, size_);
    if (handle_.fd >= 0) close(handle_.fd);
}
std::atomic<uint64_t>* Queue::readPtr() const { return reinterpret_cast<std::atomic<uint64_t>*>(memory_); }
std::atomic<uint64_t>* Queue::writePtr() const { return reinterpret_cast<std::atomic<uint64_t>*>(memory_ + 8); }
std::atomic<uint32_t>* Queue::eventPtr() const { return reinterpret_cast<std::atomic<uint32_t>*>(memory_ + eventOffset_); }
size_t Queue::available() const {
    uint64_t bytes = writePtr()->load(std::memory_order_acquire) - readPtr()->load(std::memory_order_acquire);
    return bytes <= capacity_ ? static_cast<size_t>(bytes) : SIZE_MAX;
}
bool Queue::read(void* destination, size_t bytes) {
    size_t availableBytes = available();
    if (availableBytes == SIZE_MAX || bytes > availableBytes || bytes % quantum_) return false;
    if (!bytes) return true;
    uint64_t pos = readPtr()->load(std::memory_order_relaxed);
    size_t start = pos % capacity_, first = std::min(bytes, capacity_ - start);
    memcpy(destination, memory_ + 64 + start, first);
    memcpy(static_cast<uint8_t*>(destination) + first, memory_ + 64, bytes - first);
    readPtr()->store(pos + bytes, std::memory_order_release);
    return true;
}
bool Queue::write(const void* source, size_t bytes) {
    size_t used = available();
    if (used == SIZE_MAX || bytes > capacity_ - used || bytes % quantum_) return false;
    if (!bytes) return true;
    uint64_t pos = writePtr()->load(std::memory_order_relaxed);
    size_t start = pos % capacity_, first = std::min(bytes, capacity_ - start);
    memcpy(memory_ + 64 + start, source, first);
    memcpy(memory_ + 64, static_cast<const uint8_t*>(source) + first, bytes - first);
    writePtr()->store(pos + bytes, std::memory_order_release);
    return true;
}
void Queue::wake(uint32_t bits) {
    if (!event_) return;
    eventPtr()->fetch_or(bits, std::memory_order_release);
    syscall(__NR_futex, eventPtr(), FUTEX_WAKE, INT_MAX, nullptr, nullptr, 0);
}
void Queue::wait(uint32_t bits) {
    if (!event_) return;
    uint32_t previous = eventPtr()->fetch_and(~bits, std::memory_order_acquire);
    if (previous & bits) return;
    timespec timeout{0, 50000000};
    syscall(__NR_futex, eventPtr(), FUTEX_WAIT, previous & ~bits, &timeout, nullptr, 0);
}
status_t Queue::describe(hardware::Parcel* parcel) const {
    using namespace hardware;
    if (!valid()) return BAD_VALUE;
    struct Descriptor {
        hidl_vec<GrantorDescriptor> grantors;
        const NativeHandle* handle;
        uint32_t quantum;
        uint32_t flags = 1;  // kSynchronizedReadWrite
    } descriptor;
    static_assert(sizeof(Descriptor) == 32 && offsetof(Descriptor, handle) == 16);
    descriptor.grantors.resize(event_ ? 4 : 3);
    descriptor.grantors[0] = {0, 0, 0, 8};
    descriptor.grantors[1] = {0, 0, 8, 8};
    descriptor.grantors[2] = {0, 0, 64, capacity_};
    if (event_) descriptor.grantors[3] = {0, 0, static_cast<uint32_t>(eventOffset_), 4};
    descriptor.handle = reinterpret_cast<const NativeHandle*>(&handle_);
    descriptor.quantum = quantum_;
    size_t parent, child;
    status_t rc = parcel->writeBuffer(&descriptor, sizeof(descriptor), &parent);
    if (rc == OK) rc = parcel->writeEmbeddedBuffer(descriptor.grantors.data(),
        descriptor.grantors.size() * sizeof(GrantorDescriptor), &child, parent, 0);
    if (rc == OK) rc = parcel->writeEmbeddedNativeHandle(descriptor.handle, parent, 16);
    return rc;
}
}  // namespace ssal::audio
