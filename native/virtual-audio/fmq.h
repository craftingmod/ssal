#pragma once
#include "../hwbinder/hwbinder.h"
#include <atomic>

namespace ssal::audio {
// HIDL synchronized FMQ: byte counters, shared ring and optional EventFlag word.
class Queue {
public:
    Queue(size_t capacity, uint32_t quantum, bool event = false);
    ~Queue();
    Queue(const Queue&) = delete;
    Queue& operator=(const Queue&) = delete;
    bool valid() const { return memory_ != nullptr; }
    size_t available() const;
    bool read(void*, size_t);
    bool write(const void*, size_t);
    void wake(uint32_t bits);
    void wait(uint32_t bits);
    status_t describe(hardware::Parcel*) const;
    static status_t emptyDescriptor(hardware::Parcel*);
private:
    std::atomic<uint64_t>* readPtr() const;
    std::atomic<uint64_t>* writePtr() const;
    std::atomic<uint32_t>* eventPtr() const;
    struct { int32_t version = 12, numFds = 1, numInts = 0, fd = -1; } handle_;
    size_t capacity_, size_, eventOffset_;
    uint32_t quantum_;
    uint8_t* memory_ = nullptr;
    bool event_;
};
struct WriteStatus {
    int32_t result = 0;
    int32_t replyTo = 0;
    uint64_t value = 0;
    int64_t seconds = 0;
    int64_t nanos = 0;
};
static_assert(sizeof(WriteStatus) == 32);
}  // namespace ssal::audio
