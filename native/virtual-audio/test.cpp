#define main ssal_virtual_audio_main
#include "main.cpp"
#undef main
#include <cassert>
#include <linux/futex.h>

struct ClientQueue {
    uint8_t* memory = nullptr;
    size_t size = 0;
    uint32_t event = 0;
    explicit ClientQueue(Parcel& parcel, bool hasEvent) {
        const void* raw;
        size_t parent;
        assert(parcel.readBuffer(32, &parent, &raw) == OK);
        uint32_t grantors;
        memcpy(&grantors, static_cast<const uint8_t*>(raw) + 8, 4);
        assert(grantors == (hasEvent ? 4u : 3u));
        assert(parcel.readEmbeddedBuffer(grantors * sizeof(ssal::hardware::GrantorDescriptor),
            nullptr, parent, 0, &raw) == OK);
        if (hasEvent) event = static_cast<const ssal::hardware::GrantorDescriptor*>(raw)[3].offset;
        const ssal::hardware::NativeHandle* native;
        assert(parcel.readEmbeddedNativeHandle(parent, 16, &native) == OK);
        assert(native && native->numFds == 1);
        struct stat st{};
        assert(fstat(native->data[0], &st) == 0);
        size = st.st_size;
        memory = static_cast<uint8_t*>(mmap(nullptr, size, PROT_READ | PROT_WRITE,
                                           MAP_SHARED, native->data[0], 0));
        assert(memory != MAP_FAILED);
    }
    ~ClientQueue() { munmap(memory, size); }
    std::atomic<uint64_t>& readPtr() { return *reinterpret_cast<std::atomic<uint64_t>*>(memory); }
    std::atomic<uint64_t>& writePtr() { return *reinterpret_cast<std::atomic<uint64_t>*>(memory + 8); }
};

int main() {
    StreamParams params;
    VirtualStreamOut stream(params);
    {
        Parcel request, reply;
        request.writeInterfaceToken("android.hardware.audio@7.0::IStream");
        assert(stream.onTransact(1, request, &reply, 0, {}) == OK);
        int32_t status;
        uint64_t bytes;
        assert(reply.readInt32(&status) == OK && status == 0);
        assert(reply.readUint64(&bytes) == OK && bytes == 4);
    }
    {
        Parcel bad, reply;
        bad.writeInterfaceToken("android.hardware.audio@7.0::IStream");
        assert(stream.onTransact(23, bad, &reply, 0, {}) == ssal::BAD_TYPE);
    }
    {
        Parcel request, reply;
        request.writeInterfaceToken("android.hardware.audio@7.0::IStreamOut");
        request.writeUint32(0); request.writeUint32(UINT32_MAX);
        assert(stream.onTransact(23, request, &reply, 0, {}) == OK);
        int32_t status, result;
        assert(reply.readInt32(&status) == OK && status == 0);
        assert(reply.readInt32(&result) == OK && result == 2);
    }
    {
        Parcel request, reply;
        request.writeInterfaceToken("android.hardware.audio@7.0::IStreamOut");
        request.writeUint32(4); request.writeUint32(16);
        assert(stream.onTransact(23, request, &reply, 0, {}) == OK);
        int32_t status, result, tid;
        assert(reply.readInt32(&status) == OK && status == 0);
        assert(reply.readInt32(&result) == OK && result == 0);
        ClientQueue command(reply, false), data(reply, true), response(reply, false);
        assert(reply.readInt32(&tid) == OK && tid > 0);
        for (int32_t op : {2, 1, 0}) {
            if (op == 0) {
                memset(data.memory + 64, 0, 8);
                data.writePtr().store(8, std::memory_order_release);
            }
            memcpy(command.memory + 64, &op, sizeof(op));
            command.writePtr().fetch_add(4, std::memory_order_release);
            auto* event = reinterpret_cast<std::atomic<uint32_t>*>(data.memory + data.event);
            event->fetch_or(1, std::memory_order_release);
            syscall(__NR_futex, event, FUTEX_WAKE, 1, nullptr, nullptr, 0);
            unsigned ticks = 0;
            while (response.writePtr().load(std::memory_order_acquire) == response.readPtr().load()) {
                assert(++ticks < 1000);
                usleep(1000);
            }
            ssal::audio::WriteStatus actual;
            memcpy(&actual, response.memory + 64, sizeof(actual));
            response.readPtr().fetch_add(sizeof(actual), std::memory_order_release);
            assert(actual.replyTo == op);
            if (op == 2) assert(actual.result == 0 && actual.value == 20);
            else if (op == 1) assert(actual.result == 0 && actual.seconds > 0);
            else assert(actual.result == 4); // No Host bridge in this unit test.
        }
        Parcel close, closed;
        close.writeInterfaceToken("android.hardware.audio@7.0::IStream");
        assert(stream.onTransact(19, close, &closed, 0, {}) == OK);
    }
    puts("Audio HAL prepare/command/data/status/close self-check passed");
}
