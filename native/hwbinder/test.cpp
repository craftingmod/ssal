#include "hwbinder.h"
#include "../virtual-audio/fmq.h"
#include <cassert>
#include <cstdio>
#include <thread>

using namespace ssal;
using namespace ssal::hardware;
int main() {
    {
        Parcel p;
        assert(p.writeInterfaceToken("android.hidl.base@1.0::IBase") == OK);
        assert(p.writeBool(true) == OK);
        assert(p.writeUint64(0x123456789abcdef0ULL) == OK);
        assert(p.enforceInterface("android.hidl.base@1.0::IBase"));
        bool b = false; uint64_t n = 0;
        assert(p.readBool(&b) == OK && b);
        assert(p.readUint64(&n) == OK && n == 0x123456789abcdef0ULL);
        assert(p.readUint64(&n) == BAD_VALUE);
    }
    {
        Parcel p;
        hidl_string name("primary");
        size_t root = 0;
        p.writeInt32(0); // Binder objects are 4-byte aligned, including on arm64.
        assert(p.writeBuffer(&name, sizeof(name), &root) == OK && root == 0);
        assert(writeEmbeddedToParcel(name, &p, root, 0) == OK);
        assert(p.objects().size() == 2 && p.objects()[0] == 4);
        assert(p.buffersSize() == 24);
        binder_buffer_object parent{}, child{};
        memcpy(&parent, p.bytes().data() + p.objects()[0], sizeof(parent));
        memcpy(&child, p.bytes().data() + p.objects()[1], sizeof(child));
        assert(parent.hdr.type == BINDER_TYPE_PTR && parent.length == 16);
        assert(child.flags == BINDER_BUFFER_FLAG_HAS_PARENT && child.parent == 0 && child.parent_offset == 0);
        assert(child.length == 8 && strcmp(reinterpret_cast<const char*>(child.buffer), "primary") == 0);
        int32_t result;
        assert(p.readInt32(&result) == OK);
        const void* raw;
        size_t handle;
        assert(p.readBuffer(sizeof(name), &handle, &raw) == OK);
        assert(readEmbeddedFromParcel(*static_cast<const hidl_string*>(raw), p, handle, 0) == OK);
    }
    {
        Parcel p;
        uint64_t root[2]{};
        size_t index;
        assert(p.writeBuffer(root, sizeof(root), &index) == OK);
        assert(p.writeEmbeddedBuffer("x", 2, nullptr, index, 9) == BAD_VALUE);
    }
    {
        Parcel p;
        assert(p.writeStrongBinder(nullptr) == OK && p.objects().empty());
        sp<IBinder> binder;
        assert(p.readNullableStrongBinder(&binder) == OK && !binder);
    }
    {
        Parcel p;
        assert(p.write(nullptr, 1) == BAD_VALUE);
        assert(p.writeInt32(0) == BAD_VALUE);
    }
    {
        Parcel p;
        hidl_string name("abc");
        size_t root;
        p.writeBuffer(&name, sizeof(name), &root);
        writeEmbeddedToParcel(name, &p, root, 0);
        const void* raw;
        assert(p.readBuffer(sizeof(name), &root, &raw) == OK);
        assert(p.readEmbeddedBuffer(4, nullptr, root, 8, &raw) == BAD_VALUE);
    }
    {
        audio::Queue invalid(5, 4);
        assert(!invalid.valid());
        audio::Queue ring(12, 4, true);
        assert(ring.valid());
        uint32_t in[] = {10, 20, 30}, out[3]{};
        assert(ring.write(in, 12) && !ring.write(in, 4));
        assert(ring.read(out, 8) && out[0] == 10 && out[1] == 20);
        assert(ring.write(in, 8));
        assert(ring.read(out, 12) && out[0] == 30 && out[1] == 10 && out[2] == 20);
        assert(!ring.read(out, 4) && !ring.write(in, 3));
        std::thread wake([&] { ring.wake(1); });
        ring.wait(1);
        wake.join();
        Parcel p;
        assert(ring.describe(&p) == OK && p.objects().size() == 4);
        binder_buffer_object root{};
        memcpy(&root, p.bytes().data(), sizeof(root));
        assert(root.length == 32);
        uint32_t quantum, flags;
        memcpy(&quantum, reinterpret_cast<const uint8_t*>(root.buffer) + 24, 4);
        memcpy(&flags, reinterpret_cast<const uint8_t*>(root.buffer) + 28, 4);
        assert(quantum == 4 && flags == 1);
        const void* raw; size_t parent;
        assert(p.readBuffer(32, &parent, &raw) == OK);
        assert(p.readEmbeddedBuffer(4 * sizeof(GrantorDescriptor), nullptr, parent, 0, &raw) == OK);
        const NativeHandle* native;
        assert(p.readEmbeddedNativeHandle(parent, 16, &native) == OK);
        assert(native && native->numFds == 1 && native->data[0] >= 0);
        Parcel empty;
        assert(audio::Queue::emptyDescriptor(&empty) == OK);
        assert(empty.readBuffer(32, &parent, &raw) == OK);
        assert(empty.readEmbeddedBuffer(0, nullptr, parent, 0, &raw) == OK && !raw);
        assert(empty.readEmbeddedNativeHandle(parent, 16, &native) == OK && !native);
    }
    puts("HwBinder parcel and audio FMQ self-check passed");
}
