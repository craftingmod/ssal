#pragma once

// HIDL wire types and the small HwBinder surface used by ssal's private Guest HALs.
// No platform C++ ABI or GSI headers/libraries are used.
#include <linux/android/binder.h>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <memory>
#include <map>
#include <string>
#include <vector>

namespace ssal {
using status_t = int32_t;
constexpr status_t OK = 0, BAD_VALUE = -EINVAL, BAD_TYPE = -EBADMSG;
constexpr status_t DEAD_OBJECT = -EPIPE, UNKNOWN_TRANSACTION = -EBADMSG;
constexpr status_t UNKNOWN_ERROR = -EIO;
template <typename T> using sp = std::shared_ptr<T>;

namespace hardware {
struct NativeHandle {
    int32_t version = 12;
    int32_t numFds = 0;
    int32_t numInts = 0;
    int32_t data[0];
};
struct hidl_string {
    const char* buffer = "";
    uint32_t length = 0;
    uint8_t owns = 0;
    uint8_t pad[3] = {};
    hidl_string() = default;
    hidl_string(const char* s) { *this = s; }
    hidl_string& operator=(const char* s) {
        setToExternal(s, strlen(s));
        return *this;
    }
    void setToExternal(const char* s, size_t n) {
        if (n > UINT32_MAX) abort();
        buffer = s; length = static_cast<uint32_t>(n);
    }
    const char* c_str() const { return buffer; }
    size_t size() const { return length; }
    static constexpr size_t kOffsetOfBuffer = 0;
};
template <typename T> struct hidl_vec {
    T* buffer = nullptr;
    uint32_t length = 0;
    uint8_t owns = 0;
    uint8_t pad[3] = {};
    hidl_vec() = default;
    hidl_vec(const hidl_vec&) = delete;
    hidl_vec& operator=(const hidl_vec&) = delete;
    ~hidl_vec() { if (owns) delete[] buffer; }
    void resize(size_t n) {
        if (n > UINT32_MAX) abort();
        if (owns) delete[] buffer;
        buffer = n ? new T[n]() : nullptr;
        length = static_cast<uint32_t>(n); owns = 1;
    }
    T* data() { return buffer; }
    const T* data() const { return buffer; }
    size_t size() const { return length; }
    T& operator[](size_t n) { return buffer[n]; }
    const T& operator[](size_t n) const { return buffer[n]; }
    static constexpr size_t kOffsetOfBuffer = 0;
};
struct hidl_handle {
    const NativeHandle* buffer = nullptr;
    uint8_t owns = 0;
    uint8_t pad[7] = {};
};
struct hidl_memory {
    hidl_handle native;
    uint64_t bytes;
    hidl_string label;
    const NativeHandle* handle() const { return native.buffer; }
    uint64_t size() const { return bytes; }
    const hidl_string& name() const { return label; }
};
struct GrantorDescriptor {
    uint32_t flags, fdIndex, offset;
    uint64_t extent;
};
static_assert(sizeof(void*) == 8 && sizeof(hidl_string) == 16);
static_assert(sizeof(hidl_memory) == 40 && offsetof(hidl_memory, label) == 24);
static_assert(sizeof(GrantorDescriptor) == 24);

class IBinder;
class ProcessState;
class Parcel {
public:
    Parcel() = default;
    ~Parcel();
    Parcel(const Parcel&) = delete;
    Parcel& operator=(const Parcel&) = delete;
    status_t write(const void* data, size_t size);
    status_t read(void* data, size_t size) const;
    status_t writeInterfaceToken(const char* token);
    bool enforceInterface(const char* token) const;
    status_t writeInt32(int32_t v) { return write(&v, sizeof(v)); }
    status_t writeUint32(uint32_t v) { return write(&v, sizeof(v)); }
    status_t writeInt64(int64_t v) { return write(&v, sizeof(v)); }
    status_t writeUint64(uint64_t v) { return write(&v, sizeof(v)); }
    status_t writeFloat(float v) { return write(&v, sizeof(v)); }
    status_t writeBool(bool v) { uint8_t b = v; return write(&b, 1); }
    status_t readInt32(int32_t* v) const { return read(v, sizeof(*v)); }
    status_t readUint32(uint32_t* v) const { return read(v, sizeof(*v)); }
    status_t readUint64(uint64_t* v) const { return read(v, sizeof(*v)); }
    status_t readBool(bool* v) const;
    status_t writeBuffer(const void*, size_t, size_t*);
    status_t writeEmbeddedBuffer(const void*, size_t, size_t*, size_t, size_t);
    status_t readBuffer(size_t, size_t*, const void**) const;
    status_t readEmbeddedBuffer(size_t, size_t*, size_t, size_t, const void**) const;
    status_t writeEmbeddedNativeHandle(const NativeHandle*, size_t, size_t);
    status_t readEmbeddedNativeHandle(size_t, size_t, const NativeHandle**) const;
    status_t writeStrongBinder(const sp<IBinder>&);
    status_t readNullableStrongBinder(sp<IBinder>*) const;
    status_t errorCheck() const { return error_; }
    const std::vector<uint8_t>& bytes() const { return data_; }
    const std::vector<binder_size_t>& objects() const { return offsets_; }
    size_t buffersSize() const;
    // Bind only kernel-delivered transactions from this process's mapped driver.
    status_t receive(const binder_transaction_data&);
private:
    friend class ProcessState;
    status_t fail(status_t rc) const { error_ = rc; return rc; }
    status_t object(const void*, size_t, bool nullable = false);
    const void* readObject(size_t, uint32_t, size_t* = nullptr) const;
    const binder_buffer_object* bufferObject(size_t) const;
    status_t buffer(const void*, size_t, size_t*, bool, size_t, size_t);
    status_t readBuffer(size_t, size_t*, bool, size_t, size_t, const void**) const;
    bool pointer(const void*, size_t) const;
    union WireObject {
        binder_buffer_object buffer;
        binder_fd_array_object fda;
        flat_binder_object flat;
    };
    const WireObject* cachedObject(size_t offset, size_t size) const;
    std::vector<uint8_t> data_;
    std::vector<binder_size_t> offsets_;
    std::vector<std::vector<uint8_t>> buffers_;
    std::vector<sp<IBinder>> binders_;
    binder_uintptr_t received_ = 0;
    mutable size_t position_ = 0;
    mutable status_t error_ = OK;
    mutable std::map<size_t, WireObject> cache_;
};

class IBinder {
public:
    virtual ~IBinder() = default;
    virtual status_t transact(uint32_t, const Parcel&, Parcel*) = 0;
    virtual IBinder* localBinder() { return nullptr; }
    virtual uint32_t handle() const { return 0; }
    static constexpr uint32_t FIRST_CALL_TRANSACTION = 1;
    static constexpr uint32_t FIRST_HIDL_TRANSACTION = 0x0f000000;
    static constexpr uint32_t HIDL_DESCRIPTOR_CHAIN_TRANSACTION = 256067662;
    static constexpr uint32_t HIDL_DEBUG_TRANSACTION = 256131655;
    static constexpr uint32_t HIDL_GET_DESCRIPTOR_TRANSACTION = 256136003;
    static constexpr uint32_t HIDL_HASH_CHAIN_TRANSACTION = 256398152;
    static constexpr uint32_t HIDL_SET_HAL_INSTRUMENTATION_TRANSACTION = 256462420;
    static constexpr uint32_t HIDL_LINK_TO_DEATH_TRANSACTION = 256660548;
    static constexpr uint32_t HIDL_PING_TRANSACTION = 256921159;
    static constexpr uint32_t HIDL_GET_REF_INFO_TRANSACTION = 257049926;
    static constexpr uint32_t HIDL_SYSPROPS_CHANGED_TRANSACTION = 257120595;
    static constexpr uint32_t HIDL_UNLINK_TO_DEATH_TRANSACTION = 257250372;
};
class BHwBinder : public IBinder {
public:
    using TransactCallback = std::function<void(const Parcel&)>;
    IBinder* localBinder() override { return this; }
    status_t transact(uint32_t code, const Parcel& in, Parcel* out) override {
        return onTransact(code, in, out, 0, {});
    }
    virtual status_t onTransact(uint32_t, const Parcel&, Parcel*, uint32_t, TransactCallback) = 0;
};
class ProcessState {
public:
    static ProcessState* self();
    sp<IBinder> getContextObject(void*);
    void startThreadPool();
    void joinThreadPool();
    status_t transact(uint32_t, uint32_t, const Parcel&, Parcel*);
    status_t command(uint32_t, const void* = nullptr, size_t = 0);
    void retain(const sp<IBinder>&);
    sp<IBinder> local(uintptr_t);
    sp<IBinder> remote(uint32_t);
    bool contains(const void*, size_t) const;
private:
    ProcessState();
    int fd_ = -1;
    void* mapping_ = nullptr;
    static constexpr size_t kMapSize = 1024 * 1024 - 8192;
};
class IPCThreadState {
public:
    static ProcessState* self() { return ProcessState::self(); }
};
struct Status {
    int32_t code = 0;
    static Status ok() { return {}; }
    bool isOk() const { return code == 0; }
    std::string description() const { return std::to_string(code); }
};
status_t writeToParcel(const Status&, Parcel*);
status_t readFromParcel(Status*, const Parcel&);
status_t writeEmbeddedToParcel(const hidl_string&, Parcel*, size_t, size_t);
status_t readEmbeddedFromParcel(const hidl_string&, const Parcel&, size_t, size_t);
status_t readEmbeddedFromParcel(const hidl_memory&, const Parcel&, size_t, size_t);
}  // namespace hardware
}  // namespace ssal
