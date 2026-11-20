#include "hwbinder.h"
#include <fcntl.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <algorithm>
#include <cstdio>
#include <mutex>
#include <unordered_map>

namespace ssal::hardware {
namespace {
constexpr size_t kMaxParcel = 1024 * 1024;
size_t padded(size_t n) { return (n + 3) & ~size_t(3); }
std::mutex nodesMutex;
std::unordered_map<uintptr_t, sp<IBinder>> nodes;

class RemoteBinder final : public IBinder {
public:
    explicit RemoteBinder(uint32_t handle) : handle_(handle) {
        ProcessState::self()->command(BC_INCREFS, &handle_, sizeof(handle_));
        ProcessState::self()->command(BC_ACQUIRE, &handle_, sizeof(handle_));
    }
    ~RemoteBinder() override {
        ProcessState::self()->command(BC_RELEASE, &handle_, sizeof(handle_));
        ProcessState::self()->command(BC_DECREFS, &handle_, sizeof(handle_));
    }
    uint32_t handle() const override { return handle_; }
    status_t transact(uint32_t code, const Parcel& req, Parcel* rep) override {
        return ProcessState::self()->transact(handle_, code, req, rep);
    }
private:
    uint32_t handle_;
};

struct Thread {
    std::vector<uint8_t> input;
    size_t position = 0;
    status_t next(uint32_t* cmd, std::vector<uint8_t>* payload) {
        if (position == input.size()) {
            input.resize(64 * 1024);
            binder_write_read bwr{};
            bwr.read_buffer = reinterpret_cast<uintptr_t>(input.data());
            bwr.read_size = input.size();
            int rc;
            do { rc = ioctl(driverFd, BINDER_WRITE_READ, &bwr); }
            while (rc < 0 && errno == EINTR);
            if (rc < 0) return -errno;
            input.resize(bwr.read_consumed);
            position = 0;
        }
        if (input.size() - position < sizeof(*cmd)) return BAD_VALUE;
        memcpy(cmd, input.data() + position, sizeof(*cmd));
        position += sizeof(*cmd);
        size_t size = _IOC_SIZE(*cmd);
        if (size > input.size() - position) return BAD_VALUE;
        payload->assign(input.begin() + position, input.begin() + position + size);
        position += size;
        return OK;
    }
    static int driverFd;
};
int Thread::driverFd = -1;
thread_local Thread thread;

status_t sendParcel(uint32_t command, uint32_t handle, uint32_t code,
                    const Parcel& parcel, uint32_t flags) {
    if (parcel.errorCheck() != OK) return parcel.errorCheck();
    binder_transaction_data_sg sg{};
    auto& tx = sg.transaction_data;
    tx.target.handle = handle; tx.code = code; tx.flags = flags;
    tx.data_size = parcel.bytes().size();
    tx.offsets_size = parcel.objects().size() * sizeof(binder_size_t);
    tx.data.ptr.buffer = reinterpret_cast<uintptr_t>(parcel.bytes().data());
    tx.data.ptr.offsets = reinterpret_cast<uintptr_t>(parcel.objects().data());
    sg.buffers_size = parcel.buffersSize();
    return ProcessState::self()->command(command, &sg, sizeof(sg));
}

enum class Wait { reply, complete, loop };
status_t pump(Wait wait, Parcel* reply);
status_t dispatch(const binder_transaction_data& tx) {
    Parcel input, output;
    status_t rc = input.receive(tx);
    auto target = ProcessState::self()->local(tx.cookie);
    bool sent = false;
    status_t sentStatus = OK;
    auto callback = [&](const Parcel& response) {
        if (sent || (tx.flags & TF_ONE_WAY)) return;
        sent = true;
        if (input.errorCheck() == OK) sentStatus = sendParcel(BC_REPLY_SG, 0, 0, response, 0);
        else {
            Parcel error;
            error.writeInt32(input.errorCheck());
            sentStatus = sendParcel(BC_REPLY_SG, 0, 0, error, TF_STATUS_CODE);
        }
        if (sentStatus == OK) sentStatus = pump(Wait::complete, nullptr);
    };
    if (rc == OK && target && tx.target.ptr == tx.cookie) {
        rc = static_cast<BHwBinder*>(target.get())->onTransact(
            tx.code, input, &output, tx.flags, callback);
    } else if (rc == OK) {
        rc = DEAD_OBJECT;
    }
    if (!sent && !(tx.flags & TF_ONE_WAY)) {
        if (rc == OK && input.errorCheck() == OK) {
            callback(output);
        } else {
            int32_t error = rc == OK ? input.errorCheck() : rc;
            Parcel failure;
            failure.writeInt32(error);
            sentStatus = sendParcel(BC_REPLY_SG, 0, 0, failure, TF_STATUS_CODE);
            if (sentStatus == OK) sentStatus = pump(Wait::complete, nullptr);
        }
    }
    return sentStatus;
}

status_t pump(Wait wait, Parcel* reply) {
    for (;;) {
        uint32_t cmd = 0;
        std::vector<uint8_t> payload;
        status_t rc = thread.next(&cmd, &payload);
        if (rc != OK) return rc;
        switch (cmd) {
            case BR_NOOP: case BR_OK: case BR_SPAWN_LOOPER: break;
            case BR_TRANSACTION_COMPLETE:
                if (wait == Wait::complete) return OK;
                break;
            case BR_DEAD_REPLY: return DEAD_OBJECT;
            case BR_FAILED_REPLY: return -EIO;
            case BR_ERROR: {
                int32_t error;
                memcpy(&error, payload.data(), sizeof(error));
                return error;
            }
            case BR_INCREFS: case BR_ACQUIRE: case BR_RELEASE: case BR_DECREFS: {
                binder_ptr_cookie ptr;
                memcpy(&ptr, payload.data(), sizeof(ptr));
                if (ptr.ptr != ptr.cookie || !ProcessState::self()->local(ptr.cookie)) return BAD_VALUE;
                if (cmd == BR_INCREFS || cmd == BR_ACQUIRE) {
                    rc = ProcessState::self()->command(
                        cmd == BR_INCREFS ? BC_INCREFS_DONE : BC_ACQUIRE_DONE, &ptr, sizeof(ptr));
                } else if (cmd == BR_DECREFS) {
                    sp<IBinder> released;
                    {
                        std::lock_guard<std::mutex> lock(nodesMutex);
                        auto found = nodes.find(ptr.cookie);
                        if (found != nodes.end()) { released = std::move(found->second); nodes.erase(found); }
                    }
                }
                if (rc != OK) return rc;
                break;
            }
            case BR_TRANSACTION: case BR_TRANSACTION_SEC_CTX: {
                binder_transaction_data tx;
                memcpy(&tx, payload.data(), sizeof(tx));
                rc = dispatch(tx);
                if (rc != OK) return rc;
                break;
            }
            case BR_REPLY: {
                binder_transaction_data tx;
                memcpy(&tx, payload.data(), sizeof(tx));
                Parcel ignored;
                Parcel* out = reply ? reply : &ignored;
                rc = out->receive(tx);
                if (rc == OK && (tx.flags & TF_STATUS_CODE)) {
                    if (out->readInt32(&rc) != OK) return BAD_VALUE;
                }
                return wait == Wait::reply ? rc : BAD_VALUE;
            }
            default:
                fprintf(stderr, "ssal-hwbinder: unsupported driver command 0x%x\n", cmd);
                return -ENOTSUP;
        }
    }
}
}  // namespace

const Parcel::WireObject* Parcel::cachedObject(size_t offset, size_t size) const {
    if (offset > data_.size() || size > data_.size() - offset || size > sizeof(WireObject)) return nullptr;
    auto& cached = cache_[offset];
    memcpy(&cached, data_.data() + offset, size);
    return &cached;
}
status_t Parcel::object(const void* data, size_t size, bool nullable) {
    size_t offset = data_.size();
    status_t rc = write(data, size);
    if (rc == OK && !nullable) offsets_.push_back(offset);
    return rc;
}
const void* Parcel::readObject(size_t size, uint32_t type, size_t* index) const {
    if (error_ != OK) return nullptr;
    auto found = std::lower_bound(offsets_.begin(), offsets_.end(), position_);
    uint32_t actual = 0;
    auto* cached = cachedObject(position_, size);
    if (cached) memcpy(&actual, cached, sizeof(actual));
    if (!cached || found == offsets_.end() || *found != position_ || actual != type) {
        fail(BAD_VALUE); return nullptr;
    }
    if (index) *index = found - offsets_.begin();
    position_ += size;
    return cached;
}
const binder_buffer_object* Parcel::bufferObject(size_t index) const {
    if (index >= offsets_.size()) return nullptr;
    auto* cached = cachedObject(offsets_[index], sizeof(binder_buffer_object));
    return cached && cached->buffer.hdr.type == BINDER_TYPE_PTR ? &cached->buffer : nullptr;
}
status_t Parcel::write(const void* source, size_t size) {
    if (error_ != OK) return error_;
    if (received_ || size > kMaxParcel || padded(size) > kMaxParcel - data_.size() ||
        (size && !source)) return fail(BAD_VALUE);
    size_t start = data_.size();
    data_.resize(start + padded(size), 0);
    if (size) memcpy(data_.data() + start, source, size);
    return OK;
}
status_t Parcel::read(void* dest, size_t size) const {
    if (error_ != OK) return error_;
    if (size > kMaxParcel || padded(size) > data_.size() - position_) return fail(BAD_VALUE);
    // Scalars must not consume Binder objects, whose types and offsets need validation.
    for (auto offset : offsets_) {
        if (offset >= position_ && offset < position_ + padded(size)) return fail(BAD_VALUE);
    }
    if (size) memcpy(dest, data_.data() + position_, size);
    position_ += padded(size);
    return OK;
}
status_t Parcel::writeInterfaceToken(const char* token) { return write(token, strlen(token) + 1); }
bool Parcel::enforceInterface(const char* token) const {
    size_t size = strlen(token) + 1;
    std::vector<char> actual(size);
    return read(actual.data(), size) == OK && memcmp(actual.data(), token, size) == 0;
}
status_t Parcel::readBool(bool* value) const {
    uint8_t b = 0;
    status_t rc = read(&b, 1);
    if (b > 1) return fail(BAD_VALUE);
    *value = b;
    return rc;
}
bool Parcel::pointer(const void* ptr, size_t size) const {
    return received_ ? ProcessState::self()->contains(ptr, size) : (ptr || size == 0);
}
status_t Parcel::buffer(const void* ptr, size_t size, size_t* handle,
                        bool embedded, size_t parent, size_t offset) {
    if (size > kMaxParcel || (!ptr && size)) return fail(BAD_VALUE);
    if (embedded) {
        const auto* p = bufferObject(parent);
        if (!p || offset > p->length || sizeof(void*) > p->length - offset) return fail(BAD_VALUE);
    }
    // Own the payload so nested callbacks and stack-local reply values remain valid.
    buffers_.emplace_back(size);
    if (size) memcpy(buffers_.back().data(), ptr, size);
    binder_buffer_object obj{};
    obj.hdr.type = BINDER_TYPE_PTR;
    obj.buffer = reinterpret_cast<uintptr_t>(size ? buffers_.back().data() : nullptr);
    obj.length = size;
    if (embedded) { obj.flags = BINDER_BUFFER_FLAG_HAS_PARENT; obj.parent = parent; obj.parent_offset = offset; }
    if (handle) *handle = offsets_.size();
    return object(&obj, sizeof(obj));
}
status_t Parcel::writeBuffer(const void* p, size_t n, size_t* h) { return buffer(p, n, h, false, 0, 0); }
status_t Parcel::writeEmbeddedBuffer(const void* p, size_t n, size_t* h, size_t parent, size_t offset) {
    return buffer(p, n, h, true, parent, offset);
}
status_t Parcel::readBuffer(size_t size, size_t* handle, bool embedded,
                            size_t parent, size_t offset, const void** ptr) const {
    auto* obj = static_cast<const binder_buffer_object*>(readObject(sizeof(binder_buffer_object), BINDER_TYPE_PTR, handle));
    if (!obj || obj->length != size || obj->flags != (embedded ? uint32_t(BINDER_BUFFER_FLAG_HAS_PARENT) : 0u) ||
        !pointer(reinterpret_cast<const void*>(obj->buffer), size)) return fail(BAD_VALUE);
    if (embedded) {
        const auto* p = bufferObject(parent);
        if (!p || obj->parent != parent || obj->parent_offset != offset || offset > p->length ||
            sizeof(void*) > p->length - offset || !pointer(reinterpret_cast<const void*>(p->buffer), p->length)) return fail(BAD_VALUE);
        uintptr_t fixed = 0;
        memcpy(&fixed, reinterpret_cast<const uint8_t*>(p->buffer) + offset, sizeof(fixed));
        if (received_ && fixed != obj->buffer) return fail(BAD_VALUE);
    }
    *ptr = reinterpret_cast<const void*>(obj->buffer);
    return OK;
}
status_t Parcel::readBuffer(size_t n, size_t* h, const void** p) const { return readBuffer(n, h, false, 0, 0, p); }
status_t Parcel::readEmbeddedBuffer(size_t n, size_t* h, size_t parent, size_t offset, const void** p) const {
    return readBuffer(n, h, true, parent, offset, p);
}
status_t Parcel::writeEmbeddedNativeHandle(const NativeHandle* h, size_t parent, size_t offset) {
    if (!h) return writeUint64(0);
    if (h->version != 12 || h->numFds < 0 || h->numFds > 1024 || h->numInts < 0 || h->numInts > 1024) return fail(BAD_VALUE);
    size_t size = 12 + 4 * (h->numFds + h->numInts);
    size_t index = 0;
    status_t rc = writeUint64(size);
    if (rc == OK) rc = writeEmbeddedBuffer(h, size, &index, parent, offset);
    if (rc != OK) return rc;
    binder_fd_array_object fda{};
    fda.hdr.type = BINDER_TYPE_FDA; fda.num_fds = h->numFds;
    fda.parent = index; fda.parent_offset = 12;
    return object(&fda, sizeof(fda));
}
status_t Parcel::readEmbeddedNativeHandle(size_t parent, size_t offset, const NativeHandle** h) const {
    *h = nullptr;
    uint64_t size = 0;
    if (readUint64(&size) != OK) return error_;
    if (size == 0) {
        auto* p = bufferObject(parent);
        if (!p || offset > p->length || sizeof(void*) > p->length - offset ||
            !pointer(reinterpret_cast<const void*>(p->buffer), p->length)) return fail(BAD_VALUE);
        uintptr_t ptr;
        memcpy(&ptr, reinterpret_cast<const uint8_t*>(p->buffer) + offset, sizeof(ptr));
        return ptr == 0 ? OK : fail(BAD_VALUE);
    }
    size_t index = 0;
    const void* raw = nullptr;
    if (size < 12 || size > kMaxParcel || readEmbeddedBuffer(size, &index, parent, offset, &raw) != OK || !raw) return fail(BAD_VALUE);
    const auto* handle = static_cast<const NativeHandle*>(raw);
    if (handle->version != 12 || handle->numFds < 0 || handle->numFds > 1024 || handle->numInts < 0 ||
        handle->numInts > 1024 || size != 12u + 4u * (handle->numFds + handle->numInts)) return fail(BAD_VALUE);
    auto* fda = static_cast<const binder_fd_array_object*>(readObject(sizeof(binder_fd_array_object), BINDER_TYPE_FDA));
    if (!fda || fda->parent != index || fda->parent_offset != 12 || fda->num_fds != static_cast<uint32_t>(handle->numFds)) return fail(BAD_VALUE);
    *h = handle;
    return OK;
}
status_t Parcel::writeStrongBinder(const sp<IBinder>& binder) {
    flat_binder_object obj{};
    obj.hdr.type = BINDER_TYPE_BINDER;
    if (binder) {
        obj.flags = FLAT_BINDER_FLAG_ACCEPTS_FDS;
        if (binder->localBinder()) {
            obj.binder = obj.cookie = reinterpret_cast<uintptr_t>(binder.get());
            ProcessState::self()->retain(binder);
        } else { obj.hdr.type = BINDER_TYPE_HANDLE; obj.handle = binder->handle(); }
        binders_.push_back(binder);
    }
    return object(&obj, sizeof(obj), !binder);
}
status_t Parcel::readNullableStrongBinder(sp<IBinder>* binder) const {
    binder->reset();
    if (error_ != OK || sizeof(flat_binder_object) > data_.size() - position_) return fail(BAD_VALUE);
    flat_binder_object obj;
    memcpy(&obj, data_.data() + position_, sizeof(obj));
    if (obj.hdr.type == BINDER_TYPE_BINDER && obj.binder == 0 && obj.cookie == 0) {
        position_ += sizeof(obj); return OK;
    }
    if (obj.hdr.type != BINDER_TYPE_BINDER && obj.hdr.type != BINDER_TYPE_HANDLE) return fail(BAD_TYPE);
    if (!readObject(sizeof(obj), obj.hdr.type)) return error_;
    if (obj.hdr.type == BINDER_TYPE_HANDLE) *binder = ProcessState::self()->remote(obj.handle);
    else if (obj.binder == obj.cookie) *binder = ProcessState::self()->local(obj.cookie);
    return *binder ? OK : fail(BAD_VALUE);
}
size_t Parcel::buffersSize() const {
    size_t total = 0;
    for (size_t i = 0; i < offsets_.size(); ++i) {
        const auto* obj = bufferObject(i);
        if (obj) total += (obj->length + 7) & ~size_t(7);
    }
    return total;
}
status_t Parcel::receive(const binder_transaction_data& tx) {
    if (received_ || !data_.empty()) return fail(BAD_VALUE);
    auto* process = ProcessState::self();
    const void* data = reinterpret_cast<const void*>(tx.data.ptr.buffer);
    const void* offsets = reinterpret_cast<const void*>(tx.data.ptr.offsets);
    if (tx.data_size > kMaxParcel || !process->contains(data, tx.data_size)) return fail(BAD_VALUE);
    received_ = tx.data.ptr.buffer;
    if (tx.offsets_size % sizeof(binder_size_t) || tx.offsets_size > kMaxParcel ||
        !process->contains(offsets, tx.offsets_size)) return fail(BAD_VALUE);
    const auto* bytes = static_cast<const uint8_t*>(data);
    if (tx.data_size) data_.assign(bytes, bytes + tx.data_size);
    const auto* indices = static_cast<const binder_size_t*>(offsets);
    if (tx.offsets_size) offsets_.assign(indices, indices + tx.offsets_size / sizeof(binder_size_t));
    size_t end = 0;
    for (size_t index : offsets_) {
        if (index % 4 || index < end || index > data_.size() || sizeof(binder_object_header) > data_.size() - index) return fail(BAD_VALUE);
        uint32_t type;
        memcpy(&type, data_.data() + index, sizeof(type));
        size_t size = 0;
        switch (type) {
            case BINDER_TYPE_PTR: size = sizeof(binder_buffer_object); break;
            case BINDER_TYPE_FDA: size = sizeof(binder_fd_array_object); break;
            case BINDER_TYPE_BINDER: case BINDER_TYPE_HANDLE: case BINDER_TYPE_FD: size = sizeof(flat_binder_object); break;
            default: return fail(BAD_TYPE);
        }
        if (size > data_.size() - index) return fail(BAD_VALUE);
        end = index + size;
        if (type == BINDER_TYPE_PTR) {
            auto* obj = &cachedObject(index, size)->buffer;
            if (!pointer(reinterpret_cast<const void*>(obj->buffer), obj->length)) return fail(BAD_VALUE);
        }
    }
    return OK;
}
Parcel::~Parcel() {
    if (!received_) return;
    // FDA descriptors are closed by the Binder driver on BC_FREE_BUFFER.
    for (size_t offset : offsets_) {
        if (offset > data_.size() || sizeof(flat_binder_object) > data_.size() - offset) continue;
        flat_binder_object obj;
        memcpy(&obj, data_.data() + offset, sizeof(obj));
        if (obj.hdr.type == BINDER_TYPE_FD) close(obj.handle);
    }
    ProcessState::self()->command(BC_FREE_BUFFER, &received_, sizeof(received_));
}

ProcessState::ProcessState() {
    struct stat expected{}, actual{};
    if (stat("/dev/hwbinder", &expected) != 0 || !S_ISCHR(expected.st_mode)) return;
    fd_ = open("/dev/hwbinder", O_RDWR | O_CLOEXEC);
    if (fd_ < 0) return;
    binder_version version{};
    if (fstat(fd_, &actual) != 0 || actual.st_rdev != expected.st_rdev ||
        actual.st_ino != expected.st_ino || actual.st_dev != expected.st_dev ||
        ioctl(fd_, BINDER_VERSION, &version) != 0 || version.protocol_version != 8) {
        close(fd_); fd_ = -1; return;
    }
    mapping_ = mmap(nullptr, kMapSize, PROT_READ, MAP_PRIVATE | MAP_NORESERVE, fd_, 0);
    if (mapping_ == MAP_FAILED) { close(fd_); fd_ = -1; mapping_ = nullptr; return; }
    uint32_t maxThreads = 0;  // ssal starts a fixed pool; never open a fallback Binder device.
    if (ioctl(fd_, BINDER_SET_MAX_THREADS, &maxThreads) != 0) {
        munmap(mapping_, kMapSize); close(fd_); fd_ = -1; mapping_ = nullptr; return;
    }
    Thread::driverFd = fd_;
}
ProcessState* ProcessState::self() {
    static auto* process = new ProcessState;
    return process->fd_ >= 0 ? process : nullptr;
}
bool ProcessState::contains(const void* ptr, size_t n) const {
    auto base = reinterpret_cast<uintptr_t>(mapping_);
    auto address = reinterpret_cast<uintptr_t>(ptr);
    if (!ptr && !n) return true;
    return address >= base && address - base <= kMapSize && n <= kMapSize - (address - base);
}
status_t ProcessState::command(uint32_t cmd, const void* payload, size_t size) {
    std::vector<uint8_t> output(sizeof(cmd) + size);
    memcpy(output.data(), &cmd, sizeof(cmd));
    if (size) memcpy(output.data() + sizeof(cmd), payload, size);
    size_t done = 0;
    while (done < output.size()) {
        binder_write_read bwr{};
        bwr.write_buffer = reinterpret_cast<uintptr_t>(output.data() + done);
        bwr.write_size = output.size() - done;
        int rc = ioctl(fd_, BINDER_WRITE_READ, &bwr);
        done += bwr.write_consumed;
        if (rc < 0 && errno != EINTR) return -errno;
        if (rc == 0 && bwr.write_consumed == 0) return -EIO;
    }
    return OK;
}
void ProcessState::retain(const sp<IBinder>& binder) {
    std::lock_guard<std::mutex> lock(nodesMutex);
    nodes[reinterpret_cast<uintptr_t>(binder.get())] = binder;
}
sp<IBinder> ProcessState::local(uintptr_t cookie) {
    std::lock_guard<std::mutex> lock(nodesMutex);
    auto found = nodes.find(cookie);
    return found == nodes.end() ? nullptr : found->second;
}
sp<IBinder> ProcessState::remote(uint32_t handle) { return std::make_shared<RemoteBinder>(handle); }
sp<IBinder> ProcessState::getContextObject(void*) { return remote(0); }
status_t ProcessState::transact(uint32_t handle, uint32_t code, const Parcel& request, Parcel* reply) {
    status_t rc = sendParcel(BC_TRANSACTION_SG, handle, code, request, TF_ACCEPT_FDS);
    return rc == OK ? pump(Wait::reply, reply) : rc;
}
void ProcessState::startThreadPool() {
    for (int i = 0; i < 2; ++i) {
        pthread_t id;
        int rc = pthread_create(&id, nullptr, [](void* raw) -> void* {
            static_cast<ProcessState*>(raw)->joinThreadPool(); return nullptr;
        }, this);
        if (rc != 0) { fprintf(stderr, "ssal-hwbinder: pthread_create: %s\n", strerror(rc)); _exit(1); }
        pthread_detach(id);
    }
}
void ProcessState::joinThreadPool() {
    status_t rc = command(BC_ENTER_LOOPER);
    if (rc == OK) rc = pump(Wait::loop, nullptr);
    fprintf(stderr, "ssal-hwbinder: driver loop failed: %d\n", rc);
    _exit(1);
}
status_t writeToParcel(const Status& s, Parcel* p) { return p->writeInt32(s.code); }
status_t readFromParcel(Status* s, const Parcel& p) {
    status_t rc = p.readInt32(&s->code);
    // The helpers only consume successful replies; fail closed on remote exceptions.
    return rc == OK && s->code ? UNKNOWN_ERROR : rc;
}
status_t writeEmbeddedToParcel(const hidl_string& s, Parcel* p, size_t parent, size_t offset) {
    return p->writeEmbeddedBuffer(s.c_str(), s.size() + 1, nullptr, parent, offset);
}
status_t readEmbeddedFromParcel(const hidl_string& s, const Parcel& p, size_t parent, size_t offset) {
    const void* raw = nullptr;
    status_t rc = p.readEmbeddedBuffer(s.size() + 1, nullptr, parent, offset, &raw);
    return rc == OK && raw && static_cast<const char*>(raw)[s.size()] == '\0' ? OK : BAD_VALUE;
}
status_t readEmbeddedFromParcel(const hidl_memory& m, const Parcel& p, size_t parent, size_t offset) {
    const NativeHandle* handle;
    status_t rc = p.readEmbeddedNativeHandle(parent, offset, &handle);
    return rc == OK ? readEmbeddedFromParcel(m.name(), p, parent, offset + 24) : rc;
}
}  // namespace ssal::hardware
