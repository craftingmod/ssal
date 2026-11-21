// Guest Silent Virtual HIDL 7.0 Audio HAL (IDevicesFactory + IEffectsFactory).
#include "../hwbinder/hwbinder.h"
#include "fmq.h"
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/un.h>
#include <unistd.h>

#include <pthread.h>
#include <sched.h>
#include <time.h>
#include <atomic>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <mutex>
#include <type_traits>
#include <vector>

using ssal::OK;
using ssal::sp;
using ssal::status_t;
using ssal::hardware::BHwBinder;

using ssal::hardware::hidl_string;
using ssal::hardware::hidl_vec;
using ssal::hardware::IBinder;
using ssal::hardware::IPCThreadState;

using ssal::hardware::Parcel;
using ssal::hardware::ProcessState;
using ssal::hardware::Status;
using ssal::hardware::writeEmbeddedToParcel;
using ssal::hardware::writeToParcel;

template <typename T>
static status_t writeEmbeddedToParcel(const hidl_vec<T>& vec, Parcel* parcel,
                                      size_t parent, size_t offset) {
    size_t child;
    status_t rc = parcel->writeEmbeddedBuffer(vec.data(), vec.size() * sizeof(T),
                                              &child, parent, offset);
    if constexpr (std::is_same_v<T, hidl_string>) {
        for (size_t i = 0; rc == OK && i < vec.size(); ++i) {
            rc = writeEmbeddedToParcel(vec[i], parcel, child, i * sizeof(T));
        }
    }
    return rc;
}

static status_t writeEmptyVec(Parcel* reply) {
    hidl_vec<uint8_t> empty;
    size_t handle = 0;
    status_t rc = reply->writeBuffer(&empty, sizeof(empty), &handle);
    if (rc != OK) return rc;
    return writeEmbeddedToParcel(empty, reply, handle, 0);
}

static status_t handleIBase(uint32_t code, const Parcel& data, Parcel* reply,
                            const char* const* chain, size_t chainLen,
                            BHwBinder::TransactCallback cb) {
    if (!data.enforceInterface("android.hidl.base@1.0::IBase")) {
        fprintf(stderr, "handleIBase enforceInterface failed code=0x%x\n", code);
        return ssal::BAD_TYPE;
    }
    switch (code) {
        case IBinder::HIDL_DESCRIPTOR_CHAIN_TRANSACTION: {
            writeToParcel(Status::ok(), reply);
            hidl_vec<hidl_string> vec;
            vec.resize(chainLen);
            for (size_t i = 0; i < chainLen; ++i) {
                vec[i] = chain[i];
            }
            size_t handle = 0;
            status_t rc = reply->writeBuffer(&vec, sizeof(vec), &handle);
            if (rc == OK) rc = writeEmbeddedToParcel(vec, reply, handle, 0);
            if (rc == OK && cb) cb(*reply);
            return rc;
        }
        case IBinder::HIDL_GET_DESCRIPTOR_TRANSACTION: {
            writeToParcel(Status::ok(), reply);
            hidl_string s;
            s.setToExternal(chain[0], strlen(chain[0]));
            size_t handle = 0;
            status_t rc = reply->writeBuffer(&s, sizeof(s), &handle);
            if (rc == OK) rc = writeEmbeddedToParcel(s, reply, handle, 0);
            if (rc == OK && cb) cb(*reply);
            return rc;
        }
        case IBinder::HIDL_HASH_CHAIN_TRANSACTION: {
            writeToParcel(Status::ok(), reply);
            struct Hash32 { uint8_t bytes[32]; };
            hidl_vec<Hash32> hashes;
            hashes.resize(chainLen);
            memset(hashes.data(), 0, chainLen * sizeof(Hash32));
            size_t handle = 0;
            status_t rc = reply->writeBuffer(&hashes, sizeof(hashes), &handle);
            if (rc == OK) rc = writeEmbeddedToParcel(hashes, reply, handle, 0);
            if (rc == OK && cb) cb(*reply);
            return rc;
        }
        case IBinder::HIDL_PING_TRANSACTION:
        case IBinder::HIDL_SET_HAL_INSTRUMENTATION_TRANSACTION:
        case IBinder::HIDL_LINK_TO_DEATH_TRANSACTION:
        case IBinder::HIDL_UNLINK_TO_DEATH_TRANSACTION:
        case IBinder::HIDL_SYSPROPS_CHANGED_TRANSACTION:
        case IBinder::HIDL_DEBUG_TRANSACTION: {
            status_t rc = writeToParcel(Status::ok(), reply);
            if (rc == OK && cb) cb(*reply);
            return rc;
        }
        case IBinder::HIDL_GET_REF_INFO_TRANSACTION: {
            writeToParcel(Status::ok(), reply);
            struct DebugInfo {
                int32_t pid;
                uint64_t ptr;
                int32_t arch;
            } info{getpid(), 0, 1 /* IS_64BIT */};
            status_t rc = reply->write(&info, sizeof(info));
            if (rc == OK && cb) cb(*reply);
            return rc;
        }
        default:
            return ssal::UNKNOWN_TRANSACTION;
    }
}

struct DeviceAddress70 {
    hidl_string deviceType;
    uint8_t addressDiscriminator;
    uint8_t addressPad[7];
    uint8_t addressData[16];
};

struct AudioConfigBase70 {
    hidl_string format;
    uint32_t sampleRateHz;
    hidl_string channelMask;
};

struct AudioOffloadInfo70 {
    AudioConfigBase70 base;
    hidl_string streamType;
    uint32_t bitRatePerSecond;
    int64_t durationMicroseconds;
    bool hasVideo;
    bool isStreaming;
    uint32_t bitWidth;
    uint32_t bufferSize;
    hidl_string usage;
    int32_t encapsulationMode;
    int32_t contentId;
    int32_t syncId;
};

struct AudioConfig70 {
    AudioConfigBase70 base;
    uint8_t offloadDiscriminator;
    uint8_t offloadPad[7];
    AudioOffloadInfo70 offloadInfo;
    uint64_t frameCount;
};

struct StreamParams {
    std::string format = "AUDIO_FORMAT_PCM_16_BIT";
    std::string channelMask = "AUDIO_CHANNEL_OUT_STEREO";
    uint32_t sampleRateHz = 48000;
    uint64_t frameCount = 1024;
    uint32_t channelCount = 2;
    uint32_t bytesPerSample = 2;
    uint64_t frameSize() const { return static_cast<uint64_t>(channelCount) * bytesPerSample; }
};
static_assert(sizeof(DeviceAddress70) == 40 && offsetof(DeviceAddress70, addressData) == 24);
static_assert(sizeof(AudioConfigBase70) == 40 && sizeof(AudioOffloadInfo70) == 120);
static_assert(sizeof(AudioConfig70) == 176 && offsetof(AudioConfig70, frameCount) == 168);

static bool writeExact(int fd, const void* buf, size_t len) {
    const uint8_t* p = static_cast<const uint8_t*>(buf);
    size_t done = 0;
    while (done < len) {
        ssize_t n = send(fd, p + done, len - done, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (n == 0) return false;
        done += static_cast<size_t>(n);
    }
    return true;
}

static int connectHostAudioBridge(uint32_t rate, uint32_t ch, uint32_t bps) {
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    struct sockaddr_un addr {};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, "/run/ssal/audio.sock", sizeof(addr.sun_path) - 1);
    if (connect(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }
    uint32_t hdr[3] = {rate, ch, bps};
    if (!writeExact(fd, hdr, sizeof(hdr))) {
        close(fd);
        return -1;
    }
    return fd;
}

static status_t writeAudioConfigBase(Parcel* reply, const StreamParams& sp,
                                     BHwBinder::TransactCallback cb) {
    AudioConfigBase70 cfg{};
    cfg.format.setToExternal(sp.format.c_str(), sp.format.size());
    cfg.sampleRateHz = sp.sampleRateHz;
    cfg.channelMask.setToExternal(sp.channelMask.c_str(), sp.channelMask.size());
    size_t handle = 0;
    status_t rc = reply->writeBuffer(&cfg, sizeof(cfg), &handle);
    if (rc == OK) rc = writeEmbeddedToParcel(cfg.format, reply, handle, offsetof(AudioConfigBase70, format));
    if (rc == OK) rc = writeEmbeddedToParcel(cfg.channelMask, reply, handle, offsetof(AudioConfigBase70, channelMask));
    if (rc == OK && cb) cb(*reply);
    return rc;
}

static status_t writeAudioConfig(Parcel* reply, const StreamParams& sp,
                                 BHwBinder::TransactCallback cb) {
    AudioConfig70 cfg{};
    cfg.base.format.setToExternal(sp.format.c_str(), sp.format.size());
    cfg.base.sampleRateHz = sp.sampleRateHz;
    cfg.base.channelMask.setToExternal(sp.channelMask.c_str(), sp.channelMask.size());
    cfg.offloadDiscriminator = 0; // unspecified
    cfg.frameCount = sp.frameCount;
    size_t handle = 0;
    status_t rc = reply->writeBuffer(&cfg, sizeof(cfg), &handle);
    if (rc == OK) rc = writeEmbeddedToParcel(cfg.base.format, reply, handle, offsetof(AudioConfig70, base) + offsetof(AudioConfigBase70, format));
    if (rc == OK) rc = writeEmbeddedToParcel(cfg.base.channelMask, reply, handle, offsetof(AudioConfig70, base) + offsetof(AudioConfigBase70, channelMask));
    if (rc == OK && cb) cb(*reply);
    return rc;
}

class VirtualStreamOut : public BHwBinder {
public:
    explicit VirtualStreamOut(StreamParams params) : params_(std::move(params)) {}
    ~VirtualStreamOut() override { stopWriter(); }

    status_t onTransact(uint32_t code, const Parcel& data, Parcel* reply, uint32_t,
                        TransactCallback cb) override {
        static const char* const kChain[] = {
            "android.hardware.audio@7.0::IStreamOut",
            "android.hardware.audio@7.0::IStream",
            "android.hidl.base@1.0::IBase",
        };
        status_t rc = OK;
        if (code >= IBinder::FIRST_HIDL_TRANSACTION) {
            return handleIBase(code, data, reply, kChain, 3, cb);
        }
        if (!data.enforceInterface(kChain[code <= 19 ? 1 : 0])) {
            fprintf(stderr, "guest_virtual_audio=stream_bad_type code=%u\n", code);
            return ssal::BAD_TYPE;
        }
        std::lock_guard<std::mutex> lock(mutex_);
        writeToParcel(Status::ok(), reply);
        switch (code) {
            case 1:  rc = reply->writeUint64(params_.frameSize()); break;
            case 2:  rc = reply->writeUint64(params_.frameCount); break;
            case 3:  rc = reply->writeUint64(params_.frameSize() * params_.frameCount); break;
            case 4:  reply->writeInt32(0); rc = writeEmptyVec(reply); break; // getSupportedProfiles
            case 5:  reply->writeInt32(0); return writeAudioConfigBase(reply, params_, cb);
            case 9:  // standby
            case 16: // stop
            case 30: // pause
                if (writer_) writer_->pause();
                rc = reply->writeInt32(0);
                break;
            case 19: // close
                stopWriter();
                rc = reply->writeInt32(0);
                break;
            case 10: reply->writeInt32(0); rc = writeEmptyVec(reply); break; // getDevices
            case 13: reply->writeInt32(0); rc = writeEmptyVec(reply); break; // getParameters
            case 15: // start
            case 31: // resume
                rc = reply->writeInt32(0);
                break;
            case 17: // createMmapBuffer
            case 18: // getMmapPosition
                rc = reply->writeInt32(5 /* NOT_SUPPORTED */);
                break;
            case 20: rc = reply->writeUint32(20); break;      // getLatency (20ms)
            case 23: { // prepareForWriting(frameSize, framesCount)
                uint32_t frameSize = 0, framesCount = 0;
                if (data.readUint32(&frameSize) != OK || data.readUint32(&framesCount) != OK) {
                    fprintf(stderr, "guest_virtual_audio=prepareForWriting_read_failed\n");
                    return ssal::BAD_VALUE;
                }
                int32_t result = 0;
                if (writer_) result = 4; // INVALID_STATE
                else if ((frameSize != 1 && frameSize != params_.frameSize()) || !framesCount ||
                         framesCount > 1024 * 1024 / frameSize ||
                         (static_cast<uint64_t>(frameSize) * framesCount) % params_.frameSize() != 0) {
                    result = 2; // INVALID_ARGUMENTS
                } else {
                    writer_ = std::make_unique<Writer>(params_, frameSize * framesCount);
                    if (!writer_->start()) { writer_.reset(); result = 4; }
                }
                if (result != 0) {
                    fprintf(stderr, "guest_virtual_audio=prepareForWriting_err result=%d frameSize=%u expected=%llu framesCount=%u\n",
                            result, frameSize, static_cast<unsigned long long>(params_.frameSize()), framesCount);
                }
                reply->writeInt32(result);
                if (result == 0) {
                    rc = writer_->command.describe(reply);
                    if (rc == OK) rc = writer_->data.describe(reply);
                    if (rc == OK) rc = writer_->status.describe(reply);
                } else {
                    for (int i = 0; i < 3 && rc == OK; ++i) rc = ssal::audio::Queue::emptyDescriptor(reply);
                }
                if (rc == OK) rc = reply->writeInt32(result == 0 ? writer_->tid.load() : 0);
                if (rc == OK && cb) cb(*reply);
                return rc;
            }
            case 24: // getRenderPosition
                reply->writeInt32(0);
                rc = reply->writeUint32(0);
                break;
            case 25: // getNextWriteTimestamp
                reply->writeInt32(5 /* NOT_SUPPORTED */);
                rc = reply->writeInt64(0);
                break;
            case 35: // getPresentationPosition (Host DAC position is not available)
                reply->writeInt32(5);
                reply->writeUint64(0);
                reply->writeUint64(0);
                rc = reply->writeUint64(0);
                break;
            case 29: // supportsPauseAndResume
                reply->writeBool(true);
                rc = reply->writeBool(true);
                break;
            case 32: // supportsDrain
                rc = reply->writeBool(false);
                break;
            default:
                fprintf(stderr, "guest_virtual_audio=stream_unhandled_tx code=%u\n", code);
                rc = reply->writeInt32(0 /* Result::OK */);
                break;
        }
        if (rc == OK && cb) cb(*reply);
        return rc;
    }

private:
    struct Writer {
        ssal::audio::Queue command{4, 4};
        ssal::audio::Queue data;
        ssal::audio::Queue status{32, 32};
        std::atomic<int32_t> tid{0};
        std::atomic<bool> stopped{false};
        int hostFd;
        pthread_t thread{};
        bool running = false;
        std::mutex socketMutex;
        explicit Writer(const StreamParams& params, size_t bytes)
            : data(bytes, 1, true), hostFd(connectHostAudioBridge(
                params.sampleRateHz, params.channelCount, params.bytesPerSample)) {}
        bool start() {
            if (!command.valid() || !data.valid() || !status.valid()) return false;
            int rc = pthread_create(&thread, nullptr, [](void* raw) -> void* {
                static_cast<Writer*>(raw)->run(); return nullptr;
            }, this);
            if (rc != 0) return false;
            running = true;
            while (!tid.load(std::memory_order_acquire)) sched_yield();
            fprintf(stderr, "guest_virtual_audio=prepareForWriting host_bridge=%d writer_tid=%d\n",
                    hostFd >= 0, tid.load());
            return true;
        }
        ~Writer() {
            stopped.store(true, std::memory_order_release);
            if (hostFd >= 0) shutdown(hostFd, SHUT_RDWR);
            if (data.valid()) data.wake(1);
            if (running) pthread_join(thread, nullptr);
            if (hostFd >= 0) close(hostFd);
        }
        void pause() {
            std::lock_guard<std::mutex> lock(socketMutex);
            uint32_t zero = 0;
            if (hostFd >= 0) writeExact(hostFd, &zero, sizeof(zero));
        }
        void run() {
            tid.store(gettid(), std::memory_order_release);
            while (!stopped.load(std::memory_order_acquire)) {
                int32_t op;
                if (!command.read(&op, sizeof(op))) { data.wait(1); continue; }
                ssal::audio::WriteStatus response;
                response.replyTo = op;
                if (op == 0) { // WRITE
                    size_t size = data.available();
                    if (size == SIZE_MAX) break;
                    std::vector<uint8_t> pcm(size);
                    if (!data.read(pcm.data(), size)) break;
                    std::lock_guard<std::mutex> lock(socketMutex);
                    uint32_t length = static_cast<uint32_t>(size);
                    if (hostFd >= 0 && writeExact(hostFd, &length, sizeof(length)) &&
                        writeExact(hostFd, pcm.data(), size)) response.value = size;
                    else response.result = 4; // INVALID_STATE
                } else if (op == 2) response.value = 20; // GET_LATENCY, milliseconds
                else response.result = 5; // NOT_SUPPORTED (including Host presentation position)
                if (!status.write(&response, sizeof(response))) break;
                data.wake(2); // audio MessageQueueFlagBits::NOT_FULL
            }
        }
    };
    void stopWriter() { writer_.reset(); }
    StreamParams params_;
    std::unique_ptr<Writer> writer_;
    std::mutex mutex_;
};

class VirtualPrimaryDevice : public BHwBinder {
public:
    status_t onTransact(uint32_t code, const Parcel& data, Parcel* reply, uint32_t,
                        TransactCallback cb) override {
        static const char* const kChain[] = {
            "android.hardware.audio@7.0::IPrimaryDevice",
            "android.hardware.audio@7.0::IDevice",
            "android.hidl.base@1.0::IBase",
        };
        status_t rc = OK;
        if (code >= IBinder::FIRST_HIDL_TRANSACTION) {
            return handleIBase(code, data, reply, kChain, 3, cb);
        }
        if (!data.enforceInterface(kChain[code <= 25 ? 1 : 0])) return ssal::BAD_TYPE;
        writeToParcel(Status::ok(), reply);
        switch (code) {
            case 3:  reply->writeInt32(0); rc = reply->writeFloat(1.0f); break; // getMasterVolume
            case 5:  // getMicMute
            case 7:  // getMasterMute
                reply->writeInt32(0); rc = reply->writeBool(false); break;
            case 8:  // getInputBufferSize
                reply->writeInt32(0); rc = reply->writeUint64(4096); break;
            case 9: { // openOutputStream
                StreamParams spParams;
                int32_t ioHandle = 0;
                status_t ioRc = data.readInt32(&ioHandle);
                const DeviceAddress70* devAddr = nullptr;
                size_t devH = 0;
                status_t devRc = data.readBuffer(sizeof(DeviceAddress70), &devH,
                                                 reinterpret_cast<const void**>(&devAddr));
                if (devRc == OK && devAddr) {
                    devRc = ssal::hardware::readEmbeddedFromParcel(devAddr->deviceType, data, devH, 0);
                    if (devRc == OK && devAddr->addressDiscriminator == 0) {
                        devRc = ssal::hardware::readEmbeddedFromParcel(
                            *reinterpret_cast<const hidl_string*>(devAddr->addressData), data, devH, 24);
                    } else if (devAddr->addressDiscriminator > 4) devRc = ssal::BAD_VALUE;
                }
                if (devRc != OK) return devRc;
                const AudioConfig70* reqCfg = nullptr;
                size_t cfgH = 0;
                status_t cfgRc = data.readBuffer(sizeof(AudioConfig70), &cfgH,
                                                 reinterpret_cast<const void**>(&reqCfg));
                fprintf(stderr, "guest_virtual_audio=openOutputStream_parse ioRc=%d devRc=%d cfgRc=%d\n",
                        ioRc, devRc, cfgRc);
                if (ioRc != OK || devRc != OK || cfgRc != OK || !reqCfg) return ssal::BAD_VALUE;
                {
                    status_t configRc = ssal::hardware::readEmbeddedFromParcel(
                        reqCfg->base.format, data, cfgH,
                        offsetof(AudioConfig70, base) + offsetof(AudioConfigBase70, format));
                    if (configRc != OK) return configRc;
                    configRc = ssal::hardware::readEmbeddedFromParcel(
                        reqCfg->base.channelMask, data, cfgH,
                        offsetof(AudioConfig70, base) + offsetof(AudioConfigBase70, channelMask));
                    if (configRc != OK || reqCfg->offloadDiscriminator != 0) return ssal::BAD_VALUE;
                    if (reqCfg->base.sampleRateHz > 0) {
                        spParams.sampleRateHz = reqCfg->base.sampleRateHz;
                    }
                    if (reqCfg->frameCount > 0) {
                        spParams.frameCount = reqCfg->frameCount;
                    }
                    if (reqCfg->base.format.size() > 0) {
                        spParams.format = reqCfg->base.format.c_str();
                        if (spParams.format.find("FLOAT") != std::string::npos) {
                            spParams.bytesPerSample = 4;
                        }
                    }
                    if (reqCfg->base.channelMask.size() > 0) {
                        spParams.channelMask = reqCfg->base.channelMask.c_str();
                        if (spParams.channelMask.find("MONO") != std::string::npos) {
                            spParams.channelCount = 1;
                        }
                    }
                }
                if (spParams.sampleRateHz < 8000 || spParams.sampleRateHz > 192000 ||
                    (spParams.format != "AUDIO_FORMAT_PCM_16_BIT" && spParams.format != "AUDIO_FORMAT_PCM_FLOAT") ||
                    (spParams.channelMask != "AUDIO_CHANNEL_OUT_MONO" && spParams.channelMask != "AUDIO_CHANNEL_OUT_STEREO") ||
                    spParams.frameCount > 1024 * 1024 / spParams.frameSize()) {
                    StreamParams suggested;
                    reply->writeInt32(2 /* INVALID_ARGUMENTS */);
                    reply->writeStrongBinder(nullptr);
                    return writeAudioConfig(reply, suggested, cb);
                }
                fprintf(stderr, "guest_virtual_audio=openOutputStream rate=%u fmt=%s ch=%s frames=%llu\n",
                        spParams.sampleRateHz, spParams.format.c_str(), spParams.channelMask.c_str(),
                        static_cast<unsigned long long>(spParams.frameCount));
                sp<IBinder> stream = std::make_shared<VirtualStreamOut>(spParams);
                reply->writeInt32(0 /* OK */);
                reply->writeStrongBinder(stream);
                return writeAudioConfig(reply, spParams, cb);
            }
            case 10: { // openInputStream
                StreamParams spParams;
                reply->writeInt32(5 /* NOT_SUPPORTED */);
                reply->writeStrongBinder(nullptr);
                return writeAudioConfig(reply, spParams, cb);
            }
            case 11: rc = reply->writeBool(true); break; // supportsAudioPatches
            case 12: // createAudioPatch
            case 13: // updateAudioPatch
                reply->writeInt32(0); rc = reply->writeInt32(1); break;
            case 15: // getAudioPort
                rc = reply->writeInt32(5 /* NOT_SUPPORTED */); break;
            case 17: // getHwAvSync
                reply->writeInt32(5); rc = reply->writeUint32(0); break;
            case 19: // getParameters
            case 21: // getMicrophones
                reply->writeInt32(0); rc = writeEmptyVec(reply); break;
            case 29: case 31: case 33: case 39:
                reply->writeInt32(0); rc = reply->writeBool(false); break;
            case 37: // getTtyMode
                reply->writeInt32(0); rc = reply->writeInt32(0); break;
            default:
                rc = reply->writeInt32(0 /* Result::OK */); break;
        }
        if (rc == OK && cb) cb(*reply);
        return rc;
    }
};

class VirtualDevicesFactory : public BHwBinder {
public:
    status_t onTransact(uint32_t code, const Parcel& data, Parcel* reply, uint32_t,
                        TransactCallback cb) override {
        static const char* const kChain[] = {
            "android.hardware.audio@7.0::IDevicesFactory",
            "android.hidl.base@1.0::IBase",
        };
        status_t rc = OK;
        if (code >= IBinder::FIRST_HIDL_TRANSACTION) {
            return handleIBase(code, data, reply, kChain, 2, cb);
        }
        if (!data.enforceInterface(kChain[0])) return ssal::BAD_TYPE;
        writeToParcel(Status::ok(), reply);
        if (code == 1) { // openDevice(string device)
            const hidl_string* dev = nullptr;
            size_t handle = 0;
            data.readBuffer(sizeof(hidl_string), &handle, reinterpret_cast<const void**>(&dev));
            if (dev) {
                if (ssal::hardware::readEmbeddedFromParcel(*dev, data, handle, 0) != OK) return ssal::BAD_VALUE;
            }
            const char* name = dev ? dev->c_str() : "";
            fprintf(stderr, "guest_virtual_audio=openDevice name=%s\n", name);
            if (strcmp(name, "primary") == 0) {
                reply->writeInt32(0 /* OK */);
                rc = reply->writeStrongBinder(std::make_shared<VirtualPrimaryDevice>());
            } else {
                reply->writeInt32(2 /* INVALID_ARGUMENTS */);
                rc = reply->writeStrongBinder(nullptr);
            }
            if (rc == OK && cb) cb(*reply);
            return rc;
        }
        if (code == 2) { // openPrimaryDevice()
            fprintf(stderr, "guest_virtual_audio=openPrimaryDevice\n");
            reply->writeInt32(0 /* OK */);
            rc = reply->writeStrongBinder(std::make_shared<VirtualPrimaryDevice>());
            if (rc == OK && cb) cb(*reply);
            return rc;
        }
        return ssal::UNKNOWN_TRANSACTION;
    }
};

class VirtualEffectsFactory : public BHwBinder {
public:
    status_t onTransact(uint32_t code, const Parcel& data, Parcel* reply, uint32_t,
                        TransactCallback cb) override {
        static const char* const kChain[] = {
            "android.hardware.audio.effect@7.0::IEffectsFactory",
            "android.hidl.base@1.0::IBase",
        };
        status_t rc = OK;
        if (code >= IBinder::FIRST_HIDL_TRANSACTION) {
            return handleIBase(code, data, reply, kChain, 2, cb);
        }
        if (!data.enforceInterface(kChain[0])) return ssal::BAD_TYPE;
        writeToParcel(Status::ok(), reply);
        if (code == 1) { // getAllDescriptors
            fprintf(stderr, "guest_virtual_audio=getAllDescriptors\n");
            reply->writeInt32(0 /* OK */);
            rc = writeEmptyVec(reply);
            if (rc == OK && cb) cb(*reply);
            return rc;
        }
        rc = reply->writeInt32(2 /* INVALID_ARGUMENTS */);
        if (rc == OK && cb) cb(*reply);
        return rc;
    }
};

static bool registerHidlService(const sp<IBinder>& sm, const char* instance, const sp<IBinder>& svc) {
    Parcel req, rep;
    hidl_string inst(instance);
    size_t handle = 0;
    status_t rc = req.writeInterfaceToken("android.hidl.manager@1.0::IServiceManager");
    if (rc == OK) rc = req.writeBuffer(&inst, sizeof(inst), &handle);
    if (rc == OK) rc = writeEmbeddedToParcel(inst, &req, handle, 0);
    if (rc == OK) rc = req.writeStrongBinder(svc);
    if (rc == OK) rc = sm->transact(2 /* add */, req, &rep);
    if (rc != OK) {
        fprintf(stderr, "registerHidlService transact failed rc=%d\n", rc);
        return false;
    }
    Status status;
    status_t src = ssal::hardware::readFromParcel(&status, rep);
    if (src != OK || !status.isOk()) {
        fprintf(stderr, "registerHidlService status failed src=%d desc=%s\n", src,
                status.description().c_str());
        return false;
    }
    bool added = false;
    rep.readBool(&added);
    fprintf(stderr, "registerHidlService instance=%s added=%d\n", instance, added ? 1 : 0);
    return added;
}

int main(int argc, char** argv) {
    if (argc != 3 || strcmp(argv[1], "serve") != 0) {
        fprintf(stderr, "usage: ssal-virtual-audio serve <hwbinder-rdev>\n");
        return 2;
    }
    unsigned long long rdev = strtoull(argv[2], nullptr, 10);
    struct stat st {};
    if (stat("/dev/hwbinder", &st) != 0 || !S_ISCHR(st.st_mode) || st.st_rdev != rdev) {
        fprintf(stderr, "ssal-virtual-audio: /dev/hwbinder rdev mismatch\n");
        return 1;
    }

    auto* process = ProcessState::self();
    if (!process) {
        fprintf(stderr, "ssal-virtual-audio: private hwbinder initialization failed\n");
        return 1;
    }
    process->startThreadPool();
    sp<IBinder> sm = process->getContextObject(nullptr);
    if (!sm) {
        fprintf(stderr, "ssal-virtual-audio: hwservicemanager context null\n");
        return 1;
    }

    sp<IBinder> devices = std::make_shared<VirtualDevicesFactory>();
    sp<IBinder> effects = std::make_shared<VirtualEffectsFactory>();
    if (!registerHidlService(sm, "default", devices) ||
        !registerHidlService(sm, "default", effects)) {
        fprintf(stderr, "ssal-virtual-audio: failed to register HIDL audio services\n");
        return 1;
    }

    printf("guest_hwbinder_registered=android.hardware.audio@7.0::IDevicesFactory/default\n");
    fflush(stdout);
    IPCThreadState::self()->joinThreadPool();
    return 0;
}
