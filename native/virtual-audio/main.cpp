// Guest Silent Virtual HIDL 7.0 Audio HAL (IDevicesFactory + IEffectsFactory).
#include <fcntl.h>
#include <hidl/HidlSupport.h>
#include <hidl/MQDescriptor.h>
#include <hidl/Status.h>
#include <hwbinder/IBinder.h>
#include <hwbinder/IInterface.h>
#include <hwbinder/IPCThreadState.h>
#include <hwbinder/Parcel.h>
#include <hwbinder/ProcessState.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/un.h>
#include <unistd.h>

#include <pthread.h>
#include <atomic>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace android::hardware {
status_t writeToParcel(const Status& status, Parcel* parcel);
status_t readFromParcel(Status* status, const Parcel& parcel);
status_t writeEmbeddedToParcel(const hidl_handle& handle, Parcel* parcel, size_t parentHandle,
                               size_t parentOffset);
status_t writeEmbeddedToParcel(const hidl_string& string, Parcel* parcel, size_t parentHandle,
                               size_t parentOffset);
status_t readEmbeddedFromParcel(const hidl_string& string, const Parcel& parcel,
                                size_t parentHandle, size_t parentOffset);
template <typename T>
status_t writeEmbeddedToParcel(const hidl_vec<T>& vec, Parcel* parcel, size_t parentHandle,
                               size_t parentOffset) {
    size_t childHandle = 0;
    return parcel->writeEmbeddedBuffer(vec.data(), vec.size() * sizeof(T), &childHandle,
                                       parentHandle, parentOffset + hidl_vec<T>::kOffsetOfBuffer);
}
template <>
status_t writeEmbeddedToParcel(const hidl_vec<hidl_string>& vec, Parcel* parcel,
                               size_t parentHandle, size_t parentOffset) {
    size_t childHandle = 0;
    status_t rc = parcel->writeEmbeddedBuffer(vec.data(), vec.size() * sizeof(hidl_string),
                                              &childHandle, parentHandle,
                                              parentOffset + hidl_vec<hidl_string>::kOffsetOfBuffer);
    if (rc != OK) return rc;
    for (size_t i = 0; i < vec.size(); ++i) {
        rc = writeEmbeddedToParcel(vec[i], parcel, childHandle, i * sizeof(hidl_string));
        if (rc != OK) return rc;
    }
    return OK;
}
template <typename T, android::hardware::MQFlavor flavor>
status_t writeEmbeddedToParcel(const MQDescriptor<T, flavor>& obj, Parcel* parcel,
                               size_t parentHandle, size_t parentOffset) {
    status_t rc = writeEmbeddedToParcel(
        obj.grantors(), parcel, parentHandle,
        parentOffset + MQDescriptor<T, flavor>::kOffsetOfGrantors);
    if (rc != OK) return rc;
    return writeEmbeddedToParcel(
        obj.handle(), parcel, parentHandle,
        parentOffset + MQDescriptor<T, flavor>::kOffsetOfHandle);
}
}  // namespace android::hardware

using android::OK;
using android::sp;
using android::status_t;
using android::hardware::BHwBinder;
using android::hardware::GrantorDescriptor;
using android::hardware::hidl_string;
using android::hardware::hidl_vec;
using android::hardware::IBinder;
using android::hardware::IPCThreadState;
using android::hardware::MQDescriptorSync;
using android::hardware::Parcel;
using android::hardware::ProcessState;
using android::hardware::Status;
using android::hardware::writeEmbeddedToParcel;
using android::hardware::writeToParcel;

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

static int createMemfd(const char* name, size_t size) {
    int fd = static_cast<int>(syscall(__NR_memfd_create, name, MFD_CLOEXEC));
    if (fd < 0) return -1;
    if (ftruncate(fd, static_cast<off_t>(size)) != 0) {
        close(fd);
        return -1;
    }
    return fd;
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
        return android::BAD_TYPE;
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
            return android::UNKNOWN_TRANSACTION;
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

static bool writeExact(int fd, const void* buf, size_t len) {
    const uint8_t* p = static_cast<const uint8_t*>(buf);
    size_t done = 0;
    while (done < len) {
        ssize_t n = write(fd, p + done, len - done);
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
        writeToParcel(Status::ok(), reply);
        switch (code) {
            case 1:  rc = reply->writeUint64(params_.frameSize()); break;
            case 2:  rc = reply->writeUint64(params_.frameCount); break;
            case 3:  rc = reply->writeUint64(params_.frameSize() * params_.frameCount); break;
            case 4:  reply->writeInt32(0); rc = writeEmptyVec(reply); break; // getSupportedProfiles
            case 5:  reply->writeInt32(0); return writeAudioConfigBase(reply, params_, cb);
            case 9:  // standby
            case 16: // stop
            case 19: // close
            case 30: // pause
                paused_.store(true, std::memory_order_release);
                rc = reply->writeInt32(0);
                break;
            case 10: reply->writeInt32(0); rc = writeEmptyVec(reply); break; // getDevices
            case 13: reply->writeInt32(0); rc = writeEmptyVec(reply); break; // getParameters
            case 15: // start
            case 31: // resume
                paused_.store(false, std::memory_order_release);
                rc = reply->writeInt32(0);
                break;
            case 17: // createMmapBuffer
            case 18: // getMmapPosition
                rc = reply->writeInt32(5 /* NOT_SUPPORTED */);
                break;
            case 20: rc = reply->writeUint32(20); break;      // getLatency (20ms)
            case 23: { // prepareForWriting(frameSize, framesCount)
                uint32_t frameSize = static_cast<uint32_t>(params_.frameSize());
                uint32_t framesCount = static_cast<uint32_t>(params_.frameCount);
                data.readUint32(&frameSize);
                data.readUint32(&framesCount);
                uint64_t dataBytes = static_cast<uint64_t>(frameSize) * framesCount;
                if (dataBytes == 0) dataBytes = 4096;
                size_t totalBytes = (64 + static_cast<size_t>(dataBytes) + 4095) & ~size_t(4095);
                int dataFd = createMemfd("ssal_audio_data", totalBytes);
                int statusFd = createMemfd("ssal_audio_status", 4096);
                if (dataFd < 0 || statusFd < 0) {
                    if (dataFd >= 0) close(dataFd);
                    if (statusFd >= 0) close(statusFd);
                    rc = reply->writeInt32(4 /* INVALID_STATE */);
                    break;
                }
                std::vector<GrantorDescriptor> dg(4);
                dg[0] = {0, 0, 0, 8};
                dg[1] = {0, 0, 8, 8};
                dg[2] = {0, 0, 64, dataBytes};
                dg[3] = {0, 0, 16, 4};
                native_handle_t* dh = native_handle_create(1, 0);
                dh->data[0] = dataFd;
                MQDescriptorSync<uint8_t> dataMQ(dg, dh, frameSize);

                std::vector<GrantorDescriptor> sg(4);
                sg[0] = {0, 0, 0, 8};
                sg[1] = {0, 0, 8, 8};
                sg[2] = {0, 0, 64, 32};
                sg[3] = {0, 0, 16, 4};
                native_handle_t* sh = native_handle_create(1, 0);
                sh->data[0] = statusFd;
                MQDescriptorSync<uint32_t> statusMQ(sg, sh, 32);

                int hostFd = connectHostAudioBridge(
                    params_.sampleRateHz, params_.channelCount, params_.bytesPerSample);
                fprintf(stderr, "guest_virtual_audio=prepareForWriting rate=%u ch=%u bps=%u host_bridge=%d\n",
                        params_.sampleRateHz, params_.channelCount, params_.bytesPerSample, hostFd >= 0 ? 1 : 0);

                struct ConsumerArgs {
                    int fd;
                    int hostFd;
                    size_t totalBytes;
                    size_t dataBytes;
                    std::atomic<bool>* paused;
                };
                int dupFd = dup(dataFd);
                if (dupFd >= 0) {
                    auto* args = new ConsumerArgs{
                        dupFd, hostFd, totalBytes, static_cast<size_t>(dataBytes), &paused_};
                    pthread_t tid{};
                    if (pthread_create(
                            &tid, nullptr,
                            [](void* raw) -> void* {
                                auto* a = static_cast<ConsumerArgs*>(raw);
                                int fd = a->fd;
                                int hfd = a->hostFd;
                                size_t totalSz = a->totalBytes;
                                size_t ringSz = a->dataBytes;
                                auto* paused = a->paused;
                                delete a;
                                void* mem = mmap(nullptr, totalSz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
                                close(fd);
                                if (mem == MAP_FAILED) {
                                    if (hfd >= 0) close(hfd);
                                    return nullptr;
                                }
                                auto* rd = reinterpret_cast<std::atomic<uint64_t>*>(mem);
                                auto* wr = reinterpret_cast<std::atomic<uint64_t>*>(static_cast<uint8_t*>(mem) + 8);
                                const uint8_t* ring = static_cast<const uint8_t*>(mem) + 64;
                                bool wasPaused = false;
                                std::vector<uint8_t> tmp;
                                for (;;) {
                                    uint64_t r = rd->load(std::memory_order_acquire);
                                    uint64_t w = wr->load(std::memory_order_acquire);
                                    if (w > r && (w - r) <= ringSz) {
                                        paused->store(false, std::memory_order_release);
                                        wasPaused = false;
                                        size_t avail = static_cast<size_t>(w - r);
                                        if (hfd >= 0) {
                                            tmp.resize(avail);
                                            size_t start = static_cast<size_t>(r % ringSz);
                                            size_t first = std::min(avail, ringSz - start);
                                            memcpy(tmp.data(), ring + start, first);
                                            if (first < avail) {
                                                memcpy(tmp.data() + first, ring, avail - first);
                                            }
                                            uint32_t len32 = static_cast<uint32_t>(avail);
                                            if (!writeExact(hfd, &len32, sizeof(len32)) ||
                                                !writeExact(hfd, tmp.data(), avail)) {
                                                close(hfd);
                                                hfd = -1;
                                            }
                                        }
                                        rd->store(w, std::memory_order_release);
                                    } else {
                                        if (w > r) rd->store(w, std::memory_order_release);
                                        if (hfd >= 0 && paused->load(std::memory_order_acquire) && !wasPaused) {
                                            uint32_t zero = 0;
                                            if (!writeExact(hfd, &zero, sizeof(zero))) {
                                                close(hfd);
                                                hfd = -1;
                                            }
                                            wasPaused = true;
                                        }
                                        usleep(5000);
                                    }
                                }
                                munmap(mem, totalSz);
                                if (hfd >= 0) close(hfd);
                                return nullptr;
                            },
                            args) == 0) {
                        pthread_detach(tid);
                    } else {
                        close(dupFd);
                        if (hostFd >= 0) close(hostFd);
                        delete args;
                    }
                } else if (hostFd >= 0) {
                    close(hostFd);
                }

                reply->writeInt32(0 /* OK */);
                size_t dHandle = 0, sHandle = 0;
                rc = reply->writeBuffer(&dataMQ, sizeof(dataMQ), &dHandle);
                if (rc == OK) rc = writeEmbeddedToParcel(dataMQ, reply, dHandle, 0);
                if (rc == OK) rc = reply->writeBuffer(&statusMQ, sizeof(statusMQ), &sHandle);
                if (rc == OK) rc = writeEmbeddedToParcel(statusMQ, reply, sHandle, 0);
                if (rc == OK) rc = reply->writeInt32(gettid());
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
            case 28: // getPresentationPosition
                reply->writeInt32(0);
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
                rc = reply->writeInt32(0 /* Result::OK */);
                break;
        }
        if (rc == OK && cb) cb(*reply);
        return rc;
    }

private:
    StreamParams params_;
    std::atomic<bool> paused_{false};
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
                bool enf = data.enforceInterface("android.hardware.audio@7.0::IDevice");
                int32_t ioHandle = 0;
                status_t ioRc = data.readInt32(&ioHandle);
                const DeviceAddress70* devAddr = nullptr;
                size_t devH = 0;
                status_t devRc = data.readBuffer(sizeof(DeviceAddress70), &devH,
                                                 reinterpret_cast<const void**>(&devAddr));
                const AudioConfig70* reqCfg = nullptr;
                size_t cfgH = 0;
                status_t cfgRc = data.readBuffer(sizeof(AudioConfig70), &cfgH,
                                                 reinterpret_cast<const void**>(&reqCfg));
                fprintf(stderr, "guest_virtual_audio=openOutputStream_parse enf=%d ioRc=%d devRc=%d cfgRc=%d\n",
                        enf ? 1 : 0, ioRc, devRc, cfgRc);
                if (enf && cfgRc == OK && reqCfg != nullptr) {
                    android::hardware::readEmbeddedFromParcel(
                        reqCfg->base.format, data, cfgH,
                        offsetof(AudioConfig70, base) + offsetof(AudioConfigBase70, format));
                    android::hardware::readEmbeddedFromParcel(
                        reqCfg->base.channelMask, data, cfgH,
                        offsetof(AudioConfig70, base) + offsetof(AudioConfigBase70, channelMask));
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
                fprintf(stderr, "guest_virtual_audio=openOutputStream rate=%u fmt=%s ch=%s frames=%llu\n",
                        spParams.sampleRateHz, spParams.format.c_str(), spParams.channelMask.c_str(),
                        static_cast<unsigned long long>(spParams.frameCount));
                sp<IBinder> stream = new VirtualStreamOut(spParams);
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
        writeToParcel(Status::ok(), reply);
        if (code == 1) { // openDevice(string device)
            const hidl_string* dev = nullptr;
            size_t handle = 0;
            data.enforceInterface("android.hardware.audio@7.0::IDevicesFactory");
            data.readBuffer(sizeof(hidl_string), &handle, reinterpret_cast<const void**>(&dev));
            if (dev) {
                android::hardware::readEmbeddedFromParcel(*dev, data, handle, 0);
            }
            const char* name = dev ? dev->c_str() : "";
            fprintf(stderr, "guest_virtual_audio=openDevice name=%s\n", name);
            if (strcmp(name, "primary") == 0) {
                reply->writeInt32(0 /* OK */);
                rc = reply->writeStrongBinder(new VirtualPrimaryDevice());
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
            rc = reply->writeStrongBinder(new VirtualPrimaryDevice());
            if (rc == OK && cb) cb(*reply);
            return rc;
        }
        return android::UNKNOWN_TRANSACTION;
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
    status_t src = android::hardware::readFromParcel(&status, rep);
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

    ProcessState::self()->startThreadPool();
    sp<IBinder> sm = ProcessState::self()->getContextObject(nullptr);
    if (!sm) {
        fprintf(stderr, "ssal-virtual-audio: hwservicemanager context null\n");
        return 1;
    }

    sp<IBinder> devices = new VirtualDevicesFactory();
    sp<IBinder> effects = new VirtualEffectsFactory();
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
