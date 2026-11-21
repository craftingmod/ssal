// Host NDK Sensor bridge for Guest ssal-sensors.
#include <android/looper.h>
#include <android/sensor.h>
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

struct HostEventPacket {
    int64_t timestamp;
    int32_t sensorHandle;
    int32_t sensorType;
    int32_t status;
    int32_t pad;
    float data[16];
    int64_t stepCount;
};
static_assert(sizeof(HostEventPacket) == 96, "HostEventPacket size mismatch");

static void writeJsonEscaped(std::string& out, const char* s) {
    out.push_back('"');
    if (s) {
        for (const unsigned char* p = reinterpret_cast<const unsigned char*>(s); *p; ++p) {
            unsigned char c = *p;
            if (c == '"' || c == '\\') {
                out.push_back('\\');
                out.push_back(static_cast<char>(c));
            } else if (c < 0x20) {
                char buf[8];
                snprintf(buf, sizeof(buf), "\\u%04x", c);
                out.append(buf);
            } else {
                out.push_back(static_cast<char>(c));
            }
        }
    }
    out.push_back('"');
}

static bool writeAll(int fd, const void* buf, size_t len) {
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

struct BridgeState {
    int sockFd = STDIN_FILENO;
    ALooper* looper = nullptr;
    ASensorEventQueue* queue = nullptr;
    std::vector<const ASensor*> sensors;
    std::unordered_map<int32_t, int32_t> typeToHandle;
    std::mutex queueMutex;
    std::atomic<bool> running{true};
};

static bool extractIntField(const std::string& line, const char* key, int64_t* out) {
    std::string needle = std::string("\"") + key + "\":";
    size_t pos = line.find(needle);
    if (pos == std::string::npos) return false;
    pos += needle.size();
    char* end = nullptr;
    long long val = strtoll(line.c_str() + pos, &end, 10);
    if (end == line.c_str() + pos) return false;
    *out = static_cast<int64_t>(val);
    return true;
}

static void* commandThreadFn(void* arg) {
    BridgeState* state = static_cast<BridgeState*>(arg);
    std::string buf;
    char tmp[512];
    while (state->running.load()) {
        ssize_t n = read(state->sockFd, tmp, sizeof(tmp));
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (n == 0) break;
        buf.append(tmp, static_cast<size_t>(n));
        size_t nl;
        while ((nl = buf.find('\n')) != std::string::npos) {
            std::string line = buf.substr(0, nl);
            buf.erase(0, nl + 1);
            int64_t handle = -1;
            if (!extractIntField(line, "handle", &handle) ||
                handle < 0 ||
                static_cast<size_t>(handle) >= state->sensors.size()) {
                continue;
            }
            const ASensor* sensor = state->sensors[static_cast<size_t>(handle)];
            std::lock_guard<std::mutex> lock(state->queueMutex);
            if (!state->queue) continue;
            if (line.find("\"activate\"") != std::string::npos) {
                bool enabled = line.find("\"enabled\":true") != std::string::npos;
                if (enabled) {
                    ASensorEventQueue_enableSensor(state->queue, sensor);
                } else {
                    ASensorEventQueue_disableSensor(state->queue, sensor);
                }
            } else if (line.find("\"batch\"") != std::string::npos) {
                int64_t periodNs = 20000000;
                extractIntField(line, "period_ns", &periodNs);
                int32_t periodUs = static_cast<int32_t>(periodNs / 1000);
                if (periodUs < 0) periodUs = 0;
                ASensorEventQueue_setEventRate(state->queue, sensor, periodUs);
            }
        }
    }
    state->running.store(false);
    if (state->looper) ALooper_wake(state->looper);
    return nullptr;
}

int main(int argc, char** argv) {
    if (argc != 2 || strcmp(argv[1], "serve") != 0) {
        fprintf(stderr, "usage: ssal-sensor-host serve\n");
        return 2;
    }

    BridgeState state;
    ASensorManager* mgr = ASensorManager_getInstanceForPackage("com.ssal.host");
    if (!mgr) {
        fprintf(stderr, "ssal-sensor-host: ASensorManager unavailable\n");
        return 1;
    }

    ASensorList list = nullptr;
    int count = ASensorManager_getSensorList(mgr, &list);
    if (count < 0) count = 0;

    std::string json = "{\"sensors\":[";
    for (int i = 0; i < count; ++i) {
        const ASensor* s = list[i];
        state.sensors.push_back(s);
        int32_t stype = ASensor_getType(s);
        // Map sensor handle -> index; also remember first handle per type as fallback.
        if (state.typeToHandle.find(stype) == state.typeToHandle.end()) {
            state.typeToHandle[stype] = i;
        }
        if (i > 0) json.push_back(',');
        char num[256];
        json.append("{\"handle\":");
        snprintf(num, sizeof(num), "%d", i);
        json.append(num);
        json.append(",\"name\":");
        writeJsonEscaped(json, ASensor_getName(s));
        json.append(",\"vendor\":");
        writeJsonEscaped(json, ASensor_getVendor(s));
        json.append(",\"type\":");
        snprintf(num, sizeof(num), "%d", stype);
        json.append(num);
        json.append(",\"type_str\":");
        writeJsonEscaped(json, ASensor_getStringType(s));
        json.append(",\"resolution\":");
        snprintf(num, sizeof(num), "%.6g", ASensor_getResolution(s));
        json.append(num);
        json.append(",\"min_delay\":");
        snprintf(num, sizeof(num), "%d", ASensor_getMinDelay(s));
        json.append(num);
        json.append(",\"fifo_reserved\":");
        snprintf(num, sizeof(num), "%d", ASensor_getFifoReservedEventCount(s));
        json.append(num);
        json.append(",\"fifo_max\":");
        snprintf(num, sizeof(num), "%d", ASensor_getFifoMaxEventCount(s));
        json.append(num);
        json.append(",\"reporting_mode\":");
        snprintf(num, sizeof(num), "%d", ASensor_getReportingMode(s));
        json.append(num);
        json.append(",\"wake_up\":");
        json.append(ASensor_isWakeUpSensor(s) ? "true" : "false");
        json.push_back('}');
    }
    json.append("]}\n");

    if (!writeAll(state.sockFd, json.data(), json.size())) {
        fprintf(stderr, "ssal-sensor-host: failed to write sensor list\n");
        return 1;
    }

    state.looper = ALooper_prepare(ALOOPER_PREPARE_ALLOW_NON_CALLBACKS);
    state.queue = ASensorManager_createEventQueue(mgr, state.looper, 1, nullptr, nullptr);
    if (!state.queue) {
        fprintf(stderr, "ssal-sensor-host: createEventQueue failed\n");
        return 1;
    }

    pthread_t cmdThread;
    if (pthread_create(&cmdThread, nullptr, commandThreadFn, &state) != 0) {
        fprintf(stderr, "ssal-sensor-host: pthread_create failed\n");
        return 1;
    }

    ASensorEvent events[64];
    while (state.running.load()) {
        int ident = ALooper_pollOnce(100, nullptr, nullptr, nullptr);
        if (ident == ALOOPER_POLL_ERROR) break;
        ssize_t countEvents = 0;
        {
            std::lock_guard<std::mutex> lock(state.queueMutex);
            countEvents = ASensorEventQueue_getEvents(state.queue, events, 64);
        }
        for (ssize_t i = 0; i < countEvents; ++i) {
            const ASensorEvent& ev = events[i];
            HostEventPacket pkt{};
            pkt.timestamp = ev.timestamp;
            auto it = state.typeToHandle.find(ev.type);
            pkt.sensorHandle = (it != state.typeToHandle.end()) ? it->second : ev.sensor;
            pkt.sensorType = ev.type;
            pkt.status = ev.vector.status;
            memcpy(pkt.data, ev.data, sizeof(pkt.data));
            if (ev.type == ASENSOR_TYPE_STEP_COUNTER) {
                pkt.stepCount = static_cast<int64_t>(ev.u64.step_counter);
            }
            if (!writeAll(state.sockFd, &pkt, sizeof(pkt))) {
                state.running.store(false);
                break;
            }
        }
    }

    state.running.store(false);
    pthread_join(cmdThread, nullptr);
    ASensorManager_destroyEventQueue(mgr, state.queue);
    return 0;
}
