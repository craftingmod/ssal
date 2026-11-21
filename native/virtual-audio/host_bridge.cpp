// Host AAudio bridge for Guest ssal-virtual-audio.
#include <aaudio/AAudio.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <thread>
#include <vector>

static bool readExact(int fd, void* buf, size_t len) {
    uint8_t* p = static_cast<uint8_t*>(buf);
    size_t done = 0;
    while (done < len) {
        ssize_t n = read(fd, p + done, len - done);
        if (n < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (n == 0) return false;
        done += static_cast<size_t>(n);
    }
    return true;
}

struct AudioHeader {
    uint32_t sampleRateHz;
    uint32_t channelCount;
    uint32_t bytesPerSample;
};

static void serveClient(int client) {
    AudioHeader hdr{};
    if (!readExact(client, &hdr, sizeof(hdr)) || hdr.sampleRateHz < 8000 ||
        hdr.sampleRateHz > 192000 || (hdr.channelCount != 1 && hdr.channelCount != 2) ||
        (hdr.bytesPerSample != 2 && hdr.bytesPerSample != 4)) {
        close(client);
        return;
    }

    AAudioStreamBuilder* builder = nullptr;
    AAudioStream* stream = nullptr;
    if (AAudio_createStreamBuilder(&builder) != AAUDIO_OK || !builder) {
        fprintf(stderr, "ssal-audio-host: AAudio_createStreamBuilder failed\n");
        close(client);
        return;
    }
    AAudioStreamBuilder_setDirection(builder, AAUDIO_DIRECTION_OUTPUT);
    AAudioStreamBuilder_setSharingMode(builder, AAUDIO_SHARING_MODE_SHARED);
    AAudioStreamBuilder_setPerformanceMode(builder, AAUDIO_PERFORMANCE_MODE_LOW_LATENCY);
    AAudioStreamBuilder_setSampleRate(builder, static_cast<int32_t>(hdr.sampleRateHz));
    AAudioStreamBuilder_setChannelCount(builder, static_cast<int32_t>(hdr.channelCount));
    AAudioStreamBuilder_setFormat(
        builder, hdr.bytesPerSample == 4 ? AAUDIO_FORMAT_PCM_FLOAT : AAUDIO_FORMAT_PCM_I16);

    aaudio_result_t rc = AAudioStreamBuilder_openStream(builder, &stream);
    AAudioStreamBuilder_delete(builder);
    if (rc != AAUDIO_OK || !stream) {
        fprintf(stderr, "ssal-audio-host: AAudioStreamBuilder_openStream failed: %s\n",
                AAudio_convertResultToText(rc));
        close(client);
        return;
    }
    if (AAudioStream_getSampleRate(stream) != static_cast<int32_t>(hdr.sampleRateHz) ||
        AAudioStream_getChannelCount(stream) != static_cast<int32_t>(hdr.channelCount) ||
        AAudioStream_getFormat(stream) != (hdr.bytesPerSample == 4 ? AAUDIO_FORMAT_PCM_FLOAT : AAUDIO_FORMAT_PCM_I16)) {
        fprintf(stderr,
                "ssal-audio-host: negotiated PCM configuration mismatch "
                "(req rate=%u ch=%u bps=%u, got rate=%d ch=%d fmt=%d)\n",
                hdr.sampleRateHz, hdr.channelCount, hdr.bytesPerSample,
                AAudioStream_getSampleRate(stream), AAudioStream_getChannelCount(stream),
                AAudioStream_getFormat(stream));
        AAudioStream_close(stream);
        close(client);
        return;
    }

    int32_t burst = AAudioStream_getFramesPerBurst(stream);
    if (burst > 0) {
        AAudioStream_setBufferSizeInFrames(stream, burst * 2);
    }

    fprintf(stderr, "ssal-audio-host: opened AAudio stream rate=%u ch=%u bps=%u burst=%d buf=%d\n",
            hdr.sampleRateHz, hdr.channelCount, hdr.bytesPerSample,
            burst, AAudioStream_getBufferSizeInFrames(stream));

    bool started = false;
    uint32_t frameBytes = hdr.channelCount * hdr.bytesPerSample;
    std::vector<uint8_t> buf;
    uint32_t len = 0;
    while (readExact(client, &len, sizeof(len))) {
        if (len == 0) {
            if (started) {
                if (AAudioStream_requestPause(stream) == AAUDIO_OK) {
                    aaudio_stream_state_t state = AAUDIO_STREAM_STATE_PAUSING;
                    AAudioStream_waitForStateChange(stream, AAUDIO_STREAM_STATE_PAUSING, &state, 50000000LL);
                    if (state == AAUDIO_STREAM_STATE_PAUSED) {
                        AAudioStream_requestFlush(stream);
                    }
                }
                started = false;
            }
            continue;
        }
        if (len > 1024 * 1024 || len % frameBytes) break;
        buf.resize(len);
        if (!readExact(client, buf.data(), len)) break;
        if (!started) {
            if (AAudioStream_requestStart(stream) != AAUDIO_OK) break;
            started = true;
        }
        uint32_t written = 0;
        while (written < len) {
            aaudio_result_t frames = AAudioStream_write(stream, buf.data() + written,
                static_cast<int32_t>((len - written) / frameBytes), 100000000LL /* 100ms */);
            if (frames <= 0) break;
            written += static_cast<uint32_t>(frames) * frameBytes;
        }
        if (written != len) break;
    }

    AAudioStream_requestStop(stream);
    AAudioStream_close(stream);
    close(client);
}

int main(int argc, char** argv) {
    signal(SIGPIPE, SIG_IGN);
    if (argc != 3 || strcmp(argv[1], "serve") != 0) {
        fprintf(stderr, "usage: ssal-audio-host serve <unix-socket-path>\n");
        return 2;
    }
    const char* sockPath = argv[2];
    unlink(sockPath);

    int srv = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (srv < 0) {
        fprintf(stderr, "ssal-audio-host: socket failed: %s\n", strerror(errno));
        return 1;
    }

    struct sockaddr_un addr {};
    addr.sun_family = AF_UNIX;
    if (strlen(sockPath) >= sizeof(addr.sun_path)) {
        fprintf(stderr, "ssal-audio-host: socket path too long\n");
        close(srv);
        return 1;
    }
    strncpy(addr.sun_path, sockPath, sizeof(addr.sun_path) - 1);
    if (bind(srv, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) != 0 ||
        chmod(sockPath, 0666) != 0 ||
        listen(srv, 16) != 0) {
        fprintf(stderr, "ssal-audio-host: bind/listen %s failed: %s\n", sockPath, strerror(errno));
        close(srv);
        return 1;
    }
    if (setresgid(1000, 1000, 1000) != 0 || setresuid(1000, 1000, 1000) != 0) {
        fprintf(stderr, "ssal-audio-host: drop uid to 1000 failed: %s\n", strerror(errno));
    }

    printf("host_audio_bridge_ready=%s\n", sockPath);
    fflush(stdout);

    for (;;) {
        int client = accept4(srv, nullptr, nullptr, SOCK_CLOEXEC);
        if (client < 0) {
            if (errno == EINTR) continue;
            break;
        }
        std::thread(serveClient, client).detach();
    }

    close(srv);
    unlink(sockPath);
    return 0;
}
