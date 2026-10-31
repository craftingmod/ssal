#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

struct trace_event {
    uint32_t stage;
    int32_t error;
};

int main(void) {
    const char *trace_fd = getenv("SSAL_STAGE_FD");
    if (trace_fd != NULL) {
        struct trace_event event = {10, 0};
        (void)write(atoi(trace_fd), &event, sizeof(event));
    }

    char context[128];
    int context_fd = open("/proc/self/attr/current", O_RDONLY | O_CLOEXEC);
    if (context_fd < 0) {
        perror("open /proc/self/attr/current");
        return 1;
    }
    ssize_t length = read(context_fd, context, sizeof(context) - 1);
    close(context_fd);
    if (length <= 0) {
        perror("read /proc/self/attr/current");
        return 1;
    }
    while (length > 0 && (context[length - 1] == '\0' || context[length - 1] == '\n')) {
        --length;
    }
    context[length] = '\0';

    struct stat executable;
    if (stat("/proc/self/exe", &executable) < 0) {
        perror("stat /proc/self/exe");
        return 1;
    }
    printf(
        "{\"protocol\":1,\"pid\":%d,\"context\":\"%s\","
        "\"executable_dev\":%llu,\"executable_ino\":%llu}\n",
        getpid(), context, (unsigned long long)executable.st_dev,
        (unsigned long long)executable.st_ino);
    return 0;
}
