#define _GNU_SOURCE
#include <dirent.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

/* External, bounded snapshots: never ask the stalled ART thread to unwind itself. */
static int snapshot(pid_t pid) {
    char path[128], context[128] = {0};
    snprintf(path, sizeof(path), "/proc/%d/attr/current", pid);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 1;
    ssize_t n = read(fd, context, sizeof(context) - 1);
    close(fd);
    if (n <= 0 || strcmp(context, "u:r:ssal_p0001_system_server:s0")) {
        fprintf(stderr, "refusing non-Guest SystemServer pid=%d context=%s\n", pid, context);
        return 2;
    }
    snprintf(path, sizeof(path), "/proc/%d/mem", pid);
    int memory = open(path, O_RDONLY | O_CLOEXEC);
    if (memory < 0) { perror("mem"); return 3; }
    snprintf(path, sizeof(path), "/proc/%d/task", pid);
    DIR *tasks = opendir(path);
    if (!tasks) { close(memory); return 4; }
    struct dirent *entry;
    unsigned captured = 0;
    while ((entry = readdir(tasks)) && captured < 64) {
        char *end;
        long tid = strtol(entry->d_name, &end, 10);
        if (!*entry->d_name || *end || tid <= 1) continue;
        if (ptrace(PTRACE_SEIZE, tid, 0, 0)) { perror("seize"); continue; }
        if (ptrace(PTRACE_INTERRUPT, tid, 0, 0)) {
            perror("interrupt"); ptrace(PTRACE_DETACH, tid, 0, 0); continue;
        }
        int status = 0;
        pid_t waited;
        do { waited = waitpid((pid_t)tid, &status, __WALL); } while (waited < 0 && errno == EINTR);
        if (waited == tid && WIFSTOPPED(status)) {
            uint64_t regs[34] = {0}; /* arm64 x0..x30, sp, pc, pstate */
            struct iovec io = {regs, sizeof(regs)};
            if (!ptrace(PTRACE_GETREGSET, tid, (void *)NT_PRSTATUS, &io)) {
                printf("THREAD tid=%ld pc=%#llx lr=%#llx fp=%#llx sp=%#llx\n", tid,
                       (unsigned long long)regs[32], (unsigned long long)regs[30],
                       (unsigned long long)regs[29], (unsigned long long)regs[31]);
                for (unsigned i = 0; i < 9; ++i)
                    printf("REG tid=%ld x%u=%#llx\n", tid, i, (unsigned long long)regs[i]);
                uint32_t lock[4];
                if (pread(memory, lock, sizeof(lock), (off_t)(regs[0] & UINT64_C(0x00ffffffffffffff))) == sizeof(lock))
                    printf("WAIT_WORDS tid=%ld addr=%#llx words=%08x,%08x,%08x,%08x\n", tid,
                           (unsigned long long)regs[0], lock[0], lock[1], lock[2], lock[3]);
                uint64_t fp = regs[29];
                /* shortcut: FP and raw stack only; use offline CFI for omitted frames. */
                for (unsigned i = 0; i < 40 && fp >= regs[31] && fp - regs[31] < 8*1024*1024 && !(fp & 15); ++i) {
                    uint64_t pair[2];
                    if (pread(memory, pair, sizeof(pair), (off_t)fp) != sizeof(pair)) break;
                    printf("FRAME tid=%ld index=%u fp=%#llx pc=%#llx\n", tid, i,
                           (unsigned long long)fp, (unsigned long long)(pair[1] & UINT64_C(0x0000ffffffffffff)));
                    if (pair[0] <= fp) break;
                    fp = pair[0];
                }
                uint64_t stack[128];
                n = pread(memory, stack, sizeof(stack), (off_t)regs[31]);
                for (unsigned i = 0; n > 0 && i < (unsigned)n / 8; ++i)
                    printf("STACK tid=%ld offset=%u value=%#llx\n", tid, i*8, (unsigned long long)stack[i]);
                ++captured;
            } else perror("getregset");
            /* Preserve a genuine signal-delivery stop, suppress our synthetic event stop. */
            int sig = (unsigned)status >> 16 == PTRACE_EVENT_STOP ? 0 : WSTOPSIG(status);
            if (ptrace(PTRACE_DETACH, tid, 0, (void *)(long)sig)) perror("detach");
        }
    }
    closedir(tasks);
    close(memory);
    printf("CAPTURED=%u\n", captured);
    return captured ? 0 : 5;
}

int main(int argc, char **argv) {
    if (argc != 2) return 64;
    char *end;
    long pid = strtol(argv[1], &end, 10);
    if (!*argv[1] || *end || pid <= 1 || pid > INT32_MAX) return 64;
    return snapshot((pid_t)pid);
}
