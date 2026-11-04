#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdint.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <unwind.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <ucontext.h>

static struct sigaction previous_segv;
static volatile sig_atomic_t capturing;

// No allocator, unwinder, or dynamic linker locks on the faulting thread.
static void number(const char *name, uint64_t value) {
    char line[128];
    size_t n = 0;
    while (*name && n < 100) line[n++] = *name++;
    line[n++] = '='; line[n++] = '0'; line[n++] = 'x';
    for (int shift = 60; shift >= 0; shift -= 4)
        line[n++] = "0123456789abcdef"[(value >> shift) & 15];
    line[n++] = '\n';
    (void)write(STDERR_FILENO, line, n);
}

static void words(int memory, const char *label, uintptr_t address, size_t count) {
    number(label, address);
    for (size_t i = 0; i < count; ++i) {
        uint64_t value;
        if (pread(memory, &value, sizeof(value), (off_t)(address + i * 8)) != sizeof(value)) {
            number("read_errno", errno);
            break;
        }
        number("word", value);
    }
}

static void segv(int signal_number, siginfo_t *info, void *context) {
    if (!__atomic_exchange_n(&capturing, 1, __ATOMIC_RELAXED)) {
        number("SSAL_CRASH_PID", getpid());
        number("tid", syscall(SYS_gettid));
        number("signal", signal_number);
        number("si_code", info->si_code);
        number("si_addr", (uintptr_t)info->si_addr);
        ucontext_t *uc = context;
#if defined(__aarch64__)
        for (unsigned i = 0; i < 31; ++i) {
            char name[] = "x00";
            name[1] += i / 10; name[2] += i % 10;
            number(name, uc->uc_mcontext.regs[i]);
        }
        uintptr_t pc = uc->uc_mcontext.pc, sp = uc->uc_mcontext.sp;
        uintptr_t fp = uc->uc_mcontext.regs[29];
        number("lr", uc->uc_mcontext.regs[30]);
#elif defined(__x86_64__)
        uintptr_t pc = uc->uc_mcontext.gregs[REG_RIP], sp = uc->uc_mcontext.gregs[REG_RSP];
        uintptr_t fp = uc->uc_mcontext.gregs[REG_RBP];
#else
#error Unsupported crash context
#endif
        number("pc", pc); number("sp", sp); number("fp", fp);
        int memory = open("/proc/self/mem", O_RDONLY | O_CLOEXEC);
        number("memory_open_errno", memory < 0 ? errno : 0);
        if (memory >= 0) {
            words(memory, "code_start", pc >= 32 ? pc - 32 : pc, 12);
            words(memory, "stack_start", sp, 128);
            // shortcut: FP-only unwind; use offline CFI if an optimized frame omits FP.
            number("frame_pc", pc);
            for (unsigned i = 0; i < 32 && fp >= sp && fp - sp < 8 * 1024 * 1024 && !(fp & 15); ++i) {
                uint64_t pair[2];
                if (pread(memory, pair, sizeof(pair), (off_t)fp) != sizeof(pair)) break;
                number("frame_fp", fp); number("frame_lr_raw", pair[1]);
                number("frame_pc", pair[1] & UINT64_C(0x0000ffffffffffff));
                if (pair[0] <= fp) break;
                fp = pair[0];
            }
            close(memory);
        }
        int maps = open("/proc/self/maps", O_RDONLY | O_CLOEXEC);
        number("maps_open_errno", maps < 0 ? errno : 0);
        if (maps >= 0) {
            char buffer[4096];
            for (unsigned i = 0; i < 32; ++i) {
                ssize_t n = read(maps, buffer, sizeof(buffer));
                if (n <= 0) break;
                (void)write(STDERR_FILENO, buffer, (size_t)n);
            }
            close(maps);
        }
        number("SSAL_CRASH_END", 1);
    }
    if (previous_segv.sa_handler != SIG_DFL && previous_segv.sa_handler != SIG_IGN) {
        if (previous_segv.sa_flags & SA_SIGINFO) previous_segv.sa_sigaction(signal_number, info, context);
        else previous_segv.sa_handler(signal_number);
    }
    // Restore fatal semantics even if the prior handler returns; never leave a stopped tracee.
    struct sigaction action = {.sa_handler = SIG_DFL};
    sigemptyset(&action.sa_mask);
    sigaction(signal_number, &action, NULL);
    syscall(SYS_tgkill, getpid(), syscall(SYS_gettid), signal_number);
}

__attribute__((constructor)) static void install_crash_capture(void) {
    struct sigaction action = {.sa_sigaction = segv, .sa_flags = SA_SIGINFO | SA_ONSTACK};
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGSEGV, &action, &previous_segv) < 0) number("SSAL_CAPTURE_INSTALL_ERRNO", errno);
}

static _Unwind_Reason_Code frame(struct _Unwind_Context *context, void *argument) {
    unsigned *count = argument;
    uintptr_t pc = _Unwind_GetIP(context);
    Dl_info info = {0};
    dladdr((void *)pc, &info);
    char line[512];
    int n = snprintf(line, sizeof(line), "SSAL_NATIVE_FRAME #%u pc=%p object=%s offset=%p\n",
                     (*count)++, (void *)pc, info.dli_fname ? info.dli_fname : "UNKNOWN",
                     (void *)(pc - (uintptr_t)info.dli_fbase));
    if (n > 0) (void)write(STDERR_FILENO, line, (size_t)n < sizeof(line) ? (size_t)n : sizeof(line) - 1);
    return *count < 64 ? _URC_NO_REASON : _URC_END_OF_STACK;
}

// Guest Zygote alone preloads this library; Host crash services remain untouched.
__attribute__((noreturn)) void abort(void) {
    static int aborting;
    if (!__atomic_exchange_n(&aborting, 1, __ATOMIC_RELAXED)) {
        char line[160];
        struct timespec now = {0};
        clock_gettime(CLOCK_REALTIME, &now);
        int n = snprintf(line, sizeof(line), "SSAL_NATIVE_ABORT pid=%d unix_s=%lld.%09ld\n",
                         getpid(), (long long)now.tv_sec, now.tv_nsec);
        if (n > 0) (void)write(STDERR_FILENO, line, (size_t)n);
        unsigned count = 0;
        _Unwind_Backtrace(frame, &count);
    }
    void (*real_abort)(void) = (void (*)(void))dlsym(RTLD_NEXT, "abort");
    if (real_abort) real_abort();
    // Preserve signal semantics even if libc symbol lookup fails.
    signal(SIGABRT, SIG_DFL);
    sigset_t signals;
    sigemptyset(&signals);
    sigaddset(&signals, SIGABRT);
    sigprocmask(SIG_UNBLOCK, &signals, NULL);
    raise(SIGABRT);
    _exit(128 + SIGABRT);
}
