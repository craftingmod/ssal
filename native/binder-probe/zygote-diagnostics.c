#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdint.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <unwind.h>

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
