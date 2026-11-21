#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdint.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <unwind.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <ucontext.h>
#if defined(__ANDROID__)
#include <sys/system_properties.h>
#endif

static struct sigaction previous_segv;
static volatile sig_atomic_t capturing;
static volatile sig_atomic_t guest_context_precheck_ok;
static volatile sig_atomic_t guest_context_precheck_errno;

int selinux_android_setcontext(uid_t uid, int server, const char *seinfo, const char *name) {
    int incoming = errno;
    int (*real_setcontext)(uid_t, int, const char *, const char *) = dlsym(RTLD_NEXT, "selinux_android_setcontext");
    if (getenv("SSAL_PHASE8B3B_NOOP")) {
        errno = real_setcontext ? incoming : ENOSYS;
        return real_setcontext ? real_setcontext(uid, server, seinfo, name) : -1;
    }
    int (*get_context)(char **) = dlsym(RTLD_NEXT, "getcon");
    char *original = NULL;
    int got = get_context ? get_context(&original) : -2;
    const char *expected = "u:r:ssal_guest_probe:s0";
    int valid = guest_context_precheck_ok ? (int)strlen(expected) : -1;
    int check_error = guest_context_precheck_errno;
#if !defined(__ANDROID__)
    if (getenv("SSAL_TEST_CONTEXT_VALID")) {
        valid = (int)strlen(expected) + 1;
        check_error = 0;
    }
#endif
    int original_guest_domain = got == 0 && original && strcmp(original, expected) == 0;
    dprintf(2, "SSAL_ORIGINAL_CONTEXT pid=%d getcon=%d label=%s\n", getpid(), got, original ? original : "NULL");
    free(original);
    errno = 0;
    int result = real_setcontext ? real_setcontext(uid, server, seinfo, name) : -1;
    int error = errno;
    dprintf(2, "SSAL_SETCONTEXT pid=%d uid=%d server=%d process_uid=%d process_gid=%d seinfo=%s name=%s expected_context_check=%d check_errno=%d result=%d errno=%d\n", getpid(), uid, server, getuid(), getgid(), seinfo ? seinfo : "NULL", name ? name : "NULL", valid, check_error, result, error);
    char *after = NULL;
    int got_after = get_context ? get_context(&after) : -2;
    dprintf(2, "SSAL_RESULT_CONTEXT pid=%d getcon=%d label=%s\n", getpid(), got_after, after ? after : "NULL");
    free(after);
    if (result != 0 && error == EINVAL && real_setcontext && valid > 0 && original_guest_domain
        && uid == 10000 && server == 0 && seinfo && strcmp(seinfo, "ssal_probe") == 0
        && name && strcmp(name, "ssal-fork-probe") == 0
        && getenv("SSAL_PHASE7FC_BYPASS_SETCONTEXT")) {
        dprintf(2, "SSAL_SETCONTEXT_BYPASS pid=%d uid=10000 mode=retained_guest_domain context=%s\n", getpid(), expected);
        errno = 0;
        return 0;
    }
    errno = error;
    return result;
}

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
    if (getenv("ANDROID_SOCKET_zygote")) {
        // An SELinux exec transition can reset the soft limit while preserving the hard limit.
        struct rlimit nice_limit;
        if (getrlimit(RLIMIT_NICE, &nice_limit) == 0) {
            rlim_t inherited_limit = nice_limit.rlim_max < 40 ? nice_limit.rlim_max : 40;
            if (nice_limit.rlim_cur < inherited_limit) {
                nice_limit.rlim_cur = inherited_limit;
                if (setrlimit(RLIMIT_NICE, &nice_limit) != 0)
                    number("SSAL_ZYGOTE_NICE_LIMIT_ERRNO", errno);
            }
        } else {
            number("SSAL_ZYGOTE_NICE_LIMIT_ERRNO", errno);
        }
    }
#if defined(__ANDROID__)
    for (unsigned i = 0; i < 2; ++i) {
        const char *path = i ? "/system/framework/voip-common.jar" : "/run/ssal/fork-probe.jar";
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd >= 0) {
            char link[64], target[512] = {0};
            snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
            ssize_t n = readlink(link, target, sizeof(target) - 1);
            dprintf(STDERR_FILENO, "SSAL_FD_PATH pid=%d opened=%s fd=%d target=%.*s\n", getpid(), path, fd, n > 0 ? (int)n : 0, target);
            close(fd);
        }
    }
    const char *socket_names[] = {"zygote", "usap_pool_primary"};
    for (size_t i = 0; i < 2; ++i) {
        char key[80];
        snprintf(key, sizeof(key), "ANDROID_SOCKET_%s", socket_names[i]);
        const char *value = getenv(key);
        if (!value) continue;
        int fd = atoi(value), type = -1, listening = -1;
        struct sockaddr_un address = {0};
        socklen_t length = sizeof(address), option_length = sizeof(int);
        int result = getsockname(fd, (struct sockaddr *)&address, &length);
        int error = result ? errno : 0;
        int type_result = getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &option_length);
        option_length = sizeof(int);
        int listen_result = getsockopt(fd, SOL_SOCKET, SO_ACCEPTCONN, &listening, &option_length);
        dprintf(STDERR_FILENO, "SSAL_SOCKET pid=%d name=%s env=%s getsockname=%d errno=%d family=%d path=%.*s type_result=%d type=%d listen_result=%d listening=%d\n", getpid(), socket_names[i], value, result, error, address.sun_family, (int)sizeof(address.sun_path), address.sun_path, type_result, type, listen_result, listening);
    }
    // Read in the actual Zygote process, through the same bionic area as Framework JNI.
    const char *keys[] = {"ro.build.version.sdk", "ro.build.version.codename",
                          "ro.build.version.all_codenames"};
    for (unsigned i = 0; i < sizeof(keys) / sizeof(keys[0]); ++i) {
        char value[PROP_VALUE_MAX] = {0}, line[256];
        __system_property_get(keys[i], value);
        int n = snprintf(line, sizeof(line), "SSAL_ZYGOTE_PROPERTY pid=%d key=%s present=%d value=%s\n",
                         getpid(), keys[i], __system_property_find(keys[i]) != NULL, value);
        if (n > 0 && (size_t)n < sizeof(line)) (void)write(STDERR_FILENO, line, (size_t)n);
    }
    const char *guest_context = "u:r:ssal_guest_probe:s0";
    errno = 0;
    int context_fd = open("/sys/fs/selinux/context", O_RDWR | O_CLOEXEC);
    int context_result = context_fd < 0 ? -1 : (int)write(context_fd, guest_context, strlen(guest_context));
    int context_error = errno;
    if (context_fd >= 0) close(context_fd);
    guest_context_precheck_ok = context_result == (int)strlen(guest_context);
    guest_context_precheck_errno = context_error;
    dprintf(STDERR_FILENO, "SSAL_GUEST_CONTEXT_PRECHECK pid=%d uid=%d gid=%d context=%s fd=%d result=%d errno=%d\n",
            getpid(), getuid(), getgid(), guest_context, context_fd, context_result, context_error);
#endif
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
