#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <stdio.h>
#include <stdatomic.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

static const char *source = "u:r:ssal_guest_probe:s0";
static const char *startup = "u:r:ssal_guest_ss_startup:s0";
static const char *final = "u:r:ssal_guest_ss:s0";

static void context(char *text, size_t size) {
    int fd = open("/proc/self/attr/current", O_RDONLY | O_CLOEXEC);
    ssize_t n = fd < 0 ? -1 : read(fd, text, size - 1);
    if (fd >= 0) close(fd);
    if (n > 0) { text[n] = 0; text[strcspn(text, "\n")] = 0; }
    else snprintf(text, size, "UNAVAILABLE errno=%d", errno);
}

int main(int argc, char **argv) {
    setbuf(stdout, NULL);
    int boundary = argc == 2 && !strcmp(argv[1], "--boundary");
    if (argc != 1 && !boundary) return 2;
    if (getuid() != 0) return 2;
    void *lib = dlopen("libselinux.so", RTLD_NOW);
    int (*setter)(const char *) = lib ? dlsym(lib, "setcon") : NULL;
    if (!setter) return 2;
    const char *labels[] = {source, "u:r:system_server:s0", startup, final};
    for (unsigned i = 0; i < sizeof(labels) / sizeof(labels[0]); i++) {
        int fd = open("/sys/fs/selinux/context", O_RDWR | O_CLOEXEC);
        errno = fd < 0 ? errno : 0;
        ssize_t result = fd < 0 ? -1 : write(fd, labels[i], strlen(labels[i]) + 1);
        int error = errno;
        if (fd >= 0) close(fd);
        printf("context_check label=%s result=%zd errno=%d\n", labels[i], result, error);
    }
    // Parent reports through a pre-fork mapping even if the new SID denies stdout.
    char *report = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (report == MAP_FAILED) return 2;
    atomic_int *ready = mmap(NULL, sizeof(*ready), PROT_READ | PROT_WRITE,
                            MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (ready == MAP_FAILED) return 2;
    atomic_init(ready, 0);
    pid_t parent = getpid(), canary = -1;
    if (boundary) {
        canary = fork();
        if (canary < 0) return 2;
        if (!canary) {
            if (prctl(PR_SET_PDEATHSIG, SIGKILL) || getppid() != parent) _exit(2);
            alarm(5);
            int null = open("/dev/null", O_RDONLY | O_CLOEXEC);
            if (null < 0 || dup2(null, 0) < 0 || setgroups(0, NULL) ||
                setresgid(1000, 1000, 1000) || setresuid(1000, 1000, 1000) ||
                setter("u:r:system_server:s0") || prctl(PR_SET_DUMPABLE, 1)) _exit(2);
            close(null);
            atomic_store(ready, 1);
            pause();
            _exit(0);
        }
        for (unsigned i = 0; i < 200 && !atomic_load(ready); ++i) usleep(10000);
        if (!atomic_load(ready)) {
            kill(canary, SIGKILL);
            waitpid(canary, NULL, 0);
            return 2;
        }
        char path[128], sid[256] = "";
        snprintf(path, sizeof(path), "/proc/%d/attr/current", canary);
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        ssize_t n = fd < 0 ? -1 : read(fd, sid, sizeof(sid) - 1);
        if (fd >= 0) close(fd);
        printf("canary pid=%d ready=1 sid=%s\n", canary, n > 0 ? sid : "UNAVAILABLE");
    }
    pid_t child = fork();
    if (child < 0) {
        if (canary > 0) { kill(canary, SIGKILL); waitpid(canary, NULL, 0); }
        return 2;
    }
    if (!child) {
        if (prctl(PR_SET_PDEATHSIG, SIGKILL) || getppid() != parent) _exit(2);
        alarm(3);
        if (setter(source) || setgroups(0, NULL) || setresgid(1000, 1000, 1000) ||
            setresuid(1000, 1000, 1000)) {
            snprintf(report, 4096, "setup_failed errno=%d\n", errno);
            _exit(2);
        }
        char before[256], after[256];
        context(before, sizeof(before));
        errno = 0;
        int start_result = setter(startup), start_error = errno;
        int result = -1, error = 0;
        if (start_result == 0) {
            errno = 0;
            result = setter(final);
            error = errno;
        }
        context(after, sizeof(after));
        snprintf(report, 4096, "uid=%d gid=%d before=%s\nsetcon startup=%s result=%d errno=%d\n"
                 "setcon target=%s called=%d result=%d errno=%d after=%s\n"
                 "startup_transition=ATTEMPTED direct_final_diagnostic=0\n"
                 "canary=%s forkSystemServer=NOT_RUN SystemServer_main=never\n",
                 getuid(), getgid(), before, startup, start_result, start_error,
                 final, start_result == 0, result, error, after,
                 boundary && start_result == 0 && result == 0 && !strcmp(after, final) ? "ATTEMPTED" : "NOT_RUN");
        int success = start_result == 0 && result == 0 && !strcmp(after, final);
        if (boundary && success) {
            size_t used = strlen(report);
            errno = 0;
            int rc = kill(canary, 0), err = errno;
            used += (size_t)snprintf(report + used, 4096 - used,
                                    "boundary signal0 result=%d errno=%d\n", rc, err);
            int denied = rc == -1 && (err == EACCES || err == EPERM);
            for (unsigned i = 0; i < 3; ++i) {
                char path[128];
                snprintf(path, sizeof(path), "/proc/%d/%s", canary,
                         i == 0 ? "root" : i == 1 ? "fd" : "fd/0");
                errno = 0;
                int fd = open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
                err = errno;
                if (fd >= 0) close(fd);
                used += (size_t)snprintf(report + used, 4096 - used,
                                        "boundary path=%s result=%d errno=%d\n", path, fd >= 0 ? 0 : -1, err);
                // Existing procfs may hide a live target as ENOENT. Parent verifies liveness below.
                denied = denied && fd < 0 && (err == EACCES || err == EPERM || err == ENOENT);
            }
            snprintf(report + used, 4096 - used, "canary_boundary=%s ptrace=NOT_RUN\n", denied ? "PASS" : "FAIL");
            success = denied;
        }
        _exit(success ? 0 : 1);
    }
    int status;
    pid_t waited;
    do { waited = waitpid(child, &status, 0); } while (waited < 0 && errno == EINTR);
    if (waited != child) return 2;
    printf("%sowned_child=%d reaped=1 status=%d\n", report, child, status);
    if (canary > 0) {
        int canary_status;
        do { waited = waitpid(canary, &canary_status, WNOHANG); } while (waited < 0 && errno == EINTR);
        int live = waited == 0;
        char path[128];
        snprintf(path, sizeof(path), "/proc/%d/root", canary);
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        printf("canary_reference live=%d parent_root_open=%d\n", live, fd >= 0);
        if (fd >= 0) close(fd);
        if (live) {
            // Only this unreaped direct child can be signalled here.
            kill(canary, SIGKILL);
            do { waited = waitpid(canary, &canary_status, 0); } while (waited < 0 && errno == EINTR);
        }
        printf("owned_canary=%d reaped=%d\n", canary, waited == canary);
        if (!live || fd < 0 || waited != canary) return 2;
    }
    munmap(report, 4096);
    munmap(ready, sizeof(*ready));
    return WIFEXITED(status) ? WEXITSTATUS(status) : 2;
}
