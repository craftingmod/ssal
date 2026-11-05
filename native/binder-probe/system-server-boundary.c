#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

/* Pre-mapped diagnostic output survives final-SID denial of inherited file writes. */
static char *output;
static size_t used;
static void record(const char *format, ...) {
    if (used >= 16383) _exit(16);
    va_list args;
    va_start(args, format);
    int n = vsnprintf(output + used, 16384 - used, format, args);
    va_end(args);
    if (n < 0 || (size_t)n >= 16384 - used) _exit(16);
    used += (size_t)n;
}
#define printf record

static void identity(void) {
    char buf[4096];
    for (int i = 0; i < 2; i++) {
        const char *path = i ? "/proc/self/status" : "/proc/self/attr/current";
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        ssize_t n = fd < 0 ? -1 : read(fd, buf, sizeof(buf) - 1);
        if (fd >= 0) close(fd);
        if (n <= 0) _exit(12);
        buf[n] = 0;
        printf("identity %s\n%s\n", path, buf);
    }
}

int main(int argc, char **argv) {
    setbuf(stdout, NULL);
    if (argc != 2) return 2;
    int canary = !strcmp(argv[1], "--canary");
    if (!canary && strcmp(argv[1], "--probe")) return 2;
    if (ftruncate(STDOUT_FILENO, 16384)) return 17;
    output = mmap(NULL, 16384, PROT_READ | PROT_WRITE, MAP_SHARED, STDOUT_FILENO, 0);
    if (output == MAP_FAILED) return 18;
    void *lib = dlopen("libselinux.so", RTLD_NOW);
    int (*setcon)(const char *) = lib ? dlsym(lib, "setcon") : NULL;
    // Match specialization order: credentials before the final SID.
    if (setgroups(0, NULL) || setresgid(1000, 1000, 1000) || setresuid(1000, 1000, 1000)) {
        printf("boundary_credentials_failed errno=%d\n", errno);
        return 11;
    }
    if (!setcon || setcon("u:r:system_server:s0")) {
        printf("boundary_sid_failed errno=%d\n", errno);
        return 10;
    }
    printf("boundary_sid_set=PASS\n");
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) return 12;
    identity();
    if (canary) {
        // An expendable, dumpable process; no real Host service is targeted.
        if (prctl(PR_SET_DUMPABLE, 1)) return 13;
        printf("SSAL_HOST_CANARY_READY pid=%d\n", getpid());
        sleep(12);
        return 0;
    }
    const char *value = getenv("SSAL_CANARY_PID");
    char *end = NULL;
    long parsed = value ? strtol(value, &end, 10) : 0;
    if (parsed <= 1 || !end || *end) return 14;
    pid_t pid = (pid_t)parsed;
    errno = 0;
    int rc = kill(pid, 0);
    printf("boundary signal0 result=%d errno=%d\n", rc, rc ? errno : 0);
    int allowed = rc == 0;
    for (int i = 0; i < 3; i++) {
        char path[128];
        snprintf(path, sizeof(path), "/proc/%d/%s", pid, i == 0 ? "root" : i == 1 ? "fd" : "fd/0");
        errno = 0;
        int fd = open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
        printf("boundary path=%s result=%d errno=%d\n", path, fd >= 0 ? 0 : -1, fd < 0 ? errno : 0);
        if (fd >= 0) { allowed = 1; close(fd); }
    }
    errno = 0;
    rc = ptrace(PTRACE_ATTACH, pid, NULL, NULL);
    printf("boundary ptrace_attach result=%d errno=%d\n", rc, rc ? errno : 0);
    if (!rc) {
        allowed = 1;
        int status;
        pid_t waited;
        do { waited = waitpid(pid, &status, __WALL); } while (waited < 0 && errno == EINTR);
        if (waited != pid || !WIFSTOPPED(status) || ptrace(PTRACE_DETACH, pid, NULL, NULL)) return 15;
        printf("boundary ptrace_detach=PASS\n");
    }
    printf("SSAL_SS_BOUNDARY=%s credential_model=uid1000-groups0-caps0-stock_sid\n", allowed ? "FAIL" : "PASS");
    return allowed ? 1 : 0;
}
