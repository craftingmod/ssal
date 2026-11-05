#define _GNU_SOURCE
#include <assert.h>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/capability.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

struct report { volatile int ready; size_t used; char text[16384]; };
static struct report *reports, *out;
static int (*setcon_fn)(const char *);
static void record(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(out->text + out->used, sizeof(out->text) - out->used, fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= sizeof(out->text) - out->used) _exit(20);
    out->used += n;
}
static _Noreturn void blocked(const char *stage) {
    record("BLOCKED stage=%s errno=%d\n", stage, errno);
    _exit(3);
}
static char *read_file(const char *path) {
    FILE *f = fopen(path, "re");
    if (!f) return NULL;
    char *buf = NULL; size_t size = 0, used = 0;
    for (;;) {
        if (size - used < 4096) {
            size += 8192;
            char *next = realloc(buf, size);
            if (!next) { free(buf); fclose(f); return NULL; }
            buf = next;
        }
        size_t n = fread(buf + used, 1, size - used - 1, f);
        used += n;
        if (!n) break;
    }
    int error = ferror(f); fclose(f);
    if (error) { free(buf); return NULL; }
    buf[used] = 0; return buf;
}
static int option(const char *list, const char *key) {
    size_t n = strlen(key);
    for (const char *p = list; p && *p; p = strchr(p, ','), p = p ? p + 1 : NULL)
        if (!strncmp(p, key, n) && (!p[n] || p[n] == ',')) return 1;
    return 0;
}
/* Inspect only optional propagation fields, never substrings in path names. */
static int private_line(const char *line) {
    char copy[8192];
    if (strlen(line) >= sizeof(copy)) return 0;
    strcpy(copy, line);
    char *save, *p = strtok_r(copy, " ", &save);
    for (int field = 0; p; ++field, p = strtok_r(NULL, " ", &save)) {
        if (field < 6) continue;
        if (!strcmp(p, "-")) return 1;
        if (!strncmp(p, "shared:", 7) || !strncmp(p, "master:", 7) ||
            !strncmp(p, "propagate_from:", 15)) return 0;
    }
    return 0;
}
static int mount_check(const char *path, int require_private, int guest) {
    FILE *f = fopen("/proc/self/mountinfo", "re");
    if (!f) return 0;
    char *line = NULL; size_t cap = 0; int found = 0, ok = 1, count = 0;
    while (getline(&line, &cap, f) > 0) {
        count++;
        if (require_private && !private_line(line)) ok = 0;
        char target[4096], fs[64], source[4096], opts[4096];
        char *sep = strstr(line, " - ");
        if (sscanf(line, "%*s %*s %*s %*s %4095s", target) != 1 || !sep) { ok = 0; continue; }
        if (strcmp(target, path)) continue;
        if (sscanf(sep + 3, "%63s %4095s %4095s", fs, source, opts) != 3) { ok = 0; continue; }
        record("mount_record %s", line);
        found++;
        if (strcmp(fs, "proc")) ok = 0;
        if (guest) {
            if (!(option(opts, "hidepid=4") || option(opts, "hidepid=ptraceable")) ||
                option(opts, "gid=3009")) ok = 0;
        } else if (!option(opts, "hidepid=invisible") || !option(opts, "gid=3009")) ok = 0;
    }
    if (ferror(f)) ok = 0;
    free(line); fclose(f);
    record("propagation private_required=%d records=%d result=%s\n", require_private, count, ok ? "PASS" : "FAIL");
    return ok && count > 0 && found == 1;
}
static void identity(void) {
    if (setgroups(0, NULL) || setresgid(1000, 1000, 1000) || setresuid(1000, 1000, 1000) ||
        !setcon_fn || setcon_fn("u:r:system_server:s0") || prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) blocked("credentials");
    uid_t r, e, s; gid_t gr, ge, gs, groups[128];
    struct __user_cap_header_struct hdr = { .version = _LINUX_CAPABILITY_VERSION_3 };
    struct __user_cap_data_struct caps[2] = {{0}};
    char *sid = read_file("/proc/self/attr/current");
    int ng = getgroups(128, groups);
    if (getresuid(&r, &e, &s) || getresgid(&gr, &ge, &gs) || ng < 0 ||
        syscall(SYS_capget, &hdr, caps) || !sid) blocked("identity_readback");
    record("identity uid=%u/%u/%u gid=%u/%u/%u sid=%s CapEff=%08x%08x groups=", r,e,s,gr,ge,gs,sid,caps[1].effective,caps[0].effective);
    int exception = gr == 3009 || ge == 3009 || gs == 3009;
    for (int i = 0; i < ng; i++) { record("%u,", groups[i]); exception |= groups[i] == 3009; }
    record(" count=%d gid3009_exception=%d\n", ng, exception);
    int valid = r == 1000 && e == 1000 && s == 1000 && gr == 1000 && ge == 1000 && gs == 1000 &&
        !strcmp(sid, "u:r:system_server:s0") && !caps[0].effective && !caps[1].effective && !exception && !ng;
    free(sid);
    if (!valid) blocked("identity_mismatch");
}
static int namespace_different(const struct stat *a, const struct stat *b) {
    return a->st_dev != b->st_dev || a->st_ino != b->st_ino;
}
static void probe(const char *dir, pid_t canary, const struct stat *parent, const struct stat *host) {
    DIR *tasks = opendir("/proc/self/task"); int count = 0;
    if (!tasks) blocked("task_count");
    struct dirent *entry; errno = 0;
    while ((entry = readdir(tasks))) if (entry->d_name[0] != '.') count++;
    int err = errno; closedir(tasks);
    if (err || count != 1) blocked("single_thread");
    if (unshare(CLONE_NEWNS)) blocked("unshare");
    struct stat ns;
    if (stat("/proc/self/ns/mnt", &ns)) blocked("namespace_stat");
    record("namespace parent=%llu host=%llu child=%llu single_thread=%d\n", (unsigned long long)parent->st_ino, (unsigned long long)host->st_ino, (unsigned long long)ns.st_ino, count);
    if (!namespace_different(&ns, parent) || !namespace_different(&ns, host)) blocked("namespace_independence");
    if (!mount_check("/proc", 0, 0)) blocked("pre_private_mountinfo");
    /* This is the only propagation mutation, after proving namespace separation. */
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL)) blocked("make_private");
    if (!mount_check("/proc", 1, 0)) blocked("pre_mount_propagation");
    if (mount("proc", dir, "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, "hidepid=4")) blocked("procfs_mount");
    if (!mount_check(dir, 1, 1)) blocked("post_mount_verification");
    record("ENVIRONMENT=PASS\n");
    identity();
    DIR *d = opendir(dir); if (!d) blocked("procfs_readdir");
    char pid[32]; snprintf(pid, sizeof(pid), "%d", canary);
    int seen = 0; errno = 0;
    while ((entry = readdir(d))) if (!strcmp(entry->d_name, pid)) seen = 1;
    err = errno; closedir(d);
    record("canary readdir seen=%d errno=%d\n", seen, err);
    int hidden = !seen && !err;
    const char *suffix[] = {"", "/root", "/fd", "/fd/0"};
    for (int i = 0; i < 4; i++) {
        char path[4096]; snprintf(path, sizeof(path), "%s/%d%s", dir, canary, suffix[i]);
        struct stat st; errno = 0; int rc = stat(path, &st); err = rc ? errno : 0;
        record("canary stat suffix=%s rc=%d errno=%d\n", suffix[i], rc, err);
        hidden &= rc == -1 && err == ENOENT;
        if (!i) continue;
        errno = 0; int fd = open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK); err = fd < 0 ? errno : 0;
        record("canary open suffix=%s rc=%d errno=%d\n", suffix[i], fd < 0 ? -1 : 0, err);
        hidden &= fd < 0 && err == ENOENT;
        if (fd >= 0) close(fd);
    }
    record("HIDEPID4=%s\n", hidden ? "PASS" : "FAIL");
    _exit(hidden ? 0 : 1);
}
static void child_setup(pid_t parent, int index) {
    out = &reports[index];
    if (prctl(PR_SET_PDEATHSIG, SIGKILL) || getppid() != parent) _exit(3);
    alarm(15);
}
static int reap(pid_t pid) {
    int status;
    for (int i = 0; i < 1000; i++) {
        pid_t rc = waitpid(pid, &status, WNOHANG);
        if (rc == pid) return WIFEXITED(status) ? WEXITSTATUS(status) : 3;
        if (rc < 0 && errno != EINTR) return 3;
        usleep(10000);
    }
    /* Only our unreaped direct child can still own this PID. No namespace process can fork. */
    kill(pid, SIGKILL);
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
    return 3;
}
int main(int argc, char **argv) {
    if (argc == 2 && !strcmp(argv[1], "--self-test")) {
        assert(option("rw,hidepid=4,gid=0", "hidepid=4"));
        assert(!option("rw,hidepid=40", "hidepid=4"));
        assert(private_line("1 0 0:1 / / rw - rootfs rootfs rw\n"));
        assert(!private_line("1 0 0:1 / / rw shared:1 - rootfs rootfs rw\n"));
        assert(!private_line("1 0 0:1 / / rw master:1 - rootfs rootfs rw\n"));
        assert(!private_line("1 0 0:1 / / rw propagate_from:1 - rootfs rootfs rw\n"));
        assert(!private_line("malformed"));
        puts("SELF_TEST=PASS"); return 0;
    }
    if (argc != 1) return 2;
    setbuf(stdout, NULL);
    reports = mmap(NULL, 3 * sizeof(*reports), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (reports == MAP_FAILED) return 3;
    out = &reports[0];
    char *before = read_file("/proc/1/mountinfo"), *local = read_file("/proc/self/mountinfo");
    char *enforce = read_file("/sys/fs/selinux/enforce");
    struct stat parent_ns, host_ns;
    if (!before || !local || !enforce || strcmp(enforce, "1") || stat("/proc/self/ns/mnt", &parent_ns) ||
        stat("/proc/1/ns/mnt", &host_ns) || !mount_check("/proc", 0, 0)) {
        puts("BLOCKED stage=host_baseline no_children_no_mounts"); return 3;
    }
    void *lib = dlopen("libselinux.so", RTLD_NOW);
    setcon_fn = lib ? dlsym(lib, "setcon") : NULL;
    char dir[] = "/dev/ssal-procfs-XXXXXX";
    if (!setcon_fn || !mkdtemp(dir) || chmod(dir, 0755)) { puts("BLOCKED stage=setup"); return 3; }
    pid_t owner = getpid(), canary = fork(), child = -1;
    int result = 3;
    if (!canary) {
        child_setup(owner, 1);
        int fd = open("/dev/null", O_RDONLY);
        if (fd < 0 || dup2(fd, 0) < 0) blocked("canary_fd0");
        if (fd) close(fd);
        identity();
        if (prctl(PR_SET_DUMPABLE, 1)) blocked("canary_dumpable");
        record("CANARY_READY pid=%d\n", getpid());
        __atomic_store_n(&out->ready, 1, __ATOMIC_RELEASE);
        for (;;) pause();
    }
    if (canary > 0) {
        for (int i = 0; i < 200 && !__atomic_load_n(&reports[1].ready, __ATOMIC_ACQUIRE); i++) usleep(10000);
        if (reports[1].ready) {
            child = fork();
            if (!child) { child_setup(owner, 2); probe(dir, canary, &parent_ns, &host_ns); }
            if (child > 0) result = reap(child);
        }
        siginfo_t info = {0};
        if (waitid(P_PID, canary, &info, WEXITED | WNOHANG | WNOWAIT) || info.si_pid) {
            puts("BLOCKED stage=canary_not_alive_at_completion"); result = 3;
        }
        /* Canary is an owned, unreaped child; never target an existing Host service. */
        kill(canary, SIGKILL); reap(canary);
    }
    for (int i = 0; i < 3; i++) printf("REPORT_%d\n%s", i, reports[i].text);
    printf("CHILDREN_REAPED probe=%d canary=%d\n", child, canary);
    if (rmdir(dir)) { perror("temporary_directory_cleanup"); result = 3; }
    char *after = read_file("/proc/1/mountinfo"), *after_local = read_file("/proc/self/mountinfo");
    char *after_enforce = read_file("/sys/fs/selinux/enforce");
    out = &reports[0];
    int unchanged = after && after_local && after_enforce && !strcmp(before, after) &&
        !strcmp(local, after_local) && !strcmp(enforce, after_enforce) && mount_check("/proc", 0, 0);
    printf("HOST_STATE=%s init_mountinfo=%s supervisor_mountinfo=%s enforcing=%s\n", unchanged ? "UNCHANGED" : "FAIL",
        after && !strcmp(before, after) ? "SAME" : "FAIL", after_local && !strcmp(local, after_local) ? "SAME" : "FAIL",
        after_enforce && !strcmp(after_enforce, "1") ? "YES" : "FAIL");
    printf("PROBE_RESULT=%s exit=%d\n", result == 3 ? "BLOCKED" : result ? "FAIL" : "COMPLETE", result);
    return unchanged ? result : 4;
}
