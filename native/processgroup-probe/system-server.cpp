// shortcut: pinned Guest libc++ ABI, revalidate when the GSI changes.
#include <__config_site>
#undef _LIBCPP_ABI_NAMESPACE
#undef _LIBCPP_ABI_VERSION
#define _LIBCPP_ABI_NAMESPACE __1
#define _LIBCPP_ABI_VERSION 1
#include <cerrno>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <poll.h>
#include <string>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

int createProcessGroup(uid_t, pid_t, bool);
bool UsePerAppMemcg();
bool SetProcessProfilesCached(uid_t, pid_t, const std::vector<std::string>&);

static std::string read_file(const std::string& path) {
    FILE *f = fopen(path.c_str(), "re");
    if (!f) return "UNAVAILABLE";
    std::string text;
    char buf[1024];
    while (size_t n = fread(buf, 1, sizeof(buf), f)) text.append(buf, n);
    if (ferror(f)) text = "UNAVAILABLE";
    fclose(f);
    return text;
}

static bool contained_text(const std::string& text) {
    bool v2 = false;
    size_t pos = 0;
    while (pos < text.size()) {
        size_t end = text.find('\n', pos);
        auto line = text.substr(pos, end == std::string::npos ? end : end - pos);
        size_t colon = line.find(':', line.find(':') + 1);
        if (colon == std::string::npos) return false;
        auto path = line.substr(colon + 1);
        const bool bound = line.compare(0, 3, "0::") == 0 ||
            line.find(":cpu:") != std::string::npos || line.find(":cpuset:") != std::string::npos ||
            line.find(":blkio:") != std::string::npos;
        if (!bound) { pos = end == std::string::npos ? text.size() : end + 1; continue; }
        std::string prefix = line.compare(0, 3, "0::") == 0 ? "/apps/ssal_guest" : "/ssal_guest";
        if (path != prefix && path.compare(0, prefix.size() + 1, prefix + "/") != 0) return false;
        if (prefix == "/apps/ssal_guest") v2 = true;
        if (end == std::string::npos) break;
        pos = end + 1;
    }
    return v2;
}

static bool contained(pid_t pid) {
    auto text = read_file("/proc/" + std::to_string(pid) + "/cgroup");
    printf("cgroup pid=%d\n%s", pid, text.c_str());
    return contained_text(text);
}

int main(int argc, char **argv) {
    setbuf(stdout, nullptr);
    if (argc == 2 && !strcmp(argv[1], "--self-test")) {
        assert(contained_text("5:freezer:/\n4:cpuset:/ssal_guest\n0::/apps/ssal_guest/system/uid_1000/pid_2\n"));
        assert(!contained_text("0::/apps/ssal_guest2/uid_1000\n"));
        assert(!contained_text("2:cpu:/host\n0::/apps/ssal_guest\n"));
        assert(!contained_text("UNAVAILABLE"));
        puts("SSAL_SS_CGROUP_SELF_TEST=PASS");
        return 0;
    }
    if (argc != 1) return 2;
    if (getuid() != 0) return 2;
    auto limit = read_file("/sys/fs/cgroup/memory.max");
    char *end = nullptr;
    unsigned long long bytes = strtoull(limit.c_str(), &end, 10);
    if (!bytes || !end || strcmp(end, "\n")) return 3;
    printf("guest_memory_max=%llu apps=%d per_app_memcg=%d\n", bytes,
           access("/sys/fs/cgroup/apps", F_OK) == 0, UsePerAppMemcg());
    if (access("/sys/fs/cgroup/apps", F_OK)) return 4;
    bool made_system = mkdir("/sys/fs/cgroup/system", 0755) == 0;
    if (!made_system) return 5;
    int pipefd[2];
    if (pipe2(pipefd, O_CLOEXEC)) return 6;
    pid_t parent = getpid();
    pid_t child = fork();
    if (child < 0) return 7;
    if (!child) {
        close(pipefd[1]);
        if (prctl(PR_SET_PDEATHSIG, SIGKILL) || getppid() != parent ||
            setresgid(1000, 1000, 1000) || setresuid(1000, 1000, 1000)) _exit(8);
        pollfd fd{pipefd[0], POLLIN | POLLHUP, 0};
        int n;
        do { n = poll(&fd, 1, 5000); } while (n < 0 && errno == EINTR);
        _exit(n > 0 ? 0 : 9);
    }
    close(pipefd[0]);
    errno = 0;
    int rc = createProcessGroup(1000, child, false);
    printf("createProcessGroup uid=1000 pid=%d result=%d errno=%d\n", child, rc, errno);
    bool ok = rc == 0 && contained(child);
    // Test the exact profile even when UsePerAppMemcg() makes it conditional in Zygote.
    errno = 0;
    bool profile = SetProcessProfilesCached(1000, child, {"SystemMemoryProcess"});
    printf("SystemMemoryProcess result=%d errno=%d conditional_in_zygote=%d\n", profile, errno, UsePerAppMemcg());
    ok = profile && contained(child) && ok;
    printf("profile_members=%s", read_file("/sys/fs/cgroup/system/cgroup.procs").c_str());
    auto final = read_file("/proc/" + std::to_string(child) + "/cgroup");
    // GSI ignores JoinCgroup actions on v2; a true API return does not prove movement.
    printf("SystemMemoryProcess_moved_to_system=%d\n", final.find("0::/apps/ssal_guest/system\n") != std::string::npos);
    close(pipefd[1]);
    int status = 0;
    pid_t waited;
    do { waited = waitpid(child, &status, 0); } while (waited < 0 && errno == EINTR);
    ok = waited == child && WIFEXITED(status) && WEXITSTATUS(status) == 0 && ok;
    printf("diagnostic_child_reaped pid=%d status=%d\n", child, status);
    for (const char *prefix : {"", "/apps", "/system"}) {
        auto uid = std::string("/sys/fs/cgroup") + prefix + "/uid_1000";
        auto pid = uid + "/pid_" + std::to_string(child);
        for (auto *path : {&pid, &uid}) {
            int result = rmdir(path->c_str());
            printf("cleanup path=%s result=%d errno=%d\n", path->c_str(), result, result ? errno : 0);
            if (result && errno != ENOENT) ok = false;
        }
    }
    if (rmdir("/sys/fs/cgroup/system")) ok = false;
    printf("SSAL_SS_CGROUP=%s\n", ok ? "PASS" : "FAIL");
    return ok ? 0 : 1;
}
