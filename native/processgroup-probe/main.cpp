// Use the platform libc++ ABI of the unmodified Guest library, not NDK libc++.
// shortcut: pinned Guest libc++ ABI; rebuild and revalidate when the image changes.
#include <__config_site>
#undef _LIBCPP_ABI_NAMESPACE
#undef _LIBCPP_ABI_VERSION
#define _LIBCPP_ABI_NAMESPACE __1
#define _LIBCPP_ABI_VERSION 1
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <poll.h>
#include <string>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

int createProcessGroup(uid_t, pid_t, bool);
bool SetProcessProfilesCached(uid_t, pid_t, const std::vector<std::string>&);
extern "C" const char* get_cpuset_policy_profile_name(int);

static std::string read_file(const std::string& path) {
    FILE* file = fopen(path.c_str(), "re");
    if (!file) {
        printf("read path=%s ret=-1 errno=%d\n", path.c_str(), errno);
        return {};
    }
    std::string result;
    char buffer[1024];
    while (size_t n = fread(buffer, 1, sizeof(buffer), file)) result.append(buffer, n);
    if (ferror(file)) result.clear();
    fclose(file);
    return result;
}

static bool membership(pid_t pid, const char* cpu, const char* cpuset, const char* blkio,
                       const std::string& v2) {
    std::string text = read_file("/proc/" + std::to_string(pid) + "/cgroup");
    printf("membership pid=%d\n%s", pid, text.c_str());
    for (const auto& expected : {std::string(":cpu:") + cpu + "\n",
                                 std::string(":cpuset:") + cpuset + "\n",
                                 std::string(":blkio:") + blkio + "\n",
                                 std::string("0::/apps/ssal_guest") + v2 + "\n"}) {
        if (text.find(expected) == std::string::npos) {
            printf("membership_missing=%s", expected.c_str());
            return false;
        }
    }
    return true;
}

int main() {
    setbuf(stdout, nullptr);
    if (getuid() != 1000 || geteuid() != 1000) return 2;
    printf("guest_libprocessgroup uid=%d gid=%d context=%s", getuid(), getgid(),
           read_file("/proc/self/attr/current").c_str());
    const std::string original = read_file("/proc/self/cgroup");
    for (const char* path : {"/sys/fs/cgroup", "/dev/cpuctl/foreground/cgroup.procs",
                             "/dev/cpuset/foreground/cgroup.procs", "/dev/blkio/background/cgroup.procs"}) {
        errno = 0;
        int ret = access(path, W_OK);
        printf("write_access path=%s ret=%d errno=%d\n", path, ret, errno);
        if (ret) return 3;
    }
    int pipefd[2];
    if (pipe2(pipefd, O_CLOEXEC)) return 4;
    pid_t child = fork();
    if (child < 0) return 5;
    if (!child) {
        close(pipefd[1]);
        pollfd fd{pipefd[0], POLLIN | POLLHUP, 0};
        int ret;
        do { ret = poll(&fd, 1, 15000); } while (ret < 0 && errno == EINTR);
        close(pipefd[0]);
        _exit(ret > 0 ? 0 : 6);
    }
    close(pipefd[0]);
    errno = 0;
    int ret = createProcessGroup(1000, child, false);
    int saved_errno = errno;
    printf("createProcessGroup uid=1000 pid=%d memControl=false ret=%d errno=%d controller=/sys/fs/cgroup\n",
           child, ret, saved_errno);
    bool passed = ret == 0;
    std::string pid_path;
    for (const char* prefix : {"", "/system", "/apps"}) {
        std::string path = std::string("/sys/fs/cgroup") + prefix + "/uid_1000/pid_" + std::to_string(child);
        if (!access(path.c_str(), F_OK)) pid_path = std::move(path);
    }
    if (pid_path.empty()) passed = false;
    std::string relative = pid_path.empty() ? "" : pid_path.substr(strlen("/sys/fs/cgroup"));
    if (passed) {
        std::string members = read_file(pid_path + "/cgroup.procs");
        passed = members == std::to_string(child) + "\n";
        printf("created_group path=%s members=%s", pid_path.c_str(), members.c_str());
    }
    // The exact native entry used by Android Process.setProcessGroup(), without a JVM.
    for (int policy : {0, 5, -1}) {
        if (!passed) break;
        const char* profile = get_cpuset_policy_profile_name(policy < 0 ? 1 : policy);
        if (!profile) { passed = false; break; }
        errno = 0;
        std::vector<std::string> profiles;
        profiles.emplace_back(profile);
        bool ok = SetProcessProfilesCached(1000, child, profiles);
        saved_errno = errno;
        printf("setProcessGroup.native=SetProcessProfilesCached policy=%d profile=%s ret=%d errno=%d controllers=/dev/cpuctl,/dev/cpuset,/dev/blkio\n",
               policy, profile, ok, saved_errno);
        const char* group = policy == 0 ? "/ssal_guest/background" :
                            policy == 5 ? "/ssal_guest/top-app" : "/ssal_guest/foreground";
        passed = ok && membership(child, group, group,
                                   policy == 0 ? "/ssal_guest/background" : "/ssal_guest", relative);
    }
    close(pipefd[1]); // EOF, normal child exit; never send a signal.
    int status = 0;
    pid_t waited;
    do { waited = waitpid(child, &status, 0); } while (waited < 0 && errno == EINTR);
    printf("child_normal_exit pid=%d waited=%d status=%d\n", child, waited, status);
    passed = waited == child && WIFEXITED(status) && WEXITSTATUS(status) == 0 && passed;
    // These UID directories can only have been made in this fresh Guest subtree.
    for (const char* prefix : {"", "/system", "/apps"}) {
        std::string uid_path = std::string("/sys/fs/cgroup") + prefix + "/uid_1000";
        std::string path = uid_path + "/pid_" + std::to_string(child);
        for (const auto* target : {&path, &uid_path}) {
            errno = 0;
            int removed = rmdir(target->c_str());
            int error = errno;
            printf("rmdir path=%s ret=%d errno=%d\n", target->c_str(), removed, error);
            if (removed && error != ENOENT) passed = false;
        }
    }
    passed = read_file("/proc/self/cgroup") == original && passed;
    printf("guest_libprocessgroup_runtime=%s signals_sent=false\n", passed ? "PASS" : "FAIL");
    return passed ? 0 : 1;
}
