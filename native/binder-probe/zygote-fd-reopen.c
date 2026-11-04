// Reattach detached JAR descriptions to this Guest's mounts before the stock FD allowlist.
#define _GNU_SOURCE
#include <assert.h>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

static int reattach(int fd, const char *path) {
    struct stat before, candidate;
    int flags = fcntl(fd, F_GETFL), fdflags = fcntl(fd, F_GETFD);
    if (flags < 0 || fdflags < 0 || (flags & O_ACCMODE) != O_RDONLY ||
        fstat(fd, &before) || (!S_ISREG(before.st_mode) &&
            !(S_ISCHR(before.st_mode) && !strcmp(path, "/dev/urandom"))) || stat(path, &candidate) ||
        before.st_dev != candidate.st_dev || before.st_ino != candidate.st_ino ||
        before.st_rdev != candidate.st_rdev) return 0;
    off_t offset = lseek(fd, 0, SEEK_CUR);
    if (offset < 0) return -1;
    int replacement = open(path, flags | O_CLOEXEC);
    if (replacement < 0) return -1;
    int result = -1;
    if (fstat(replacement, &candidate) == 0 && before.st_dev == candidate.st_dev &&
        before.st_ino == candidate.st_ino && lseek(replacement, offset, SEEK_SET) == offset &&
        // Keep ART's fdsan owner tag on the existing descriptor number.
        syscall(SYS_dup3, replacement, fd, fdflags & FD_CLOEXEC ? O_CLOEXEC : 0) == fd) result = 1;
    int error = errno;
    close(replacement);
    errno = error;
    return result;
}

static int detach_stdio_clone(int fd) {
    struct stat clone, standard;
    if (fstat(fd, &clone) || !S_ISFIFO(clone.st_mode)) return 0;
    for (int stream = 1; stream <= 2; ++stream) {
        if (fstat(stream, &standard) || clone.st_dev != standard.st_dev || clone.st_ino != standard.st_ino) continue;
        int flags = fcntl(fd, F_GETFD), nullfd = open("/dev/null", O_WRONLY | O_CLOEXEC);
        if (flags < 0 || nullfd < 0) return -1;
        int result = syscall(SYS_dup3, nullfd, fd, flags & FD_CLOEXEC ? O_CLOEXEC : 0) == fd ? 1 : -1;
        close(nullfd);
        return result;
    }
    return 0;
}

void __android_log_close(void) {
    void (*real_close)(void) = dlsym(RTLD_NEXT, "__android_log_close");
    if (real_close) real_close();
    if (!getenv("SSAL_PHASE7FB_FD_REOPEN") || getuid() != 0 || syscall(SYS_gettid) != getpid()) return;
    DIR *directory = opendir("/proc/self/fd");
    if (!directory) _exit(120);
    struct dirent *entry;
    while ((entry = readdir(directory))) {
        char *end;
        long number = strtol(entry->d_name, &end, 10);
        if (!*entry->d_name || *end || number < 3 || number > INT_MAX || number == dirfd(directory)) continue;
        int fd = (int)number;
        // Libcore clones Java stdout/stderr during preload. Keep native 1/2 pipes intact;
        // RuntimeInit closes these Java clones when it installs Android log streams in the child.
        int detached = detach_stdio_clone(fd);
        if (detached < 0) _exit(124);
        if (detached > 0) dprintf(2, "SSAL_STDIO_CLONE pid=%d fd=%d target=/dev/null native_stdout_stderr=retained\n", getpid(), fd);
        char link[64], raw[PATH_MAX], path[PATH_MAX];
        snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
        ssize_t size = readlink(link, raw, sizeof(raw) - 1);
        if (size < 0) continue;
        raw[size] = 0;
        const char *base = strrchr(raw, '/');
        const char *resources[] = {"/system/framework/framework-res.apk", "/system/framework/org.lineageos.platform-res.apk", "/system/framework/am.jar", "/dev/urandom"};
        int resource = 0;
        for (unsigned i = 0; i < sizeof(resources) / sizeof(resources[0]) && !resource; ++i) {
            if (strcmp(raw, resources[i])) {
                resource = reattach(fd, resources[i]);
                if (resource > 0) snprintf(path, sizeof(path), "%s", resources[i]);
            }
        }
        if (resource < 0) _exit(122);
        if (resource > 0) {
            dprintf(2, "SSAL_FD_REATTACH pid=%d fd=%d raw=%s guest=%s identity=same readonly=true\n", getpid(), fd, raw, path);
            continue;
        }
        if (!base || size < 4 || strcmp(raw + size - 4, ".jar")) continue;
        const char *classpath = getenv("BOOTCLASSPATH");
        char *paths = strdup(classpath ? classpath : "");
        if (!paths) _exit(121);
        char *save = NULL, *candidate = strtok_r(paths, ":", &save);
        int fixed = 0;
        while (candidate && !fixed) {
            const char *name = strrchr(candidate, '/');
            if (name && !strcmp(base, name) && strcmp(raw, candidate)) {
                fixed = reattach(fd, candidate);
                if (fixed > 0) snprintf(path, sizeof(path), "%s", candidate);
            }
            candidate = strtok_r(NULL, ":", &save);
        }
        free(paths);
        for (unsigned i = 0; i < 2 && !fixed; ++i) {
            int n = snprintf(path, sizeof(path), "%s%s", i ? "/system_ext/framework" : "/system/framework", base);
            if (n > 0 && (size_t)n < sizeof(path) && strcmp(raw, path)) fixed = reattach(fd, path);
        }
        if (fixed < 0) _exit(122);
        if (fixed > 0) {
            char actual[PATH_MAX];
            ssize_t n = readlink(link, actual, sizeof(actual) - 1);
            if (n < 0 || (size_t)n != strlen(path) || memcmp(actual, path, (size_t)n)) _exit(123);
            dprintf(2, "SSAL_FD_REATTACH pid=%d fd=%d raw=%s guest=%s identity=same readonly=true\n", getpid(), fd, raw, path);
        }
    }
    closedir(directory);
}

#ifdef SSAL_FD_TEST
int main(void) {
    char first[] = "/tmp/ssal-fd-first-XXXXXX", second[] = "/tmp/ssal-fd-second-XXXXXX";
    int writer = mkstemp(first), other = mkstemp(second);
    assert(writer >= 0 && other >= 0 && write(writer, "abcd", 4) == 4);
    int fd = open(first, O_RDONLY | O_CLOEXEC);
    assert(fd >= 0 && lseek(fd, 2, SEEK_SET) == 2);
    assert(reattach(fd, second) == 0);
    assert(reattach(writer, first) == 0);
    assert(reattach(fd, first) == 1 && lseek(fd, 0, SEEK_CUR) == 2);
    assert(fcntl(fd, F_GETFD) & FD_CLOEXEC);
    char value; assert(read(fd, &value, 1) == 1 && value == 'c');
    close(fd); close(writer); close(other); unlink(first); unlink(second);
    int pipes[2]; assert(pipe(pipes) == 0);
    int saved = dup(1); assert(saved >= 0 && dup2(pipes[1], 1) == 1);
    int clone = fcntl(1, F_DUPFD_CLOEXEC, 0); assert(clone > 2);
    assert(detach_stdio_clone(clone) == 1);
    struct stat actual, expected; assert(fstat(clone, &actual) == 0 && stat("/dev/null", &expected) == 0);
    assert(actual.st_rdev == expected.st_rdev && S_ISCHR(actual.st_mode));
    assert(write(1, "x", 1) == 1 && read(pipes[0], &value, 1) == 1 && value == 'x');
    assert(dup2(saved, 1) == 1); close(saved); close(clone); close(pipes[0]); close(pipes[1]);
    return 0;
}
#endif
