#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/memfd.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/system_properties.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define ASHMEM_GET_SIZE _IO(0x77, 4)

static void result(const char *operation, long value) {
    int error = value < 0 ? errno : 0;
    printf("%s result=%ld errno=%d (%s)\n", operation, value, error, strerror(error));
}

static void path_probe(const char *path) {
    struct stat st;
    errno = 0;
    int rc = stat(path, &st);
    result(path, rc);
    if (!rc) printf("device mode=%o uid=%u gid=%u rdev=%llu\n", st.st_mode,
                    st.st_uid, st.st_gid, (unsigned long long)st.st_rdev);
    errno = 0;
    int fd = open(path, O_RDWR | O_CLOEXEC);
    result("open(O_RDWR|O_CLOEXEC)", fd);
    if (fd >= 0) close(fd);
}

int main(int argc, char **argv) {
    setbuf(stdout, NULL);
    char value[PROP_VALUE_MAX];
    const char *keys[] = {"ro.treble.enabled", "sys.use_memfd"};
    for (unsigned i = 0; i < sizeof(keys) / sizeof(keys[0]); ++i) {
        __system_property_get(keys[i], value);
        printf("property %s=%s\n", keys[i], value);
    }
    char context[256] = {0};
    int attr = open("/proc/self/attr/current", O_RDONLY | O_CLOEXEC);
    assert(attr >= 0);
    assert(read(attr, context, sizeof(context) - 1) > 0);
    close(attr);
    printf("context=%s uid=%u\n", context, getuid());
    char boot[80] = {0}, path[128];
    int proc = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC);
    assert(proc >= 0);
    assert(read(proc, boot, sizeof(boot) - 1) > 0);
    close(proc);
    boot[strcspn(boot, "\n")] = 0;
    snprintf(path, sizeof(path), "/dev/ashmem%s", boot);
    path_probe("/dev/ashmem");
    path_probe(path);

    int memfd = syscall(__NR_memfd_create, "ssal-kernel-check", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    result("memfd_create", memfd);
    if (memfd >= 0) {
        result("F_SEAL_FUTURE_WRITE", fcntl(memfd, F_ADD_SEALS, F_SEAL_FUTURE_WRITE));
        result("ftruncate", ftruncate(memfd, getpagesize()));
        result("memfd ASHMEM_GET_SIZE", ioctl(memfd, ASHMEM_GET_SIZE, 0));
        result("F_GET_SEALS", fcntl(memfd, F_GET_SEALS));
        close(memfd);
    }
    if (argc == 2 && strcmp(argv[1], "--kernel-only") == 0) return 0;

    void *lib = dlopen("libcutils.so", RTLD_NOW);
    if (!lib) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 1; }
    int (*create)(const char *, size_t) = dlsym(lib, "ashmem_create_region");
    int (*protect)(int, int) = dlsym(lib, "ashmem_set_prot_region");
    int (*size)(int) = dlsym(lib, "ashmem_get_size_region");
    _Bool (*supported)(void) = dlsym(lib, "_Z17has_memfd_supportv");
    assert(create && protect && size);
    assert(supported);
    printf("libcutils has_memfd_support=%d\n", supported());
    int fd = create("ApplicationSharedMemory-ssal-probe", getpagesize());
    result("libcutils ashmem_create_region", fd);
    if (fd < 0) { puts("SSAL_ASHMEM_MEMORY=FAIL"); dlclose(lib); return 0; }
    assert(size(fd) == getpagesize());
    char *shared = mmap(NULL, getpagesize(), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    assert(shared != MAP_FAILED);
    strcpy(shared, "parent");
    pid_t child = fork();
    assert(child >= 0);
    if (!child) {
        assert(munmap(shared, getpagesize()) == 0);
        char *received = mmap(NULL, getpagesize(), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        assert(received != MAP_FAILED && strcmp(received, "parent") == 0);
        strcpy(received, "child");
        assert(munmap(received, getpagesize()) == 0);
        close(fd);
        _exit(0);
    }
    int status;
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    assert(strcmp(shared, "child") == 0);
    assert(protect(fd, PROT_READ) == 0);
    errno = 0;
    void *write_map = mmap(NULL, getpagesize(), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    assert(write_map == MAP_FAILED && (errno == EPERM || errno == EACCES));
    char *readonly = mmap(NULL, getpagesize(), PROT_READ, MAP_SHARED, fd, 0);
    assert(readonly != MAP_FAILED && strcmp(readonly, "child") == 0);
    assert(munmap(readonly, getpagesize()) == 0);
    assert(munmap(shared, getpagesize()) == 0);
    close(fd);
    dlclose(lib);
    puts("SSAL_ASHMEM_MEMORY=PASS create=PASS mmap=PASS fork_share=PASS protect=PASS");
    return 0;
}
