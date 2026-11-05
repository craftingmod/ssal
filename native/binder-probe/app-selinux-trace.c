#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <elf.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

// Guest-only diagnostic: observe libc PLT calls even when libselinux calls hidden functions.
FILE *fopen(const char *path, const char *mode) {
    int incoming = errno;
    FILE *(*real)(const char *, const char *) = dlsym(RTLD_NEXT, "fopen");
    errno = incoming;
    FILE *result = real(path, mode);
    int error = errno;
    if (strstr(path, "seapp_contexts"))
        dprintf(2, "SSAL_APP_TRACE pid=%d fopen=%s mode=%s ok=%d errno=%d\n", getpid(), path, mode, result != NULL, error);
    if (result && !strcmp(path, "/system/etc/selinux/plat_seapp_contexts")) {
        char rule[256] = {0};
        ssize_t n = pread(fileno(result), rule, sizeof(rule) - 1, 0);
        if (n > 0 && strstr(rule, "seinfo=ssal_probe"))
            dprintf(2, "SSAL_APP_TRACE pid=%d plat_rule=%s", getpid(), rule);
    }
    errno = error;
    return result;
}

ssize_t __write_chk(int fd, const void *data, size_t length, size_t size) {
    int incoming = errno;
    ssize_t (*real)(int, const void *, size_t, size_t) = dlsym(RTLD_NEXT, "__write_chk");
    char link[64], path[256];
    snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
    ssize_t n = readlink(link, path, sizeof(path) - 1);
    if (n >= 0) path[n] = 0; else path[0] = 0;
    errno = incoming;
    ssize_t result = real(fd, data, length, size);
    int error = errno;
    if (strstr(path, "selinux/context") || strstr(path, "attr/current"))
        dprintf(2, "SSAL_APP_TRACE pid=%d write=%s context=%.*s length=%zu result=%zd errno=%d\n",
                getpid(), path, (int)length, (const char *)data, length, result, error);
    errno = error;
    return result;
}

int setcon(const char *context) {
    int incoming = errno;
    int (*real)(const char *) = dlsym(RTLD_NEXT, "setcon");
    errno = incoming;
    int result = real(context), error = errno;
    dprintf(2, "SSAL_APP_TRACE pid=%d setcon=%s result=%d errno=%d\n", getpid(), context, result, error);
    errno = error;
    return result;
}

// Reuse the transparent API wrapper and exec-preload cleanup.
#include "zygote-selinux-noop.c"

#ifdef SSAL_APP_PROBE
int main(void) {
    if ((getuid() != 0 && getuid() != 1000 && getuid() != 10000) || getgid() != getuid()) return 2;
    dprintf(2, "SSAL_APP_PROBE credentials uid=%d gid=%d\n", getuid(), getgid());
    FILE *status = fopen("/proc/self/status", "re");
    if (!status) return 2;
    char line[256];
    while (fgets(line, sizeof(line), status))
        if (!strncmp(line, "Cap", 3)) dprintf(2, "SSAL_APP_PROBE %s", line);
    fclose(status);
    void *lib = dlopen("libselinux.so", RTLD_NOW | RTLD_GLOBAL);
    int (*api)(uid_t, bool, const char *, const char *) = lib ? dlsym(lib, "selinux_android_setcontext") : NULL;
    Dl_info info;
    if (!api || !dladdr(api, &info)) return 2;
    uintptr_t base = (uintptr_t)info.dli_fbase;
    const unsigned char build_id[] = {0x72,0x88,0xc5,0xfc,0x0e,0xb3,0x40,0x82,0x20,0xb5,0x89,0x3e,0x7d,0x0e,0x2b,0x89};
    Elf64_Ehdr *elf = (void *)base;
    Elf64_Phdr *headers = (void *)(base + elf->e_phoff);
    bool supported = false;
    for (size_t i = 0; i < elf->e_phnum; ++i) {
        if (headers[i].p_type != PT_NOTE) continue;
        uintptr_t end = base + headers[i].p_vaddr + headers[i].p_memsz;
        for (uintptr_t p = base + headers[i].p_vaddr; p + sizeof(Elf64_Nhdr) <= end;) {
            Elf64_Nhdr *note = (void *)p;
            uintptr_t desc = p + sizeof(*note) + ((note->n_namesz + 3) & ~3u);
            if (desc + note->n_descsz > end) return 2;
            if (note->n_type == NT_GNU_BUILD_ID && note->n_namesz == 4
                && !memcmp((void *)(p + sizeof(*note)), "GNU", 4)
                && note->n_descsz == sizeof(build_id) && !memcmp((void *)desc, build_id, sizeof(build_id))) supported = true;
            p = desc + ((note->n_descsz + 3) & ~3u);
        }
    }
    if (!supported) return 2;
    dprintf(2, "SSAL_APP_PROBE library=%s build_id=7288c5fc0eb3408220b5893e7d0e2b89\n", info.dli_fname);
    // shortcut: offsets are for build 7288c5fc0eb3408220b5893e7d0e2b89 only; rederive for another GSI.
    const struct { size_t offset; uint32_t instruction; } checks[] = {
        {0x169ac, 0xd10183ff}, {0xa424, 0xa9ba7bfd}, {0xd664, 0xa9bc7bfd},
        {0xd854, 0xa9be7bfd}, {0xd0f0, 0xa9bd7bfd}, {0xd7d0, 0xb4000400},
        {0x16a98, 0x97ffce63},
#ifdef SSAL_APP_FIXED
        {0x16abc, 0xf94003e1},
#else
        {0x16abc, 0x97ffd98d},
#endif
        {0x16ad8, 0x94000632},
    };
    for (size_t i = 0; i < sizeof(checks)/sizeof(checks[0]); ++i) {
        uint32_t actual = *(uint32_t *)(base + checks[i].offset);
        if (actual != checks[i].instruction) {
            dprintf(2, "SSAL_APP_PROBE unsupported offset=%zx actual=%08x\n", checks[i].offset, actual);
            return 2;
        }
    }
    void *(*make)(const char *) = (void *)(base + 0xd664);
    const char *(*string)(void *) = (void *)(base + 0xd854);
    void (*destroy)(void *) = (void *)(base + 0xd7d0);
    int (*lookup)(int, uid_t, bool, const char *, const char *, void *) = (void *)(base + 0xa424);
    int (*check)(const char *) = (void *)(base + 0xd0f0);
    char before[512];
    sid(before, sizeof(before));
    const char *samples[] = {before, "u:r:system_server_startup:s0"};
    for (size_t i = 0; i < sizeof(samples)/sizeof(samples[0]); ++i) {
        for (size_t nul = 0; nul <= 1; ++nul) {
            int fd = open("/sys/fs/selinux/context", O_RDWR | O_CLOEXEC);
            if (fd < 0) return 2;
            errno = 0;
            size_t length = strlen(samples[i]) + nul;
            ssize_t written = write(fd, samples[i], length);
            int saved = errno;
            char canonical[512] = {0};
            ssize_t got = written < 0 ? -1 : read(fd, canonical, sizeof(canonical) - 1);
            dprintf(2, "SSAL_APP_PROBE context_matrix context=%s nul=%zu length=%zu write=%zd errno=%d read=%zd canonical=%s\n",
                    samples[i], nul, length, written, saved, got, canonical);
            close(fd);
            bool invalid = i == 0 && getuid() >= 10000;
            if (invalid ? (written != -1 || saved != EINVAL)
                        : (written != (ssize_t)length || got <= 0 || strcmp(canonical, samples[i]))) return 2;
        }
    }
    void *context = make(before);
    if (!context) return 2;
    errno = 0;
    int result = lookup(1, 10000, false, "ssal_probe", "ssal-fork-probe", context);
    int error = errno;
    dprintf(2, "SSAL_APP_PROBE lookup result=%d errno=%d before=%s target=%s\n", result, error, before, string(context));
    if (result != 0 || strcmp(string(context), before)) return 2;
    if (result == 0) {
        errno = 0;
        result = check(string(context)); error = errno;
        dprintf(2, "SSAL_APP_PROBE security_check_context result=%d errno=%d\n", result, error);
        if (getuid() >= 10000 ? (result != -1 || error != EINVAL) : result != 0) return 2;
    }
    destroy(context);
    errno = 0;
    result = api(10000, false, "ssal_probe", "ssal-fork-probe"); error = errno;
    dprintf(2, "SSAL_APP_PROBE original_api result=%d errno=%d\n", result, error);
#ifdef SSAL_APP_FIXED
    if (result != 0) return 2;
    errno = 0;
    result = api(10000, false, "ssal_missing_probe", "ssal-fork-probe"); error = errno;
    dprintf(2, "SSAL_APP_PROBE unmatched_api result=%d errno=%d\n", result, error);
    if (result != -1) return 2;
#else
    if (getuid() >= 10000 ? (result != -1 || error != EINVAL) : result != 0) return 2;
#endif
    sid(before, sizeof(before));
    dprintf(2, "SSAL_APP_PROBE after=%s\n", before);
    return 0;
}
#endif
