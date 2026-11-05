"""Check trace wrappers preserve pointers, sizes, results and errno."""
from pathlib import Path
import os
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory() as temporary:
    folder = Path(temporary)
    mock = folder / "mock.c"
    mock.write_text(r'''
#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <sys/types.h>
ssize_t __write_chk(int fd, const void *data, size_t n, size_t size) {
    assert(fd == 123 && !strcmp(data, "u:r:ssal_guest_probe:s0"));
    assert(n == 24 && size == (size_t)-1);
    assert(errno == 71);
    errno = 22; return -1;
}
int setcon(const char *context) {
    assert(!strcmp(context, "u:r:ssal_guest_probe:s0"));
    assert(errno == 72);
    errno = 13; return -1;
}
''')
    caller = folder / "caller.c"
    caller.write_text(r'''
#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <sys/types.h>
int main(void) {
    ssize_t (*writer)(int, const void *, size_t, size_t) = dlsym(RTLD_DEFAULT, "__write_chk");
    int (*setter)(const char *) = dlsym(RTLD_DEFAULT, "setcon");
    assert(writer && setter);
    errno = 71;
    assert(writer(123, "u:r:ssal_guest_probe:s0", 24, (size_t)-1) == -1 && errno == 22);
    errno = 72;
    assert(setter("u:r:ssal_guest_probe:s0") == -1 && errno == 13);
    errno = 0;
    assert(!fopen("/ssal-missing-seapp_contexts", "re") && errno == 2);
    return 0;
}
''')
    for source, name, flags in [
        (root / "native/binder-probe/app-selinux-trace.c", "trace.so", ["-shared", "-fPIC"]),
        (mock, "mock.so", ["-shared", "-fPIC"]),
        (caller, "caller", []),
    ]:
        subprocess.run(["cc", "-Wall", "-Wextra", "-Werror", *flags, str(source),
                        "-ldl", "-o", str(folder / name)], check=True)
    environment = dict(os.environ, LD_PRELOAD=f"{folder}/trace.so:{folder}/mock.so")
    subprocess.run([str(folder / "caller")], env=environment, check=True)
print("PASS: trace wrappers preserve context, length, failure result and errno")
