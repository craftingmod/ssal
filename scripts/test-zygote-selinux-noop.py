"""Disposable Linux processes: verify argument, return and errno transparency."""
import os
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix="ssal-noop-") as temporary:
    directory = Path(temporary)
    def build(source, output, *flags):
        subprocess.run(["cc", "-Wall", "-Wextra", "-Werror", str(source),
                        *flags, "-ldl", "-o", str(output)], check=True)

    noop = directory / "noop.so"
    diag = directory / "diag.so"
    build(root / "native/binder-probe/zygote-selinux-noop.c", noop, "-shared", "-fPIC")
    build(root / "native/binder-probe/zygote-diagnostics.c", diag, "-shared", "-fPIC")
    mock = directory / "mock.c"
    mock.write_text(r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
static const char *expected_info, *expected_name;
static int calls;
void expect(const char *info, const char *name) { expected_info = info; expected_name = name; calls = 0; }
int count(void) { return calls; }
int selinux_android_setcontext(uid_t uid, bool server, const char *info, const char *name) {
    assert(uid == 10000 && server == (getenv("SERVER") != NULL));
    assert(info == expected_info && name == expected_name);
    assert(errno == 71); ++calls;
    errno = getenv("SUCCESS") ? 83 : EINVAL;
    return getenv("SUCCESS") ? 0 : -1;
}
int selinux_android_setcon(const char *context) {
    assert(context == expected_info); assert(errno == 72); ++calls;
    errno = getenv("SUCCESS") ? 84 : EACCES;
    return getenv("SUCCESS") ? 0 : -1;
}
''')
    build(mock, directory / "mock.so", "-shared", "-fPIC")
    runner = directory / "runner.c"
    runner.write_text(r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/types.h>
extern void expect(const char *, const char *);
extern int count(void);
extern int selinux_android_setcontext(uid_t, bool, const char *, const char *);
extern int selinux_android_setcon(const char *);
int main(void) {
    assert(getenv("LD_PRELOAD") == NULL);
    const char *info = getenv("NULL_ARGS") ? NULL : "ssal_probe";
    const char *name = getenv("NULL_ARGS") ? NULL : "ssal-fork-probe";
    expect(info, name);
    errno = 71;
    int result = selinux_android_setcontext(10000, getenv("SERVER") != NULL, info, name);
    assert(result == (getenv("SUCCESS") ? 0 : -1));
    assert(errno == (getenv("SUCCESS") ? 83 : EINVAL));
    assert(count() == 1);
    errno = 72;
    result = selinux_android_setcon(info);
    assert(result == (getenv("SUCCESS") ? 0 : -1));
    assert(errno == (getenv("SUCCESS") ? 84 : EACCES));
    assert(count() == 2);
    return 0;
}
''')
    build(runner, directory / "runner", f"-L{directory}", f"-Wl,-rpath,{directory}", "-l:mock.so")
    for success in (False, True):
        for null in (False, True):
            for server in (False, True):
                env = {**os.environ, "LD_PRELOAD": f"{noop}:{diag}",
                       "SSAL_PHASE8B3B_NOOP": "1", "SSAL_PHASE7FC_BYPASS_SETCONTEXT": "1",
                       "SSAL_TEST_CONTEXT_VALID": "1"}
                for key, value in (("SUCCESS", success), ("NULL_ARGS", null), ("SERVER", server)):
                    env.pop(key, None)
                    if value:
                        env[key] = "1"
                result = subprocess.run([str(directory / "runner")], env=env,
                                        capture_output=True, timeout=5)
                assert result.returncode == 0, result.stderr.decode()
                assert result.stderr.count(b"SSAL_SELINUX_NOOP api=") == 2
                assert b"SSAL_SETCONTEXT_BYPASS" not in result.stderr
                assert b"before=" in result.stderr and b"after=" in result.stderr
    print("PASS: 8 cases; original arguments/pointers, exactly-once calls, return/errno, legacy bypass disabled, exec environment cleared")
    runner.write_text(r'''
#define _GNU_SOURCE
#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <stdbool.h>
#include <sys/types.h>
int main(void) {
    int (*context)(uid_t, bool, const char *, const char *) = dlsym(RTLD_DEFAULT, "selinux_android_setcontext");
    int (*con)(const char *) = dlsym(RTLD_DEFAULT, "selinux_android_setcon");
    assert(context && con);
    errno = 0; assert(context(1000, true, 0, 0) == -1); assert(errno == ENOSYS);
    errno = 0; assert(con(0) == -1); assert(errno == ENOSYS);
    return 0;
}
''')
    build(runner, directory / "missing")
    result = subprocess.run([str(directory / "missing")],
                            env={**os.environ, "LD_PRELOAD": str(noop)},
                            capture_output=True, timeout=5)
    assert result.returncode == 0, result.stderr.decode()
    assert result.stderr.count(b"resolved=0") == 2
    print("PASS: missing originals return -1/ENOSYS, never fabricated success")
