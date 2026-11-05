"""Exercise only a disposable Linux process, never Android/Host crash services."""
import os
from pathlib import Path
import resource
import signal
import subprocess
import tempfile


def no_core():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


root = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix="ssal-7b-") as temporary:
    directory = Path(temporary)
    library = directory / "diag.so"
    subprocess.run([
        "cc", "-shared", "-fPIC", "-g", "-Wall", "-Wextra", "-Werror",
        str(root / "native/binder-probe/zygote-diagnostics.c"), "-ldl", "-o", str(library),
    ], check=True)
    mock = directory / "setcontext-mock.so"
    (directory / "setcontext-mock.c").write_text(r'''#define _GNU_SOURCE
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
int getcon(char **context) {
    *context = strdup("u:r:ssal_guest_probe:s0");
    return *context ? 0 : -1;
}
int selinux_android_setcontext(uid_t uid, int server, const char *seinfo, const char *name) {
    (void)uid; (void)server; (void)seinfo; (void)name;
    errno = EINVAL;
    return -1;
}
''')
    subprocess.run([
        "cc", "-shared", "-fPIC", "-Wall", "-Wextra", "-Werror",
        str(directory / "setcontext-mock.c"), "-o", str(mock),
    ], check=True)
    runner_source = directory / "setcontext-test.c"
    runner_source.write_text(r'''#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
extern int selinux_android_setcontext(uid_t, int, const char *, const char *);
int main(int argc, char **argv) {
    if (argc != 6) return 2;
    int expected = atoi(argv[5]);
    int result = selinux_android_setcontext((uid_t)atoi(argv[1]), atoi(argv[2]), argv[3], argv[4]);
    fprintf(stderr, "MOCK_SETCONTEXT result=%d\n", result);
    return (result == 0) == expected ? 0 : 1;
}
''')
    runner = directory / "setcontext-test"
    subprocess.run([
        "cc", str(runner_source), f"-L{directory}", f"-Wl,-rpath,{directory}",
        "-l:setcontext-mock.so", "-o", str(runner),
    ], check=True)
    preload = f"{library}:{mock}"
    bypass_env = {
        **os.environ,
        "LD_PRELOAD": preload,
        "SSAL_PHASE7FC_BYPASS_SETCONTEXT": "1",
        "SSAL_TEST_CONTEXT_VALID": "1",
    }
    valid_context_no_bypass = {
        **os.environ,
        "LD_PRELOAD": preload,
        "SSAL_TEST_CONTEXT_VALID": "1",
    }
    result = subprocess.run(
        [str(runner), "10000", "0", "ssal_probe", "ssal-fork-probe", "0"],
        env=valid_context_no_bypass, capture_output=True, timeout=5,
    )
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    assert b"SSAL_SETCONTEXT_BYPASS" not in result.stderr
    invalid_context = {**bypass_env}
    invalid_context.pop("SSAL_TEST_CONTEXT_VALID")
    result = subprocess.run(
        [str(runner), "10000", "0", "ssal_probe", "ssal-fork-probe", "0"],
        env=invalid_context, capture_output=True, timeout=5,
    )
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    assert b"SSAL_SETCONTEXT_BYPASS" not in result.stderr
    result = subprocess.run(
        [str(runner), "10000", "0", "ssal_probe", "ssal-fork-probe", "1"],
        env=bypass_env, capture_output=True, timeout=5,
    )
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    assert b"SSAL_SETCONTEXT_BYPASS" in result.stderr
    result = subprocess.run(
        [str(runner), "10001", "0", "ssal_probe", "ssal-fork-probe", "0"],
        env=bypass_env, capture_output=True, timeout=5,
    )
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    assert b"SSAL_SETCONTEXT_BYPASS" not in result.stderr
    print("PASS: setcontext EINVAL bypass is valid-context, Guest-probe, UID/name/seinfo gated")
    source = directory / "abort.c"
    source.write_text('#include <stdlib.h>\n#include <stdio.h>\nint main(void) { fputs("fatal test marker\\n", stderr); abort(); }\n')
    executable = directory / "abort-test"
    subprocess.run(["cc", "-g", str(source), "-o", str(executable)], check=True)
    result = subprocess.run([str(executable)], env={**os.environ, "LD_PRELOAD": str(library)},
                            capture_output=True, timeout=5, preexec_fn=no_core)
    assert result.returncode == -signal.SIGABRT, result.returncode
    assert b"fatal test marker" in result.stderr
    assert b"SSAL_NATIVE_ABORT pid=" in result.stderr
    assert b"SSAL_NATIVE_FRAME #0" in result.stderr
    assert b"object=" in result.stderr and b"offset=" in result.stderr
    assert result.stderr.count(b"SSAL_NATIVE_FRAME") <= 64
    print("PASS: native abort marker, bounded PC frames, stderr payload, SIGABRT preserved")
    source.write_text('int main(void) { *(volatile int *)0 = 1; }\n')
    subprocess.run(["cc", "-g", "-fno-omit-frame-pointer", str(source), "-o", str(executable)], check=True)
    result = subprocess.run([str(executable)], env={**os.environ, "LD_PRELOAD": str(library)},
                            capture_output=True, timeout=5, preexec_fn=no_core)
    assert result.returncode == -signal.SIGSEGV, result.returncode
    for marker in [b"SSAL_CRASH_PID=", b"si_addr=0x0000000000000000", b"pc=", b"sp=",
                   b"stack_start=", b"frame_pc=", b"SSAL_CRASH_END=", b"/abort-test"]:
        assert marker in result.stderr, marker
    assert result.stderr.count(b"frame_pc=") <= 33
    assert len(result.stderr) < 150000
    print("PASS: SIGSEGV context, maps, bounded stack/FP chain, fatal semantics preserved")
