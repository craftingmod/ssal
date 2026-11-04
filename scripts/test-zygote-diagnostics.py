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
