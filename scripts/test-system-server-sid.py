"""Check the pinned patch and a refused setter without touching Android policy."""
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("sid_patch", root / "scripts/patch-system-server-sid.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
runtime = (root / "out/phase7fb/source/libandroid_runtime.so").read_bytes()
seapp = (root / "out/selinux-check/2026-10-30T21-06-36-556Z-feba58ef/guest/system/etc/selinux/plat_seapp_contexts").read_bytes()
patched, contexts = module.patch(runtime, seapp)
assert len(patched) == len(runtime)
assert patched[:0x948fc] == runtime[:0x948fc]
assert patched[0x948fc + len(module.OLD):] == runtime[0x948fc + len(module.OLD):]
assert patched[0x948fc:0x948fc + len(module.FINAL)] == module.FINAL
assert b"isSystemServer=true domain=ssal_guest_ss_startup\n" in contexts
assert contexts.replace(b"isSystemServer=true domain=ssal_guest_ss_startup", b"isSystemServer=true domain=system_server_startup") == seapp
for bad_runtime, bad_seapp in [(b"bad", seapp), (runtime, b"bad")]:
    try:
        module.patch(bad_runtime, bad_seapp)
    except ValueError:
        pass
    else:
        raise AssertionError("unsupported input accepted")

with tempfile.TemporaryDirectory() as temporary:
    folder = Path(temporary)
    output = folder / "patched"
    command = ["python3", str(root / "scripts/patch-system-server-sid.py"),
               str(root / "out/phase7fb/source/libandroid_runtime.so"),
               str(root / "out/selinux-check/2026-10-30T21-06-36-556Z-feba58ef/guest/system/etc/selinux/plat_seapp_contexts"), str(output)]
    subprocess.run(command, check=True, capture_output=True)
    refused = subprocess.run(command, capture_output=True)
    assert refused.returncode != 0
    assert (output / "libandroid_runtime.so").read_bytes() == patched
    assert (output / "plat_seapp_contexts").read_bytes() == contexts
    mock = folder / "mock.c"
    mock.write_text('''
#include <errno.h>
#include <stdlib.h>
#include <string.h>
int setcon(const char *context) {
    if (getenv("SSAL_TEST_CANARY") && !strcmp(context, "u:r:system_server:s0")) return 0;
    if (!strcmp(context, "u:r:ssal_guest_probe:s0")) return 0;
    if (!strcmp(context, "u:r:ssal_guest_ss_startup:s0")) {
        if (getenv("SSAL_TEST_STARTUP_FAIL")) { errno = EACCES; return -1; }
        return 0;
    }
    if (!strcmp(context, "u:r:ssal_guest_ss:s0")) { errno = EINVAL; return -1; }
    abort();
}
''')
    for source, name, flags in [
        (mock, "libselinux.so", ["-shared", "-fPIC"]),
        (root / "native/binder-probe/guest-system-server-sid.c", "probe", []),
    ]:
        subprocess.run(["cc", "-Wall", "-Wextra", "-Werror", *flags, str(source), "-ldl", "-o", str(folder / name)], check=True)
    run = subprocess.run([str(folder / "probe")], env=dict(os.environ, LD_LIBRARY_PATH=str(folder)), capture_output=True, text=True)
    assert run.returncode == 1, run.stdout + run.stderr
    assert "startup=u:r:ssal_guest_ss_startup:s0 result=0 errno=0" in run.stdout
    assert "target=u:r:ssal_guest_ss:s0 called=1 result=-1 errno=22" in run.stdout
    assert "reaped=1 status=256" in run.stdout
    assert "canary=NOT_RUN forkSystemServer=NOT_RUN" in run.stdout
    invalid = subprocess.run([str(folder / "probe"), "--invalid"], capture_output=True)
    assert invalid.returncode == 2
    failed_boundary = subprocess.run([str(folder / "probe"), "--boundary"],
        env=dict(os.environ, LD_LIBRARY_PATH=str(folder), SSAL_TEST_CANARY="1"), capture_output=True, text=True)
    assert failed_boundary.returncode in (1, 2), failed_boundary.stdout + failed_boundary.stderr
    assert "owned_canary=" in failed_boundary.stdout and "reaped=1" in failed_boundary.stdout
    assert "boundary signal0" not in failed_boundary.stdout
    failed_startup = subprocess.run([str(folder / "probe")],
        env=dict(os.environ, LD_LIBRARY_PATH=str(folder), SSAL_TEST_STARTUP_FAIL="1"), capture_output=True, text=True)
    assert failed_startup.returncode == 1
    assert "startup=u:r:ssal_guest_ss_startup:s0 result=-1 errno=13" in failed_startup.stdout
    assert "target=u:r:ssal_guest_ss:s0 called=0" in failed_startup.stdout
print("PASS: pinned patch, unchanged code, input rejection, setter failure and child reap")
