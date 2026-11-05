"""Patch one pinned arm64 Guest runtime and its seapp selector; never edit inputs."""
import hashlib
from pathlib import Path
import struct
import sys

RUNTIME_SHA = "d35220026ef94be6992d8b9b31cd446f937b8e782833813b2ac68140f41fc035"
SEAPP_SHA = "7a4d14a898fb234d87cd49ae106e245324ad365d9029230d2a6306e6d4aa7a7a"
OLD = b"u:r:system_server:s0\0"
FINAL = b"u:r:ssal_guest_ss:s0\0"
STARTUP = b"ssal_guest_ss_startup"


def patch(runtime, seapp):
    if hashlib.sha256(runtime).hexdigest() != RUNTIME_SHA:
        raise ValueError("unsupported Guest libandroid_runtime.so")
    if hashlib.sha256(seapp).hexdigest() != SEAPP_SHA:
        raise ValueError("unsupported Guest plat_seapp_contexts")
    # Equal-length label keeps ELF layout and the setter/fatal path unchanged.
    assert len(OLD) == len(FINAL)
    assert runtime[0x948fc:0x948fc + len(OLD)] == OLD
    assert struct.unpack_from("<4I", runtime, 0x260dc8) == (
        0x90fff1a0, 0x9123f000, 0x94010d24, 0x34000560)
    result = bytearray(runtime)
    result[0x948fc:0x948fc + len(OLD)] = FINAL
    selector = b"isSystemServer=true domain=system_server_startup"
    assert seapp.count(selector) == 1
    contexts = seapp.replace(selector, b"isSystemServer=true domain=" + STARTUP)
    # Installed seapp_contexts has already had source neverallow checks stripped.
    return bytes(result), contexts


if __name__ == "__main__":
    runtime_path, seapp_path, output = map(Path, sys.argv[1:])
    destinations = [output / "libandroid_runtime.so", output / "plat_seapp_contexts"]
    if any(dst.exists() for dst in destinations):
        raise SystemExit("outputs must not exist; no files written")
    runtime, seapp = patch(runtime_path.read_bytes(), seapp_path.read_bytes())
    output.mkdir(parents=True, exist_ok=True)
    for path, data in zip(destinations, [runtime, seapp]):
        with path.open("xb") as stream:
            stream.write(data)
        print(f"{hashlib.sha256(data).hexdigest()}  {path}")
