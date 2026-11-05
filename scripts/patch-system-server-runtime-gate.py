"""Derive a diagnostic-only runtime from the existing Guest SID patch."""
import hashlib
from pathlib import Path
import struct
import sys

SID_SHA = "aa9ba993930cdf961c2d2a8e5022a87fca79283688faa8135d414cf7c656a923"
OFFSET = 0x260DD4
EXIT_PLT = 0x29BF70


def patch(data):
    if hashlib.sha256(data).hexdigest() != SID_SHA:
        raise ValueError("unsupported Guest SID runtime")
    assert struct.unpack_from("<I", data, OFFSET)[0] == 0x34000560
    # Even a missing interposer cannot return from the final setter into Java.
    branch = 0x14000000 | ((EXIT_PLT - OFFSET) // 4)
    result = bytearray(data)
    struct.pack_into("<I", result, OFFSET, branch)
    assert result[:OFFSET] == data[:OFFSET] and result[OFFSET + 4:] == data[OFFSET + 4:]
    assert OFFSET + ((branch & 0x3FFFFFF) << 2) == EXIT_PLT
    return bytes(result)


if __name__ == "__main__":
    source, destination = map(Path, sys.argv[1:])
    result = patch(source.read_bytes())
    with destination.open("xb") as output:
        output.write(result)
    print(hashlib.sha256(result).hexdigest(), destination)
