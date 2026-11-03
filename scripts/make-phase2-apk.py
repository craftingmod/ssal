#!/usr/bin/env python3
"""Generate a deterministic empty DEX APK; no Host APK or application data."""
import hashlib
import pathlib
import struct
import zipfile
import zlib


def dex():
    data = bytearray(140)
    data[:8] = b"dex\n035\0"
    struct.pack_into("<5I", data, 32, len(data), 112, 0x12345678, 0, 0)
    struct.pack_into("<I", data, 52, 112)
    struct.pack_into("<2I", data, 104, 28, 112)
    struct.pack_into("<I", data, 112, 2)
    struct.pack_into("<HHII", data, 116, 0, 0, 1, 0)
    struct.pack_into("<HHII", data, 128, 0x1000, 0, 1, 112)
    data[12:32] = hashlib.sha1(data[32:]).digest()
    struct.pack_into("<I", data, 8, zlib.adler32(data[12:]))
    return bytes(data)


if __name__ == "__main__":
    payload = dex()
    assert len(payload) == struct.unpack_from("<I", payload, 32)[0] == 140
    assert payload[12:32] == hashlib.sha1(payload[32:]).digest()
    assert struct.unpack_from("<I", payload, 8)[0] == zlib.adler32(payload[12:])
    path = pathlib.Path("out/bin/ssal-phase2.apk")
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(zipfile.ZipInfo("classes.dex", (1980, 1, 1, 0, 0, 0)), payload)
    with zipfile.ZipFile(path) as archive:
        assert archive.read("classes.dex") == payload
