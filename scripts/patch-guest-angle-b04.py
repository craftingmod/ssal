#!/usr/bin/env python3
"""Write a B0.4 diagnostic copy of the exact ANGLE ELF from the B0.3 GSI."""

import argparse
import hashlib
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("original", type=Path)
    parser.add_argument("diagnostic", type=Path)
    args = parser.parse_args()
    original = args.original.read_bytes()
    digest = hashlib.sha256(original).hexdigest()
    if digest != "9114d0748ef743a1d3c4aecf5a51e17cebdec869e369ac3661ba5781af5954fb":
        parser.error(f"unexpected original ANGLE SHA-256: {digest}")

    # Always take the existing cache-clear branch in initSupportedSurfaceFormatColorspaces.
    offset = 0x24A014
    if original[offset:offset + 4] != bytes.fromhex("21 2b 00 54"):
        parser.error("unexpected gate instruction")
    diagnostic = original[:offset] + bytes.fromhex("59 01 00 14") + original[offset + 4:]
    with args.diagnostic.open("xb") as output:
        output.write(diagnostic)
    print(f"{digest}  {args.original}")
    print(f"{hashlib.sha256(diagnostic).hexdigest()}  {args.diagnostic}")


if __name__ == "__main__":
    main()
