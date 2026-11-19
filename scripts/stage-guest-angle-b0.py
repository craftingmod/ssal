#!/usr/bin/env python3
"""Stage an ANGLE or Vulkan loader probe root without mounting the GSI."""

import argparse
import os
from pathlib import Path
import re
import runpy
import shutil
import subprocess
import tempfile
import zipfile


image_tools = runpy.run_path(str(Path(__file__).with_name("probe-guest-graphics-image.py")))
dump = image_tools["dump"]
entries = image_tools["entries"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path)
    parser.add_argument("probe", type=Path)
    parser.add_argument("root", type=Path, help="new directory for the probe root")
    parser.add_argument("--vulkan-only", action="store_true", help="stage B0.1 without ANGLE")
    args = parser.parse_args()
    args.root.mkdir()
    system = args.root / "system/lib64"
    system.mkdir(parents=True)
    runtime = args.root / "apex/com.android.runtime"
    bionic = runtime / "lib64/bionic"
    bionic.mkdir(parents=True)
    linker = runtime / "bin/linker64"
    linker.parent.mkdir()
    probe = args.root / ("system/bin/ssal-vulkan-b01" if args.vulkan_only else "b0")
    probe.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(args.probe, probe)
    probe.chmod(0o755)

    with tempfile.TemporaryDirectory() as scratch:
        apex = Path(scratch) / "runtime.apex"
        payload = Path(scratch) / "apex_payload.img"
        dump(args.image, "/system/apex/com.android.runtime.apex", apex)
        with zipfile.ZipFile(apex) as archive:
            archive.extract(payload.name, scratch)
        dump(payload, "/bin/linker64", linker)
        linker.chmod(0o755)
        for name in entries(payload, "/lib64/bionic"):
            if name.endswith(".so"):
                dump(payload, f"/lib64/bionic/{name}", bionic / name)

    pending = [probe, linker, *sorted(bionic.glob("*.so")), system / "libvulkan.so"]
    if not args.vulkan_only:
        pending.append(system / "libEGL_angle.so")
    seen = set()
    while pending:
        elf = pending.pop()
        if elf in seen:
            continue
        seen.add(elf)
        if not elf.exists():
            dump(args.image, f"/system/lib64/{elf.name}", elf)
        dynamic = subprocess.check_output(["readelf", "-Wd", elf], text=True)
        needed = re.findall(r"\(NEEDED\).*?\[([^\]]+)\]", dynamic)
        print(f"{elf.relative_to(args.root)}: {' '.join(needed) or 'no DT_NEEDED'}")
        for name in needed:
            if name == "ld-android.so":
                continue  # Bionic's linker supplies this SONAME.
            if os.path.basename(name) != name:
                raise ValueError(f"unexpected dependency in {elf}: {name}")
            runtime_lib = bionic / name
            pending.append(runtime_lib if runtime_lib.is_file() else system / name)


if __name__ == "__main__":
    main()
