#!/usr/bin/env python3
"""Read-only Experiment B inventory for a raw ext4 GSI. No Android code runs."""

import argparse
import hashlib
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
import zipfile


GRAPHICS = re.compile(r"egl|gles|angle|swiftshader|pastel|gralloc|graphics[._-](?:allocator|mapper)|vulkan", re.I)
MARKERS = re.compile(
    rb"swiftshader|pastel|vulkan\.([a-z0-9_-]+)\.so|ro\.hardware\.(?:egl|vulkan)|"
    rb"AIMapper_loadIMapper|AHardwareBuffer_(?:allocate|lock|unlock|release|sendHandleToUnixSocket|"
    rb"recvHandleFromUnixSocket)|AServiceManager_openDeclaredPassthroughHal|"
    rb"EGL_ANDROID_(?:get_native_client_buffer|image_native_buffer|native_fence_sync)|"
    rb"VK_ANDROID_external_memory_android_hardware_buffer|"
    rb"VK_EXTERNAL_SEMAPHORE_HANDLE_TYPE_SYNC_FD_BIT",
    re.I,
)
EXTRA_ELFS = {"libandroid.so", "libui.so", "libgraphicsenv.so"}
PARTITIONS = ("/system", "/system/system_ext", "/system/product", "/system/vendor",
              "/vendor", "/vendor/odm", "/odm", "/system/odm")
APEX_ROOTS = ("bin", "bin/hw", "lib", "lib/hw", "lib/egl", "lib64", "lib64/hw",
              "lib64/egl", "etc/vulkan", "etc/init")


def debugfs(image, request, *, optional=False):
    result = subprocess.run(["debugfs", "-R", request, image], capture_output=True, check=True)
    diagnostic = result.stderr.decode(errors="replace").splitlines()[1:]
    if optional and len(diagnostic) == 1 and "File not found by ext2_lookup" in diagnostic[0]:
        return None
    if optional and len(diagnostic) == 1 and "Ext2 inode is not a directory" in diagnostic[0]:
        print(f"SKIP {request}: inode is not a directory (may be a partition symlink)")
        return None
    if diagnostic:
        raise RuntimeError(f"{image}: {request}: {'; '.join(diagnostic)}")
    return result.stdout


def entries(image, directory):
    data = debugfs(image, f"ls -p {directory}", optional=True)
    if data is None:
        return {}
    listing = {}
    for line in data.decode().splitlines():
        if line:
            _, _, mode, _, _, name, _, _ = line.split("/")
            if name not in {".", ".."}:
                listing[name] = int(mode, 8)
    return listing


def dump(image, path, output):
    debugfs(image, f"dump \"{path}\" \"{output}\"")


def inspect_elf(image, path, scratch):
    dump(image, path, scratch)
    data = scratch.read_bytes()
    if not data.startswith(b"\x7fELF"):
        return
    result = subprocess.run(["readelf", "-Whdn", scratch], capture_output=True, text=True, check=True)
    for line in result.stdout.splitlines():
        if re.search(r"Class:|Machine:|Build ID:|\((NEEDED|SONAME|RPATH|RUNPATH)\)", line):
            print(f"  {line.strip()}")
    markers = sorted({match.group().decode() for match in MARKERS.finditer(data)}, key=str.lower)
    if markers:
        print("  ELF strings (capability unverified):", ", ".join(markers))
    if Path(path).name == "libGLESv2_angle.so":
        strings = set(re.findall(rb"[ -~]{4,}", data))
        for value in sorted(strings):
            if b"swiftshader" in value.lower() and len(value) <= 160:
                print("  SwiftShader string:", value.decode())
    if Path(path).name in {"libandroid.so", "libui.so", "libEGL.so"}:
        result = subprocess.run(["readelf", "-W", "--dyn-syms", scratch],
                                capture_output=True, text=True, check=True)
        for line in result.stdout.splitlines():
            if MARKERS.search(line.encode()):
                print(f"  {line.strip()}")


def inspect_directory(image, directory, label, scratch, *, elf=False):
    listing = entries(image, directory)
    matches = [name for name in listing if GRAPHICS.search(name) or (elf and name in EXTRA_ELFS)]
    print(f"SCAN {label}{directory} entries={len(listing)} matches={len(matches)}")
    for name in sorted(matches):
        path = f"{directory}/{name}"
        mode = listing[name]
        print(f"  {label}{path} mode={mode:o}")
        if elf and mode & 0o170000 == 0o100000:
            inspect_elf(image, path, scratch)


def inspect_vintf(image, directory, label, scratch):
    listing = entries(image, directory)
    candidates = ["manifest.xml"] if "manifest.xml" in listing else []
    if listing.get("manifest", 0) & 0o170000 == 0o040000:
        candidates.extend(f"manifest/{name}" for name in entries(image, f"{directory}/manifest")
                          if name.endswith(".xml"))
    candidates.extend(name for name in listing if name.startswith("compatibility_matrix") and name.endswith(".xml"))
    for name in sorted(candidates):
        path = f"{directory}/{name}"
        dump(image, path, scratch)
        root = ET.parse(scratch).getroot()
        hals = [hal for hal in root.findall("hal")
                if (hal.findtext("name") or "").startswith("android.hardware.graphics.")]
        print(f"VINTF {label}{path} {root.tag} type={root.get('type')} graphics_hals={len(hals)}")
        for hal in hals:
            values = [re.sub(r"\s+", "", node.text or "") for node in hal.iter()
                      if node.tag in {"name", "version", "instance", "fqname"}]
            print(f"  format={hal.get('format')} optional={hal.get('optional')} {' '.join(values)}")


def copy_entry(archive_path, name, output):
    with zipfile.ZipFile(archive_path) as archive, archive.open(name) as source, output.open("wb") as target:
        shutil.copyfileobj(source, target)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path)
    parser.add_argument("--linker-config", type=Path, help="previously captured Guest ld.config.txt")
    args = parser.parse_args()
    with args.image.open("rb") as image:
        print(f"GSI sha256={hashlib.file_digest(image, 'sha256').hexdigest()} bytes={args.image.stat().st_size}")
    with tempfile.TemporaryDirectory(prefix="ssal-graphics-") as tmp:
        directory = Path(tmp)
        scratch = directory / "entry"
        for partition in PARTITIONS:
            if "build.prop" in entries(args.image, partition):
                dump(args.image, f"{partition}/build.prop", scratch)
                for line in scratch.read_text().splitlines():
                    if re.match(r"ro\..*(?:fingerprint|version\.sdk|hardware\.(?:egl|vulkan)|angle)=", line):
                        print(f"PROPERTY {partition}/build.prop", line)
            for name in (*APEX_ROOTS, "app", "priv-app"):
                inspect_directory(args.image, f"{partition}/{name}", "", scratch, elf=name.startswith(("bin", "lib")))
            for name in ("etc/linker.config.pb", "etc/vulkan/icd.d", "etc/public.libraries.txt"):
                parent, basename = f"{partition}/{name}".rsplit("/", 1)
                if basename in entries(args.image, parent):
                    print("PATH", f"{parent}/{basename}")
            inspect_vintf(args.image, f"{partition}/etc/vintf", "", scratch)
            for package in sorted(entries(args.image, f"{partition}/apex")):
                if not package.endswith((".apex", ".capex")):
                    continue
                path = f"{partition}/apex/{package}"
                archive, original, payload = (directory / name for name in ("package", "original", "payload"))
                dump(args.image, path, archive)
                if package.endswith(".capex"):
                    copy_entry(archive, "original_apex", original)
                    archive = original
                copy_entry(archive, "apex_payload.img", payload)
                label = f"{path}!"
                for name in APEX_ROOTS:
                    inspect_directory(payload, f"/{name}", label, scratch, elf=name.startswith(("bin", "lib")))
                inspect_vintf(payload, "/etc/vintf", label, scratch)
        print(f"IMAGE /linkerconfig entries={len(entries(args.image, '/linkerconfig'))}")
    if args.linker_config:
        for number, line in enumerate(args.linker_config.read_text().splitlines(), 1):
            if re.match(r"^\[|^dir\.|^namespace\.(?:default|sphal)\."
                        r"(?:isolated|search\.paths|permitted\.paths|links)", line) or GRAPHICS.search(line):
                print(f"LINKER {number}: {line}")
    print("RUNTIME UNKNOWN: this inventory does not load an EGL driver or invoke a graphics HAL")


if __name__ == "__main__":
    main()
