#!/usr/bin/env python3
"""Build a separate, prelabelled Sysconfig ext4. Original GSI is always read-only."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess

XML_NAME = "ssal-lockscreen.xml"
LABEL = b"u:object_r:system_file:s0\0"
BASE_SHA = "7b9ba62e8b48b6e40432be949ae0858a8971175c79502550e74691222d3889ff"


def sha(path):
    with path.open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def run(args):
    result = subprocess.run([str(x) for x in args], capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError(f"{args}: {result.stderr}")
    return result.stdout


def debug(image, request, write=False):
    # The only caller of write=True passes the newly created output image.
    text = run(["debugfs", *( ["-w"] if write else []), "-R", request, image])
    return text


def entries(image, root="/system/etc/sysconfig"):
    result = {}
    def walk(directory, prefix):
        for line in debug(image, f"ls -p {directory}").splitlines():
            fields = line.split("/")
            if len(fields) < 7 or not fields[1].isdigit():
                continue
            inode, mode, uid, gid, name = fields[1:6]
            if name == "..":
                continue
            if not re.fullmatch(r"[A-Za-z0-9._-]+", name):
                raise ValueError("unsafe image member name")
            path = prefix if name == "." else f"{prefix}/{name}".lstrip("/")
            if name == "." and prefix:
                continue
            info = {"inode": int(inode), "mode": int(mode, 8), "uid": int(uid), "gid": int(gid)}
            result[path] = info
            if name != "." and stat.S_ISDIR(info["mode"]):
                walk(f"{directory}/{name}", path)
    walk(root, "")
    if "" not in result:
        raise ValueError("root inode missing")
    return result


def content(path):
    mode = path.lstat().st_mode
    if stat.S_ISLNK(mode):
        return {"symlink": os.readlink(path)}
    if stat.S_ISREG(mode):
        return {"sha256": sha(path), "size": path.stat().st_size}
    if stat.S_ISDIR(mode):
        return {"directory": True}
    raise ValueError("special file forbidden")


def build(gsi, xml, out):
    gsi = gsi.resolve(strict=True)
    out = out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    image = out / "sysconfig.ext4"
    if image.is_symlink() or image.resolve() == gsi:
        raise ValueError("output may not alias original image")
    if sha(gsi) != BASE_SHA:
        raise ValueError("GSI baseline hash changed")
    original = entries(gsi)
    if XML_NAME in original:
        raise ValueError("XML injection collision")
    extract = out / "extract"
    if extract.exists():
        raise ValueError("fresh output directory required for extraction")
    extract.mkdir()
    debug(gsi, f"rdump /system/etc/sysconfig {extract}")
    tree = extract / "sysconfig"
    labels = out / "labels"
    labels.mkdir()
    manifest = {}
    for index, (name, meta) in enumerate(sorted(original.items())):
        label_file = labels / f"{index}.bin"
        debug(gsi, f"ea_get -f {label_file} <{meta['inode']}> security.selinux")
        if not label_file.is_file() or not label_file.read_bytes().rstrip(b"\0"):
            raise ValueError("missing original SELinux xattr")
        manifest[name] = {**{k: v for k, v in meta.items() if k != "inode"}, "content": content(tree / name),
                          "context": label_file.read_bytes().rstrip(b"\0").decode(), "xattr_hex": label_file.read_bytes().hex()}
    shutil.copyfile(xml, tree / XML_NAME)
    os.chmod(tree / XML_NAME, 0o644)
    xml_label = labels / "xml.bin"
    xml_label.write_bytes(LABEL)
    manifest[XML_NAME] = {"mode": stat.S_IFREG | 0o644, "uid": 0, "gid": 0, "content": content(tree / XML_NAME),
                          "context": LABEL.rstrip(b"\0").decode(), "xattr_hex": LABEL.hex()}
    with image.open("wb") as f:
        f.truncate(8 * 1024 * 1024)
    run(["mke2fs", "-q", "-t", "ext4", "-F", "-m", "0", "-O", "^has_journal", "-d", tree, image])
    debug(image, "rmdir /lost+found", write=True)
    for index, (name, meta) in enumerate(sorted(manifest.items())):
        destination = "/" + name
        for key in ("mode", "uid", "gid"):
            value = oct(meta[key]) if key == "mode" else str(meta[key])
            # debugfs interprets 0-prefixed octal, not Python's 0o prefix.
            if key == "mode":
                value = "0" + format(meta[key], "o")
            debug(image, f"set_inode_field {destination} {key} {value}", write=True)
        label_file = labels / ("xml.bin" if name == XML_NAME else f"{list(sorted(original)).index(name)}.bin")
        debug(image, f"ea_set -f {label_file} {destination} security.selinux", write=True)
    observed = entries(image, "/")
    if set(observed) != set(manifest):
        raise ValueError("output names differ")
    verify_dir = out / "verify"
    verify_dir.mkdir()
    for index, (name, meta) in enumerate(sorted(manifest.items())):
        actual = observed[name]
        if any(actual[key] != meta[key] for key in ("mode", "uid", "gid")):
            raise ValueError(f"DAC mismatch: {name}")
        dest = verify_dir / f"{index}.xattr"
        debug(image, f"ea_get -f {dest} <{actual['inode']}> security.selinux")
        if dest.read_bytes().hex() != meta["xattr_hex"]:
            raise ValueError(f"xattr mismatch: {name}")
        if "sha256" in meta["content"]:
            dest = verify_dir / f"{index}.data"
            debug(image, f"dump <{actual['inode']}> {dest}")
            if sha(dest) != meta["content"]["sha256"]:
                raise ValueError(f"content mismatch: {name}")
        elif "symlink" in meta["content"]:
            # rdump preserves the link; lstat/content never follows its target.
            temp = verify_dir / f"links-{index}"
            temp.mkdir()
            debug(image, f"rdump / {temp}")
            if os.readlink(temp / name) != meta["content"]["symlink"]:
                raise ValueError(f"symlink mismatch: {name}")
    report = {"status": "passed", "source_sha256": BASE_SHA, "image": str(image), "image_sha256": sha(image),
              "source_original_entries": len(original) - 1, "source_symlinks": sum("symlink" in x["content"] for x in manifest.values()),
              "xml_sha256": sha(xml), "manifest": manifest, "xattr_validation": "passed (debugfs ea_get byte comparison)",
              "source_unchanged": sha(gsi) == BASE_SHA, "runtime_validation": "not_run"}
    (out.parent / "ext4-image-validation.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gsi", type=Path, required=True)
    parser.add_argument("--xml", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    result = build(args.gsi, args.xml, args.out)
    print(json.dumps({key: value for key, value in result.items() if key != "manifest"}, indent=2))

if __name__ == "__main__":
    main()