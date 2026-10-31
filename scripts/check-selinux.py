#!/usr/bin/env python3
"""Offline analysis of exported policy artifacts; never loads a policy."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
import tarfile

import setools

PARTITIONS = ("system", "system_ext", "product", "vendor", "odm")


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def run(argv):
    result = subprocess.run([str(a) for a in argv], capture_output=True, text=True, timeout=180)
    return {"command": [str(a) for a in argv], "exit_code": result.returncode,
            "stdout": result.stdout, "stderr": result.stderr}


def save(path, value):
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n")


def policy_info(path):
    policy = setools.SELinuxPolicy(str(path))
    types = list(policy.types())
    return {"path": str(path), "sha256": digest(path), "version": policy.version,
            "type_count": len(types), "allow_count": policy.allow_count,
            "permissive_domains": sorted(str(t) for t in types if t.ispermissive),
            "types": sorted(str(t) for t in types)}


def prepare(folder, image):
    host = folder / "host"
    host.mkdir()
    # Only copy regular files from the five exported policy trees. Do not follow
    # archive symlinks or preserve device ownership/permissions on the workstation.
    with tarfile.open(folder / "host-selinux.tar") as archive:
        for entry in archive:
            parts = Path(entry.name).parts
            if len(parts) < 3 or parts[0] not in PARTITIONS or parts[1:3] != ("etc", "selinux") or ".." in parts:
                raise ValueError(f"Unexpected archive path: {entry.name}")
            if entry.isfile():
                target = host / entry.name
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.extractfile(entry) as source, target.open("wb") as output:
                    import shutil
                    shutil.copyfileobj(source, output)
    guest = folder / "guest"
    extraction = []
    for partition in ("system", "system_ext", "product"):
        parent = guest / partition / "etc"
        parent.mkdir(parents=True)
        candidates = ["/system/etc/selinux", "/etc/selinux"] if partition == "system" else [
            f"/system/{partition}/etc/selinux", f"/{partition}/etc/selinux"]
        for source in candidates:
            record = run(["debugfs", "-R", f"rdump {source} {parent}", image])
            extraction.append(record)
            if (parent / "selinux").is_dir() and any((parent / "selinux").iterdir()):
                break
        if partition == "system" and not (parent / "selinux/plat_sepolicy.cil").is_file():
            raise ValueError("Cannot extract Guest platform policy from raw ext4 image")
    props = run(["debugfs", "-R", "cat /system/build.prop", image])
    extraction.append(props)
    properties = {}
    for line in props["stdout"].splitlines():
        if "=" in line and not line.startswith("#"):
            key, value = line.split("=", 1)
            if key in ("ro.build.fingerprint", "ro.build.version.release", "ro.build.version.sdk", "ro.build.version.sdk_full", "ro.build.date.utc"):
                properties[key] = value
    vendor_api = (host / "vendor/etc/selinux/plat_sepolicy_vers.txt").read_text().strip()
    if not re.fullmatch(r"[0-9]+(?:\.[0-9]+)?", vendor_api):
        raise ValueError("Unexpected vendor policy API")
    genfs_file = host / "vendor/etc/selinux/genfs_labels_version.txt"
    genfs = genfs_file.read_text().strip() if genfs_file.exists() else "202404"
    if not genfs.isdecimal():
        raise ValueError("Unexpected genfs labels version")
    analyses = {}
    for name, base in (("host_reconstructed", host), ("guest_with_host_vendor", guest)):
        def policy(partition, filename):
            root = host if partition in ("vendor", "odm") else base
            return root / partition / "etc/selinux" / filename
        inputs = [policy("system", "plat_sepolicy.cil"), policy("system", f"mapping/{vendor_api}.cil")]
        mandatory = inputs + [policy("vendor", "plat_pub_versioned.cil"), policy("vendor", "vendor_sepolicy.cil")]
        missing = [str(p) for p in mandatory if not p.is_file()]
        inputs += [policy("system", f"mapping/{vendor_api}.compat.cil")]
        for partition in ("system_ext", "product"):
            inputs += [policy(partition, f"{partition}_sepolicy.cil"), policy(partition, f"mapping/{vendor_api}.cil")]
            if partition == "system_ext":
                inputs += [policy(partition, f"mapping/{vendor_api}.compat.cil")]
        inputs += [policy("vendor", "plat_pub_versioned.cil"), policy("vendor", "vendor_sepolicy.cil"),
                   policy("odm", "odm_sepolicy.cil"), policy("system", f"plat_sepolicy_genfs_{genfs}.cil")]
        inputs = [p for p in inputs if p.is_file()]
        output = folder / f"{name}.policy"
        command = ["secilc", "-m", "-M", "true", "-G", "-c", "33", *inputs, "-o", output, "-f", "/dev/null"]
        result = {"inputs": [{"path": str(p), "sha256": digest(p)} for p in inputs], "missing_inputs": missing}
        genfs_rules = {}
        for path in inputs:
            for number, line in enumerate(path.read_text().splitlines(), 1):
                match = re.match(r'^\(genfscon\s+(\S+)\s+"([^"]+)"\s+(.+)\)$', line)
                if match:
                    filesystem, target, context = match.groups()
                    genfs_rules.setdefault((filesystem, target), []).append({"path": str(path), "line": number, "context": context})
        result["genfs_same_path_differences"] = [{"filesystem": key[0], "target": key[1], "rules": rules}
                                                for key, rules in genfs_rules.items() if len({r["context"] for r in rules}) > 1]
        if not missing:
            result["strict_compile"] = run(command)
            if result["strict_compile"]["exit_code"]:
                # Android init uses -N. Record this separately; never count it as
                # successful neverallow validation or silently relax a check.
                result["init_mode_compile"] = run([*command[:1], "-N", *command[1:]])
            successful = result.get("init_mode_compile", result["strict_compile"])["exit_code"] == 0
            if successful:
                try:
                    result["policy"] = policy_info(output)
                except Exception as error:
                    result["analysis_error"] = str(error)
        analyses[name] = result
    precompiled = host / "odm/etc/selinux/precompiled_sepolicy"
    if not precompiled.is_file():
        precompiled = host / "vendor/etc/selinux/precompiled_sepolicy"
    if precompiled.is_file():
        analyses["host_precompiled"] = {"policy": policy_info(precompiled), "component_hash_matches": {}}
        for partition, prefix in (("system", "plat"), ("system_ext", "system_ext"), ("product", "product")):
            current = host / partition / f"etc/selinux/{prefix}_sepolicy_and_mapping.sha256"
            prior = Path(str(precompiled) + f".{prefix}_sepolicy_and_mapping.sha256")
            analyses["host_precompiled"]["component_hash_matches"][partition] = (
                current.read_text().strip() == prior.read_text().strip() if current.exists() and prior.exists() else None)
    inventory = {}
    context_files = []
    for partition in PARTITIONS:
        root = host if partition in ("vendor", "odm") else guest
        directory = root / partition / "etc/selinux"
        for path in sorted(directory.glob("*contexts")):
            if not path.is_file():
                continue
            context_files.append({"path": str(path), "sha256": digest(path)})
            text = path.read_text(errors="replace")
            for line in text.splitlines():
                line = line.split("#", 1)[0]
                labels = re.findall(r"u:(?:object_r|r):[A-Za-z0-9_]+:s0(?:[:][A-Za-z0-9_,.\-]+)?", line)
                if path.name.endswith("seapp_contexts"):
                    labels += [f"u:r:{name}:s0" for name in re.findall(r"\bdomain=([A-Za-z0-9_]+)", line)]
                    labels += [f"u:object_r:{name}:s0" for name in re.findall(r"\btype=([A-Za-z0-9_]+)", line)]
                for label in labels:
                    record = inventory.setdefault(label, {"files": [], "service_names": []})
                    if str(path) not in record["files"]:
                        record["files"].append(str(path))
                    if path.name.endswith("service_contexts") and not path.name.endswith(("hwservice_contexts", "vndservice_contexts", "tee_service_contexts")):
                        fields = line.split()
                        if len(fields) >= 2 and fields[1] == label:
                            record["service_names"].append(fields[0])
    contract = json.loads(Path("module/profiles/services/initial.json").read_text())
    for service in contract["services"]:
        inventory.setdefault(service["domain"], {"files": [], "service_names": []})["contract_service"] = service["name"]
    inventory.setdefault("u:object_r:ssal_image_file:s0", {"files": ["module/sepolicy.rule"], "service_names": []})
    lines = ["C\t" + label for label in sorted(inventory)]
    for label, record in sorted(inventory.items()):
        if record["service_names"]:
            for domain, perms in (("system_server", ("add", "find")), ("servicemanager", ("add", "find")), ("shell", ("find",))):
                for permission in perms:
                    lines.append(f"A\tu:r:{domain}:s0\t{label}\tservice_manager\t{permission}")
    for source in ("shell", "system_server", "servicemanager"):
        for target in ("shell", "system_server", "servicemanager"):
            for permission in ("call", "transfer"):
                lines.append(f"A\tu:r:{source}:s0\tu:r:{target}:s0\tbinder\t{permission}")
    for target, class_name, permission in (("u:r:servicemanager:s0", "process", "transition"),
                                          ("u:object_r:servicemanager_exec:s0", "file", "execute")):
        lines.append(f"A\tu:r:ksu:s0\t{target}\t{class_name}\t{permission}")
    (folder / "queries.tsv").write_text("\n".join(lines) + "\n")
    for analysis in analyses.values():
        if "policy" in analysis:
            types = set(analysis["policy"].pop("types"))
            analysis["missing_inventory_types"] = sorted({label.split(":")[2] for label in inventory if label.split(":")[2] not in types})
    report = {"schema": 1, "vendor_policy_api": vendor_api, "genfs_labels_version": genfs,
              "genfs_version_file_present": genfs_file.exists(), "guest_build": properties,
              "offline": analyses, "extraction": extraction, "context_files": context_files,
              "inventory": inventory, "query_count": len(lines),
              "scope": "Offline source reconstruction is not the current loaded kernel policy. Context checks do not validate regex matching, app signing, MLS combinations, ioctl xperms, actual exec or service registration."}
    # Debian's compiler may lack Android CIL extensions. Package only exported
    # input copies for an optional compile by the device's own compiler. Generated
    # binaries stay in the unique scratch directory and are never loaded.
    fallback = {name: a for name, a in analyses.items() if a.get("strict_compile", {}).get("exit_code", 0) and not a["missing_inputs"]}
    if fallback:
        compile_lines = ["#!/system/bin/sh", "set -u"]
        outputs = []
        with tarfile.open(folder / "device-compile-inputs.tar", "w") as archive:
            index = 0
            for name, analysis in fallback.items():
                names = []
                for item in analysis["inputs"]:
                    filename = f"input-{index:04d}.cil"
                    archive.add(item["path"], arcname=filename, recursive=False)
                    names.append(filename)
                    index += 1
                for mode, flags in (("strict", ""), ("init", "-N")):
                    prefix = f"{name}.{mode}"
                    compile_lines += [f"/system/bin/secilc -m -M true -G -c 33 {flags} {' '.join(names)} -o {prefix}.policy -f /dev/null >{prefix}.log 2>&1",
                              f"printf '%s\\n' \"$?\" >{prefix}.rc"]
                    outputs += [f"{prefix}.log", f"{prefix}.rc"]
            compile_lines += ["set -- " + " ".join(outputs),
                              'for policy in *.policy; do if [ -f "$policy" ]; then set -- "$@" "$policy"; fi; done',
                              'tar -cf results.tar "$@"']
            content = ("\n".join(compile_lines) + "\n").encode()
            info = tarfile.TarInfo("compile.sh")
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))
        report["device_compile_requested"] = list(fallback)
    save(folder / "offline.json", report)
    print(json.dumps({"queries": len(lines), "contexts": len(inventory), "compiles": {
        name: {k: v["exit_code"] for k, v in result.items() if k.endswith("compile")}
        for name, result in analyses.items()}}, indent=2))


def finish(folder):
    report = json.loads((folder / "offline.json").read_text())
    device_archive = folder / "device-compile-results.tar"
    if device_archive.exists():
        with tarfile.open(device_archive) as archive:
            for entry in archive:
                if not re.fullmatch(r"(?:host_reconstructed|guest_with_host_vendor)\.(?:strict|init)\.(?:policy|log|rc)", entry.name) or not entry.isfile():
                    raise ValueError(f"Unexpected device compiler result: {entry.name}")
                (folder / entry.name).write_bytes(archive.extractfile(entry).read())
        for name in report.get("device_compile_requested", []):
            result = report["offline"][name]
            result["device_compile"] = {}
            for mode in ("strict", "init"):
                prefix = folder / f"{name}.{mode}"
                code = int(Path(str(prefix) + ".rc").read_text().strip())
                record = {"exit_code": code, "stderr": Path(str(prefix) + ".log").read_text(), "neverallow_check": mode == "strict"}
                if not code:
                    try:
                        record["policy"] = policy_info(Path(str(prefix) + ".policy"))
                        types = set(record["policy"].pop("types"))
                        record["missing_inventory_types"] = sorted({label.split(":")[2] for label in report["inventory"] if label.split(":")[2] not in types})
                    except Exception as error:
                        record["analysis_error"] = str(error)
                result["device_compile"][mode] = record
    events = [json.loads(line) for line in (folder / "live.jsonl").read_text().splitlines() if line]
    contexts = [e for e in events if e["kind"] == "context"]
    accesses = [e for e in events if e["kind"] == "access"]
    states = [e for e in events if e["kind"] == "state"]
    expected = report["query_count"]
    if len(contexts) + len(accesses) != expected or len(states) != 2:
        raise ValueError("Incomplete live query output")
    live = {"states": states, "contexts": contexts, "access_queries": accesses,
            "invalid_contexts": [e for e in contexts if not e["valid"]],
            "service_invalid_contexts": [e for e in contexts if not e["valid"] and report["inventory"][e["label"]]["service_names"]],
            "sequence_values": sorted({e["sequence"] for e in accesses if not e["errno"]}),
            "summary": {"contexts": len(contexts), "valid": sum(e["valid"] for e in contexts),
                        "access_queries": len(accesses), "allowed": sum(e["allowed"] is True for e in accesses),
                        "denied": sum(e["allowed"] is False for e in accesses), "errors": sum(bool(e["errno"]) for e in accesses)}}
    observation = {}
    for name in ("host-observation",):
        before, after = (folder / f"{name}-before.txt").read_bytes(), (folder / f"{name}-after.txt").read_bytes()
        observation[name] = {"equal": before == after, "before_sha256": hashlib.sha256(before).hexdigest(), "after_sha256": hashlib.sha256(after).hexdigest()}
    report.update({"live": live, "observations": observation,
                   "policy_modified": False, "services_started": False, "mounts_created": False,
                   "cleanup": json.loads((folder / "cleanup.json").read_text())})
    report["overall"] = "blocked" if live["invalid_contexts"] or any(s["enforce"] != "1" or any(s["state_errno"]) for s in states) else "contexts_valid_only"
    save(folder / "report.json", report)
    print(json.dumps({"overall": report["overall"], **live["summary"],
                      "invalid_service_types": [e["label"] for e in live["service_invalid_contexts"]],
                      "observation": observation, "cleanup": report["cleanup"]}, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("prepare", "finish"))
    parser.add_argument("folder", type=Path)
    parser.add_argument("--image", type=Path)
    args = parser.parse_args()
    if args.mode == "prepare":
        if not args.image:
            parser.error("prepare requires --image")
        prepare(args.folder, args.image)
    else:
        finish(args.folder)
