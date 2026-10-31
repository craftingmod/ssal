#!/usr/bin/env python3
"""Offline only: never invokes adb, mounts, guest services or authentication HALs.

Run after preparing evidence described in docs/guest-lock-compat.md. Missing
evidence is blocked, never a positive result. aapt2 must match modern ARSC.
"""
import argparse
import concurrent.futures
import hashlib
import json
import re
from pathlib import Path
import shutil
import struct
import subprocess
import xml.etree.ElementTree as ET
import zipfile

ROOT = Path(__file__).resolve().parent.parent
FEATURES = {
    "android.software.secure_lock_screen",
    "android.hardware.fingerprint",
    "android.hardware.biometrics.face",
    "android.hardware.biometrics.iris",
    "android.hardware.strongbox_keystore",
    "android.hardware.device_unique_attestation",
    "android.hardware.keystore.app_attest_key",
    "android.hardware.se.omapi.ese",
    "android.hardware.nfc.ese",
    "android.software.managed_users",
    "android.software.device_admin",
}
RESOURCE = "config_disableWeaverOnUnsecuredUsers"
SOURCE = ROOT / "guest-compat/lockscreen"


def validate_xml(data):
    root = ET.fromstring(data)
    children = list(root)
    if root.tag != "permissions" or root.attrib or len(children) != len(FEATURES):
        raise ValueError("expected permissions and the required unavailable-features")
    names = []
    for item in children:
        if item.tag != "unavailable-feature" or set(item.attrib) != {"name"} or list(item):
            raise ValueError("incorrect unavailable feature")
        names.append(item.attrib["name"])
    if set(names) != FEATURES:
        raise ValueError("incorrect unavailable features")


def arsc_overlayable_count(apk):
    """Count actual RES_TABLE_OVERLAYABLE_TYPE chunks (not textual matches)."""
    with zipfile.ZipFile(apk) as archive:
        data = archive.read("resources.arsc")

    def walk(start, end):
        count = 0
        while start < end:
            if start + 8 > end:
                raise ValueError("truncated ARSC chunk")
            kind, header, size = struct.unpack_from("<HHI", data, start)
            if header < 8 or size < header or start + size > end:
                raise ValueError("invalid ARSC chunk")
            count += kind == 0x0204
            if kind in (0x0002, 0x0200):  # table and package containers
                count += walk(start + header, start + size)
            start += size
        return count
    return walk(0, len(data))


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--aapt2", required=True)
    parser.add_argument("--framework", type=Path, default=ROOT / "out/selinux-check/2026-10-31-guest-v3/framework-res.apk")
    parser.add_argument("--services", type=Path, default=ROOT / "out/selinux-check/2026-10-31-guest-v3/services.jar")
    parser.add_argument("--out", type=Path, default=ROOT / "out/guest-lock-compat")
    parser.add_argument("--test-rust", action="store_true")
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    evidence = out / "evidence"
    evidence.mkdir(exist_ok=True)
    aapt = str(Path(args.aapt2).resolve())

    def run(command):
        result = subprocess.run([str(x) for x in command], capture_output=True, text=True, cwd=ROOT)
        if result.returncode:
            raise RuntimeError(f"command failed: {command[0]}: {result.stderr[-3000:]}")
        return result.stdout

    def save(name, obj):
        (out / name).write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    def read(name):
        p = evidence / name
        return p.read_text(encoding="utf-8") if p.exists() else ""

    xml = (SOURCE / "ssal-lockscreen.xml").read_bytes()
    validate_xml(xml)
    shutil.copyfile(SOURCE / "ssal-lockscreen.xml", out / "ssal-lockscreen.xml")
    target = run([aapt, "dump", "resources", args.framework])
    (evidence / "resources.txt").write_text(target, encoding="utf-8")
    chunks = arsc_overlayable_count(args.framework)
    apk = out / "SSALWeaverOverlay-unsigned.apk"
    build = {"status": "blocked", "reason": "target resource missing"}
    if f"bool/{RESOURCE}" in target:
        run([aapt, "compile", "--dir", SOURCE / "overlay/res", "-o", out / "compiled.zip"])
        run([aapt, "link", "-o", apk, "--manifest", SOURCE / "overlay/AndroidManifest.xml", "-I", args.framework, out / "compiled.zip"])
        manifest = run([aapt, "dump", "xmltree", "--file", "AndroidManifest.xml", apk])
        values = run([aapt, "dump", "resources", apk])
        (evidence / "overlay-manifest.txt").write_text(manifest, encoding="utf-8")
        (evidence / "overlay-resources.txt").write_text(values, encoding="utf-8")
        if not ("dev.ssal.overlay.weaver" in manifest
                and re.search(r'targetPackage[^\n]*="android"', manifest)
                and re.search(r'isStatic[^\n]*=true', manifest)
                and re.search(r'hasCode[^\n]*=false', manifest)):
            raise ValueError("compiled overlay manifest mismatch")
        if f"bool/{RESOURCE}" not in values or "() true" not in values:
            raise ValueError("compiled overlay value mismatch")
        build = {"status": "passed", "apk": apk.name, "sha256": sha(apk), "signature": "unsigned; not an installable/certified release artifact"}

    def inspect_overlay(path):
        resources = run([aapt, "dump", "resources", path])
        manifest = run([aapt, "dump", "xmltree", "--file", "AndroidManifest.xml", path])
        return {"path": str(path.relative_to(evidence)), "sha256": sha(path),
                "weaver_resource_present": RESOURCE in resources,
                "ssal_package_collision": "dev.ssal.overlay.weaver" in manifest}

    overlays = list((evidence / "product-overlay").rglob("*.apk"))
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        scanned = list(pool.map(inspect_overlay, overlays))
    save("overlay-inventory.json", scanned)
    conflicts = [entry for entry in scanned if entry["weaver_resource_present"] or entry["ssal_package_collision"]]
    guest_config = read("SystemConfig-guest.java")
    fallback = read("SystemConfig-guest-fallback.java")
    ro = read("RoSystemFeatures-guest.java")
    lss_path = args.services.parent / "LockSettingsService.java"
    lss = lss_path.read_text(encoding="utf-8") if lss_path.exists() else ""
    ro_clear = "Boolean maybeHasFeature(String str, int i) {\n        return null;" in ro
    sys_checks = {
        "xml_parsing_and_feature_name": True,
        "guest_target": "/system/etc/sysconfig/ssal-lockscreen.xml",
        "system_scan_ALLOW_ALL": 'Environment.getRootDirectory(), new String[]{"etc", "sysconfig"}), -1)' in guest_config,
        "binary_parser_dispatch": '"unavailable-feature"' in fallback and "readUnavailableFeature" in fallback,
        "remove_after_all_partitions_and_environment": "readAllPermissionsFromEnvironment();\n        Iterator it = this.mUnavailableFeatures.iterator();" in guest_config,
        "readonly_feature_exception_absent_in_guest_build": ro_clear,
        "credential_guard": "if (!this.mHasSecureLockScreen && lockscreenCredential != null && lockscreenCredential.getType() != -1)" in lss,
        "token_LocalService_guard": "if (!LockSettingsService.this.mHasSecureLockScreen && lockscreenCredential.getType() != -1)" in lss,
    }
    static_ok = all(value for value in sys_checks.values())
    resource_match = re.search(r'resource (0x[0-9a-f]+) bool/' + RESOURCE + r'\s+\(\) (true|false)', target)
    image_binding_path = evidence / "image-binding.json"
    image_binding = json.loads(image_binding_path.read_text()) if image_binding_path.exists() else {"status": "not_run"}
    save("sysconfig-validation.json", {
        "status": "blocked", "static_validation": "passed" if static_ok else "blocked",
        "reason": "runtime feature removal and API rejection not_run", "checks": sys_checks,
        "xml_sha256": sha(SOURCE / "ssal-lockscreen.xml"),
        "image_binding": image_binding,
        "runtime_feature_removal": "not_run", "PackageManager_feature_list": "not_run",
        "runtime_credential_rejection": "not_run",
        "selinux": {"directory": "root:root 0755 system_file", "file": "root:root 0644 u:object_r:system_file:s0", "enforcing_access": "not_run"},
        "limits": ["SystemConfig main parser needed fallback decompilation; no execution inferred", "token guard is at LocalService entry, not every internal helper", "any later feature recomputation or runtime override requires pm list features and credential API tests"]})
    save("rro-validation.json", {
        "status": "blocked", "build": build, "target_resource_present": f"bool/{RESOURCE}" in target,
        "target_resource_id": resource_match[1] if resource_match else None,
        "target_default": resource_match[2] == "true" if resource_match else None,
        "framework_overlayable_chunk_count": chunks,
        "targetName": "omitted: actual target has no overlayable chunks" if chunks == 0 else "blocked: inspect target overlayable policy",
        "policy": "preinstalled product policy is source-supported when target has no overlayable declarations; actual fulfilled policy not_run",
        "candidate_path": "/product/overlay/SSALWeaverOverlay.apk",
        "product_config": read("product-overlay-config.txt").strip(),
        "immutable": "static manifest fallback is a candidate only while partition config/config.xml is absent; enabled immutable required even for Resources.getSystem()",
        "existing_overlays_scanned": len(scanned), "conflicts": conflicts,
        "conflict_scope": "GSI product partition only; Host vendor/odm overlays and runtime property selection not certified",
        "idmap2": "not_run: no host-native idmap2 in available build environment",
        "zygote_immutable_activation": "not_run", "system_server_effective_value": "not_run",
        "image_binding": image_binding,
        "fresh_userdata_only": True, "existing_protector_migration": "prohibited",
    })
    tests = {"status": "not_run"}
    if args.test_rust:
        result = subprocess.run(["cargo", "test", "--locked", "--lib", "--bin", "ssald"], cwd=ROOT, capture_output=True, text=True)
        (out / "rust-tests.txt").write_text(result.stdout + result.stderr, encoding="utf-8")
        tests = {"status": "passed" if result.returncode == 0 else "failed", "exit_code": result.returncode, "log": "rust-tests.txt"}
    save("mount-integration-test.json", {
        "status": "blocked", "reason": "actual mount, Enforcing and rollback not_run", "offline_tests": tests,
        "strategy": "existing private namespace; tmpfs directory projection with read-only binds preserving original inodes and symlinks; reverse Mounts cleanup",
        "enabled_default": False, "runtime_enabled_gate": "blocked unconditionally",
        "rro_mount": "blocked pending idmap/immutable certification; never silently skipped",
        "actual_mount_injection": "not_run", "Enforcing_labels": "not_run",
        "host_namespace_during_actual_mount": "not_run", "partial_mount_rollback": "not_run",
        "offline_collision_test": "existing file and dangling symlink rejected before mounts; repeated rejection; originals and local mountinfo unchanged" if args.test_rust and tests["status"] == "passed" else "not_run",
        "device_access": False, "guest_service_execution": False,
    })
    provenance = {}
    for path in [args.framework, args.services, *sorted(evidence.glob("*.java")), evidence / "framework.jar", evidence / "ResourceMapping.cpp"]:
        if path.is_file():
            provenance[str(path.relative_to(ROOT))] = sha(path)
    save("provenance.json", provenance)
    save("manifest.json", {"version": 1, "enabled": False, "launch_enabled": False,
        "sysconfig": {"path": "ssal-lockscreen.xml", "target": sys_checks["guest_target"], "sha256": sha(SOURCE / "ssal-lockscreen.xml")},
        "rro": build, "rro_validation": "blocked", "fresh_userdata_required": True})
    (out / "report.md").write_text(
        "# Guest lock compatibility — offline validation\n\n"
        f"Sysconfig static verification: {'static_verified' if static_ok else 'blocked'}. "
        f"RRO build: {build['status']} (unsigned). Rust tests: {tests['status']}.\n\n"
        "Overall runtime readiness: **blocked**; launch_enabled=false.\n\n"
        f"Scanned {len(scanned)} original GSI product overlays; {len(conflicts)} resource/package collision candidates. "
        "Other partitions and property selection remain unverified.\n\n"
        "Feature removal and credential rejection at runtime, idmap2, immutable overlay activation before "
        "system_server, SELinux Enforcing reads, successful injection and partial rollback, and Host HAL isolation: **not_run**.\n\n"
        "No device access, Host modification, GSI modification, policy installation, daemon replacement or Guest service execution. "
        "These resources restrict credentials and reduce Weaver dependence; they do not block Gatekeeper, Weaver, KeyMint, "
        "StrongBox, AuthSecret, RebootEscrow or TEE access. KeyMint/Keystore2/FBE remain separate requirements. "
        "Private Binder and independent /data do not establish Vendor HAL isolation.\n\n"
        "Only a new independent userdata before its first service is a candidate. Existing Weaver protectors may trigger "
        "migration/destruction and must not be reused. DSU properties/markers are not set. KernelSU root itself is outside "
        "the threat model; SSAL control remains a trusted allowlisted layer.\n\n"
        "Next: offline idmap2 and signed APK validation, then a separately authorized isolated mount/Enforcing test. "
        "Framework boot is not ready or authorized. See docs/guest-lock-compat.md and individual JSON results.\n",
        encoding="utf-8")
    if tests["status"] == "failed":
        raise SystemExit(1)
    print(json.dumps({"sysconfig": "static_verified" if static_ok else "blocked", "rro": "blocked", "tests": tests["status"], "launch_enabled": False}))


if __name__ == "__main__":
    main()
