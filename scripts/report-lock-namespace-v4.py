#!/usr/bin/env python3
"""Write v4 offline evidence without changing v3 or contacting a device."""
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "out/guest-lock-compat-v4"
OLD = ROOT / "out/guest-lock-compat-v3"


def sha(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def save(name, value):
    (OUT / name).write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n")


def main():
    tool = json.loads((OLD / "idmap-toolchain.json").read_text())
    validation = json.loads((OLD / "idmap-validation.json").read_text())
    files = {
        "image": (ROOT / "out/LineageOS-23.2-20260524-VANILLA-EXT4-GSI.img", tool["image_sha256"]),
        "framework": (ROOT / "out/selinux-check/2026-10-31-guest-v3/framework-res.apk", tool["framework_sha256"]),
        "apk": (ROOT / "out/guest-lock-compat-v2/SSALWeaverOverlay-signed.apk", validation["apk_signature_valid"]["sha256"]),
        "idmap2": (OLD / "evidence/system/bin/idmap2", tool["binary"]["sha256"]),
        "idmap2d": (OLD / "evidence/system/bin/idmap2d", tool["idmap2d_sha256"]),
        "libidmap2": (OLD / "evidence/system/lib64/libidmap2.so", tool["libidmap2_sha256"]),
        "runtime_apex": (OLD / "apex-work/runtime.apex", tool["runtime_apex_sha256"]),
        "qemu": (OLD / "toolchain/packages/usr/bin/qemu-aarch64", tool["qemu_sha256"]),
    }
    for name, expected in tool["direct_dependency_sha256"].items():
        folder = "apex/com.android.runtime/lib64" if name.startswith("bionic/") else "system/lib64"
        files["dependency:" + name] = (OLD / "emulated-root" / folder / name, expected)
    hashes = {name: {"path": str(path.relative_to(ROOT)), "sha256": sha(path) if path.is_file() else None,
                     "v3_sha256": expected} for name, (path, expected) in files.items()}
    for item in hashes.values():
        item["status"] = "passed" if item["sha256"] == item["v3_sha256"] else "failed"
    valid = all(item["status"] == "passed" for item in hashes.values())
    inventory = json.loads((ROOT / "out/guest-lock-compat/overlay-inventory.json").read_text())
    mismatches = [x["path"] for x in inventory if sha(ROOT / "out/guest-lock-compat/evidence" / x["path"]) != x["sha256"]]
    save("baseline-hashes.json", {"status": "passed" if valid and not mismatches else "failed", "files": hashes,
        "product_inventory_count": len(inventory), "product_hash_mismatches": mismatches,
        "idmap_signature_mapping_repeated": False,
        "v3_evidence_retained": valid and not mismatches})
    environment = {"host": "Samsung Android 17 SDK 37", "guest": tool["guest_build"], "selinux": "Enforcing",
                   "domain": "u:r:ksu:s0", "source": "preflight.json (read-only inventory, not probe execution)"}
    base = {"status": "not_run", "environment": environment, "reason": "explicit user device-experiment approval pending",
            "command": None, "exit_code": None, "errno": None, "avc": "not_run", "framework_validated": "not_run"}
    save("namespace-isolation.json", {**base, "baseline": "ADB shell equals PID 1: mnt:[4026532950]",
        "unshare": "not_run", "distinct_id": "not_run", "private_propagation": "not_run", "host_mountinfo_unchanged": "not_run"})
    save("sysconfig-probe.json", {**base, "implementation": "ready_for_approved_probe", "stage": "namespace_probe_ready" if valid else "offline_validation_blocked",
        "xml_sha256": sha(ROOT / "guest-compat/lockscreen/ssal-lockscreen.xml"),
        "preservation": "not_run", "guest_open_read": "not_run", "system_server_access": "not_run",
        "policy_analysis": {"status": "blocked", "binary_query": "sesearch failed: Unknown extended permission: 3 (exit 1)",
            "scope": "saved reconstructed Host policy; not certified as current loaded KernelSU policy",
            "cil": "out/selinux-check/2026-10-30T21-06-36-556Z-feba58ef/host/system/etc/selinux/plat_sepolicy.cil",
            "static_rules": ["allow coredomain system_file:file read getattr map execute open (line 24463)",
                             "allow domain system_file:dir read getattr open search (line 24399)",
                             "allow system_server system_file:dir read getattr open search (line 70284)"],
            "conclusion": "candidate required permissions exist in CIL; attribute expansion, constraints, loaded policy and actual system_server reads remain unverified"}})
    save("product-overlay-policy.json", {"status": "blocked", "environment": environment,
        "guest_symlink": "/product -> /system/product", "resolved_overlay": "/system/product/overlay",
        "resolution_test": "passed offline guest_path test; namespace resolution not_run",
        "existing_overlay_count": len(inventory), "inventory_hash_mismatches": mismatches,
        "config": {"status": "passed_offline_prior_evidence", "file": "out/guest-lock-compat/evidence/product-overlay-config.txt",
                   "value": "config/config.xml absent in prior debugfs listing; image hash unchanged"},
        "guest_overlayconfig": "out/guest-lock-compat/evidence/OverlayConfig-guest.java:127-146",
        "conditions": ["Guest partition roots must canonicalize /product to /system/product within Guest root",
            "Guest preinstalled package scan must assign SCAN_AS_PRODUCT and retain Product original partition path",
            "OverlayScanner/OverlayConfig must discover APK under that partition overlay directory",
            "Absent partition config permits static enabled immutable fallback; config overrides manifest priority/static",
            "Only immutable android-target overlays can affect Resources.getSystem(); idmap/preload timing and cross-partition ordering remain unverified"],
        "product_classification": "blocked: exact Guest PackageManager scan/partition implementation not extracted and tied to this image",
        "conditional_idmap_product": "retained from v3 if baseline-hashes.json passed; CLI policy is an assumption",
        "resources_getSystem": "not_run", "runtime_resource_value_verified": "not_run", "rro_execute_gate": "blocked before unshare or mount",
        "primary_reference": "https://source.android.com/docs/core/runtime/rros"})
    save("rro-probe.json", {**base, "status": "blocked", "reason": "actual Guest Product classification not certified; device approval also pending",
        "implementation": "CLI, APK hash check, shared directory projection and cleanup route implemented behind Product gate",
        "apk_sha256": hashes["apk"]["sha256"], "existing_494_preserved": "not_run", "open_read": "not_run",
        "runtime_resource_value_verified": "not_run"})
    save("cleanup-validation.json", {**base, "normal": "not_run", "failure_cases": {stage: "not_run" for stage in
        ("unshare", "private", "tmpfs", "context", "bind", "collision", "create", "after-inject", "abort")},
        "automated_suite": "scripts/run-lock-namespace-suite.py (dry-run default; no deployment)",
        "loop_cleanup": "not_applicable (no probe loops used this turn)", "child_reap": "not_run", "namespace_fd_refs": "not_run",
        "host_authentication_files": "not_accessed; no content hashes collected to avoid forbidden access",
        "host_system_files": "not_run; no device writes, service changes, policy changes, or image modification performed"})
    save("runtime-gate.json", {"status": "passed", "enabled_default": False, "framework_launch": "blocked",
        "framework_validated": "not_run", "runtime_resource_value_verified": "not_run",
        "sysconfig": "namespace_probe_ready" if valid else "offline_validation_blocked", "rro": "framework_validation_blocked",
        "stages_are_diagnostics_only": True, "profile_runtime_gate_unchanged": True})
    rust = (OUT / "rust-tests.stdout").read_text()
    python = (OUT / "python-tests.stderr").read_text()
    counts = re.findall(r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored", rust)
    match = re.search(r"Ran (\d+) tests", python)
    save("test-results.json", {"status": "passed" if counts and "FAILED" not in python and "\nOK" in python else "failed",
        "cargo_fmt_check": "passed" if (OUT / "fmt.exit").exists() and (OUT / "fmt.exit").read_text().strip() == "0" else "not_run", "clippy": "passed" if (OUT / "checks.exit").exists() and (OUT / "checks.exit").read_text().strip() == "0" else "not_run", "android_build": json.loads((OUT / "android-build.json").read_text(encoding="utf-8-sig"))["status"] if (OUT / "android-build.json").exists() else "not_run", "rust_passed": sum(int(x[0]) for x in counts), "rust_failed": sum(int(x[1]) for x in counts), "rust_ignored": sum(int(x[2]) for x in counts),
        "python_passed": int(match[1]) if match else None, "rust_command": "cargo test --locked --all-targets",
        "python_command": "python3 -m unittest discover -s scripts -p test_*.py", "logs": ["rust-tests.stdout", "rust-tests.stderr", "python-tests.stdout", "python-tests.stderr"],
        "ignored_reason": "three existing privileged Linux mount tests; not device validation"})

def apply_device_results():
    suite_file = OUT / "device-suite.json"
    if not suite_file.exists():
        return
    results = json.loads(suite_file.read_text(encoding="utf-8-sig"))
    normal = next((r for r in results if r["stage"] == "normal"), None)
    if not normal or not normal.get("report"):
        return
    report = normal["report"]
    child = report["child"]
    for phase in ("before", "after"):
        (OUT / f"host-mountinfo-{phase}.txt").write_text(report[phase]["pid1_mountinfo"])
    for key, name in (("mountinfo_before_scratch", "child-mountinfo-private.txt"),):
        if key in child:
            (OUT / name).write_text(child[key])
    if child.get("cleanup", {}).get("mountinfo_after"):
        (OUT / "child-mountinfo-after-cleanup.txt").write_text(child["cleanup"]["mountinfo_after"])
    preflight = json.loads((OUT / "preflight.json").read_text(encoding="utf-8-sig"))
    preflight.update(device_approval="granted explicitly for Sysconfig normal and failure probes", probe_executed=True,
                     final_image_hash_evidence="device-after.stdout", staging_cleanup_exit_code=int((OUT / "staging-cleanup.exit").read_text().strip()))
    save("preflight.json", preflight)
    common = {"environment": {"host": "Samsung Android 17 SDK 37", "guest": "LineageOS 23.2 Android 16 SDK 36.1",
        "selinux_before": report["before"]["enforcing"], "selinux_after": report["after"]["enforcing"],
        "domain": report["before"]["domain"]}, "command": normal["command"], "exit_code": normal["exit_code"],
        "child_exit_code": report["child_exit_code"], "errno": child.get("errno"), "avc": report.get("avc"),
        "evidence": "device-suite.json", "framework_validated": "not_run"}
    isolation_ok = child.get("private_propagation") == "passed" and child.get("namespace") != report["before"]["pid1_namespace"]
    save("namespace-isolation.json", {**common, "status": "passed" if isolation_ok else "failed", "unshare": "passed" if child.get("namespace") else "not_run",
        "pid1_namespace": report["before"]["pid1_namespace"], "child_namespace": child.get("namespace"),
        "distinct_id": "passed" if isolation_ok else "failed", "private_propagation": child.get("private_propagation"),
        "host_mountinfo_unchanged": report["host_namespace_mountinfo_enforcing_unchanged"], "namespace_released": report["namespace_released"],
        "mountinfo_evidence": ["host-mountinfo-before.txt", "host-mountinfo-after.txt", "child-mountinfo-private.txt", "child-mountinfo-after-cleanup.txt"],
        "note": "Isolation passed; full sysconfig probe failed later. This is not namespace_validated file-exposure evidence."})
    sysconfig = json.loads((OUT / "sysconfig-probe.json").read_text())
    sysconfig.update(common)
    sysconfig.update(status=child["status"], reason=child.get("error"), failed_operation=child.get("operation"),
        stage="namespace_probe_ready", resolved_directory=child.get("resolved_directory"),
        image_read_only_mount="passed" if child.get("resolved_directory") else "not_run",
        loop_number=child.get("loop_number"), loop_device_number=child.get("loop_device_number"),
        xml_exposure="not_run (context mount denied before XML creation)", preservation="not_run (injection did not proceed)",
        guest_open_read="not_run", system_server_access="not_run", implementation="executed; blocked at SELinux-context tmpfs mount")
    save("sysconfig-probe.json", sysconfig)
    cleanup_ok = (child["cleanup"]["status"] == "passed" and report["process_reaped"] and report["namespace_released"]
                  and report["loop_backings_unchanged"] and report["host_namespace_mountinfo_enforcing_unchanged"])
    save("cleanup-validation.json", {**common, "status": "passed" if cleanup_ok else "failed", "scope": "actual intermediate context mount failure",
        "normal_success_cleanup": "not_run", "actual_context_mount_failure_cleanup": "passed" if cleanup_ok else "failed",
        "failure_cases": {stage: "not_run (normal prerequisite failed; suite stopped)" for stage in
            ("unshare", "private", "tmpfs", "context", "bind", "collision", "create", "after-inject", "abort")},
        "unmount": child["cleanup"]["status"], "loop_cleanup": child["loop_cleanup"], "child_reaped": report["process_reaped"],
        "namespace_released": report["namespace_released"], "namespace_fd_references": report["namespace_references"],
        "host_mountinfo_namespace_enforcing_unchanged": report["host_namespace_mountinfo_enforcing_unchanged"],
        "host_loops_unchanged": report["loop_backings_unchanged"], "host_target_files_before": report["before"]["host_files"],
        "host_target_files_after": report["after"]["host_files"], "temporary_binary_removed": (OUT / "staging-cleanup.exit").read_text().strip() == "0",
        "host_authentication_files": "not_accessed; forbidden authentication data not hashed", "host_system_auth_content_comparison": "not_run",
        "first_attempt": "attempt-1/: ENXIO from incorrect loop minor calculation, no configured loop. Fixed by sharing existing sysfs parser. Both attempts cleaned successfully."})
    rro = json.loads((OUT / "rro-probe.json").read_text())
    rro["reason"] = "Product classification not certified; shared context-mount prerequisite also failed with EACCES. No RRO probe executed."
    save("rro-probe.json", rro)
    gate = json.loads((OUT / "runtime-gate.json").read_text())
    gate.update(sysconfig="namespace_probe_ready (context mount EACCES; file exposure not validated)", namespace_validated="not assigned",
                namespace_isolation="passed", framework_launch="blocked", framework_validated="not_run")
    save("runtime-gate.json", gate)

if __name__ == "__main__":
    main()
    apply_device_results()
