#!/usr/bin/env python3
"""Explicitly approved, standalone namespace-probe suite. Never deploys a binary.

Default prints commands only. --execute --acknowledge-risk is required to invoke
ADB. The supplied binary must already be staged separately by the operator.
"""
import argparse
import json
from pathlib import Path
import shlex
import subprocess

STAGES = ("unshare", "private", "tmpfs", "context", "bind", "collision", "create", "after-inject", "abort")


def assess(run, stage=None):
    report = run.get("report", {})
    child = report.get("child", {})
    clean = (report.get("process_reaped") is True
             and report.get("host_namespace_mountinfo_enforcing_unchanged") is True
             and report.get("loop_backings_unchanged") is True
             and report.get("namespace_released") is True)
    if stage is None:
        return "passed" if clean and run["exit_code"] == 0 and report.get("status") == "passed" else "failed"
    if stage == "abort":
        reached = report.get("child_exit_code") == 86
    elif stage == "collision":
        reached = child.get("error") == "compatibility target collision"
    else:
        reached = child.get("error") == f"injected failure: {stage}"
    if not reached:
        return "blocked"
    # Before-scratch failures have nothing to unmount. An abnormal exit relies
    # on kernel namespace teardown and parent observations, not child cleanup.
    if stage != "abort":
        clean = clean and child.get("cleanup", {}).get("status") == "passed"
    return "passed" if clean and run["exit_code"] != 0 else "failed"


def command(binary, image, stage=None):
    args = [binary, "probe", "lock-sysconfig", "--image", image,
            "--execute", "--acknowledge-risk"]
    if stage:
        args.extend(["--fail-at", stage])
    # shell protocol propagates the remote exit status; exec-out always reports
    # success on some ADB versions even when the probe exits with an error.
    return ["adb", "shell", "-T", "su", "-c", shlex.join(args)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--adb", default="adb", help="ADB executable on this workstation")
    parser.add_argument("--image", required=True)
    parser.add_argument("--out", type=Path, default=Path("out/guest-lock-compat-v4"))
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--acknowledge-risk", action="store_true")
    args = parser.parse_args()
    if args.execute != args.acknowledge_risk:
        parser.error("--execute and --acknowledge-risk must be supplied together after user approval")
    commands = [command(args.binary, args.image, stage) for stage in (None, *STAGES)]
    for cmd in commands:
        cmd[0] = args.adb
    if not args.execute:
        print(json.dumps({"status": "not_run", "mode": "dry_run", "commands": commands}, indent=2))
        return 0
    args.out.mkdir(parents=True, exist_ok=True)
    results = []
    for stage, cmd in zip((None, *STAGES), commands):
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=150)
            run = {"stage": stage or "normal", "command": cmd, "exit_code": proc.returncode,
                   "stdout": proc.stdout, "stderr": proc.stderr}
            try:
                run["report"] = json.loads(proc.stdout)
            except ValueError:
                run["report"] = {}
            run["status"] = assess(run, stage)
        except subprocess.TimeoutExpired as error:
            # Killing ADB does not prove remote process termination or cleanup.
            run = {"stage": stage or "normal", "command": cmd, "status": "failed",
                   "error": str(error), "remote_cleanup": "unknown"}
        results.append(run)
        (args.out / "device-suite.json").write_text(json.dumps(results, indent=2) + "\n")
        if run["status"] != "passed":
            break
    complete = len(results) == len(commands) and all(r["status"] == "passed" for r in results)
    print(json.dumps({"status": "passed" if complete else "blocked", "results": results}, indent=2))
    return 0 if complete else 1


if __name__ == "__main__":
    raise SystemExit(main())
