#!/usr/bin/env python3
"""v5 approved comparisons or separately approved prelabelled ext4 namespace suite.
No deployment, policy edits, host relabel, services or Framework operations.
"""
import argparse
import json
from pathlib import Path
import shlex
import subprocess


def cleanup_valid(report):
    return all(report.get(key) is True for key in (
        "process_reaped", "host_namespace_mountinfo_enforcing_unchanged",
        "loop_backings_unchanged", "namespace_released"))


def assess(run, stage=None, comparison=False):
    report=run.get("report",{})
    child=report.get("child",{})
    if not cleanup_valid(report):
        return "failed"
    if stage=="abort":
        return "passed" if report.get("child_exit_code")==86 and run["exit_code"]!=0 else "blocked"
    if stage=="cleanup":
        return "detected_cleanup_failure" if child.get("cleanup",{}).get("status")=="failed" and report.get("status")=="failed" and run["exit_code"]!=0 else "failed"
    if child.get("cleanup",{}).get("status")!="passed":
        return "failed"
    if stage:
        return "passed" if child.get("error")==f"injected failure: {stage}" and run["exit_code"]!=0 else "blocked"
    if comparison and child.get("mount_attempt") and child.get("operation")=="comparison_tmpfs_mount" and child.get("errno")==13:
        return "observed_denial"
    if comparison and child.get("operation")=="namespace_temporary_file_fsetxattr" and child.get("errno") in (13,95):
        return "observed_relabel_denial"
    return "passed" if report.get("status")=="passed" and run["exit_code"]==0 else "failed"


def plans(args):
    if args.phase=="comparison":
        return [(name,[args.binary,"probe",kind,"--execute","--acknowledge-risk"]+
                 (["--image",args.image] if kind.startswith("lock-target-") else []),None) for name,kind in (
                     ("plain_tmpfs","lock-mount-plain"),("context_tmpfs","lock-mount-context"),
                     ("temporary_file_relabel","lock-mount-relabel"),("guest_target_plain","lock-target-plain"),
                     ("guest_target_context","lock-target-context"))]
    normal=[args.binary,"probe","lock-sysconfig","--image",args.image,
            "--method","prelabelled-ext4","--sysconfig-image","/data/local/tmp/ssal-lock-v5-sysconfig.ext4",
            "--sysconfig-sha256",args.sysconfig_sha256,"--execute","--acknowledge-risk"]
    return [(stage or "normal",normal+(["--fail-at",stage] if stage else []),stage)
            for stage in (None,"unshare","private","tmpfs","after-ext4","bind","after-inject","abort","cleanup")]


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase",choices=("comparison","ext4"),required=True)
    parser.add_argument("--adb",default="adb")
    parser.add_argument("--binary",default="/data/local/tmp/ssal-lock-probe-v5")
    parser.add_argument("--image",default="/data/local/ssal/images/1793366406758-25627/system.img")
    parser.add_argument("--sysconfig-sha256")
    parser.add_argument("--out",type=Path,default=Path("out/guest-lock-compat-v5"))
    parser.add_argument("--execute",action="store_true")
    parser.add_argument("--acknowledge-risk",action="store_true")
    args=parser.parse_args()
    if args.execute!=args.acknowledge_risk:
        parser.error("execution requires both flags after explicit user approval")
    if args.phase=="ext4" and not args.sysconfig_sha256:
        parser.error("--sysconfig-sha256 required")
    plan=plans(args)
    commands=[(name,[args.adb,"shell","-T","su","-c",shlex.join(cmd)],stage) for name,cmd,stage in plan]
    if not args.execute:
        print(json.dumps({"status":"not_run","phase":args.phase,"commands":[c for _,c,_ in commands]},indent=2))
        return 0
    args.out.mkdir(parents=True,exist_ok=True)
    runs=[]
    for name,command,stage in commands:
        try:
            result=subprocess.run(command,capture_output=True,text=True,timeout=150)
            run={"name":name,"command":command,"exit_code":result.returncode,"stderr":result.stderr}
            try:
                run["report"]=json.loads(result.stdout)
            except ValueError:
                run["report"]={}
                run["stdout"]=result.stdout
            run["assessment"]=assess(run,stage,args.phase=="comparison")
        except subprocess.TimeoutExpired as error:
            run={"name":name,"command":command,"assessment":"failed","error":str(error),"remote_cleanup":"unknown"}
        runs.append(run)
        (args.out/f"{args.phase}-runs.json").write_text(json.dumps(runs,indent=2)+"\n")
        print(json.dumps({"name":name,"assessment":run["assessment"],"child_error":run.get("report",{}).get("child",{}).get("error")}),flush=True)
        if run["assessment"] not in ("passed","observed_denial","observed_relabel_denial","detected_cleanup_failure"):
            return 1
        # A successful plain mount is prerequisite for all subsequent comparisons.
        if name=="plain_tmpfs" and run["assessment"]!="passed":
            return 1
    return 0

if __name__=="__main__":
    raise SystemExit(main())
