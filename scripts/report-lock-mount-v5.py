#!/usr/bin/env python3
"""Convert v5 observed evidence into independent validation results. No device I/O."""
import hashlib
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/"out/guest-lock-compat-v5"

def read(name,default=None):
    path=OUT/name
    return json.loads(path.read_text(encoding="utf-8-sig")) if path.exists() else default

def save(name,value):
    (OUT/name).write_text(json.dumps(value,indent=2,ensure_ascii=False)+"\n")

def reclaimed(report):
    return all(report.get(k) is True for k in ("process_reaped","namespace_released","loop_backings_unchanged","host_namespace_mountinfo_enforcing_unchanged"))

def summarize(run):
    report=run.get("report",{});child=report.get("child",{})
    return {"name":run["name"],"probe_status":report.get("status","not_run"),"assessment":run["assessment"],"command":run["command"],
        "exit_code":run.get("exit_code"),"child_exit_code":report.get("child_exit_code"),"operation":child.get("operation"),
        "errno":child.get("errno",0 if child.get("status")=="passed" else None),"error":child.get("error"),
        "namespace":child.get("namespace"),"private_propagation":child.get("private_propagation"),
        "target_before_context":child.get("target_before_context"),"parent_context":child.get("parent_context"),
        "mount_root_context":child.get("mount_root_context"),"created_file_context":child.get("created_file_context"),
        "final_file_context":child.get("final_file_context"),"selinux_label_correct":child.get("selinux_label_correct","not_run"),
        "filesystem_access_valid":child.get("filesystem_access_valid","not_run"),"mount_attempt":child.get("mount_attempt"),
        "avc":report.get("avc"),"inprocess_cleanup":child.get("cleanup",{}).get("status","not_run"),
        "cleanup_error":child.get("cleanup",{}).get("error"),"loop_cleanup":child.get("loop_cleanup","not_applicable"),
        "post_exit_resources_reclaimed":reclaimed(report),"namespace_references":report.get("namespace_references"),
        "enforcing_before":report.get("before",{}).get("enforcing"),"enforcing_after":report.get("after",{}).get("enforcing"),
        "execution_domain":report.get("before",{}).get("domain")}

def main():
    comparison=read("comparison-runs.json",[])
    ext4=read("ext4-runs.json",[])
    all_runs=comparison+ext4
    summaries=[summarize(run) for run in all_runs]
    save("mount-comparison.json",{"status":"passed" if len(comparison)==5 and all(reclaimed(x.get("report",{})) for x in comparison) else "not_run" if not comparison else "failed",
        "scope":"independent diagnostic namespaces; successful plain mount is not correct-label XML injection",
        "runs":[summarize(x) for x in comparison],"evidence":"comparison-runs.json"})
    policy=[]
    for run in all_runs:
        current=run.get("report",{}).get("child",{}).get("policy")
        if current:
            policy.append({"run":run["name"],**current})
    successful_queries=[q for p in policy for q in p["queries"] if q.get("status")=="passed"]
    save("loaded-policy-analysis.json",{"status":"passed" if successful_queries else "blocked",
        "binary_export":read("policy-export.json"),"binary_policy_offline_analysis":"blocked (policy acquisition EINVAL)",
        "equivalent_live_decisions":"selinuxfs access transactions; no policy change","live_policy_query_batches":policy,
        "offline_compatibility":{"status":"passed","tool":"official Android libsepol 6f8f496eabd35f28dfa6b4be5fc82e325e1df620, DISABLE_CIL=y",
            "source_supports":"Android netlink extended permissions (type 3)","saved_reconstructed_associate_result":read("offline-associate.json"),
            "scope":"saved reconstructed policy; not substituted for live policy"},
        "system_server_actual_io":"not_run"})
    associate=[q for q in successful_queries if q["source"]=="u:object_r:system_file:s0" and q["target"]=="u:object_r:system_file:s0" and q["class"]=="filesystem" and q["permission"]=="associate"]
    denied=any(q["allowed"] is False and q.get("source_domain_permissive") is False for q in associate)
    denials=[s for s in summaries if s["name"] in ("context_tmpfs","guest_target_context")]
    save("mount-denial-analysis.json",{"status":"passed" if denied and denials else "blocked",
        "context_mount_results":denials,"additional_permission":"system_file system_file:filesystem associate after context changes superblock SID",
        "live_associate_decisions":associate,"policy_denial_explains_failure":denied,
        "exact_running_kernel_instruction_traced":False,
        "kernel_source_match":"Samsung S937NKSU2BYI3 common 6.6.77 differs from running S937NKSSBDZJ2 6.6.127; inspected paths match Android GKI source",
        "conclusion":"loaded decision and differential tests support the associate denial; exact Samsung running branch is inferred, not instrumented" if denied else "insufficient evidence for exact cause",
        "avc_absence":"inspect returned auditdeny masks; no AVC never implies no SELinux denial",
        "minimum_rule_candidate_for_original_context_method":["allow system_file system_file:filesystem associate;"] if denied else [],
        "candidate_applied":False,"candidate_required_for_alternative":"not inferred; see actual prelabelled ext4 result"})
    normal=next((x for x in ext4 if x["name"]=="normal"),None)
    report=normal.get("report",{}) if normal else {};child=report.get("child",{})
    namespace_valid=bool(normal and normal["assessment"]=="passed" and child.get("file",{}).get("context")=="u:object_r:system_file:s0" and child.get("preservation",{}).get("status")=="passed")
    server=[q for q in successful_queries if q["source"]=="u:r:system_server:s0"]
    server_checked=bool(server) and all(q["allowed"] is True for q in server)
    save("sysconfig-namespace.json",{"status":"passed" if namespace_valid else "not_run" if not normal else "failed",
        "stage":"namespace_validated" if namespace_valid else "namespace_probe_ready","method":"prelabelled-ext4",
        "run":summarize(normal) if normal else None,"file":child.get("file"),"preservation":child.get("preservation"),
        "artifact_sha256":child.get("alternative_image_sha256"),"loaded_system_server_read_policy":"allowed for queried permissions" if server_checked else "unknown_or_denied",
        "system_server_actual_read":"not_run","SystemConfig_feature_removal":"not_run","framework_validated":"not_run",
        "source_gsi_after":"device-after.stdout","host_invariance_scope":"PID1 namespace/mountinfo; global enforcing; all loop backings; two Host compatibility target paths; namespace and FD references",
        "host_authentication_data":"not_accessed; no comprehensive Host system/authentication content hash comparison"})
    validation=read("ext4-image-validation.json",{})
    validation["runtime_validation"]="passed" if namespace_valid else "not_run" if not normal else "failed"
    validation["runtime_label"]=child.get("file",{}).get("context","not_run")
    validation["system_server_actual_read"]="not_run"
    save("ext4-image-validation.json",validation)
    relabel=next((summarize(x) for x in comparison if x["name"]=="temporary_file_relabel"),None)
    save("alternative-methods.json",{"status":"passed" if namespace_valid else "blocked",
        "context_tmpfs":{"status":"failed" if any(x.get("errno")==13 for x in denials) else "not_run","evidence":"mount-comparison.json"},
        "plain_tmpfs_per_file_label":{"diagnostic":relabel,"full_guest_directory_injection":"not_run; only disposable-file fsetxattr tested; scratch root label differs"},
        "prelabelled_ext4":{"status":"passed" if namespace_valid else "not_run" if not normal else "failed","system_file_xattrs_preserved":namespace_valid,"policy_modified":False},
        "selected_method":"prelabelled-ext4" if namespace_valid else "none validated","sysconfig_frozen":namespace_valid,
        "rro_design":"same directory image method could preserve existing Product files, but requires independent Product classification, overlay config and activation checks; not executed",
        "overlayfs":"not considered; simpler ext4 candidate tested first","RRO_signature_idmap_repeated":False})
    save("cleanup-validation.json",{"status":"passed" if summaries and all(x["post_exit_resources_reclaimed"] for x in summaries) else "not_run" if not summaries else "failed",
        "scope":"post-exit resource reclamation, with inprocess cleanup status separately preserved for each run",
        "runs":summaries,"intentional_EBUSY_probe_status":"failed as required, even when kernel namespace teardown and parent observations confirm eventual reclamation",
        "normal_ext4_cleanup":child.get("cleanup",{}).get("status","not_run"),
        "temporary_staging_cleanup":read("staging-cleanup.json"),"parent_death_and_watchdog_tests":"not_run (existing mechanisms retained)",
        "host_authentication_data":"not_accessed; no forbidden content hashes"})
    isolation=bool(normal) and child.get("private_propagation")=="passed" and child.get("namespace") != report.get("before",{}).get("pid1_namespace") and reclaimed(report)
    save("runtime-gate.json",{"status":"passed","guest_lock_compat_enabled":False,"launch_enabled":False,"framework_validated":"not_run",
        "framework_validation_blocked":True,"mount_isolation_validated":"passed" if isolation else "not_run",
        "sysconfig_mount_validated":"passed" if namespace_valid else "not_run","sysconfig_label_validated":"passed" if namespace_valid else "not_run",
        "sysconfig_access_policy_checked":"passed for requested system_file permissions" if server_checked else "blocked",
        "namespace_validation":"namespace_validated" if namespace_valid else "not_run","system_server_actual_read":"not_run",
        "runtime_resource_value_verified":"not_run","Product_classification":"blocked","RRO":"not_run","profile_runtime_gate_unchanged":True})

if __name__=="__main__":main()