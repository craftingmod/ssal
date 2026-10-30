//! Disposable runtime investigation. No service exec, setexeccon or relabeling.
use super::preflight::{digest, fds, metadata, observe, rc_spec};
use super::*;
use serde::Serialize;
use serde_json::{json, Value};
use std::os::unix::fs::MetadataExt;

#[derive(Serialize)]
struct ServiceExecutionSpec {
    version: u32,
    executable: &'static str,
    selinux_domain: &'static str,
    uid: u32,
    gid: u32,
    supplementary_groups: Vec<u32>,
    capabilities: Value,
    fd_allowlist: Value,
    rlimits: Value,
    namespaces: Value,
    task_profiles: Vec<&'static str>,
    environment: Value,
    launch_enabled: bool,
}

impl ServiceExecutionSpec {
    fn servicemanager() -> Self {
        Self {
            version: 1,
            executable: "/system/bin/servicemanager",
            selinux_domain: TARGET,
            uid: 1000,
            gid: 1000,
            supplementary_groups: vec![3009],
            capabilities: json!({"inheritable": 0, "permitted": 0, "effective": 0, "ambient": 0, "bounding": 0}),
            fd_allowlist: json!({"0": "/dev/null read", "1": "session log write", "2": "session log write", "other": "close; no host root, Binder, property, kmsg or socket FDs", "kmsg_rc_override": "omit; guest logging backend required"}),
            rlimits: json!({"nofile": {"soft": 1024, "hard": 1024}, "core": {"soft": 0, "hard": 0}, "other": "preserve worker_limits snapshot in this report; verify after applying overrides"}),
            namespaces: json!({"mount": "private recursively; chroot/pivot_root required", "pid": "new with private proc required", "net": "new required", "user": "host UID mapping, no new user namespace", "uts": "new required", "ipc": "new required", "cgroup": "guest-owned task profile destination required"}),
            task_profiles: vec!["ProcessCapacityHigh"],
            environment: json!({"clear_inherited": true, "PATH": "/system/bin", "ANDROID_ROOT": "/system", "ANDROID_DATA": "/data", "ANDROID_SOCKET_*": "forbidden", "ANDROID_FILE_*": "forbidden"}),
            launch_enabled: false,
        }
    }
}

fn stage(report: &mut Value, name: &str, operation: impl FnOnce() -> io::Result<Value>) {
    // Independent stages continue after a missing path or failed policy query.
    report["stages"][name] = match operation() {
        Ok(value) => value,
        Err(error) => json!({"status": "failed", "error": error.to_string()}),
    };
}

fn label_access(label: &str, class: &str, permissions: &[&str]) -> io::Result<Value> {
    let decisions = permissions
        .iter()
        .map(|p| query(TARGET, label, class, p))
        .collect::<io::Result<Vec<_>>>()?;
    let sequence = decisions.first().map(|d| d.sequence);
    let allowed = !decisions.is_empty()
        && decisions
            .iter()
            .all(|d| d.allowed && !d.permissive_domain && Some(d.sequence) == sequence);
    Ok(
        json!({"label": label, "class": class, "status": if allowed { "passed" } else { "blocked" }, "decisions": decisions}),
    )
}

fn compatibility(root: &Path) -> io::Result<Value> {
    let mut paths = Vec::new();
    let mut candidates = std::collections::BTreeSet::new();
    for (path, class, permissions) in [
        ("linkerconfig", "dir", &["search", "getattr"][..]),
        (
            "linkerconfig/ld.config.txt",
            "file",
            &["open", "read", "getattr", "map"][..],
        ),
        (
            "dev/binder",
            "chr_file",
            &["open", "read", "write", "getattr", "ioctl", "map"][..],
        ),
    ] {
        let observation = observe(root, path);
        for side in ["host", "guest"] {
            if let Some(label) = observation[side]["label"].as_str() {
                candidates.insert((label.to_owned(), class.to_owned()));
            }
        }
        let access = observation["guest"]["label"]
            .as_str()
            .map(|label| label_access(label, class, permissions))
            .transpose()?;
        paths.push(json!({"observation": observation, "guest_access": access}));
    }
    let mut reuse = Vec::new();
    for (label, class) in candidates {
        let perms: &[&str] = match class.as_str() {
            "dir" => &["search", "getattr"],
            "chr_file" => &["open", "read", "write", "getattr", "ioctl", "map"],
            _ => &["open", "read", "getattr", "map"],
        };
        reuse.push(label_access(&label, &class, perms)?);
    }
    let blocked = paths
        .iter()
        .any(|p| p["guest_access"]["status"] != "passed");
    Ok(
        json!({"status": if blocked { "blocked" } else { "passed" }, "paths": paths, "observed_type_candidates": reuse,
        "context_manager": query(TARGET, TARGET, "binder", "set_context_mgr")?,
        "scope": "loaded effective policy queries for observed types only; not exhaustive policy type enumeration; ioctl xperms not proven",
        "label_reuse": "an allowed Host type is only a candidate: filesystem labeling support, type semantics and guest/host MAC separation require review; never copy Host linkerconfig contents",
        "guest_specific_type": "private Binder separates registries even with a reused type, but a shared servicemanager domain/type provides no guest-specific MAC boundary; new types require explicit policy design if that boundary is required",
        "labels_modified": false, "policy_modified": false}),
    )
}

fn spec_preflight(root: &Path) -> io::Result<Value> {
    let rc = rc_spec(&fs::read_to_string(crate::guest_mounts::guest_path(
        root,
        "system/etc/init/servicemanager.rc",
    )?)?)?;
    let status = fs::read_to_string("/proc/self/status")?;
    let effective = status
        .lines()
        .find_map(|l| l.strip_prefix("CapEff:"))
        .and_then(|v| u64::from_str_radix(v.trim(), 16).ok());
    let capability_prerequisites: Vec<_> = [("CAP_SETGID", 6), ("CAP_SETUID", 7), ("CAP_SETPCAP", 8), ("CAP_SYS_CHROOT", 18), ("CAP_SYS_ADMIN", 21)].iter()
        .map(|(name, bit)| json!({"name": name, "present": effective.map(|mask| mask & (1 << bit) != 0), "syscall_application": "not_run"})).collect();
    let binder_path = crate::guest_mounts::guest_path(root, "dev/binder")?;
    let binder_meta = fs::metadata(&binder_path)?;
    let binder_dac_rw = dac_allows(&binder_meta, 6);
    let mut traversal = Vec::new();
    let mut ancestor = binder_path.parent();
    while let Some(path) = ancestor.filter(|p| p.starts_with(root)) {
        let meta = fs::metadata(path)?;
        traversal.push(json!({"path": path, "search_allowed_by_mode": dac_allows(&meta, 1)}));
        if path == root {
            break;
        }
        ancestor = path.parent();
    }
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut profile_files = Vec::new();
    for path in [
        "system/etc/task_profiles.json",
        "vendor/etc/task_profiles.json",
        "system/etc/cgroups.json",
    ] {
        let contents = crate::guest_mounts::guest_path(root, path).and_then(fs::read_to_string);
        let parsed = contents
            .as_ref()
            .ok()
            .and_then(|v| serde_json::from_str::<Value>(v).ok());
        let profile = parsed
            .as_ref()
            .and_then(|v| v["Profiles"].as_array())
            .and_then(|v| v.iter().find(|p| p["Name"] == "ProcessCapacityHigh"))
            .cloned();
        profile_files.push(json!({"path": path, "readable": contents.is_ok(), "json_parsed": parsed.is_some(), "profile": profile, "error": contents.err().map(|e| e.to_string())}));
    }
    Ok(
        json!({"status": "blocked", "spec": ServiceExecutionSpec::servicemanager(), "rc": rc,
        "worker_status": status.lines().filter(|l| ["Uid:", "Gid:", "Groups:", "Cap", "NoNewPrivs:"].iter().any(|p| l.starts_with(p))).collect::<Vec<_>>(),
        "nofile_hard_sufficient": limit.rlim_max >= 1024, "worker_nofile": {"soft": limit.rlim_cur, "hard": limit.rlim_max},
        "task_profile_files": profile_files, "worker_fds": fds()?,
        "worker_limits": fs::read_to_string("/proc/self/limits")?,
        "capability_prerequisites": capability_prerequisites,
        "private_binder_dac": {"status": if binder_dac_rw { "passed" } else { "blocked" }, "read_write_allowed_by_mode": binder_dac_rw, "metadata": metadata(&binder_path)?, "traversal": traversal, "scope": "mode bits for spec UID/GID/groups; ACL/target SELinux and ioctl not replaced by this check; no chmod/chown"},
        "application": "not_run", "prerequisites": ["verify CAP_SETUID/CAP_SETGID/CAP_SETPCAP/CAP_SYS_ADMIN and syscall results in disposable child", "validate every rc directive or explicit logging override", "resolve task profile actions and guest-owned cgroup destinations; do not apply Host task profile", "implement close-all-except allowlist and verify resulting FDs", "apply and verify all credentials/capability sets, rlimits, namespaces and root in disposable child", "freeze remaining inherited rlimits; exact target-domain loader and ioctl access remain untested"]}),
    )
}

fn dac_allows(meta: &fs::Metadata, required: u32) -> bool {
    let shift = if meta.uid() == 1000 {
        6
    } else if [1000, 3009].contains(&meta.gid()) {
        3
    } else {
        0
    };
    (meta.mode() >> shift) & required == required
}

fn protections(root: &Path) -> io::Result<Value> {
    let media = observe(root, "data/media");
    // Directory-backed userdata can legitimately reside on the same filesystem.
    // Distinct inode identity and absence of nested mounts are the relevant
    // checks, not different st_dev values.
    let media_path = crate::guest_mounts::guest_path(root, "data/media")?;
    let nested_mounts: Vec<_> = fs::read_to_string("/proc/self/mountinfo")?
        .lines()
        .filter_map(|l| l.split_whitespace().nth(4))
        .filter(|p| Path::new(p).starts_with(&media_path))
        .map(str::to_owned)
        .collect();
    let media_ok = media["same_host_object"] == false
        && media["guest"]["directory"] == true
        && media["host"]["directory"] == true
        && nested_mounts.is_empty();
    let paths: Vec<_> = [
        "dev/__properties__",
        "dev/socket/property_service",
        "dev/socket/property_service_for_system",
        "dev/kmsg",
        "dev/hwbinder",
        "dev/vndbinder",
        "dev/binderfs/binder",
        "dev/binder",
        "dev/binderfs/ssal-probe",
        "dev/cpuset/foreground/tasks",
    ]
    .iter()
    .map(|p| observe(root, p))
    .collect();
    // proc root is a kernel magic link. guest_path deliberately interprets
    // ordinary Android absolute symlinks within root and is unsuitable here.
    let proc_binder = metadata(&root.join("proc/1/root/dev/binder"));
    let host_binder = metadata(Path::new("/dev/binder"));
    let proc_host_shared = proc_binder
        .as_ref()
        .ok()
        .zip(host_binder.as_ref().ok())
        .map(|(a, b)| a["dev"] == b["dev"] && a["ino"] == b["ino"] && a["rdev"] == b["rdev"]);
    let ns = namespaces()?;
    let mut same_ns = serde_json::Map::new();
    for name in ["mnt", "pid", "net", "ipc", "uts"] {
        let host = fs::read_link(format!("/proc/1/ns/{name}"));
        let worker = fs::read_link(format!("/proc/self/ns/{name}"));
        same_ns.insert(name.into(), json!({"same": host.as_ref().ok().zip(worker.as_ref().ok()).map(|(a,b)| a == b), "host_error": host.err().map(|e| e.to_string()), "worker_error": worker.err().map(|e| e.to_string())}));
    }
    Ok(
        json!({"status": "blocked", "media": {"status": if media_ok { "passed" } else { "failed" }, "observation": media, "nested_mounts": nested_mounts, "scope": "directory identity and mount topology; directory-backed userdata may share filesystem; no file content scan"},
        "paths": paths, "namespaces": ns, "shares_host_init_namespace": same_ns,
        "proc_magic_host_binder": {"observation": proc_binder.as_ref().ok(), "error": proc_binder.err().map(|e| e.to_string()), "same_host_object": proc_host_shared, "scope": "observed by privileged worker through kernel magic link, not proof of target-domain access"},
        "fallback": {"status": "blocked", "default_driver": "see private_binder stage identity; never accepted without successful provisioning", "remaining": "host PID/proc root and inherited FD escape routes, other dev aliases and exact binary fallback closure not excluded"},
        "property": "no connect/request performed; path absence is not complete isolation; shared property area recorded",
        "kmsg": "exposure recorded; no open/write or init file directive applied",
        "fd_inheritance": fds()?, "root_applied": "not_run"}),
    )
}

pub fn verify(root: &Path) -> io::Result<()> {
    let mut report = json!({"validation_scope": "servicemanager_runtime_preflight", "launch_enabled": false,
        "service_executed": false, "policy_modified": false, "labels_modified": false,
        "stages": {"selinux_labels": {"status": "not_run"}, "private_binder": {"status": "not_run"}, "execution_spec": {"status": "not_run"}, "host_protection": {"status": "not_run"}, "host_unchanged": {"status": "not_run"}, "cleanup": {"status": "not_run"}},
        "domain_transition": "not_run", "service_launch": "not_run", "ready_for_service_launch": false});
    let before = host_services();
    report["boot_id"] = json!(context("/proc/sys/kernel/random/boot_id").ok());
    report["executable_sha256"] = json!(crate::guest_mounts::guest_path(
        root,
        "system/bin/servicemanager"
    )
    .and_then(|p| digest(&p))
    .ok());
    let policy_before = policy_hash();
    report["policy_sha256"] = json!(policy_before.as_ref().ok());
    report["policy_hash_error"] = json!(policy_before.as_ref().err().map(ToString::to_string));
    let enforcing = context("/sys/fs/selinux/enforce");
    let initial_av = query(TARGET, TARGET, "process", "getattr");
    let host_binder = metadata(Path::new("/dev/binder"));
    let mut binder = crate::binder_probe::Session::new();
    let admitted = before.as_ref().is_ok_and(|v| {
        v.as_object()
            .is_some_and(|m| m.values().all(|p| p["alive"] == true))
    }) && enforcing.as_ref().is_ok_and(|v| v == "1")
        && initial_av.as_ref().is_ok_and(|d| !d.permissive_domain);
    if admitted {
        stage(&mut report, "private_binder", || {
            let (major, minor, protocol) = binder.provision(root)?;
            Ok(
                json!({"status": "passed", "major": major, "minor": minor, "protocol": protocol, "identity": observe(root, "dev/binder"), "context_manager": "not_run", "ipc": "not_run"}),
            )
        });
        stage(&mut report, "selinux_labels", || compatibility(root));
        stage(&mut report, "execution_spec", || spec_preflight(root));
        stage(&mut report, "host_protection", || protections(root));
    } else {
        report["admission"] = json!({"status": "blocked", "reason": "Host snapshot/global Enforcing/enforcing target AV unavailable", "host_error": before.as_ref().err().map(ToString::to_string)});
    }
    let cleanup = binder.cleanup();
    report["stages"]["cleanup"] = json!({"status": if cleanup.is_ok() { "passed" } else { "failed" }, "scope": "private Binder FD and mounts only; rootfs/loop/scratch reports follow", "recovery_required": cleanup.is_err(), "error": cleanup.as_ref().err().map(ToString::to_string)});
    let after = host_services();
    let policy_after = policy_hash();
    let policy_hash_same = policy_before
        .as_ref()
        .ok()
        .zip(policy_after.as_ref().ok())
        .map(|(a, b)| a == b);
    report["policy_hash_same"] = json!(policy_hash_same);
    let final_av = query(TARGET, TARGET, "process", "getattr");
    let unchanged = before.as_ref().is_ok_and(|a| {
        after.as_ref().is_ok_and(|b| {
            a == b
                && b.as_object()
                    .is_some_and(|m| m.values().all(|p| p["alive"] == true))
        })
    }) && host_binder
        .as_ref()
        .is_ok_and(|a| metadata(Path::new("/dev/binder")).is_ok_and(|b| *a == b))
        && context("/sys/fs/selinux/enforce").is_ok_and(|v| v == "1")
        && policy_hash_same != Some(false)
        && initial_av.as_ref().is_ok_and(|a| {
            final_av
                .as_ref()
                .is_ok_and(|b| a.sequence == b.sequence && !b.permissive_domain)
        });
    report["stages"]["host_unchanged"] = json!({"status": if unchanged { "passed" } else { "failed" }, "before": before.as_ref().ok(), "after": after.as_ref().ok(), "after_error": after.err().map(|e| e.to_string()), "initial_av": initial_av.ok(), "final_av": final_av.ok(), "scope": "observed key process identities/alive/context, host Binder identity, enforce and AV sequence; not all intermediate Host state"});
    report["remaining_blockers"] = json!({"selinux": "see selinux_labels observed file/chr_file AV denials; allowed reuse candidates do not authorize relabeling; full dependency/xperm checks pending", "runtime": "see execution_spec and host_protection; PID/net/root/FD/property/logging/task-profile enforcement incomplete"});
    println!("Servicemanager runtime preflight summary: {report}");
    cleanup?;
    if !unchanged {
        return Err(io::Error::other(
            "runtime preflight Host observation failed",
        ));
    }
    Err(io::Error::other(
        "runtime preflight blocked; no Android service executed; launch_enabled=false",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn independent_failures_remain_visible() {
        let mut report = json!({"stages": {}});
        stage(&mut report, "binder", || {
            Err(io::Error::other("identity mismatch"))
        });
        stage(&mut report, "spec", || Ok(json!({"status": "blocked"})));
        assert_eq!(report["stages"]["binder"]["status"], "failed");
        assert_eq!(report["stages"]["spec"]["status"], "blocked");
    }
}
