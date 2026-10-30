//! Read-only observations. No setexeccon, exec, Binder open/ioctl, or socket connect.
use super::*;
use serde_json::{json, Value};
use std::os::unix::fs::{FileTypeExt, MetadataExt};

fn digest(path: &Path) -> io::Result<String> {
    use sha2::{Digest, Sha256};
    let mut file = fs::File::open(path)?;
    let mut hash = Sha256::new();
    let mut bytes = [0; 65536];
    loop {
        let n = file.read(&mut bytes)?;
        if n == 0 {
            break;
        }
        hash.update(&bytes[..n]);
    }
    Ok(hash.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

fn metadata(path: &Path) -> io::Result<Value> {
    let meta = fs::metadata(path)?;
    let name =
        std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).map_err(io::Error::other)?;
    let mut bytes = [0; 4096];
    let n = unsafe {
        libc::getxattr(
            name.as_ptr(),
            c"security.selinux".as_ptr(),
            bytes.as_mut_ptr().cast(),
            bytes.len(),
        )
    };
    let label = if n < 0 {
        None
    } else {
        Some(
            std::str::from_utf8(&bytes[..n as usize])
                .map_err(io::Error::other)?
                .trim_matches('\0')
                .to_owned(),
        )
    };
    Ok(
        json!({"path": path, "dev": meta.dev(), "ino": meta.ino(), "rdev": meta.rdev(),
        "major": libc::major(meta.rdev()), "minor": libc::minor(meta.rdev()), "mode": format!("{:o}", meta.mode()),
        "uid": meta.uid(), "gid": meta.gid(), "label": label, "char_device": meta.file_type().is_char_device(),
        "socket": meta.file_type().is_socket(), "directory": meta.is_dir()}),
    )
}

fn observe(root: &Path, name: &str) -> Value {
    let guest = crate::guest_mounts::guest_path(root, name).and_then(|p| metadata(&p));
    let host = metadata(&Path::new("/").join(name));
    let same = match (&guest, &host) {
        (Ok(a), Ok(b)) => {
            Some(a["dev"] == b["dev"] && a["ino"] == b["ino"] && a["rdev"] == b["rdev"])
        }
        _ => None,
    };
    json!({"guest_path": format!("/{name}"), "guest": guest.as_ref().ok(), "guest_error": guest.as_ref().err().map(ToString::to_string),
        "host": host.as_ref().ok(), "host_error": host.as_ref().err().map(ToString::to_string), "same_host_object": same})
}

fn rc_spec(contents: &str) -> io::Result<Value> {
    let mut active = false;
    let mut directives = std::collections::BTreeMap::new();
    let mut service = None;
    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if !line.starts_with(char::is_whitespace) {
            active = trimmed == "service servicemanager /system/bin/servicemanager";
            if active {
                service = Some(trimmed.to_owned());
            }
            continue;
        }
        if active {
            let (key, value) = trimmed
                .split_once(char::is_whitespace)
                .unwrap_or((trimmed, ""));
            if [
                "user",
                "group",
                "file",
                "task_profiles",
                "capabilities",
                "rlimit",
                "seclabel",
                "namespace",
            ]
            .contains(&key)
            {
                directives
                    .entry(key.to_owned())
                    .or_insert_with(Vec::new)
                    .push(value.trim().to_owned());
            }
        }
    }
    if service.is_none() {
        return Err(io::Error::other(
            "Guest servicemanager service block not found",
        ));
    }
    let matches = directives.get("user") == Some(&vec!["system".into()])
        && directives.get("group") == Some(&vec!["system readproc".into()]);
    Ok(
        json!({"service": service, "directives": directives, "matches_android16_credentials": matches,
        "expected": {"uid": 1000, "gid": 1000, "supplementary_groups": [3009], "file_fd": "/dev/kmsg write via init file directive",
            "explicit_capabilities_in_reference_rc": false, "task_profile": "ProcessCapacityHigh", "reference": "android-16.0.0_r2"},
        "init_onrestart_actions": "not inherited or executed by SSAL; no host restart actions allowed"}),
    )
}

fn fds() -> io::Result<Value> {
    let numbers: Vec<i32> = fs::read_dir("/proc/self/fd")?
        .filter_map(|e| e.ok()?.file_name().to_str()?.parse().ok())
        .collect();
    let mut result = Vec::new();
    for fd in numbers {
        if let Ok(target) = fs::read_link(format!("/proc/self/fd/{fd}")) {
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            result.push(json!({"fd": fd, "target": target, "cloexec": flags >= 0 && flags & libc::FD_CLOEXEC != 0}));
        }
    }
    Ok(json!(result))
}

pub fn verify(root: &Path) -> io::Result<()> {
    let source = context("/proc/thread-self/attr/current")?;
    let host_before = host_services()?;
    let before_ns = namespaces()?;
    let global_before = context("/sys/fs/selinux/enforce")?;
    let mut report = json!({"validation_scope": "formal_servicemanager_read_only_preflight", "policy_permissions": "unavailable",
        "entrypoint": "unavailable", "domain_transition": "not_run", "execution_prerequisites": "blocked", "host_isolation": "blocked",
        "cleanup": "passed", "cleanup_scope": "preflight_fds_only; session_resource_reports_follow", "service_executed": false,
        "policy_modified": false, "labels_modified": false, "source": source, "target": TARGET, "global_enforcing": global_before == "1",
        "launch_enabled": false, "boot_id": context("/proc/sys/kernel/random/boot_id")?, "host_before": host_before, "worker_namespaces": before_ns});
    let result = (|| -> io::Result<()> {
        if source != "u:r:ksu:s0" || global_before != "1" {
            return Err(io::Error::other("requires ksu and global Enforcing"));
        }
        let path = crate::guest_mounts::guest_path(root, "system/bin/servicemanager")?;
        let file = fs::File::open(&path)?;
        let label = file_label(&file)?;
        report["executable"] = json!({"metadata": metadata(&path)?, "sha256": digest(&path)?, "expected_label": "u:object_r:servicemanager_exec:s0"});
        let mut decisions = vec![
            query(&source, &source, "process", "setexec")?,
            query(&source, TARGET, "process", "transition")?,
            query(TARGET, &label, "file", "entrypoint")?,
        ];
        for permission in ["execute", "open", "read", "getattr", "map"] {
            decisions.push(query(&source, &label, "file", permission)?);
        }
        let seq = decisions[0].sequence;
        let permissions_ok = decisions.iter().all(|d| d.allowed && d.sequence == seq);
        report["policy_permissions"] = json!(if permissions_ok { "passed" } else { "failed" });
        report["entrypoint"] = json!(if label == "u:object_r:servicemanager_exec:s0"
            && decisions[2].allowed
        {
            "passed"
        } else {
            "failed"
        });
        report["source_domain_permissive"] = json!(decisions[0].permissive_domain);
        report["permission_decisions"] = json!(decisions);
        report["permission_scope"] = json!("loaded kernel effective AV only; not proof of unmodified Samsung allow rules or successful exec");
        let target = query(TARGET, TARGET, "process", "getattr")?;
        report["target_domain_enforcing"] = json!(!target.permissive_domain);
        report["target_domain_query"] = json!(target);
        report["automatic_transition_prediction"] = json!(automatic_context(&source, &label)?);
        report["explicit_transition_prerequisites"] =
            json!(if permissions_ok && !target.permissive_domain {
                "allowed_by_queried_effective_AV"
            } else {
                "blocked"
            });
        let mountinfo = fs::read_to_string("/proc/self/mountinfo")?;
        let execution_mount = mountinfo
            .lines()
            .filter_map(|line| {
                let mountpoint = line.split_whitespace().nth(4)?;
                if path.starts_with(mountpoint) {
                    Some((mountpoint.len(), line))
                } else {
                    None
                }
            })
            .max_by_key(|(length, _)| *length)
            .map(|(_, line)| line);
        report["executable_mountinfo"] = json!(execution_mount);
        let cap_path = "/sys/fs/selinux/policy_capabilities/nnp_nosuid_transition";
        let cap = context(cap_path);
        let mut process2 = Vec::new();
        if Path::new("/sys/fs/selinux/class/process2").exists() {
            for permission in ["nosuid_transition", "nnp_transition"] {
                let decision = query(&source, TARGET, "process2", permission);
                process2.push(json!({"permission": permission, "decision": decision.as_ref().ok(), "error": decision.as_ref().err().map(ToString::to_string)}));
            }
        }
        report["nnp_nosuid_transition"] = json!({"policy_capability": cap.as_ref().ok(), "capability_read_error": cap.as_ref().err().map(ToString::to_string), "decisions": process2,
            "scope": "additional transition constraints; mount nosuid and process NoNewPrivs must be accounted for; no exec proof"});
        let policy = policy_hash();
        report["policy_sha256"] = json!(policy.as_ref().ok());
        report["policy_read_error"] = json!(policy.as_ref().err().map(ToString::to_string));
        report["stock_samsung_policy_only"] = json!("unavailable: current kernel has KernelSU and permissive ksu; original policy not independently available");
        let rc_path = crate::guest_mounts::guest_path(root, "system/etc/init/servicemanager.rc")?;
        report["rc"] = rc_spec(&fs::read_to_string(&rc_path)?)?;
        report["rc"]["sha256"] = json!(digest(&rc_path)?);
        report["rc"]["path"] = json!(rc_path);
        let status = fs::read_to_string("/proc/self/status")?;
        report["worker_credentials"] = json!(status
            .lines()
            .filter(|l| [
                "Uid:",
                "Gid:",
                "Groups:",
                "CapInh:",
                "CapPrm:",
                "CapEff:",
                "CapBnd:",
                "CapAmb:",
                "NoNewPrivs:"
            ]
            .iter()
            .any(|p| l.starts_with(p)))
            .collect::<Vec<_>>());
        report["credentials_applied_to_service"] = json!("not_run; uid/gid/groups/capabilities/rlimits/task profile launcher not implemented or verified here");
        report["worker_fds"] = fds()?;
        report["init_fd_environment"] = json!(std::env::vars()
            .filter(
                |(key, _)| key.starts_with("ANDROID_SOCKET_") || key.starts_with("ANDROID_FILE_")
            )
            .collect::<std::collections::BTreeMap<_, _>>());
        let binder = observe(root, "dev/binder");
        if let Some(label) = binder["guest"]["label"].as_str() {
            let mut access = Vec::new();
            for permission in ["open", "read", "write", "getattr", "ioctl", "map"] {
                access.push(query(TARGET, label, "chr_file", permission)?);
            }
            report["binder_target_permissions"] = json!(access);
        }
        report["binder_context_manager_permission"] =
            json!(query(TARGET, TARGET, "binder", "set_context_mgr")?);
        report["binder"] = binder;
        report["binder_dac_scope"] = json!("observed mode/owner only; inspect node permission bits for uid 1000/gid 1000/groups 3009; host Binder must not be accepted as a private context; path traversal and ioctl xperms not proven");
        report["paths"] = json!([
            "dev/hwbinder",
            "dev/vndbinder",
            "dev/binderfs",
            "dev/__properties__",
            "dev/socket/property_service",
            "dev/socket/property_service_for_system",
            "dev/socket/logdw",
            "dev/kmsg",
            "proc",
            "sys/fs/selinux",
            "linkerconfig/ld.config.txt",
            "system/etc/selinux/plat_service_contexts",
            "vendor/etc/selinux/vendor_service_contexts"
        ]
        .iter()
        .map(|p| observe(root, p))
        .collect::<Vec<_>>());
        let mut runtime = Vec::new();
        let mut runtime_denials = Vec::new();
        for (name, class, permissions) in [
            (
                "linkerconfig",
                "dir",
                &["search", "open", "read", "getattr"][..],
            ),
            (
                "dev/__properties__",
                "dir",
                &["search", "open", "read", "getattr"][..],
            ),
            (
                "system/bin/linker64",
                "file",
                &["execute", "open", "read", "getattr", "map"][..],
            ),
            (
                "linkerconfig/ld.config.txt",
                "file",
                &["open", "read", "getattr", "map"][..],
            ),
            (
                "system/etc/selinux/plat_service_contexts",
                "file",
                &["open", "read", "getattr", "map"][..],
            ),
            (
                "vendor/etc/selinux/vendor_service_contexts",
                "file",
                &["open", "read", "getattr", "map"][..],
            ),
            (
                "sys/fs/selinux/status",
                "file",
                &["open", "read", "getattr", "map"][..],
            ),
            (
                "system/lib64/libbinder.so",
                "file",
                &["open", "read", "getattr", "map", "execute"][..],
            ),
            (
                "apex/com.android.runtime/lib64/bionic/libc.so",
                "file",
                &["open", "read", "getattr", "map", "execute"][..],
            ),
        ] {
            let observation = observe(root, name);
            let mut decisions = Vec::new();
            if let Some(label) = observation["guest"]["label"].as_str() {
                for permission in permissions {
                    let decision = query(TARGET, label, class, permission)?;
                    if !decision.allowed {
                        runtime_denials.push(json!({"path": name, "decision": decision}));
                    }
                    decisions.push(decision);
                }
            }
            runtime.push(json!({"path": name, "observation": observation, "decisions": decisions}));
        }
        report["target_runtime_access"] = json!(runtime);
        report["target_runtime_denials"] = json!(runtime_denials);
        report["runtime_access_scope"] = json!("representative path AV checks only; mmap/ioctl xperms, full dependency closure, DAC traversal and dynamic loader operation not proven");
        report["runtime_denial_interpretation"] = json!("directory open/read are exploratory and not all required for traversal; linkerconfig file open/read denial is a concrete loader configuration access blocker; search is reported independently");
        let mut candidate = Vec::new();
        for permission in ["open", "read", "write", "getattr", "ioctl", "map"] {
            candidate.push(query(
                TARGET,
                "u:object_r:binderfs:s0",
                "chr_file",
                permission,
            )?);
        }
        report["private_binder_candidate"] = json!({"label": "u:object_r:binderfs:s0", "scope": "candidate based on earlier Test A label; no private node created, opened or relabeled in this run", "decisions": candidate});
        report["namespaces"] = json!({"worker_vs_host_init_mount": fs::read_link("/proc/1/ns/mnt").ok().map(|v| json!(v)), "pid_namespace_isolation": "not_created_by_prepare", "proc_view": "fresh proc mount does not by itself isolate PIDs", "net_namespace_isolation": "not_created_by_prepare", "root_for_service": "not_applied; diagnostic examines composed root by path", "mount_policy": "private mount namespace, shared host dev with socket/block masks"});
        report["runtime_requirements"] = json!({"binder": "fresh private framework context, explicit driver path, no fallback, DAC uid 1000/gid 1000 and SELinux chr_file access plus context-manager permission",
            "fds": "close inherited host Binder/property/root-directory FDs; provide deliberate stdio and logging FD policy; runtime verification not performed",
            "property": "AOSP main writes servicemanager.ready; bionic connects /dev/socket/property_service, sys.powerctl may use property_service_for_system; no requests or connections sent",
            "logging": "rc opens /dev/kmsg write and main uses KernelLogger; host kernel/log sockets must not be mistaken for isolated guest logging",
            "runtime": "linker libraries, service_contexts, SELinux status access, task profile and rlimits need target-credential runtime proof"});
        report["binder_fallback_reference"] = json!("AOSP android-16.0.0_r2 ProcessState::init falls back to /dev/binder when access(requested_driver, R_OK) fails; an explicit private path alone does not protect host Binder");
        let mut blockers = vec![
            "service credential/capability/FD/task-profile launcher not verified",
            "private framework Binder not provisioned by this preflight",
            "property client/FD/namespace isolation not proven for exact guest binaries",
            "guest property area/service not initialized",
            "host kernel logging path exposed",
            "target-domain dynamic linker/library/context-file access not runtime verified",
        ];
        if report["binder"]["same_host_object"] == true {
            blockers.push("guest /dev/binder is the same host Binder object; must never start guest context manager here");
        }
        if report["rc"]["matches_android16_credentials"] != true {
            blockers.push("guest rc credentials differ from Android 16 reference");
        }
        if !permissions_ok {
            blockers.push("formal executable transition AV permission denied or inconsistent");
        }
        if !runtime_denials.is_empty() {
            blockers.push("target-domain AV denies recorded runtime path permissions; see target_runtime_denials");
        }
        if candidate.iter().any(|d| !d.allowed) {
            blockers.push("target-domain access denied for prior Test A private Binder candidate label binderfs; no policy changes attempted");
        }
        report["blockers"] = json!(blockers);
        report["unsafe_paths_used"] = json!(false);
        let final_query = query(&source, &source, "process", "setexec")?;
        let target_after = query(TARGET, TARGET, "process", "getattr")?;
        let stable = final_query.sequence == seq
            && target_after.sequence == seq
            && target_after.permissive_domain == target.permissive_domain;
        report["target_domain_after_query"] = json!(target_after);
        report["policy_sequence_unchanged"] = json!(stable);
        if !stable {
            report["policy_permissions"] = json!("unavailable");
            report["entrypoint"] = json!("unavailable");
        }
        Ok(())
    })();
    let host_after = host_services();
    let unchanged = host_after.as_ref().is_ok_and(|v| *v == host_before)
        && namespaces().is_ok_and(|v| v == before_ns)
        && context("/proc/thread-self/attr/current").is_ok_and(|v| v == source)
        && context("/sys/fs/selinux/enforce").is_ok_and(|v| v == global_before);
    report["host_after"] = json!(host_after.as_ref().ok());
    report["observed_host_unchanged"] = json!(if unchanged { "passed" } else { "failed" });
    report["diagnostic_error"] = json!(result.as_ref().err().map(ToString::to_string));
    println!("Servicemanager preflight summary: {report}");
    result?;
    Err(io::Error::other("servicemanager preflight blocked: execution prerequisites and host isolation not ready; no service executed"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rc_credentials_must_come_from_exact_service_block() {
        let text = "service servicemanager /system/bin/servicemanager\n    user system\n    group system readproc\nservice other /bin/other\n    user root\n";
        assert_eq!(
            rc_spec(text).unwrap()["matches_android16_credentials"],
            true
        );
        assert_eq!(
            rc_spec(&text.replace("group system readproc", "group root")).unwrap()
                ["matches_android16_credentials"],
            false
        );
        assert!(rc_spec(
            "service other /system/bin/other\n    user system\n    group system readproc\n"
        )
        .is_err());
    }
}
