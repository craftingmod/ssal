//! Query the loaded policy; never execute an Android service or modify policy.
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::path::Path;
use std::time::{Duration, Instant};

#[cfg(target_os = "android")]
unsafe fn errno_ptr() -> *mut i32 {
    libc::__errno()
}
#[cfg(not(target_os = "android"))]
unsafe fn errno_ptr() -> *mut i32 {
    libc::__errno_location()
}

const TARGET: &str = "u:r:servicemanager:s0";

pub mod preflight;

fn context(path: &str) -> io::Result<String> {
    Ok(fs::read_to_string(path)?.trim_matches('\0').trim().into())
}

fn policy_hash() -> io::Result<String> {
    use sha2::{Digest, Sha256};
    let mut file = fs::File::open("/sys/fs/selinux/policy")?;
    let mut hash = Sha256::new();
    let mut buffer = [0; 65536];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hash.update(&buffer[..n]);
    }
    Ok(hash.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

#[derive(serde::Serialize)]
struct Decision {
    api: &'static str,
    class_index: u32,
    requested_mask: u32,
    allowed_mask: u32,
    flags: u32,
    raw_response: String,
    source: String,
    target: String,
    class: String,
    permission: String,
    allowed: bool,
    permissive_domain: bool,
    sequence: u32,
}

fn parse_av(reply: &str, requested: u32) -> io::Result<(bool, bool, u32)> {
    let fields: Vec<_> = reply.split_whitespace().collect();
    if fields.len() != 6 {
        return Err(io::Error::other("incomplete SELinux AV response"));
    }
    let hex = |s| u32::from_str_radix(s, 16).map_err(io::Error::other);
    let allowed = hex(fields[0])?;
    let decided = hex(fields[1])?;
    if decided & requested != requested {
        return Err(io::Error::other("permission not decided"));
    }
    Ok((
        allowed & requested == requested,
        hex(fields[5])? & 1 != 0,
        fields[4].parse().map_err(io::Error::other)?,
    ))
}

fn query(source: &str, target: &str, class: &str, permission: &str) -> io::Result<Decision> {
    let base = format!("/sys/fs/selinux/class/{class}");
    let index: u32 = fs::read_to_string(format!("{base}/index"))?
        .trim()
        .parse()
        .map_err(io::Error::other)?;
    let bit: u32 = fs::read_to_string(format!("{base}/perms/{permission}"))?
        .trim()
        .parse()
        .map_err(io::Error::other)?;
    let requested = bit
        .checked_sub(1)
        .and_then(|b| 1u32.checked_shl(b))
        .ok_or_else(|| io::Error::other("invalid permission bit"))?;
    let mut access = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/sys/fs/selinux/access")?;
    access
        .write_all(format!("{source} {target} {index} {requested:x}").as_bytes())
        .map_err(|e| io::Error::other(format!("AV write {class}:{permission}: {e}")))?;
    let mut reply = String::new();
    access
        .read_to_string(&mut reply)
        .map_err(|e| io::Error::other(format!("AV read {class}:{permission}: {e}")))?;
    let (allowed, permissive_domain, sequence) = parse_av(&reply, requested)?;
    Ok(Decision {
        api: "selinuxfs/access (security_compute_av_flags_raw wire protocol)",
        class_index: index,
        requested_mask: requested,
        allowed_mask: u32::from_str_radix(reply.split_whitespace().next().unwrap_or(""), 16)
            .map_err(io::Error::other)?,
        flags: u32::from_str_radix(reply.split_whitespace().nth(5).unwrap_or(""), 16)
            .map_err(io::Error::other)?,
        raw_response: reply,
        source: source.into(),
        target: target.into(),
        class: class.into(),
        permission: permission.into(),
        allowed,
        permissive_domain,
        sequence,
    })
}

// Create the pipe before fork; the child performs only libc calls, never Rust allocation,
// locks, exec, or a domain change. A pending exec context disappears on exit.
fn pending_exec_test() -> io::Result<(i32, u32)> {
    let mut pipe = [0; 2];
    if unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let reader = unsafe { <fs::File as std::os::fd::FromRawFd>::from_raw_fd(pipe[0]) };
    let writer = unsafe { <fs::File as std::os::fd::FromRawFd>::from_raw_fd(pipe[1]) };
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(io::Error::last_os_error());
    }
    if pid == 0 {
        unsafe {
            libc::close(reader.as_raw_fd());
            let fd = libc::open(
                c"/proc/thread-self/attr/exec".as_ptr(),
                libc::O_WRONLY | libc::O_CLOEXEC,
            );
            let errno = if fd < 0 { *errno_ptr() } else { 0 };
            let result = if fd < 0 {
                -1
            } else {
                libc::write(
                    fd,
                    c"u:r:servicemanager:s0".as_ptr().cast(),
                    TARGET.len() + 1,
                )
            };
            let error = if fd < 0 {
                errno
            } else if result < 0 {
                *errno_ptr()
            } else if result as usize != TARGET.len() + 1 {
                libc::EIO
            } else {
                0
            };
            libc::write(
                writer.as_raw_fd(),
                (&error as *const i32).cast(),
                std::mem::size_of::<i32>(),
            );
            libc::_exit(if error == 0 { 0 } else { 1 });
        }
    }
    drop(writer);
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut status = 0;
    loop {
        let waited = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if waited == pid {
            break;
        }
        if waited < 0 {
            if io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(io::Error::last_os_error());
        }
        if Instant::now() >= deadline {
            unsafe {
                libc::kill(pid, libc::SIGKILL);
                libc::waitpid(pid, &mut status, 0);
            }
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "pending exec child timed out; killed and reaped",
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let mut bytes = [0; 4];
    (&reader).read_exact(&mut bytes)?;
    let error = i32::from_ne_bytes(bytes);
    if !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != i32::from(error != 0) {
        return Err(io::Error::other("pending exec child status mismatch"));
    }
    Ok((error, pid as u32))
}

fn file_label(file: &fs::File) -> io::Result<String> {
    let mut bytes = [0; 4096];
    let n = unsafe {
        libc::fgetxattr(
            file.as_raw_fd(),
            c"security.selinux".as_ptr(),
            bytes.as_mut_ptr().cast(),
            bytes.len(),
        )
    };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(std::str::from_utf8(&bytes[..n as usize])
        .map_err(io::Error::other)?
        .trim_matches('\0')
        .into())
}

fn automatic_context(source: &str, label: &str) -> io::Result<String> {
    let class = context("/sys/fs/selinux/class/process/index")?;
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/sys/fs/selinux/create")?;
    file.write_all(format!("{source} {label} {class}").as_bytes())?;
    let mut reply = String::new();
    file.read_to_string(&mut reply)?;
    Ok(reply.trim_matches('\0').trim().into())
}

fn namespaces() -> io::Result<serde_json::Value> {
    let mut values = serde_json::Map::new();
    for entry in fs::read_dir("/proc/self/ns")? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        values.insert(name, serde_json::json!(fs::read_link(entry.path())?));
    }
    Ok(values.into())
}

fn host_services() -> io::Result<serde_json::Value> {
    let mut services = std::collections::BTreeMap::new();
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        if entry.file_name().to_string_lossy().parse::<u32>().is_err() {
            continue;
        }
        let command = match fs::read_to_string(entry.path().join("cmdline")) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let name = command
            .split('\0')
            .next()
            .unwrap_or("")
            .rsplit('/')
            .next()
            .unwrap_or("");
        if ![
            "init",
            "servicemanager",
            "zygote",
            "zygote64",
            "surfaceflinger",
        ]
        .contains(&name)
        {
            continue;
        }
        let stat = fs::read_to_string(entry.path().join("stat"))?;
        let fields: Vec<_> = stat
            .rsplit_once(") ")
            .ok_or_else(|| io::Error::other("invalid host stat"))?
            .1
            .split_whitespace()
            .collect();
        services.insert(entry.file_name().to_string_lossy().into_owned(), serde_json::json!({
            "name": name, "start_time": fields.get(19).ok_or_else(|| io::Error::other("missing start time"))?,
            "alive": !["Z", "X", "x"].contains(&fields[0]), "context": context(entry.path().join("attr/current").to_str().ok_or_else(|| io::Error::other("invalid proc path"))?)?,
            "executable": fs::read_link(entry.path().join("exe"))?
        }));
    }
    for required in ["init", "servicemanager", "zygote64", "surfaceflinger"] {
        if !services.values().any(|v| v["name"] == required) {
            return Err(io::Error::other(format!("missing host {required}")));
        }
    }
    Ok(serde_json::json!(services))
}

// The helper is pinned open and exec'd through that FD. Labels are only read.
fn exec_identity(
    helper: &fs::File,
    expected_ns: &serde_json::Value,
) -> io::Result<serde_json::Value> {
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};
    let meta = helper.metadata()?;
    let executable = format!("/proc/self/fd/{}", helper.as_raw_fd());
    let inherited: Vec<i32> = fs::read_dir("/proc/self/fd")?
        .filter_map(|e| e.ok()?.file_name().to_str()?.parse().ok())
        .filter(|fd| *fd > 2)
        .collect();
    let mut cmd = Command::new(executable);
    cmd.env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    unsafe {
        cmd.pre_exec(move || {
            for fd in &inherited {
                let flags = libc::fcntl(*fd, libc::F_GETFD);
                if flags >= 0 && libc::fcntl(*fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            let fd = libc::open(
                c"/proc/thread-self/attr/exec".as_ptr(),
                libc::O_WRONLY | libc::O_CLOEXEC,
            );
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            let n = libc::write(
                fd,
                c"u:r:servicemanager:s0".as_ptr().cast(),
                TARGET.len() + 1,
            );
            let error = io::Error::last_os_error();
            libc::close(fd);
            if n != (TARGET.len() + 1) as isize {
                return Err(error);
            }
            Ok(())
        });
    }
    let mut child = cmd.spawn()?;
    let pid = child.id();
    let deadline = Instant::now() + Duration::from_secs(3);
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            result => {
                let _ = child.kill();
                child.wait()?;
                return Err(match result {
                    Err(e) => e,
                    _ => io::Error::new(
                        io::ErrorKind::TimedOut,
                        "identity helper timed out; PID killed and reaped",
                    ),
                });
            }
        }
    };
    let mut output = String::new();
    child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("missing identity stdout"))?
        .take(16384)
        .read_to_string(&mut output)?;
    let identity: serde_json::Value = serde_json::from_str(&output)
        .map_err(|e| io::Error::other(format!("post-exec identity unavailable ({status}): {e}")))?;
    let valid = status.success()
        && identity["protocol"] == 1
        && identity["pid"] == pid
        && identity["context"] == TARGET
        && identity["uid"] == unsafe { libc::getuid() }
        && identity["euid"] == unsafe { libc::geteuid() }
        && identity["gid"] == unsafe { libc::getgid() }
        && identity["egid"] == unsafe { libc::getegid() }
        && identity["namespaces"] == *expected_ns
        && identity["executable_dev"] == meta.dev()
        && identity["executable_ino"] == meta.ino();
    Ok(
        serde_json::json!({"pid": pid, "child_reaped": true, "normal_exit": status.success(), "identity": identity, "matches_expected": valid}),
    )
}

pub fn verify(root: &Path) -> io::Result<()> {
    let source = context("/proc/thread-self/attr/current")?;
    let global_before = context("/sys/fs/selinux/enforce")?;
    let host_before = host_services()?;
    let ns = namespaces()?;
    let mut report = serde_json::json!({
        "validation_scope": "disposable_helper_explicit_exec_transition", "source": source, "target": TARGET,
        "global_enforcing": global_before == "1", "policy_permission_check": "unavailable",
        "source_domain_permissive": null, "target_domain_enforcing": null,
        "setexeccon": "not_run", "exec_transition": "not_run", "post_exec_identity": "not_run",
        "host_unchanged": "unavailable", "cleanup": "passed", "cleanup_scope": "probe_child_and_fds; mount_and_loop_result_follows",
        "host_before": host_before, "policy_modified": false, "servicemanager": "not_run",
        "boot_id": context("/proc/sys/kernel/random/boot_id")?
    });
    let hash_before = policy_hash();
    report["policy_sha256"] = serde_json::json!(hash_before.as_ref().ok());
    report["policy_hash_error"] =
        serde_json::json!(hash_before.as_ref().err().map(ToString::to_string));
    report["policy_permission_scope"] = serde_json::json!("kernel_computed_access_vectors; static allow rules not inspected; source permissive does not imply policy enforcement");
    report["parent_namespaces"] = ns.clone();
    report["automatic_transition_api"] = serde_json::json!(
        "selinuxfs/create process class; policy prediction only, no automatic exec performed"
    );
    let result = (|| -> io::Result<()> {
        if source != "u:r:ksu:s0" || global_before != "1" {
            return Err(io::Error::other("requires ksu and global Enforcing"));
        }
        let guest = fs::File::open(crate::guest_mounts::guest_path(
            root,
            "system/bin/servicemanager",
        )?)?;
        let guest_label = file_label(&guest)?;
        let mut original = vec![
            query(&source, &source, "process", "setexec")?,
            query(&source, TARGET, "process", "transition")?,
            query(TARGET, &guest_label, "file", "entrypoint")?,
        ];
        for permission in ["execute", "open", "read", "getattr", "map"] {
            original.push(query(&source, &guest_label, "file", permission)?);
        }
        report["source_domain_permissive"] = serde_json::json!(original[0].permissive_domain);
        let target = query(TARGET, TARGET, "process", "getattr")?;
        report["target_domain_enforcing"] = serde_json::json!(!target.permissive_domain);
        report["target_domain_query"] = serde_json::json!(target);
        report["guest_automatic_transition"] =
            serde_json::json!(automatic_context(&source, &guest_label)?);
        report["guest_permissions"] = serde_json::json!(original);
        let helper_path = std::env::current_exe()?.with_file_name("ssal-selinux-identity");
        let helper = fs::File::open(&helper_path)?;
        let label = file_label(&helper)?;
        report["helper"] = serde_json::json!({"path": helper_path, "label": label, "automatic_transition": automatic_context(&source, &label)?, "explicit_target": TARGET});
        let mut checks = vec![query(TARGET, &label, "file", "entrypoint")?];
        for permission in ["execute", "open", "read", "getattr", "map"] {
            checks.push(query(&source, &label, "file", permission)?);
        }
        let seq = original[0].sequence;
        let policy_ok = original
            .iter()
            .chain(checks.iter())
            .all(|d| d.allowed && d.sequence == seq)
            && target.sequence == seq;
        report["policy_permission_check"] =
            serde_json::json!(if policy_ok { "passed" } else { "failed" });
        report["denied_permissions"] = serde_json::json!(original
            .iter()
            .chain(checks.iter())
            .filter(|d| !d.allowed)
            .collect::<Vec<_>>());
        report["guest_permission_check"] =
            serde_json::json!(if original.iter().all(|d| d.allowed) {
                "passed"
            } else {
                "failed"
            });
        report["helper_permissions"] = serde_json::json!(checks);
        report["cleanup"] = serde_json::json!("unavailable");
        let (pending, pending_pid) = pending_exec_test()?;
        report["pending_child"] = serde_json::json!({"pid": pending_pid, "reaped": true});
        report["cleanup"] = serde_json::json!("passed");
        report["setexeccon"] = serde_json::json!(if pending == 0 { "passed" } else { "failed" });
        report["setexeccon_api"] = serde_json::json!(
            "/proc/thread-self/attr/exec (setexeccon kernel interface); disposable child only"
        );
        report["setexeccon_errno"] = serde_json::json!(pending);
        if !can_attempt_exec(policy_ok, target.permissive_domain, pending) {
            report["exec_transition"] = serde_json::json!("blocked");
            return Err(io::Error::other(format!("exec blocked: denied_permissions={}, target_permissive={}, setexeccon_errno={pending}; labels and policy unchanged", report["denied_permissions"], target.permissive_domain)));
        }
        let actual = exec_identity(&helper, &ns);
        match actual {
            Ok(value) => {
                let ok = value["matches_expected"] == true;
                report["exec_transition"] =
                    serde_json::json!(if value["identity"]["context"] == TARGET {
                        "passed"
                    } else {
                        "failed"
                    });
                report["post_exec_identity"] =
                    serde_json::json!(if ok { "passed" } else { "failed" });
                report["child"] = value;
                if !ok {
                    return Err(io::Error::other("post-exec identity mismatch"));
                }
            }
            Err(e) => {
                report["exec_transition"] = serde_json::json!("failed");
                report["cleanup"] = serde_json::json!("unavailable");
                return Err(e);
            }
        }
        Ok(())
    })();
    let host_after = host_services();
    let target_after = query(TARGET, TARGET, "process", "getattr");
    report["target_domain_after_query"] = serde_json::json!(target_after.as_ref().ok());
    let hash_after = policy_hash();
    let hash_same = match (&hash_before, &hash_after) {
        (Ok(a), Ok(b)) => Some(a == b),
        _ => None,
    };
    report["policy_hash_same"] = serde_json::json!(hash_same);
    let final_query = query(&source, &source, "process", "setexec");
    let stable = final_query
        .as_ref()
        .is_ok_and(|v| report["guest_permissions"][0]["sequence"] == v.sequence)
        && hash_same != Some(false)
        && target_after.as_ref().is_ok_and(|v| {
            !v.permissive_domain && report["guest_permissions"][0]["sequence"] == v.sequence
        })
        && context("/sys/fs/selinux/enforce").is_ok_and(|s| s == global_before)
        && context("/proc/thread-self/attr/current").is_ok_and(|s| s == source);
    let host_ok = host_after.as_ref().is_ok_and(|v| *v == host_before)
        && stable
        && namespaces().is_ok_and(|v| v == ns);
    report["host_after"] = serde_json::json!(host_after.as_ref().ok());
    report["host_after_error"] =
        serde_json::json!(host_after.as_ref().err().map(ToString::to_string));
    report["host_unchanged"] = serde_json::json!(if host_ok { "passed" } else { "failed" });
    report["policy_av_sequence_unchanged"] = serde_json::json!(stable);
    report["failure"] = serde_json::json!(result.as_ref().err().map(ToString::to_string));
    println!("SELinux transition probe summary: {report}");
    result?;
    if !host_ok {
        return Err(io::Error::other("host or policy state changed"));
    }
    Ok(())
}

fn can_attempt_exec(
    permissions_allowed: bool,
    target_permissive: bool,
    setexec_errno: i32,
) -> bool {
    permissions_allowed && !target_permissive && setexec_errno == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn denied_entrypoint_or_permissive_target_never_reaches_exec() {
        assert!(!can_attempt_exec(false, false, 0));
        assert!(!can_attempt_exec(true, true, 0));
        assert!(!can_attempt_exec(true, false, libc::EACCES));
        // A permissive source is reported separately; it cannot turn a target
        // entrypoint denial into permission to run the experiment.
        assert!(can_attempt_exec(true, false, 0));
    }
    #[test]
    fn av_denial_permissive_and_incomplete_are_distinct() {
        assert_eq!(
            parse_av("4 ffffffff 0 0 42 0", 4).unwrap(),
            (true, false, 42)
        );
        assert_eq!(
            parse_av("0 ffffffff 0 0 42 1", 4).unwrap(),
            (false, true, 42)
        );
        assert!(parse_av("4 0 0 0 42 0", 4).is_err());
        assert!(parse_av("4 ffffffff 0 0 42", 4).is_err());
    }
}
