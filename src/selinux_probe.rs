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
fn pending_exec_test() -> io::Result<i32> {
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
    Ok(error)
}

pub fn verify(root: &Path) -> io::Result<()> {
    let source = context("/proc/thread-self/attr/current")?;
    if source != "u:r:ksu:s0" || context("/sys/fs/selinux/enforce")? != "1" {
        return Err(io::Error::other(
            "requires ksu domain and SELinux Enforcing",
        ));
    }
    let hash_before = policy_hash();
    let executable = crate::guest_mounts::guest_path(root, "system/bin/servicemanager")?;
    let path = std::ffi::CString::new(executable.as_os_str().as_encoded_bytes())
        .map_err(io::Error::other)?;
    let mut label = [0u8; 4096];
    let n = unsafe {
        libc::getxattr(
            path.as_ptr(),
            c"security.selinux".as_ptr(),
            label.as_mut_ptr().cast(),
            label.len(),
        )
    };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    let label = std::str::from_utf8(&label[..n as usize])
        .map_err(io::Error::other)?
        .trim_matches('\0');
    if label != "u:object_r:servicemanager_exec:s0" {
        return Err(io::Error::other(format!(
            "unexpected guest entrypoint label: {label}"
        )));
    }
    let mut decisions = vec![
        query(&source, &source, "process", "setexec")?,
        query(&source, TARGET, "process", "transition")?,
        query(TARGET, label, "file", "entrypoint")?,
    ];
    for permission in ["execute", "open", "read", "getattr", "map"] {
        decisions.push(query(&source, label, "file", permission)?);
    }
    let pending_errno = pending_exec_test()?;
    let hash_after = policy_hash();
    let hash_same = match (&hash_before, &hash_after) {
        (Ok(a), Ok(b)) => Some(a == b),
        _ => None,
    };
    let final_sequence = query(&source, &source, "process", "setexec")?.sequence;
    let stable = hash_same != Some(false)
        && final_sequence == decisions[0].sequence
        && source == context("/proc/thread-self/attr/current")?
        && context("/sys/fs/selinux/enforce")? == "1";
    let allowed = stable
        && pending_errno == 0
        && decisions
            .iter()
            .all(|d| d.allowed && !d.permissive_domain && d.sequence == decisions[0].sequence);
    println!(
        "SELinux transition probe summary: {}",
        serde_json::json!({
            "validation_scope": "policy_prerequisites_and_pending_exec_only", "source": source, "target": TARGET,
            "guest_executable": executable, "entrypoint_label": label, "policy_sha256": hash_before.as_ref().ok(), "policy_hash_error": hash_before.as_ref().err().map(ToString::to_string), "policy_hash_same": hash_same,
            "boot_id": context("/proc/sys/kernel/random/boot_id")?, "decisions": decisions,
            "pending_exec_errno": pending_errno, "policy_av_sequence_and_parent_unchanged": stable,
            "queried_permissions_allowed": decisions.iter().all(|d| d.allowed),
            "source_domain_enforcing": !decisions[0].permissive_domain,
            "block_reason": if decisions.iter().any(|d| d.permissive_domain) { Some("permissive_source_domain_prevents_enforcing_validation") } else { None },
            "prerequisites": if allowed { "passed" } else { "failed" },
            "actual_exec_transition": "not_run", "servicemanager": "not_run", "policy_modified": false,
            "guest_security_boundary_verified": false, "child_reaped": true
        })
    );
    if !allowed {
        return Err(io::Error::other(
            "SELinux transition prerequisites blocked; no service executed or policy modified",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
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
