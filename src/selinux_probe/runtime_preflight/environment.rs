//! Guest-only mutable preparation and a fixed, non-service identity worker.
use super::*;
use std::ffi::CString;
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};

const BINDER_LABEL: &str = "u:object_r:binder_device:s0";
const LINKER_LABEL: &str = "u:object_r:linkerconfig_file:s0";

fn cpath(path: &Path) -> io::Result<CString> {
    CString::new(path.as_os_str().as_encoded_bytes()).map_err(io::Error::other)
}

fn syscall_result(rc: i32) -> io::Result<()> {
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn set_label(file: &fs::File, label: &str) -> io::Result<()> {
    syscall_result(unsafe {
        libc::fsetxattr(
            file.as_raw_fd(),
            c"security.selinux".as_ptr(),
            label.as_ptr().cast(),
            label.len(),
            0,
        )
    })
}

fn attempt(result: io::Result<()>) -> Value {
    match result {
        Ok(()) => json!({"status": "passed"}),
        Err(e) => json!({"status": "blocked", "errno": e.raw_os_error(), "error": e.to_string()}),
    }
}

pub(crate) fn prepare_labels(
    root: &Path,
    binder: &mut crate::binder_probe::Session,
) -> io::Result<Value> {
    let original_binder = file_label(binder.private_device()?)?;
    let mut attempts = if original_binder == BINDER_LABEL {
        vec![json!({"method":"original_genfs_label","result":{"status":"passed"}})]
    } else {
        vec![
            json!({"method": "private_fd_fsetxattr", "result": attempt(set_label(binder.private_device()?, BINDER_LABEL))}),
        ]
    };
    if file_label(binder.private_device()?)? != BINDER_LABEL {
        // A fresh security-context mount is also scoped to our private superblock.
        // Never remount, relabel or chmod the shared Host device/superblock.
        binder.cleanup()?;
        *binder = crate::binder_probe::Session::new();
        let labeled = binder.provision_with_context(root, Some(BINDER_LABEL));
        attempts.push(json!({"method": "fresh_private_binderfs_context_mount", "result": match &labeled { Ok(v) => json!({"status": "passed", "identity": v}), Err(e) => json!({"status": "blocked", "error": e.to_string()}) }}));
        if labeled.is_err() {
            binder.cleanup()?;
            *binder = crate::binder_probe::Session::new();
            binder.provision(root)?;
        }
    }
    let binder_label = file_label(binder.private_device()?)?;
    let linker = crate::guest_mounts::guest_path(root, "linkerconfig/ld.config.txt")?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&linker)?;
    let meta = file.metadata()?;
    let host = fs::metadata("/linkerconfig/ld.config.txt")?;
    let parent = fs::metadata(root.join("linkerconfig"))?;
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    syscall_result(unsafe { libc::fstatfs(file.as_raw_fd(), &mut stat) })?;
    // Generated file on the dedicated Guest tmpfs, never a shared source inode.
    if linker != root.join("linkerconfig/ld.config.txt")
        || !meta.is_file()
        || meta.nlink() != 1
        || (meta.dev(), meta.ino()) == (host.dev(), host.ino())
        || meta.dev() != parent.dev()
        || parent.dev() == host.dev()
        || stat.f_type as u64 != 0x01021994
    {
        return Err(io::Error::other(
            "Guest linkerconfig ownership guard failed",
        ));
    }
    let original_linker = file_label(&file)?;
    let linker_attempt = attempt(set_label(&file, LINKER_LABEL));
    let linker_label = file_label(&file)?;
    let binder_av = label_access(
        &binder_label,
        "chr_file",
        &["open", "read", "write", "getattr", "ioctl", "map"],
    )?;
    let linker_av = label_access(&linker_label, "file", &["open", "read", "getattr", "map"])?;
    let ok = binder_label == BINDER_LABEL
        && linker_label == LINKER_LABEL
        && binder_av["status"] == "passed"
        && linker_av["status"] == "passed";
    Ok(
        json!({"status": if ok { "passed" } else { "blocked" }, "binder": {"original_label": original_binder, "attempts": attempts, "label": binder_label, "av": binder_av, "identity": observe(root, "dev/binder")}, "linkerconfig": {"original_label": original_linker, "attempt": linker_attempt, "label": linker_label, "av": linker_av}, "scope": "temporary owned Guest resources and loaded-policy AV only; no target-domain exec or xperm proof"}),
    )
}

pub(crate) struct Masks {
    pub(crate) paths: Vec<std::path::PathBuf>,
}
impl Masks {
    pub(crate) fn mount(
        &mut self,
        source: &str,
        target: &Path,
        kind: Option<&str>,
        flags: libc::c_ulong,
        options: &str,
    ) -> io::Result<()> {
        let source = CString::new(source).map_err(io::Error::other)?;
        let kind = kind
            .map(CString::new)
            .transpose()
            .map_err(io::Error::other)?;
        let options = CString::new(options).map_err(io::Error::other)?;
        syscall_result(unsafe {
            libc::mount(
                source.as_ptr(),
                cpath(target)?.as_ptr(),
                kind.as_ref().map_or(std::ptr::null(), |v| v.as_ptr()),
                flags,
                options.as_ptr().cast(),
            )
        })?;
        self.paths.push(target.to_owned());
        Ok(())
    }
    pub(crate) fn cleanup(&mut self) -> io::Result<()> {
        while let Some(path) = self.paths.last() {
            syscall_result(unsafe { libc::umount2(cpath(path)?.as_ptr(), 0) })?;
            self.paths.pop();
        }
        Ok(())
    }
}
impl Drop for Masks {
    fn drop(&mut self) {
        if let Err(e) = self.cleanup() {
            eprintln!("RECOVERY_REQUIRED runtime masks: {e}");
        }
    }
}

fn run_identity(root: &Path, private_rdev: u64, host_rdev: u64) -> io::Result<Value> {
    let mut command = Command::new(std::env::current_exe()?);
    command
        .arg("--runtime-credentials-worker")
        .arg(root)
        .arg(private_rdev.to_string())
        .arg(host_rdev.to_string())
        .env_clear()
        .env("PATH", "/system/bin")
        .env("ANDROID_ROOT", "/system")
        .env("ANDROID_DATA", "/data")
        .stdin(Stdio::null());
    let inherited: Vec<i32> = fs::read_dir("/proc/self/fd")?
        .filter_map(|e| e.ok()?.file_name().to_str()?.parse().ok())
        .filter(|fd| *fd > 2)
        .collect();
    unsafe {
        command.pre_exec(move || {
            syscall_result(libc::setpgid(0, 0))?;
            for fd in &inherited {
                let flags = libc::fcntl(*fd, libc::F_GETFD);
                if flags >= 0 {
                    syscall_result(libc::fcntl(*fd, libc::F_SETFD, flags | libc::FD_CLOEXEC))?;
                }
            }
            Ok(())
        });
    }
    let output = crate::guest_probe::run_with_timeout(
        &mut command,
        "runtime credentials",
        Duration::from_secs(5),
    )?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "identity worker {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    let value: Value = serde_json::from_slice(&output.stdout).map_err(io::Error::other)?;
    if value["protocol"] != 2 || value["child_pid"].as_u64().is_none() {
        return Err(io::Error::other("invalid identity protocol"));
    }
    Ok(json!({"status": "passed", "child_reaped": true, "identity": value}))
}

pub(crate) fn minimal_devices(
    root: &Path,
    binder: &crate::binder_probe::Session,
    masks: &mut Masks,
) -> io::Result<()> {
    let dev = root.join("dev");
    masks.mount(
        "tmpfs",
        &dev,
        Some("tmpfs"),
        libc::MS_NOSUID | libc::MS_NOEXEC,
        "mode=0755",
    )?;
    for directory in ["socket", "__properties__"] {
        fs::create_dir(dev.join(directory))?;
        fs::set_permissions(dev.join(directory), fs::Permissions::from_mode(0o555))?;
    }
    for name in ["binder", "null", "kmsg"] {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o000)
            .open(dev.join(name))?;
    }
    masks.mount(
        &format!("/proc/self/fd/{}", binder.private_device()?.as_raw_fd()),
        &dev.join("binder"),
        None,
        libc::MS_BIND,
        "",
    )?;
    masks.mount("/dev/null", &dev.join("null"), None, libc::MS_BIND, "")?;
    masks.mount(
        "tmpfs",
        &root.join("proc"),
        Some("tmpfs"),
        libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
        "mode=0555",
    )?;
    Ok(())
}

pub(super) fn verify(root: &Path, binder: &mut crate::binder_probe::Session) -> io::Result<Value> {
    let mut report = json!({"selinux_label_compatibility": {"status":"not_run"}, "binder_dac": {"status":"not_run"}, "binder_isolation": {"status":"not_run"}, "execution_credentials": {"status":"not_run"}, "namespace_isolation": {"status":"not_run"}, "property_isolation": {"status":"not_run"}, "media_isolation": {"status":"not_run"}});
    if fs::read_link("/proc/self/ns/mnt")? == fs::read_link("/proc/1/ns/mnt")? {
        return Err(io::Error::other(
            "Guest mutation requires separate mount namespace",
        ));
    }
    match prepare_labels(root, binder) {
        Ok(value) => report["selinux_label_compatibility"] = value,
        Err(e) => {
            report["selinux_label_compatibility"] =
                json!({"status":"failed", "error": e.to_string()});
            return Ok(report);
        }
    }
    let device = binder.private_device()?;
    let dac = syscall_result(unsafe { libc::fchown(device.as_raw_fd(), 1000, 1000) })
        .and_then(|()| syscall_result(unsafe { libc::fchmod(device.as_raw_fd(), 0o600) }));
    if let Err(e) = dac {
        report["binder_dac"] = json!({"status":"failed", "error": e.to_string()});
        return Ok(report);
    }
    let private = device.metadata()?.rdev();
    let host = fs::metadata("/dev/binder")?.rdev();
    report["prepared_binder"] = json!({"uid": device.metadata()?.uid(), "gid": device.metadata()?.gid(), "mode": device.metadata()?.mode(), "private_rdev": private, "host_rdev": host});
    report["composed_view_trial"] = match run_identity(root, private, host) {
        Ok(v) => v,
        Err(e) => json!({"status":"failed", "error":e.to_string()}),
    };
    let mut masks = Masks { paths: Vec::new() };
    let result = (|| -> io::Result<()> {
        minimal_devices(root, binder, &mut masks)?;
        let trial = run_identity(root, private, host)?;
        let identity = &trial["identity"];
        report["execution_credentials"] = json!({"status": if valid_credentials(identity) { "passed" } else { "failed" }, "trial": trial, "selinux_service_domain": "not_run; identity worker domain must not be treated as servicemanager success"});
        let identity = report["execution_credentials"]["trial"]["identity"].clone();
        report["binder_dac"] = json!({"status": if identity["private_binder"]["opened_private"] == true { "passed" } else { "blocked" }, "result": identity["private_binder"], "scope": "actual open and BINDER_VERSION under UID/GID 1000 and observed domain"});
        report["namespace_isolation"] = json!({"status": "blocked", "namespaces": identity["namespaces"], "root": identity["root"], "proc": identity["access"]["/proc/1/root/dev/binder"], "reason": "empty proc mask removes Host proc paths but is not a functional private proc/PID environment; task profile destination remains unprepared"});
        let paths = &identity["access"];
        let property_ok = denied(paths, "/dev/socket/property_service")
            && denied(paths, "/dev/socket/property_service_for_system")
            && paths["/dev/__properties__/properties_serial"]["errno"] == libc::ENOENT;
        report["property_isolation"] = json!({"status": if property_ok && valid_credentials(&identity) { "passed" } else { "blocked" }, "scope": "minimal dev has fresh empty property area/socket directory, no inherited sockets; tested paths only, no requests sent; Guest property service unavailable", "paths": paths});
        report["logging"] = json!({"status": if denied(paths, "/dev/kmsg") { "passed" } else { "blocked" }, "backend": "session stdout/stderr pipes; no init kmsg FD; exact servicemanager logging adaptation not implemented", "result": paths["/dev/kmsg"]});
        let media = protections(root)?;
        report["media_isolation"] = media["media"].clone();
        report["isolated_view_privileged_observation"] = media;
        // Negative control: default Binder path becomes a private denied file.
        let denied_file = root.join("run/ssal/runtime-denied-binder");
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o000)
            .open(&denied_file)?;
        masks.mount(
            denied_file
                .to_str()
                .ok_or_else(|| io::Error::other("invalid deny path"))?,
            &root.join("dev/binder"),
            None,
            libc::MS_BIND,
            "",
        )?;
        let negative = run_identity(root, private, host)?;
        let positive = &report["execution_credentials"]["trial"]["identity"];
        let isolated = positive["private_binder"]["opened_private"] == true
            && denied(&positive["access"], "/proc/1/root/dev/binder")
            && negative["identity"]["private_binder"]["opened_private"] == false
            && negative["identity"]["private_binder"]["host_open_attempted"] == false
            && valid_credentials(&negative["identity"]);
        report["binder_isolation"] = json!({"status": if isolated { "passed" } else { "blocked" }, "negative_control": negative, "scope": "fixed helper uses only default driver; minimal dev and empty proc remove Host driver aliases; actual libbinder/servicemanager fallback and service-domain access remain not_run"});
        Ok(())
    })();
    let cleanup = masks.cleanup();
    report["temporary_view_cleanup"] = json!({"status": if cleanup.is_ok() { "passed" } else { "failed" }, "error": cleanup.as_ref().err().map(ToString::to_string)});
    cleanup
        .map_err(|e| io::Error::other(format!("RECOVERY_REQUIRED: runtime mask cleanup: {e}")))?;
    if let Err(e) = result {
        if report["execution_credentials"]["status"] == "not_run" {
            report["execution_credentials"] = json!({"status":"failed", "error": e.to_string()});
        }
        report["diagnostic_error"] = json!(e.to_string());
    }
    Ok(report)
}

fn denied(paths: &Value, path: &str) -> bool {
    paths[path]["errno"].as_i64().is_some_and(|e| {
        [
            i64::from(libc::EACCES),
            i64::from(libc::ENOENT),
            i64::from(libc::EPERM),
        ]
        .contains(&e)
    })
}

fn valid_credentials(identity: &Value) -> bool {
    identity["uid"] == 1000
        && identity["euid"] == 1000
        && identity["gid"] == 1000
        && identity["egid"] == 1000
        && identity["groups"] == json!([3009])
        && identity["capabilities_zero"] == true
        && identity["bounding_zero"] == true
        && identity["ambient_zero"] == true
        && identity["no_new_privs"] == 1
        && identity["extra_fds"] == json!([])
        && identity["stdio_cloexec"] == true
        && identity["stdio_allowlist_valid"] == true
        && identity["root_matches"] == true
        && identity["nofile"] == json!([1024, 1024])
        && identity["core"] == json!([0, 0])
        && identity["environment"]
            == json!({"PATH": "/system/bin", "ANDROID_ROOT": "/system", "ANDROID_DATA": "/data"})
}

#[repr(C)]
struct CapHeader {
    version: u32,
    pid: i32,
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

/// Fixed harmless program. No arbitrary executable, property connect or Binder transaction.
pub(crate) fn identity_worker(
    root: &Path,
    private_rdev: &str,
    host_rdev: &str,
) -> io::Result<Value> {
    let private: u64 = private_rdev.parse().map_err(io::Error::other)?;
    let host: u64 = host_rdev.parse().map_err(io::Error::other)?;
    if private == host {
        return Err(io::Error::other("host and private Binder must differ"));
    }
    let context_file = fs::File::open("/proc/self/attr/current")?;
    let status_file = fs::File::open("/proc/self/status")?;
    let expected_root = fs::metadata(root)?;
    let cap_last: i32 = fs::read_to_string("/proc/sys/kernel/cap_last_cap")?
        .trim()
        .parse()
        .map_err(io::Error::other)?;
    if !(0..=63).contains(&cap_last) {
        return Err(io::Error::other("unknown capability range"));
    }
    let mut ns = json!({});
    syscall_result(unsafe { libc::unshare(libc::CLONE_NEWNS) })?;
    syscall_result(unsafe {
        libc::mount(
            std::ptr::null(),
            c"/".as_ptr(),
            std::ptr::null(),
            libc::MS_PRIVATE | libc::MS_REC,
            std::ptr::null(),
        )
    })?;
    for (name, flag) in [
        ("net", libc::CLONE_NEWNET),
        ("uts", libc::CLONE_NEWUTS),
        ("ipc", libc::CLONE_NEWIPC),
    ] {
        ns[name] = attempt(syscall_result(unsafe { libc::unshare(flag) }));
    }
    ns["identities"] = namespaces()?;
    ns["pid_namespace_available"] = json!(Path::new("/proc/self/ns/pid").exists());
    ns["pid_for_children_attempt"] =
        attempt(syscall_result(unsafe { libc::unshare(libc::CLONE_NEWPID) }));
    ns["pid_active_namespace"] = json!("unchanged; no fork into child PID namespace attempted");
    let all_fds: Vec<i32> = fs::read_dir("/proc/self/fd")?
        .filter_map(|e| e.ok()?.file_name().to_str()?.parse().ok())
        .collect();
    for (resource, soft, hard) in [(libc::RLIMIT_NOFILE, 1024, 1024), (libc::RLIMIT_CORE, 0, 0)] {
        let limit = libc::rlimit {
            rlim_cur: soft,
            rlim_max: hard,
        };
        syscall_result(unsafe { libc::setrlimit(resource, &limit) })?;
    }
    syscall_result(unsafe { libc::chroot(cpath(root)?.as_ptr()) })?;
    syscall_result(unsafe { libc::chdir(c"/".as_ptr()) })?;
    syscall_result(unsafe {
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL,
            0,
            0,
            0,
        )
    })?;
    for capability in 0..=cap_last {
        syscall_result(unsafe { libc::prctl(libc::PR_CAPBSET_DROP, capability, 0, 0, 0) })?;
    }
    syscall_result(unsafe { libc::prctl(libc::PR_SET_KEEPCAPS, 0, 0, 0, 0) })?;
    syscall_result(unsafe { libc::setgroups(1, [3009 as libc::gid_t].as_ptr()) })?;
    syscall_result(unsafe { libc::setresgid(1000, 1000, 1000) })?;
    syscall_result(unsafe { libc::setresuid(1000, 1000, 1000) })?;
    let mut header = CapHeader {
        version: 0x20080522,
        pid: 0,
    };
    let mut caps = [CapData::default(); 2];
    if unsafe { libc::syscall(libc::SYS_capset, &header, caps.as_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    syscall_result(unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) })?;
    if unsafe { libc::syscall(libc::SYS_capget, &mut header, caps.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let bounding_zero =
        (0..=cap_last).all(|c| unsafe { libc::prctl(libc::PR_CAPBSET_READ, c, 0, 0, 0) } == 0);
    let ambient_zero = (0..=cap_last).all(
        |c| unsafe { libc::prctl(libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_IS_SET, c, 0, 0) } == 0,
    );
    let mut groups = [0 as libc::gid_t; 64];
    let ngroups = unsafe { libc::getgroups(groups.len() as _, groups.as_mut_ptr()) };
    if ngroups < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut current_context = String::new();
    (&context_file).read_to_string(&mut current_context)?;
    let mut current_status = String::new();
    (&status_file).read_to_string(&mut current_status)?;
    drop(context_file);
    drop(status_file);
    for fd in 0..=2 {
        syscall_result(unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) })?;
    }
    let mut stdio = Vec::new();
    for fd in 0..=2 {
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        syscall_result(unsafe { libc::fstat(fd, &mut stat) })?;
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        stdio.push(json!({"fd":fd,"mode":stat.st_mode,"rdev":stat.st_rdev,"access_mode":flags & libc::O_ACCMODE}));
    }
    let stdio_allowlist_valid = stdio[0]["rdev"] == libc::makedev(1, 3)
        && stdio[0]["access_mode"] == libc::O_RDONLY
        && stdio[1..].iter().all(|v| {
            v["mode"]
                .as_u64()
                .is_some_and(|m| m & u64::from(libc::S_IFMT) == u64::from(libc::S_IFIFO))
                && v["access_mode"] == libc::O_WRONLY
        });
    let extras: Vec<_> = all_fds
        .into_iter()
        .filter(|fd| *fd > 2)
        .filter(|fd| unsafe { libc::fcntl(*fd, libc::F_GETFD) } >= 0)
        .collect();
    if !extras.is_empty() {
        return Err(io::Error::other(format!(
            "unexpected inherited FDs {extras:?}"
        )));
    }
    let actual_root = fs::metadata("/")?;
    let mut access = json!({});
    for path in [
        "/proc/1/root/dev/binder",
        "/proc/self/root/dev/binder",
        "/dev/hwbinder",
        "/dev/vndbinder",
        "/dev/binderfs/binder",
        "/dev/__properties__/properties_serial",
        "/dev/socket/property_service",
        "/dev/socket/property_service_for_system",
        "/dev/kmsg",
        "/sys/fs/cgroup/cgroup.procs",
        "/sys/fs/bpf",
        "/dev/cpuset/foreground/tasks",
    ] {
        let flags = if path == "/dev/kmsg" {
            libc::O_WRONLY | libc::O_NONBLOCK
        } else {
            libc::O_PATH
        };
        let fd = unsafe { libc::open(cpath(Path::new(path))?.as_ptr(), flags | libc::O_CLOEXEC) };
        access[path] = if fd < 0 {
            let e = io::Error::last_os_error();
            json!({"opened": false, "errno": e.raw_os_error(), "error": e.to_string()})
        } else {
            unsafe {
                libc::close(fd);
            }
            json!({"opened": true, "errno": null, "scope": "no read/write/connect/ioctl"})
        };
    }
    let binder = private_open(private, host)?;
    let linker_read = (|| -> io::Result<Value> {
        let mut file = fs::File::open("/linkerconfig/ld.config.txt")?;
        let mut byte = [0u8; 1];
        let read = file.read(&mut byte)?;
        let address = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                1,
                libc::PROT_READ,
                libc::MAP_PRIVATE,
                file.as_raw_fd(),
                0,
            )
        };
        if address == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        syscall_result(unsafe { libc::munmap(address, 1) })?;
        Ok(
            json!({"status":"passed", "read_bytes":read, "mmap":"passed", "label":file_label(&file)?, "scope":"observed helper domain only; no contents logged"}),
        )
    })();
    let linker_read = match linker_read {
        Ok(v) => v,
        Err(e) => json!({"status":"blocked", "error":e.to_string()}),
    };
    let read_limit = |resource| -> io::Result<Value> {
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        syscall_result(unsafe { libc::getrlimit(resource, &mut limit) })?;
        Ok(json!([limit.rlim_cur, limit.rlim_max]))
    };
    Ok(
        json!({"protocol": 2, "child_pid": std::process::id(), "uid": unsafe { libc::getuid() }, "euid": unsafe { libc::geteuid() }, "gid": unsafe { libc::getgid() }, "egid": unsafe { libc::getegid() }, "groups": &groups[..ngroups as usize], "capabilities_zero": caps.iter().all(|c| c.effective == 0 && c.permitted == 0 && c.inheritable == 0), "bounding_zero": bounding_zero, "ambient_zero": ambient_zero, "no_new_privs": unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) }, "context": current_context.trim_matches('\0').trim(), "status": current_status, "extra_fds": extras, "stdio": stdio, "stdio_allowlist_valid": stdio_allowlist_valid, "stdio_cloexec": (0..=2).all(|fd| unsafe { libc::fcntl(fd, libc::F_GETFD) } & libc::FD_CLOEXEC != 0), "namespaces": ns, "root": {"dev": actual_root.dev(), "ino": actual_root.ino()}, "root_matches": (actual_root.dev(), actual_root.ino()) == (expected_root.dev(), expected_root.ino()), "nofile": read_limit(libc::RLIMIT_NOFILE)?, "core": read_limit(libc::RLIMIT_CORE)?, "environment": std::env::vars().collect::<std::collections::BTreeMap<_,_>>(), "private_binder": binder, "linkerconfig_access": linker_read, "access": access, "task_profile": "not_run; no Host cgroup writes"}),
    )
}

fn private_open(private: u64, host: u64) -> io::Result<Value> {
    let meta = match fs::metadata("/dev/binder") {
        Ok(m) => m,
        Err(e) => {
            return Ok(
                json!({"opened_private": false, "host_open_attempted": false, "error": e.to_string(), "errno": e.raw_os_error()}),
            )
        }
    };
    if !meta.file_type().is_char_device() || meta.rdev() != private || meta.rdev() == host {
        return Ok(
            json!({"opened_private": false, "host_open_attempted": false, "reason": "driver identity guard rejected default path", "rdev": meta.rdev()}),
        );
    }
    let file = match OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/dev/binder")
    {
        Ok(f) => f,
        Err(e) => {
            return Ok(
                json!({"opened_private": false, "host_open_attempted": false, "errno": e.raw_os_error(), "error": e.to_string()}),
            )
        }
    };
    if file.metadata()?.rdev() != private {
        return Err(io::Error::other("Binder identity changed during open"));
    }
    let mut protocol: i32 = 0;
    syscall_result(unsafe { libc::ioctl(file.as_raw_fd(), 0xc0046209u32 as _, &mut protocol) })?;
    Ok(
        json!({"opened_private": protocol == 8, "protocol": protocol, "host_open_attempted": false, "rdev": file.metadata()?.rdev(), "cloexec": unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC != 0}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn absence_and_denial_are_not_inferred_from_unknown_errors() {
        assert!(denied(&json!({"p": {"errno": libc::EACCES}}), "p"));
        assert!(denied(&json!({"p": {"errno": libc::ENOENT}}), "p"));
        assert!(!denied(&json!({"p": {"errno": libc::EIO}}), "p"));
        assert!(!denied(&json!({}), "p"));
    }
    #[test]
    fn root_uid_or_leaked_fd_cannot_pass_credentials() {
        let mut v = json!({"uid":1000,"euid":1000,"gid":1000,"egid":1000,"groups":[3009],"capabilities_zero":true,"bounding_zero":true,"ambient_zero":true,"no_new_privs":1,"extra_fds":[],"stdio_cloexec":true,"stdio_allowlist_valid":true,"root_matches":true,"nofile":[1024,1024],"core":[0,0],"environment":{"PATH":"/system/bin","ANDROID_ROOT":"/system","ANDROID_DATA":"/data"}});
        assert!(valid_credentials(&v));
        v["extra_fds"] = json!([9]);
        assert!(!valid_credentials(&v));
        v["extra_fds"] = json!([]);
        v["euid"] = json!(0);
        assert!(!valid_credentials(&v));
    }
}
