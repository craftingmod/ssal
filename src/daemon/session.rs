use super::{atomic, now};
use ssal::unix::{label_image, receive, reply, valid_image_name, ROOT, VERSION};
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

#[derive(Clone)]
struct RunningGuest {
    profile: String,
    pid: u32,
    log_path: PathBuf,
}

type ActiveGuest = Arc<Mutex<Option<RunningGuest>>>;

fn log(root: &Path, text: &str) {
    if let Ok(mut f) = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(root.join("logs/ssald.log"))
    {
        let _ = writeln!(f, "{text}");
    }
}
fn peer_root(s: &UnixStream) -> io::Result<bool> {
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of_val(&cred) as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            s.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast(),
            &mut len,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(cred.uid == 0)
}
fn handle(
    mut stream: UnixStream,
    root: PathBuf,
    busy: Arc<Mutex<bool>>,
    active_guest: ActiveGuest,
    relay: super::presenter_relay::RelayHandle,
) -> io::Result<()> {
    stream.set_read_timeout(Some(std::time::Duration::from_secs(10)))?;
    if !peer_root(&stream)? {
        return reply(&mut stream, false, "root peer required");
    }
    let (req, fd) = receive(&mut stream)?;
    if req.version != VERSION {
        return reply(&mut stream, false, "unsupported protocol version");
    }
    if (req.force_regen || req.native_sepolicy) && req.command != "prepare" {
        return reply(&mut stream, false, "--regen is only supported by prepare");
    }
    match req.command.as_str() {
        "status" => {
            let job = fs::read_to_string(root.join("state/last-job.json")).unwrap_or_else(|_| "none".into());
            let images = super::images::image_list(&root)?;
            let profiles = super::profiles::profile_list(&root)?;
            let guest = active_guest
                .lock()
                .unwrap()
                .as_ref()
                .map(|g| format!("\nGUEST_RUNNING profile={} pid={} log={}", g.profile, g.pid, g.log_path.display()))
                .unwrap_or_default();
            reply(&mut stream, true, format!("HOST_ACTIVE{guest}\nimages:\n{images}\nprofiles:\n{profiles}\nlast job: {job}"))
        }
        "doctor" if req.profile_name.is_some() => {
            match crate::guest::prepare::check(&root, req.profile_name.as_deref().unwrap()) {
                Ok(profile) => reply(&mut stream, true, profile.report),
                Err(e) => reply(&mut stream, false, format!("profile check failed: {e}")),
            }
        }
        "doctor" => reply(&mut stream, true, format!("daemon and root socket: OK\nmount namespace: {}\nloop control: {}\ndevice profile, Binder, property, HAL and guest services: not implemented; switching unavailable", Path::new("/proc/self/ns/mnt").exists(), Path::new("/dev/loop-control").exists())),
        "prepare" | "probe-binder" | "probe-selinux-transition" | "probe-servicemanager-preflight" | "probe-servicemanager-runtime-preflight" | "probe-servicemanager" | "probe-guest-data" => {
            let Some(name) = req.profile_name.as_deref().filter(|name| valid_image_name(name)) else { return reply(&mut stream, false, "invalid profile name"); };
            let guard = busy.lock().unwrap();
            if *guard { return reply(&mut stream, false, "another operation is running"); }
            let result = prepare_session(&root, name, &req.command, req.force_regen, req.native_sepolicy);
            match result { Ok(message) => { log(&root, &message); reply(&mut stream, true, message) }, Err(e) => { let message = format!("prepare failed: {e}"); log(&root, &message); reply(&mut stream, false, message) } }
        }
        "start" => {
            let Some(name) = req.profile_name.as_deref().filter(|name| valid_image_name(name)) else {
                return reply(&mut stream, false, "invalid profile name");
            };
            let guard = busy.lock().unwrap();
            if *guard {
                return reply(&mut stream, false, "another operation is running");
            }
            drop(guard);
            match start_session(&root, name, &active_guest) {
                Ok(message) => {
                    log(&root, &message);
                    reply(&mut stream, true, message)
                }
                Err(e) => {
                    let message = format!("start failed: {e}");
                    log(&root, &message);
                    reply(&mut stream, false, message)
                }
            }
        }
        "stop" => {
            if let Some(name) = req.profile_name.as_deref() {
                if !valid_image_name(name) {
                    return reply(&mut stream, false, "invalid profile name");
                }
            }
            let guard = active_guest.lock().unwrap();
            let Some(running) = guard.as_ref() else {
                return reply(&mut stream, false, "no Guest session is running");
            };
            if let Some(name) = req.profile_name.as_deref() {
                if name != running.profile {
                    return reply(
                        &mut stream,
                        false,
                        format!("running Guest profile is {}, not {name}", running.profile),
                    );
                }
            }
            let pid = running.pid;
            let profile = running.profile.clone();
            drop(guard);
            if unsafe { libc::kill(pid as i32, libc::SIGTERM) } != 0 {
                return reply(
                    &mut stream,
                    false,
                    format!("failed to signal Guest {profile} (pid={pid}): {}", io::Error::last_os_error()),
                );
            }
            let message = format!("stopping Guest profile {profile} (pid={pid})");
            log(&root, &message);
            reply(&mut stream, true, message)
        }
        "remove" => {
            let Some(name) = req.profile_name.as_deref().filter(|name| valid_image_name(name)) else { return reply(&mut stream, false, "invalid profile name"); };
            let Ok(guard) = busy.try_lock() else { return reply(&mut stream, false, "another operation is running"); };
            if *guard { return reply(&mut stream, false, "another operation is running"); }
            match super::profiles::remove_profile(&root, name) {
                Ok(()) => { let message = format!("removed profile {name} and its userdata"); log(&root, &message); reply(&mut stream, true, message) },
                Err(e) => reply(&mut stream, false, format!("profile removal failed: {e}")),
            }
        }
        "stop-for-restart" => {
            let guard = busy.lock().unwrap();
            if *guard || active_guest.lock().unwrap().is_some() {
                return reply(&mut stream, false, "an operation or Guest session is running; try again later");
            }
            reply(&mut stream, true, "daemon stopping")?;
            std::process::exit(0);
        }
        "logs" => reply(&mut stream, true, fs::read_to_string(root.join("logs/ssald.log")).unwrap_or_default()),
        "allow" => {
            let Some(pkg) = req.profile_name.as_deref() else {
                return reply(&mut stream, false, "package name required");
            };
            match super::presenter_relay::allow_package(&root, pkg, &relay) {
                Ok(message) => {
                    log(&root, &message);
                    reply(&mut stream, true, message)
                }
                Err(e) => reply(&mut stream, false, format!("allow failed: {e}")),
            }
        }
        "register-presenter" => {
            let Some(fd) = fd else {
                return reply(&mut stream, false, "presenter socket fd required");
            };
            super::presenter_relay::set_composer_fd(&relay, fd);
            log(&root, "registered virtual-composer presenter fd");
            reply(&mut stream, true, "presenter fd registered")
        }
        "register-input" => {
            let Some(fd) = fd else {
                return reply(&mut stream, false, "input socket fd required");
            };
            super::presenter_relay::set_input_fd(&relay, fd);
            log(&root, "registered guest input injector fd");
            reply(&mut stream, true, "input fd registered")
        }
        "switch" if !req.image_name.as_deref().is_some_and(valid_image_name) => reply(&mut stream, false, "invalid image name"),
        "switch" | "return" => reply(&mut stream, false, crate::service_contract::blocked_summary()?),
        "create" => {
            let Some(image_name) = req.image_name.as_deref().filter(|name| valid_image_name(name)) else { return reply(&mut stream, false, "invalid image name"); };
            if req.profile_name.as_deref().is_some_and(|name| !valid_image_name(name)) { return reply(&mut stream, false, "invalid profile name"); }
            let guard = busy.lock().unwrap();
            if *guard { return reply(&mut stream, false, "another operation is running"); }
            let result = super::profiles::create_profile(&root, image_name, req.profile_name.as_deref(), crate::guest::userdata::SIZE);
            match result { Ok(message) => reply(&mut stream, true, message), Err(e) => reply(&mut stream, false, format!("profile creation failed: {e}")) }
        }
        "add" => {
            let Some(image_name) = req.image_name.filter(|name| valid_image_name(name)) else { return reply(&mut stream, false, "invalid image name: use 1-64 ASCII letters, digits, underscores or hyphens"); };
            let Some(fd) = fd else { return reply(&mut stream, false, "image file descriptor required"); };
            let mut guard = busy.lock().unwrap(); if *guard { return reply(&mut stream, false, "another operation is running"); } *guard = true;
            let id = format!("{}-{}", now(), std::process::id());
            let journal = root.join("state/last-job.json");
            if let Err(e) = atomic(&journal, serde_json::json!({"id":id,"operation":"add","image_name":image_name,"status":"running"}).to_string().as_bytes()) { *guard = false; return reply(&mut stream, false, e.to_string()); }
            drop(guard);
            let job_id = id.clone();
            std::thread::spawn(move || {
                let result = super::images::register(&root, fd, &job_id, &image_name, label_image);
                let (status, message) = match result { Ok(s) => ("completed", s), Err(e) => ("failed", e.to_string()) };
                let record = serde_json::json!({"id":job_id,"operation":"add","image_name":image_name,"status":status,"message":message});
                if let Err(e) = atomic(&journal, record.to_string().as_bytes()) { log(&root, &format!("journal update failed: {e}")); }
                log(&root, &record.to_string()); *busy.lock().unwrap() = false;
            });
            reply(&mut stream, true, format!("job {id} accepted; use ssal status"))
        }
        _ => reply(&mut stream, false, "unknown command")
    }
}
fn prepare_session(
    root: &Path,
    name: &str,
    mode: &str,
    force_regen: bool,
    native_sepolicy: bool,
) -> io::Result<String> {
    if mode == "prepare" {
        crate::guest::prepare::check_boot_binaries(std::env::current_exe()?.parent().unwrap())?;
    }
    crate::diagnostics::selinux::servicemanager::check_recovery()?;
    let profile = crate::guest::prepare::check(root, name)?;
    let base = root
        .join("mnt")
        .join(format!("prepare-{}-{}", std::process::id(), now()));
    fs::create_dir(&base)?;
    let result = (|| {
        fs::create_dir(base.join("system"))?;
        fs::create_dir(base.join("data"))?;
        let mut worker = Command::new(std::env::current_exe()?);
        worker
            .arg(match mode {
                "probe-binder" => "--binder-probe-worker",
                "probe-servicemanager" => "--servicemanager-worker",
                "probe-guest-data" => "--guest-data-worker",
                "probe-selinux-transition" => "--selinux-probe-worker",
                "probe-servicemanager-preflight" => "--servicemanager-preflight-worker",
                "probe-servicemanager-runtime-preflight" => {
                    "--servicemanager-runtime-preflight-worker"
                }
                _ => "--prepare-worker",
            })
            .arg(&profile.system)
            .arg(&profile.userdata)
            .arg(&base);
        if force_regen {
            worker.arg("--regen");
        }
        worker.env(
            "SSAL_PREPARE_SEPOLICY_BACKEND",
            if native_sepolicy { "native" } else { "ksud" },
        );
        let output = worker.output()?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !output.status.success() {
            return Err(io::Error::other(format!(
                "{}\nworker exited {}\n{stdout}{stderr}",
                profile.report, output.status
            )));
        }
        Ok(format!(
            "{}\n{stdout}prepare complete; worker exited; session-path host mounts checked absent",
            profile.report
        ))
    })();
    if let Err(error) = crate::diagnostics::selinux::servicemanager::check_recovery() {
        return Err(io::Error::other(format!(
            "{error}; scratch retained at {}; previous result: {result:?}",
            base.display()
        )));
    }
    let mut cleanup = Vec::new();
    // Inspect this namespace explicitly before removing session scratch.
    // Worker exit alone is not proof that every namespace reference is gone.
    let host_mounts = fs::read_to_string("/proc/self/mountinfo")?;
    if host_mounts
        .lines()
        .filter_map(|line| line.split_whitespace().nth(4))
        .any(|path| Path::new(path).starts_with(&base))
    {
        return Err(io::Error::other(format!("host namespace still has a mount under {}; scratch cleanup refused; previous result: {result:?}", base.display())));
    }
    log(
        root,
        "prepare host namespace residual mount check: verified absent for session path",
    );
    for scratch in ["rootfs", "apex-cache", "loop-devices", "selinux-overlay"] {
        let path = base.join(scratch);
        if let Err(e) = fs::remove_dir_all(&path) {
            if e.kind() != io::ErrorKind::NotFound {
                cleanup.push(format!("{}: {e}", path.display()));
            }
        }
    }
    for path in [base.join("data"), base.join("system"), base.clone()] {
        if let Err(e) = fs::remove_dir(&path) {
            if e.kind() != io::ErrorKind::NotFound {
                cleanup.push(format!("{}: {e}", path.display()));
            }
        }
    }
    if !cleanup.is_empty() {
        return Err(io::Error::other(format!(
            "temporary directory cleanup failed: {}; previous result: {:?}",
            cleanup.join(", "),
            result
        )));
    }
    result
}

fn cleanup_guest_scratch(base: &Path) -> io::Result<()> {
    let host_mounts = fs::read_to_string("/proc/self/mountinfo")?;
    if host_mounts
        .lines()
        .filter_map(|line| line.split_whitespace().nth(4))
        .any(|path| Path::new(path).starts_with(base))
    {
        return Err(io::Error::other(format!(
            "host namespace still has a mount under {}; scratch cleanup refused",
            base.display()
        )));
    }
    for scratch in ["rootfs", "apex-cache", "loop-devices", "selinux-overlay", "phase7b"] {
        let path = base.join(scratch);
        if let Err(e) = fs::remove_dir_all(&path) {
            if e.kind() != io::ErrorKind::NotFound {
                return Err(e);
            }
        }
    }
    for path in [base.join("data"), base.join("system"), base.to_path_buf()] {
        if let Err(e) = fs::remove_dir(&path) {
            if e.kind() != io::ErrorKind::NotFound {
                return Err(e);
            }
        }
    }
    Ok(())
}

fn start_session(root: &Path, name: &str, active_guest: &ActiveGuest) -> io::Result<String> {
    {
        let guard = active_guest.lock().unwrap();
        if let Some(running) = guard.as_ref() {
            return Err(io::Error::other(format!(
                "Guest session already running (profile={}, pid={})",
                running.profile, running.pid
            )));
        }
    }
    crate::guest::prepare::check_boot_binaries(std::env::current_exe()?.parent().unwrap())?;
    crate::diagnostics::selinux::servicemanager::check_recovery()?;
    let profile = crate::guest::prepare::check(root, name)?;
    if !root.join("guests").join(name).join("selinux/plan.json").is_file() {
        return Err(io::Error::other(format!(
            "profile {name} is not prepared; run 'ssal prepare {name}' first"
        )));
    }
    let base = root.join("mnt").join(format!("guest-{name}-{}", now()));
    fs::create_dir(&base)?;
    fs::create_dir(base.join("system"))?;
    fs::create_dir(base.join("data"))?;
    let log_path = root.join("logs").join(format!("guest-{name}.log"));
    let stdout = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(&log_path)?;
    let stderr = stdout.try_clone()?;
    let mut worker = Command::new(std::env::current_exe()?);
    worker
        .arg("--guest-start-worker")
        .arg(&profile.system)
        .arg(&profile.userdata)
        .arg(&base)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr));
    let mut child = match worker.spawn() {
        Ok(child) => child,
        Err(error) => {
            let _ = cleanup_guest_scratch(&base);
            return Err(error);
        }
    };
    let pid = child.id();
    *active_guest.lock().unwrap() = Some(RunningGuest {
        profile: name.to_owned(),
        pid,
        log_path: log_path.clone(),
    });
    let root_owned = root.to_path_buf();
    let name_owned = name.to_owned();
    let active_owned = Arc::clone(active_guest);
    let base_owned = base.clone();
    std::thread::spawn(move || {
        let status = child.wait();
        let cleanup = cleanup_guest_scratch(&base_owned);
        let mut guard = active_owned.lock().unwrap();
        if guard.as_ref().is_some_and(|g| g.pid == pid) {
            *guard = None;
        }
        drop(guard);
        log(
            &root_owned,
            &format!("Guest profile {name_owned} (pid={pid}) exited: {status:?}; cleanup={cleanup:?}"),
        );
    });
    std::thread::sleep(std::time::Duration::from_millis(250));
    if active_guest.lock().unwrap().as_ref().is_none_or(|g| g.pid != pid) {
        let tail = fs::read_to_string(&log_path)
            .unwrap_or_default()
            .lines()
            .rev()
            .take(10)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect::<Vec<_>>()
            .join("\n");
        return Err(io::Error::other(format!(
            "Guest exited immediately; see {}:\n{tail}",
            log_path.display()
        )));
    }
    Ok(format!(
        "started Guest profile {name} (pid={pid}, log={})",
        log_path.display()
    ))
}

#[cfg(feature = "phase2c-diagnostic")]
pub(crate) fn run_phase2c_diagnostic(
    root: &Path,
    profile: &str,
    probe: &Path,
) -> io::Result<String> {
    std::env::set_var("SSAL_PHASE2C_RSBINDER_PROBE", probe);
    prepare_session(root, profile, "probe-servicemanager", false)
}
#[cfg(feature = "phase3-diagnostic")]
pub(crate) fn run_phase3_diagnostic(
    root: &Path,
    profile: &str,
    phase2_probe: &Path,
    phase3_probe: &Path,
) -> io::Result<String> {
    std::env::set_var("SSAL_PHASE2C_RSBINDER_PROBE", phase2_probe);
    std::env::set_var("SSAL_PHASE3_RSBINDER_PROBE", phase3_probe);
    prepare_session(root, profile, "probe-servicemanager", false)
}
pub(crate) fn run() -> io::Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(io::Error::other("ssald must run as root"));
    }
    let root = PathBuf::from(ROOT);
    for dir in [
        "config",
        "images",
        "guests",
        "mnt",
        "state",
        "state/image-refs",
        "logs",
        "run",
    ] {
        fs::create_dir_all(root.join(dir))?;
        fs::set_permissions(root.join(dir), fs::Permissions::from_mode(0o700))?;
    }
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .open(root.join("run/ssald.lock"))?;
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(io::Error::other("ssald is already running"));
    }
    for entry in fs::read_dir(root.join("guests"))? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.strip_prefix(".create-").is_some_and(valid_image_name)
            && entry.file_type()?.is_dir()
        {
            fs::remove_dir_all(entry.path())?;
        }
    }
    super::images::migrate_legacy_image(&root)?;
    let journal = root.join("state/last-job.json");
    if let Ok(data) = fs::read(&journal) {
        if let Ok(mut v) = serde_json::from_slice::<serde_json::Value>(&data) {
            if v["status"] == "running" {
                v["status"] = "interrupted".into();
                v["message"] = "daemon restarted; registration may need to be repeated".into();
                atomic(&journal, v.to_string().as_bytes())?;
            }
        }
    }
    let socket = root.join("run/ssald.sock");
    if socket.exists() {
        fs::remove_file(&socket)?;
    }
    let listener = UnixListener::bind(&socket)?;
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))?;
    let busy = Arc::new(Mutex::new(false));
    let active_guest: ActiveGuest = Arc::new(Mutex::new(None));
    let relay = super::presenter_relay::start(&root);
    log(&root, "ssald started");
    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                let r = root.clone();
                let b = busy.clone();
                let ag = active_guest.clone();
                let rel = relay.clone();
                std::thread::spawn(move || {
                    if let Err(e) = handle(s, r.clone(), b, ag, rel) {
                        log(&r, &format!("request error: {e}"));
                    }
                });
            }
            Err(e) => log(&root, &format!("accept: {e}")),
        }
    }
    Ok(())
}
