//! Disposable Guest service launcher; shared PID namespace is intentional.
use ssal::namespace_mounts::Mounts;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

mod fork_probe;
mod system_server_preflight;
mod system_server_runtime_sid;
pub(crate) use fork_probe::client as fork_client;

const GUEST_PROBE_CONTEXT: &[u8] = b"u:r:ssal_guest_probe:s0\0";
const PROPERTY_SERVICE_CONTEXT: &[u8] = b"u:r:ssal_property:s0\0";

fn mapped_exec_domain(executable: &str, exec_context: Option<&[u8]>) -> &'static str {
    if exec_context == Some(PROPERTY_SERVICE_CONTEXT) {
        "init"
    } else {
        match executable {
            "/system/bin/app_process64" => "zygote",
            "/system/bin/servicemanager" => "servicemanager",
            "/apex/com.android.runtime/bin/linkerconfig" | "/system/bin/linkerconfig" => {
                "linkerconfig"
            }
            _ => "shell",
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct GuestClasspaths {
    boot: String,
    dex2oat: Option<String>,
    system_server: String,
    standalone_system_server: Option<String>,
}

fn join_cgroups(groups: &[std::path::PathBuf]) -> io::Result<()> {
    let pid = std::process::id().to_string();
    for group in groups {
        fs::write(group.join("cgroup.procs"), &pid)?;
    }
    for group in groups {
        let members = fs::read_to_string(group.join("cgroup.procs"))?;
        if !members.split_whitespace().any(|member| member == pid) {
            return Err(io::Error::other(format!(
                "Guest pre-exec membership missing: pid={pid} group={}",
                group.display()
            )));
        }
    }
    Ok(())
}

pub(crate) fn command(
    root: &Path,
    executable: &str,
    uid: u32,
    exec_context: Option<&[u8]>,
) -> io::Result<Command> {
    crate::memory_cgroup::check_interrupted()?;
    // A real Guest mount root also gives Zygote's FD allowlist Guest-relative proc paths.
    let pivot = executable == "/system/bin/app_process64"
        && std::env::var_os("SSAL_PHASE7FB_FORK").is_some();
    let mut command = crate::guest_probe::root_command(root, executable, pivot)?;
    let exec_context = if let Some(plan) = ssal::guest_policy::runtime::load(root)? {
        let original = mapped_exec_domain(executable, exec_context);
        let mut context = plan.context(original, true)?.into_bytes();
        context.push(0);
        Some(context)
    } else {
        exec_context.map(<[u8]>::to_vec)
    };
    let pre_exec_cgroups: Vec<_> =
        crate::guest_mounts::guest_cgroup_mounts(crate::memory_cgroup::backend()?)
            .into_iter()
            .map(|(_, target)| Path::new("/").join(target))
            .collect();
    command.env("LD_LIBRARY_PATH", "/run/ssal");
    if executable == "/system/bin/bootstrap/linker64" {
        command.env("LD_LIBRARY_PATH", "/system/lib64/bootstrap:/system/lib64");
    }
    command
        .env("ANDROID_ROOT", "/system")
        .env("ANDROID_DATA", "/data")
        .env("ANDROID_RUNTIME_ROOT", "/apex/com.android.runtime")
        .env("ANDROID_ART_ROOT", "/apex/com.android.art")
        .env("ASEC_MOUNTPOINT", "/mnt/asec")
        .env("ANDROID_STORAGE", "/storage")
        .env("ANDROID_I18N_ROOT", "/apex/com.android.i18n")
        .env("ANDROID_TZDATA_ROOT", "/apex/com.android.tzdata")
        .stdin(Stdio::null());
    if executable == "/apex/com.android.art/bin/artd" {
        command.env("LD_LIBRARY_PATH", "/run/ssal:/apex/com.android.art/lib64:/system/lib64:/apex/com.android.os.statsd/lib64:/apex/com.android.i18n/lib64");
    }
    if executable == "/apex/com.android.sdkext/bin/derive_classpath" {
        command.env(
            "LD_LIBRARY_PATH",
            "/run/ssal:/apex/com.android.sdkext/lib64:/system/lib64",
        );
    }
    let parent = std::process::id() as libc::pid_t;
    unsafe {
        command.pre_exec(move || {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 || libc::getppid() != parent
            {
                return Err(io::Error::other("Guest launcher parent disappeared"));
            }
            // The root transition already ran; only this child joins Guest cgroups.
            join_cgroups(&pre_exec_cgroups)?;
            if let Some(context) = &exec_context {
                fs::write("/proc/thread-self/attr/exec", context)?;
            }
            if libc::setgroups(0, std::ptr::null()) != 0
                || libc::setresgid(uid, uid, uid) != 0
                || libc::setresuid(uid, uid, uid) != 0
            {
                return Err(io::Error::last_os_error());
            }
            crate::memory_cgroup::verify_guest_mount_membership(std::process::id())?;
            Ok(())
        });
    }
    Ok(command)
}

fn zygote_sockets(command: &mut Command, directory: &Path) -> io::Result<Vec<UnixListener>> {
    let mut sockets = Vec::new();
    for name in ["zygote", "usap_pool_primary"] {
        let raw = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let socket = unsafe { UnixListener::from_raw_fd(raw) };
        let fd = socket.as_raw_fd();
        let path = directory.join(name);
        command.env(format!("ANDROID_SOCKET_{name}"), fd.to_string());
        unsafe {
            command.pre_exec(move || {
                let bound = UnixListener::bind(&path)?;
                if name == "zygote" {
                    let cpath = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())?;
                    if libc::chown(cpath.as_ptr(), !0, 1000) != 0 {
                        return Err(io::Error::last_os_error());
                    }
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o660))?;
                }
                if libc::dup2(bound.as_raw_fd(), fd) < 0 {
                    return Err(io::Error::last_os_error());
                }
                if libc::fcntl(fd, libc::F_SETFD, 0) != 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        sockets.push(socket);
    }
    Ok(sockets)
}

fn run(root: &Path, exe: &str, args: &[&str], uid: u32) -> io::Result<String> {
    run_as(root, exe, args, uid, GUEST_PROBE_CONTEXT)
}

fn run_as(root: &Path, exe: &str, args: &[&str], uid: u32, context: &[u8]) -> io::Result<String> {
    let mut child_command = command(root, exe, uid, Some(context))?;
    child_command.args(args);
    if std::env::var_os("SSAL_TRACE_GUEST_SIGABRT").is_some()
        && (exe == "/apex/com.android.runtime/bin/linkerconfig"
            || exe == "/system/bin/linkerconfig")
    {
        let executable_copy = root
            .parent()
            .ok_or_else(|| io::Error::other("Guest worker directory missing"))?
            .join("linkerconfig.debug.elf");
        fs::copy(
            crate::guest_mounts::guest_path(root, exe.trim_start_matches('/'))?,
            &executable_copy,
        )?;
        println!(
            "linkerconfig trace binary copy: {}",
            executable_copy.display()
        );
        child_command.env("LD_PRELOAD", "/run/ssal/ssal-abort-trace.so");
    }
    let output =
        crate::guest_probe::run_with_timeout(&mut child_command, exe, Duration::from_secs(20))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    println!(
        "Guest call executable={exe} args={args:?} return={}\n{stdout}{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "Guest call {exe} {args:?}: {}",
            output.status
        )));
    }
    Ok(stdout.into_owned())
}

pub(crate) fn readiness_client() -> io::Result<()> {
    let (uid, euid, gid, egid) = unsafe {
        (
            libc::getuid(),
            libc::geteuid(),
            libc::getgid(),
            libc::getegid(),
        )
    };
    if (uid, euid, gid, egid) != (1000, 1000, 1000, 1000) {
        return Err(io::Error::other(format!(
            "unexpected client credentials uid={uid} euid={euid} gid={gid} egid={egid}"
        )));
    }
    let status = fs::read_to_string("/proc/self/status")?;
    for name in ["CapInh:", "CapPrm:", "CapEff:", "CapAmb:"] {
        let value = status
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .ok_or_else(|| io::Error::other("capability status missing"))?;
        if u64::from_str_radix(value.trim(), 16).unwrap_or(u64::MAX) != 0 {
            return Err(io::Error::other(format!(
                "client capability {name}={value}"
            )));
        }
    }
    let mut socket = match UnixStream::connect("zygote") {
        Ok(socket) => socket,
        Err(e)
            if e.kind() == io::ErrorKind::ConnectionRefused
                || e.kind() == io::ErrorKind::NotFound =>
        {
            eprintln!("connect pending: {e}");
            std::process::exit(2);
        }
        Err(e) => return Err(io::Error::other(format!("connect: {e}"))),
    };
    socket.set_read_timeout(Some(Duration::from_secs(30)))?;
    socket.set_write_timeout(Some(Duration::from_secs(30)))?;
    query_abi(&mut socket)?;
    println!("Guest Zygote ABI socket query=arm64-v8a client_pid={} uid={uid} euid={euid} gid={gid} egid={egid} capabilities=0", std::process::id());
    Ok(())
}

fn guest_servicemanager_property(root: &Path) -> io::Result<String> {
    let mut command = command(root, "/system/bin/getprop", 1000, Some(GUEST_PROBE_CONTEXT))?;
    command.arg("servicemanager.ready");
    let output = crate::guest_probe::run_with_timeout(
        &mut command,
        "Guest servicemanager.ready readback",
        Duration::from_secs(2),
    )?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "Guest getprop servicemanager.ready: {}",
            output.status
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn probe_guest_context_manager(root: &Path) -> io::Result<String> {
    let mut command = command(
        root,
        "/system/bin/bootstrap/linker64",
        1000,
        Some(GUEST_PROBE_CONTEXT),
    )?;
    command.args(["/run/ssal/phase3-ipc", "context-manager"]);
    let output = crate::guest_probe::run_with_timeout(
        &mut command,
        "Guest Binder Context Manager probe",
        Duration::from_secs(2),
    )?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "Guest Binder Context Manager probe: {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    if !stdout.contains("\"event\":\"context_manager_lookup_passed\"") {
        return Err(io::Error::other(
            "Guest Binder Context Manager probe returned no success evidence",
        ));
    }
    Ok(stdout)
}

fn query_abi(socket: &mut UnixStream) -> io::Result<()> {
    socket
        .write_all(b"1\n--query-abi-list\n")
        .map_err(|e| io::Error::other(format!("ABI request: {e}")))?;
    let mut length = [0; 4];
    socket
        .read_exact(&mut length)
        .map_err(|e| io::Error::other(format!("ABI length: {e}")))?;
    if u32::from_be_bytes(length) != 9 {
        return Err(io::Error::other(format!(
            "invalid ABI response length {}",
            u32::from_be_bytes(length)
        )));
    }
    let mut abi = [0; 9];
    socket
        .read_exact(&mut abi)
        .map_err(|e| io::Error::other(format!("ABI response: {e}")))?;
    if &abi != b"arm64-v8a" {
        return Err(io::Error::other(format!(
            "unexpected ABI response: {:?}",
            String::from_utf8_lossy(&abi)
        )));
    }
    Ok(())
}

struct Service {
    child: Child,
    log: std::path::PathBuf,
    stopped: bool,
    diagnostics: Option<crate::zygote_diagnostics::Diagnostics>,
    output: Vec<crate::zygote_diagnostics::Stream>,
}
impl Service {
    fn exit_status(&self) -> io::Result<Option<(i32, i32)>> {
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        if unsafe {
            libc::waitid(
                libc::P_PID,
                self.child.id(),
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok((unsafe { info.si_pid() } != 0).then(|| (info.si_code, unsafe { info.si_status() })))
    }
    fn exited(&self) -> io::Result<bool> {
        Ok(self.exit_status()?.is_some())
    }
    fn start(
        root: &Path,
        exe: &str,
        args: &[&str],
        name: &str,
        uid: u32,
        exec_context: Option<&[u8]>,
        env: &[(&str, &str)],
    ) -> io::Result<Self> {
        let log = root.join(format!("run/ssal/{name}.log"));
        let output = File::create(&log)?;
        let mut command = command(root, exe, uid, exec_context)?;
        command
            .stdin(Stdio::null())
            .env("LD_PRELOAD", "/run/ssal/ssal-phase2-log.so");
        if name == "memory-probe" {
            command.env_remove("LD_PRELOAD");
        }
        for (key, value) in env {
            command.env(key, value);
        }
        let diagnostic_dir = root
            .parent()
            .ok_or_else(|| io::Error::other("session parent missing"))?
            .join("phase7b");
        let is_zygote = name == "guest-zygote";
        let diagnostic = is_zygote || name == "memory-probe";
        if diagnostic {
            crate::zygote_diagnostics::Diagnostics::prepare(&diagnostic_dir)?;
        }
        if is_zygote {
            fs::copy(
                root.join("linkerconfig/ld.config.txt"),
                diagnostic_dir.join("ld.config.txt"),
            )?;
            if !root.join("run/ssal/ssal-zygote-diag.so").is_file() {
                return Err(io::Error::other("Guest Zygote diagnostic preload missing"));
            }
            command
                .env(
                    "LD_PRELOAD",
                    "/run/ssal/ssal-phase2-log.so:/run/ssal/ssal-zygote-diag.so",
                )
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            if std::env::var_os("SSAL_PHASE7FB_FORK").is_some() {
                command.env("LD_PRELOAD", "/run/ssal/ssal-phase2-log.so:/run/ssal/ssal-zygote-diag.so:/run/ssal/ssal-zygote-fd-reopen.so")
                    .env("SSAL_PHASE7FB_FD_REOPEN", "1");
            }
            if std::env::var_os("SSAL_PHASE8B3B_NOOP").is_some() {
                let preload = command
                    .get_envs()
                    .find_map(|(key, value)| {
                        (key == "LD_PRELOAD")
                            .then_some(value.unwrap().to_string_lossy().into_owned())
                    })
                    .unwrap();
                command
                    .env(
                        "LD_PRELOAD",
                        format!("/run/ssal/ssal-zygote-selinux-noop.so:{preload}"),
                    )
                    .env("SSAL_PHASE8B3B_NOOP", "1")
                    .env_remove("SSAL_PHASE7FC_BYPASS_SETCONTEXT");
            }
            if std::env::var_os("SSAL_PHASE8B5_ONCE").is_some() {
                command.env("LD_PRELOAD", "/run/ssal/ssal-system-server-runtime-sid.so:/run/ssal/ssal-phase2-log.so:/run/ssal/ssal-zygote-diag.so:/run/ssal/ssal-zygote-fd-reopen.so");
            }
        } else if diagnostic || name == "guest-property-service" {
            command.stdout(Stdio::piped()).stderr(Stdio::piped());
        } else {
            command.stdout(output.try_clone()?).stderr(output);
        }
        let sockets = if is_zygote {
            zygote_sockets(&mut command, Path::new("/dev/socket"))?
        } else {
            Vec::new()
        };
        if ssal::guest_policy::runtime::load(root)?.is_some() {
            let preload = command
                .get_envs()
                .find_map(|(key, value)| {
                    (key == "LD_PRELOAD").then(|| value.map(|s| s.to_string_lossy().into_owned()))
                })
                .flatten();
            command.env(
                "LD_PRELOAD",
                preload.map_or_else(
                    || "/run/ssal/ssal-context-map.so".into(),
                    |s| format!("/run/ssal/ssal-context-map.so:{s}"),
                ),
            );
        }
        let launch_ms = crate::zygote_diagnostics::launch_time();
        let started = Instant::now();
        let child = command.args(args).spawn()?;
        drop(sockets);
        println!("Guest service={name} pid={} executable={exe}", child.id());
        let mut service = Self {
            child,
            log,
            stopped: false,
            diagnostics: None,
            output: Vec::new(),
        };
        if name == "guest-property-service" {
            // The parent writes logs; Guest init need not write a system_file.
            service.output.push(crate::zygote_diagnostics::Stream::new(
                service.child.stdout.take().unwrap(),
                File::options().append(true).open(&service.log)?,
            )?);
            service.output.push(crate::zygote_diagnostics::Stream::new(
                service.child.stderr.take().unwrap(),
                File::options().append(true).open(&service.log)?,
            )?);
            service.drain_output()?;
        }
        if let Some((code, status)) = service.exit_status()? {
            service.drain_output()?;
            let log = fs::read_to_string(&service.log).unwrap_or_default();
            if !log.is_empty() {
                println!("Guest service log before cleanup:\n{log}");
            }
            return Err(io::Error::other(format!(
                "Guest service={name} exited after exec: waitid_code={code} status={status}; pre-exec cgroups verified"
            )));
        }
        let membership = match crate::memory_cgroup::verify_guest_membership(service.child.id()) {
            Ok(membership) => membership,
            Err(error) => {
                let cgroup = fs::read_to_string(format!("/proc/{}/cgroup", service.child.id()))
                    .unwrap_or_else(|e| format!("unavailable: {e}"));
                let log = fs::read_to_string(&service.log).unwrap_or_default();
                println!(
                    "{} Guest service membership failed pid={} cgroup={cgroup} exit_status={:?} error={error}; pre-exec cgroups verified; membership mismatch does not establish exit cause",
                    crate::zygote_diagnostics::launch_time(),
                    service.child.id(),
                    service.exit_status()?
                );
                if !log.is_empty() {
                    println!("Guest service log before cleanup:\n{log}");
                }
                return Err(error);
            }
        };
        println!(
            "Guest service memory cgroup membership pid={} path={membership}",
            service.child.id()
        );
        if diagnostic {
            service.diagnostics = Some(crate::zygote_diagnostics::Diagnostics::attach(
                &mut service.child,
                &diagnostic_dir,
                &crate::memory_cgroup::memory_group(crate::memory_cgroup::backend()?),
                launch_ms,
                started,
            )?);
            println!("Guest diagnostics={}", diagnostic_dir.display());
        }
        Ok(service)
    }
    fn drain_output(&mut self) -> io::Result<()> {
        for stream in &mut self.output {
            stream.drain()?;
        }
        Ok(())
    }
    fn wait_text(&mut self, text: &str) -> io::Result<()> {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            crate::memory_cgroup::check_interrupted()?;
            let exited = self.exited()?;
            self.drain_output()?;
            let log = fs::read_to_string(&self.log)?;
            if exited {
                return Err(io::Error::other(format!(
                    "Guest service exited before readiness: {log}"
                )));
            }
            if log.contains(text) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(io::Error::other(format!(
                    "Guest service readiness timeout ({text}): {log}"
                )));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    fn readiness_diagnostics(&self, root: &Path, reason: &str, service_lookup: &str) {
        let pid = self.child.id();
        let wchan = fs::read_to_string(format!("/proc/{pid}/wchan"))
            .unwrap_or_else(|error| format!("unavailable: {error}"));
        let mut fds = fs::read_dir(format!("/proc/{pid}/fd"))
            .map(|entries| {
                let mut fds: Vec<_> = entries
                    .flatten()
                    .map(|entry| {
                        let number = entry.file_name().to_string_lossy().into_owned();
                        let target = fs::read_link(entry.path())
                            .map(|path| path.display().to_string())
                            .unwrap_or_else(|error| format!("unavailable: {error}"));
                        let rdev = fs::metadata(entry.path())
                            .ok()
                            .filter(|metadata| metadata.file_type().is_char_device())
                            .map(|metadata| format!(" rdev={}", metadata.rdev()))
                            .unwrap_or_default();
                        format!("{number}->{target}{rdev}")
                    })
                    .collect();
                fds.sort();
                fds.join(",")
            })
            .unwrap_or_else(|error| format!("unavailable: {error}"));
        if fds.len() > 4096 {
            fds.truncate(4096);
        }
        let binder = fs::metadata(root.join("dev/binder"))
            .map(|metadata| format!("rdev={}", metadata.rdev()))
            .unwrap_or_else(|error| format!("unavailable: {error}"));
        let property_area = fs::metadata(root.join("dev/__properties__"))
            .map(|metadata| format!("dev={} ino={}", metadata.dev(), metadata.ino()))
            .unwrap_or_else(|error| format!("unavailable: {error}"));
        let property = guest_servicemanager_property(root)
            .map(|value| format!("{value:?}"))
            .unwrap_or_else(|error| format!("unavailable: {error}"));
        let context_manager = probe_guest_context_manager(root)
            .map(|value| value.trim().to_owned())
            .unwrap_or_else(|error| format!("failed: {error}"));
        let log = fs::read_to_string(&self.log)
            .map(|value| value.chars().take(4096).collect::<String>())
            .unwrap_or_else(|error| format!("unavailable: {error}"));
        println!(
            "Guest servicemanager readiness diagnostics: reason={reason:?} pid={pid} exit_status={:?} wchan={wchan:?} property={property} guest_property_area={property_area} guest_binder={binder} service_lookup={service_lookup:?}",
            self.exit_status()
        );
        println!("Guest servicemanager FDs: {fds}");
        println!("Guest Binder Context Manager probe: {context_manager}");
        println!("Guest servicemanager log: {log}");
    }
    fn wait_guest_context_manager(&mut self, root: &Path, expected_binder: u64) -> io::Result<()> {
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut context_manager = Err("not checked".to_owned());
        let mut next_context_manager_probe = Instant::now();
        loop {
            crate::memory_cgroup::check_interrupted()?;
            if self.exited()? {
                self.readiness_diagnostics(root, "Guest servicemanager exited", "not run");
                return Err(io::Error::other(
                    "Guest servicemanager exited before semantic readiness",
                ));
            }
            if Instant::now() >= next_context_manager_probe {
                context_manager =
                    probe_guest_context_manager(root).map_err(|error| error.to_string());
                next_context_manager_probe = Instant::now() + Duration::from_secs(1);
            }
            if let Ok(evidence) = &context_manager {
                let actual_binder = fs::metadata(root.join("dev/binder"))?.rdev();
                if actual_binder != expected_binder {
                    self.readiness_diagnostics(root, "Guest Binder identity changed", "not run");
                    return Err(io::Error::other(
                        "Guest Binder device changed during Context Manager readiness",
                    ));
                }
                println!(
                    "Guest Binder Context Manager=reachable pid={} private_binder_rdev={actual_binder}\n{evidence}",
                    self.child.id()
                );
                return Ok(());
            }
            if Instant::now() >= deadline {
                self.readiness_diagnostics(root, "semantic readiness timeout", "not run");
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("Guest Binder Context Manager timeout: {context_manager:?}"),
                ));
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    }
    fn wait_guest_servicemanager_property(
        &mut self,
        root: &Path,
        service_lookup: &str,
    ) -> io::Result<()> {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            crate::memory_cgroup::check_interrupted()?;
            if self.exited()? {
                self.readiness_diagnostics(root, "Guest servicemanager exited", service_lookup);
                return Err(io::Error::other(
                    "Guest servicemanager exited before servicemanager.ready=true",
                ));
            }
            let property = guest_servicemanager_property(root)
                .unwrap_or_else(|error| format!("unavailable: {error}"));
            if property == "true" {
                return Ok(());
            }
            if Instant::now() >= deadline {
                self.readiness_diagnostics(root, "servicemanager.ready timeout", service_lookup);
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("Guest servicemanager.ready remained {property:?}"),
                ));
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    }
    fn wait_for_socket(&mut self, socket_path: &Path) -> io::Result<()> {
        let deadline = Instant::now() + Duration::from_secs(90);
        loop {
            crate::memory_cgroup::check_interrupted()?;
            if let Some(diagnostics) = &mut self.diagnostics {
                diagnostics.tick()?;
            }
            let log = fs::read_to_string(&self.log)?;
            if self.exited()? {
                return Err(io::Error::other(format!(
                    "Guest Zygote exited before socket readiness: {log}"
                )));
            }
            if socket_path.exists() {
                let mut command = Command::new("/proc/self/exe");
                command
                    .arg("--zygote-readiness-client")
                    .current_dir(
                        socket_path
                            .parent()
                            .ok_or_else(|| io::Error::other("socket parent missing"))?,
                    )
                    .stdin(Stdio::null());
                unsafe {
                    command.pre_exec(|| {
                        ssal::unix::cloexec_unexpected_fds()?;
                        if libc::setgroups(0, std::ptr::null()) != 0
                            || libc::setresgid(1000, 1000, 1000) != 0
                            || libc::setresuid(1000, 1000, 1000) != 0
                            || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
                        {
                            return Err(io::Error::last_os_error());
                        }
                        Ok(())
                    });
                }
                let output = command.output()?;
                if output.status.success() {
                    if self.exited()? {
                        return Err(io::Error::other("Guest Zygote exited after ABI response"));
                    }
                    print!("{}", String::from_utf8_lossy(&output.stdout));
                    return Ok(());
                }
                if output.status.code() != Some(2) {
                    return Err(io::Error::other(format!(
                        "Guest Zygote readiness client failed: {}",
                        String::from_utf8_lossy(&output.stderr)
                    )));
                }
            }
            if Instant::now() >= deadline {
                return Err(io::Error::other(format!(
                    "Guest Zygote socket readiness timeout ({}): {log}",
                    socket_path.display()
                )));
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
    fn stop(&mut self) -> io::Result<()> {
        if self.stopped {
            return Ok(());
        }
        // Keep the leader unreaped until the owned process group has been stopped.
        if unsafe { libc::kill(-(self.child.id() as i32), libc::SIGKILL) } != 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) {
                return Err(error);
            }
        }
        let status = self.child.wait()?;
        self.drain_output()?;
        self.stopped = true;
        if let Some(diagnostics) = &mut self.diagnostics {
            diagnostics.finish(status)?;
        }
        println!(
            "Guest owned service pid={} stopped={status}\n{}",
            self.child.id(),
            fs::read_to_string(&self.log)?
        );
        Ok(())
    }
}

pub(crate) fn memory_probe(root: &Path, hierarchy_test: bool) -> io::Result<()> {
    let oom_test = hierarchy_test && std::env::var_os("SSAL_PHASE7D_FIX_OOM").is_some();
    let backend = crate::memory_cgroup::backend()?;
    if hierarchy_test && backend == crate::memory_cgroup::Backend::V1 {
        // shortcut: the Phase 7D OOM proof is v2-only, add a v1 probe before using that phase there.
        return Err(io::Error::other(
            "phase 7D OOM hierarchy probe currently requires cgroup v2",
        ));
    }
    let group = crate::memory_cgroup::memory_group(backend);
    let mut service = Service::start(
        root,
        if hierarchy_test {
            "/system/bin/bootstrap/linker64"
        } else {
            "/system/bin/sh"
        },
        if oom_test {
            &["/run/ssal/phase7d-fix-probe", "--oom"]
        } else if hierarchy_test {
            &["/run/ssal/phase7d-fix-probe"]
        } else {
            &["-c", "sleep 10"]
        },
        "memory-probe",
        1000,
        Some(GUEST_PROBE_CONTEXT),
        &[],
    )?;
    let pid = service.child.id();
    if hierarchy_test {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let status = fs::read_to_string(format!("/proc/{pid}/status"))?;
            if status
                .lines()
                .any(|line| line.starts_with("State:") && line.contains("stopped"))
            {
                break;
            }
            if service.exited()? || Instant::now() >= deadline {
                return Err(io::Error::other("allocator did not stop"));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let subgroup = crate::guest_mounts::task_cgroup_path()?.join("phase7d_fix");
        fs::write(subgroup.join("cgroup.procs"), pid.to_string())?;
        let before = crate::memory_cgroup::usage(&group, backend)?;
        if unsafe { libc::kill(pid as i32, libc::SIGCONT) } != 0 {
            return Err(io::Error::last_os_error());
        }
        if oom_test {
            let events = group.join("memory.events");
            loop {
                if let Some(diagnostics) = &mut service.diagnostics {
                    diagnostics.tick()?;
                }
                let text = fs::read_to_string(&events)?;
                let count = text
                    .lines()
                    .find_map(|line| line.strip_prefix("max "))
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(0);
                if count > 0 {
                    let limit: u64 = crate::memory_cgroup::read(group.join("memory.max"))?
                        .parse()
                        .map_err(io::Error::other)?;
                    let current: u64 = crate::memory_cgroup::read(group.join("memory.current"))?
                        .parse()
                        .map_err(io::Error::other)?;
                    if current > limit {
                        return Err(io::Error::other("memory.current exceeded max"));
                    }
                    println!("HIERARCHICAL_LIMIT current={current} max={limit} events={text:?}");
                    service.stop()?;
                    return Ok(());
                }
                if service.exited()? || Instant::now() >= deadline {
                    return Err(io::Error::other(format!(
                        "subgroup memory.max not observed: {text}"
                    )));
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        let stdout = root.parent().unwrap().join("phase7b/stdout.log");
        let children = loop {
            if let Some(diagnostics) = &mut service.diagnostics {
                diagnostics.tick()?;
            }
            let content = fs::read_to_string(&stdout)?;
            if let Some(line) = content.lines().find(|line| line.starts_with("normal=")) {
                break line.to_owned();
            }
            if service.exited()? || Instant::now() >= deadline {
                return Err(io::Error::other("allocator children not ready"));
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        for field in children.split_whitespace() {
            let (kind, value) = field
                .split_once('=')
                .ok_or_else(|| io::Error::other("invalid child report"))?;
            let child: u32 = value.parse().map_err(io::Error::other)?;
            if kind == "detached" {
                loop {
                    let stat = fs::read_to_string(format!("/proc/{child}/stat"))?;
                    let session = stat
                        .rsplit_once(')')
                        .and_then(|(_, rest)| rest.split_whitespace().nth(3))
                        .and_then(|value| value.parse::<u32>().ok());
                    if session == Some(child) {
                        break;
                    }
                    if Instant::now() >= deadline {
                        return Err(io::Error::other("setsid child not ready"));
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
            let member = crate::memory_cgroup::verify_membership(
                child,
                &crate::memory_cgroup::memory_mount(backend),
                &subgroup,
            )?;
            println!("GUEST_CHILD pid={child} membership={member}");
        }
        let after = crate::memory_cgroup::usage(&group, backend)?;
        if after < before + 8 * 1024 * 1024 {
            return Err(io::Error::other(format!(
                "hierarchical memory charge too small: {before} -> {after}"
            )));
        }
        println!(
            "HIERARCHICAL_MEMORY before={before} after={after} delta={}",
            after - before
        );
    }
    let membership = crate::memory_cgroup::verify_guest_membership(pid)?;
    let current = crate::memory_cgroup::usage(&group, backend)?;
    if current == 0 {
        return Err(io::Error::other("Guest memory accounting is empty"));
    }
    println!("GUEST_MEMORY_PROBE pid={pid} membership={membership} memory_usage={current}");
    if let Some(diagnostics) = &mut service.diagnostics {
        diagnostics.tick()?;
    }
    if hierarchy_test
        && (std::env::var_os("SSAL_PHASE7D_FIX_HOLD").is_some()
            || std::env::var_os("SSAL_PHASE7D_FIX_TIMEOUT").is_some())
    {
        let timeout = std::env::var_os("SSAL_PHASE7D_FIX_TIMEOUT").is_some();
        let deadline = Instant::now() + Duration::from_secs(if timeout { 2 } else { 30 });
        println!("GUEST_LIFECYCLE_WAIT timeout_test={timeout}");
        loop {
            crate::memory_cgroup::check_interrupted()?;
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "Guest lifecycle test timeout",
                ));
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    service.stop()?;
    Ok(())
}
impl Drop for Service {
    fn drop(&mut self) {
        if let Err(e) = self.stop() {
            eprintln!("Guest service cleanup: {e}");
        }
    }
}

fn classpath_exports(content: &str) -> io::Result<GuestClasspaths> {
    let mut boot = None;
    let mut dex2oat = None;
    let mut system_server = None;
    let mut standalone_system_server = None;
    let mut standalone_seen = false;
    for line in content.lines() {
        let mut fields = line.split_whitespace();
        if fields.next() != Some("export") {
            continue;
        }
        let Some(name) = fields.next() else {
            continue;
        };
        let value = fields.next();
        if fields.next().is_some() {
            return Err(io::Error::other("invalid Guest classpath export"));
        }
        let destination = match name {
            "BOOTCLASSPATH" => &mut boot,
            "DEX2OATBOOTCLASSPATH" => &mut dex2oat,
            "SYSTEMSERVERCLASSPATH" => &mut system_server,
            "STANDALONE_SYSTEMSERVER_JARS" => {
                if standalone_seen {
                    return Err(io::Error::other(
                        "duplicate Guest STANDALONE_SYSTEMSERVER_JARS",
                    ));
                }
                standalone_seen = true;
                standalone_system_server =
                    value.filter(|value| !value.is_empty()).map(str::to_owned);
                continue;
            }
            _ => continue,
        };
        let value = value
            .filter(|value| !value.is_empty())
            .ok_or_else(|| io::Error::other(format!("Guest {name} missing")))?;
        if destination.replace(value.to_owned()).is_some() {
            return Err(io::Error::other(format!("duplicate Guest {name}")));
        }
    }
    Ok(GuestClasspaths {
        boot: boot.ok_or_else(|| io::Error::other("Guest BOOTCLASSPATH missing"))?,
        dex2oat,
        system_server: system_server
            .ok_or_else(|| io::Error::other("Guest SYSTEMSERVERCLASSPATH missing"))?,
        standalone_system_server,
    })
}

fn checked_guest_classpath_paths(classpaths: &GuestClasspaths) -> io::Result<Vec<String>> {
    let mut paths = Vec::new();
    for classpath in std::iter::once(classpaths.boot.as_str())
        .chain(classpaths.dex2oat.iter().map(String::as_str))
        .chain(std::iter::once(classpaths.system_server.as_str()))
        .chain(
            classpaths
                .standalone_system_server
                .iter()
                .map(String::as_str),
        )
    {
        for path in classpath.split(':') {
            if !["/apex/", "/product/", "/system/", "/system_ext/"]
                .iter()
                .any(|prefix| path.starts_with(prefix))
                || path
                    .split('/')
                    .skip(1)
                    .any(|part| part.is_empty() || part == "." || part == "..")
                || path
                    .bytes()
                    .any(|byte| byte.is_ascii_whitespace() || byte == b'\\' || byte == 0)
            {
                return Err(io::Error::other(format!(
                    "Guest classpath escaped system/APEX roots: {path}"
                )));
            }
            paths.push(path.to_owned());
        }
    }
    paths.extend([
        "/system/framework/services.jar".to_owned(),
        "/system/lib64/libandroid_servers.so".to_owned(),
    ]);
    Ok(paths)
}

fn guest_env_value<'a>(environ: &'a [u8], name: &str) -> Option<&'a [u8]> {
    let prefix = format!("{name}=");
    environ
        .split(|byte| *byte == 0)
        .find_map(|entry| entry.strip_prefix(prefix.as_bytes()))
}

fn derive_guest_classpath(root: &Path) -> io::Result<GuestClasspaths> {
    const OUTPUT: &str = "/run/ssal/phase7a-classpath.env";
    run(
        root,
        "/apex/com.android.sdkext/bin/derive_classpath",
        &[
            "--override-device-sdk-version=36",
            "--override-device-codename=REL",
            OUTPUT,
        ],
        0,
    )?;
    let result = classpath_exports(&fs::read_to_string(
        root.join(OUTPUT.trim_start_matches('/')),
    )?);
    fs::remove_file(root.join(OUTPUT.trim_start_matches('/')))?;
    let classpaths = result?;
    let paths = checked_guest_classpath_paths(&classpaths)?;
    let mut args = vec![
        "-c",
        "set -eu; for path do test -f \"$path\" || { echo \"missing Guest classpath file: $path\" >&2; exit 1; }; done",
        "ssal-classpath-preflight",
    ];
    args.extend(paths.iter().map(String::as_str));
    run(root, "/system/bin/sh", &args, 0)?;
    println!(
        "Guest classpath source=derive_classpath(Guest SDK 36, REL) boot_entries={} dex2oat_entries={} system_server_entries={} standalone_system_server_entries={}",
        classpaths.boot.split(':').count(),
        classpaths.dex2oat.as_deref().map_or(0, |v| v.split(':').count()),
        classpaths.system_server.split(':').count(),
        classpaths
            .standalone_system_server
            .as_deref()
            .map_or(0, |v| v.split(':').count())
    );
    Ok(classpaths)
}

fn start_property_service(
    mounts: &mut Mounts,
    root: &Path,
    bin: &Path,
    host_mount_namespace: &Path,
) -> io::Result<Service> {
    let runtime = crate::guest_mounts::directory(root, "run/ssal", 0o755)?;
    let contexts = runtime.join("guest_property_contexts");
    fs::write(
        &contexts,
        "persist.ssal_probe u:object_r:ssal_guest_property_area:s0 exact uint\n",
    )?;
    let overrides = runtime.join("guest_build.prop");
    fs::write(
        &overrides,
        [
            "servicemanager.ready=false",
            "ro.product.cpu.abilist64=arm64-v8a",
            "ro.build.version.codename=REL",
            "dalvik.vm.dex2oat64.enabled=true",
            "ro.zygote.disable_gl_preload=1",
        ]
        .join("\n")
            + "\n",
    )?;
    if !root.join("system/build.prop").is_file() {
        return Err(io::Error::other("Guest /system/build.prop missing"));
    }
    let identity = |path: &Path| -> io::Result<[u64; 2]> {
        let metadata = fs::metadata(path)?;
        Ok([metadata.dev(), metadata.ino()])
    };
    let host_property_identity = identity(Path::new("/dev/__properties__"))?;
    let host_socket_identity = identity(Path::new("/dev/socket"))?;
    let host_data_identity = identity(Path::new("/data"))?;
    let host_persistent_identity = identity(Path::new("/data/property"))?;
    let mut config = serde_json::json!({
        "host_mount_namespace": host_mount_namespace.display().to_string(),
        "host_property_identity": host_property_identity,
        "host_socket_identity": host_socket_identity,
        "host_data_identity": host_data_identity,
        "host_persistent_identity": host_persistent_identity,
        "property_contexts": ["/run/ssal/guest_property_contexts"],
        "build_props": ["/system/build.prop", "/run/ssal/guest_build.prop"],
    });
    let plan = ssal::guest_policy::runtime::load(root)?;
    if let Some(plan) = &plan {
        let mut paths = Vec::new();
        for (path, text) in &plan.contexts {
            if path.ends_with("property_contexts") {
                let name = format!("mapped_{}", path.replace('/', "_"));
                fs::write(runtime.join(&name), text)?;
                paths.push(format!("/run/ssal/{name}"));
            }
        }
        config["property_contexts"] = serde_json::to_value(paths)?;
        config["selinux_types"] = serde_json::to_value(&plan.types)?;
    }
    fs::write(
        runtime.join("property-service.json"),
        serde_json::to_vec(&config).map_err(io::Error::other)?,
    )?;

    let property_dir = crate::guest_mounts::directory(root, "data/property", 0o700)?;
    let metadata = fs::metadata(&property_dir)?;
    if metadata.uid() != 0 || metadata.mode() & 0o077 != 0 {
        return Err(io::Error::other(
            "Guest /data/property must be root-owned mode 0700",
        ));
    }
    let area = crate::guest_mounts::directory(root, "dev/__properties__", 0o755)?;
    if fs::read_dir(&area)?.next().is_some() {
        return Err(io::Error::other("Guest property area is not fresh"));
    }
    let executable = runtime.join("property-service");
    File::create(&executable)?;
    ssal::guest_policy::runtime::bind_file(
        mounts,
        root,
        &bin.join("ssal-property-service"),
        &executable,
    )?;
    let mut service = Service::start(
        root,
        "/system/bin/bootstrap/linker64",
        &[
            "/run/ssal/property-service",
            "--config",
            "/run/ssal/property-service.json",
        ],
        "guest-property-service",
        0,
        Some(PROPERTY_SERVICE_CONTEXT),
        &[],
    )?;
    service.wait_text("guest_property_service_ready")?;
    let process_context = fs::read_to_string(format!("/proc/{}/attr/current", service.child.id()))?;
    let expected = plan
        .as_ref()
        .map(|p| p.context("init", true))
        .transpose()?
        .unwrap_or_else(|| "u:r:ssal_property:s0".into());
    if process_context.trim_matches('\0').trim() != expected {
        return Err(io::Error::other(format!(
            "Guest property service SID mismatch: {process_context:?}"
        )));
    }
    for (guest, host, name) in [
        (identity(&area)?, host_property_identity, "property area"),
        (
            identity(&root.join("dev/socket"))?,
            host_socket_identity,
            "socket directory",
        ),
        (
            identity(&root.join("data"))?,
            host_data_identity,
            "userdata",
        ),
        (
            identity(&property_dir)?,
            host_persistent_identity,
            "persistent directory",
        ),
    ] {
        if guest == host {
            return Err(io::Error::other(format!("Host {name} selected")));
        }
    }
    let guest_socket = identity(&root.join("dev/socket/property_service"))?;
    if guest_socket == identity(Path::new("/dev/socket/property_service"))? {
        return Err(io::Error::other("Host property socket selected"));
    }
    println!(
        "PHASE7I_PROPERTY_SERVICE=PASS pid={} sid={expected} host_area={host_property_identity:?} guest_area={:?} host_data={host_data_identity:?} guest_data={:?}",
        service.child.id(),
        identity(&area)?,
        identity(&root.join("data"))?
    );
    Ok(service)
}

fn isolated(root: &Path, userdata: &Path) -> io::Result<()> {
    let identity = |path: &Path| -> io::Result<_> {
        let m = fs::metadata(path)?;
        Ok((m.dev(), m.ino()))
    };
    if identity(&root.join("data"))? != identity(userdata)?
        || identity(userdata)?.0 == identity(Path::new("/data"))?.0
    {
        return Err(io::Error::other("Guest userdata identity mismatch"));
    }
    for path in [
        "dev/socket/property_service",
        "dev/socket/property_service_for_system",
        "dev/socket/init",
        "dev/socket/ctl.start",
        "dev/hwbinder",
        "dev/vndbinder",
    ] {
        if fs::symlink_metadata(root.join(path)).is_ok() {
            return Err(io::Error::other(format!(
                "unexpected Guest endpoint {path}"
            )));
        }
    }
    if fs::read_dir(root.join("dev/socket"))?.next().is_some() {
        return Err(io::Error::other(
            "Guest control socket directory is not empty",
        ));
    }
    Ok(())
}

pub(crate) fn verify(
    mounts: &mut Mounts,
    root: &Path,
    userdata: &Path,
    phase6a: bool,
    phase6b: bool,
    phase7a: bool,
    host_mount_namespace: &Path,
) -> io::Result<()> {
    let phase7i_property_tests = std::env::var_os("SSAL_PHASE7I_PROPERTIES").is_some();
    if ssal::guest_policy::runtime::load(root)?.is_some()
        && [
            "SSAL_PHASE7FC_BYPASS_SETCONTEXT",
            "SSAL_PHASE8B3B_NOOP",
            "SSAL_PHASE8B3D_SAME_CONTEXT",
            "SSAL_PHASE8B5_ONCE",
        ]
        .iter()
        .any(|key| std::env::var_os(key).is_some())
    {
        return Err(io::Error::other(
            "profile SELinux mapping cannot use fixed-SID or SELinux-bypass diagnostic runtimes",
        ));
    }
    let system_server_preflight = system_server_preflight::enabled()?;
    let runtime_sid = system_server_runtime_sid::enabled(phase7a)?;
    if system_server_preflight
        && (!phase7a
            || [
                "SSAL_PHASE8B3B_NOOP",
                "SSAL_PHASE8B3D_TRACE",
                "SSAL_PHASE8B3D_SAME_CONTEXT",
            ]
            .iter()
            .any(|key| std::env::var_os(key).is_some()))
    {
        return Err(io::Error::other(
            "8B-4B-1 requires Phase 7I and unmodified Guest SELinux libraries",
        ));
    }
    if fs::read_to_string("/sys/fs/selinux/enforce")?.trim() != "1" {
        return Err(io::Error::other("Host global Enforcing required"));
    }
    isolated(root, userdata)?;
    if phase7a {
        let host_net_namespace = fs::read_link("/proc/1/ns/net")?;
        if unsafe { libc::unshare(libc::CLONE_NEWNET) } != 0 {
            return Err(io::Error::other(format!(
                "Guest Zygote network namespace: {}",
                io::Error::last_os_error()
            )));
        }
        let guest_net_namespace = fs::read_link("/proc/self/ns/net")?;
        if host_net_namespace == guest_net_namespace {
            return Err(io::Error::other(
                "Guest Zygote still shares Host abstract socket namespace",
            ));
        }
        println!(
            "Guest Zygote network namespace isolated: Host={} Guest={}",
            host_net_namespace.display(),
            guest_net_namespace.display()
        );
    }
    let runtime = crate::guest_mounts::directory(root, "run/ssal", 0o755)?;
    let bin = std::env::current_exe()?.parent().unwrap().to_owned();
    let mut runtime_bins = vec![
        "guest_probe",
        "phase3-ipc",
        "ssal-phase2-log.so",
        "ssal-zygote-diag.so",
        "ssal-property-service",
    ];
    if std::env::var_os("SSAL_TRACE_GUEST_SIGABRT").is_some() {
        runtime_bins.push("ssal-abort-trace.so");
    }
    if phase7a && std::env::var_os("SSAL_PHASE8B3B_NOOP").is_some() {
        runtime_bins.extend(["ssal-zygote-selinux-noop.so", "ssal-selinux-startup-probe"]);
    }
    for name in runtime_bins {
        if name == "ssal-zygote-diag.so" && !phase7a {
            continue;
        }
        let target = runtime.join(name);
        File::create(&target)?;
        ssal::guest_policy::runtime::bind_file(mounts, root, &bin.join(name), &target)?;
    }
    if phase7a && std::env::var_os("SSAL_PHASE8B3D_SAME_CONTEXT").is_some() {
        mounts.bind(
            &bin.join("ssal-libselinux-same-context.so"),
            &root.join("system/lib64/libselinux.so"),
            true,
            false,
        )?;
    }
    let mut binder = crate::binder_probe::Session::new();
    if system_server_preflight {
        system_server_preflight::prepare(mounts, root, &bin)?;
    }
    let mut property_service = None;
    let result = (|| {
        // Reuse the established servicemanager view: libselinux rejects an RO root.
        // All control endpoints stay RO; only existing AV/context query files are RW.
        mounts.bind(
            Path::new("/sys/fs/selinux"),
            &root.join("sys/fs/selinux"),
            false,
            false,
        )?;
        for entry in fs::read_dir("/sys/fs/selinux")? {
            let entry = entry?;
            if ["access", "context", "create", "relabel", "member", "user"]
                .contains(&entry.file_name().to_str().unwrap_or(""))
            {
                continue;
            }
            mounts.bind(
                &entry.path(),
                &root.join("sys/fs/selinux").join(entry.file_name()),
                true,
                entry.file_type()?.is_dir(),
            )?;
        }
        {
            property_service = Some(start_property_service(
                mounts,
                root,
                &bin,
                host_mount_namespace,
            )?);
            let property_script = if !phase7i_property_tests {
                r#"set -eu
test "$(getprop ro.build.version.sdk)" = 36
test "$(getprop ro.product.cpu.abilist64)" = arm64-v8a
test "$(getprop servicemanager.ready)" = false
echo SSAL_GUEST_PRIVATE_PROPERTIES=PASS
"#
            } else if std::env::var_os("SSAL_PHASE7I_VERIFY_PERSIST").is_some() {
                r#"set -eu
test "$(getprop ro.build.version.sdk)" = 36
test "$(getprop servicemanager.ready)" = false
test "$(getprop persist.ssal_probe)" = 7
test -z "$(getprop sys.ssal_probe)"
echo SSAL_PROPERTY_RESTORE=PASS
"#
            } else {
                r#"set -eu
test "$(getprop ro.build.version.sdk)" = 36
test "$(getprop ro.product.cpu.abilist64)" = arm64-v8a
test "$(getprop servicemanager.ready)" = false
setprop sys.ssal_probe phase7i
test "$(getprop sys.ssal_probe)" = phase7i
setprop persist.ssal_probe 7
test "$(getprop persist.ssal_probe)" = 7
echo SSAL_PROPERTY_BIONIC=PASS
"#
            };
            let property_output = run(root, "/system/bin/sh", &["-c", property_script], 1000)?;
            let expected_marker = if phase7i_property_tests {
                "SSAL_PROPERTY_"
            } else {
                "SSAL_GUEST_PRIVATE_PROPERTIES=PASS"
            };
            if !property_output.contains(expected_marker) {
                return Err(io::Error::other("Guest Bionic property evidence missing"));
            }
        }
        let (major, minor, _) = binder.provision(root)?;
        let device = binder.private_device()?;
        if unsafe { libc::fchmod(device.as_raw_fd(), 0o666) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let area = fs::metadata(root.join("dev/__properties__"))?;
        let host = fs::metadata("/dev/__properties__")?;
        if (area.dev(), area.ino()) == (host.dev(), host.ino()) {
            return Err(io::Error::other("Host property area selected"));
        }
        // Linkerconfig must see Guest properties and only the private Binder alias.
        run(
            root,
            crate::guest_mounts::linkerconfig_binary(root)?,
            &["--target", "/linkerconfig"],
            0,
        )?;
        let sentinel = File::open("/data")?;
        if unsafe { libc::fcntl(sentinel.as_raw_fd(), libc::F_SETFD, 0) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let guest_local = crate::guest_mounts::directory(root, "data/local", 0o751)?;
        fs::set_permissions(&guest_local, fs::Permissions::from_mode(0o751))?;
        let guest_tmp = crate::guest_mounts::directory(root, "data/local/tmp", 0o1771)?;
        let guest_tmp_c = std::ffi::CString::new(guest_tmp.as_os_str().as_encoded_bytes())?;
        if unsafe { libc::chown(guest_tmp_c.as_ptr(), 0, 1000) } != 0 {
            return Err(io::Error::last_os_error());
        }
        fs::set_permissions(&guest_tmp, fs::Permissions::from_mode(0o1771))?;
        if let Some(plan) = ssal::guest_policy::runtime::load(root)? {
            ssal::guest_policy::runtime::set_label(
                &guest_tmp,
                &plan.context("shell_data_file", false)?,
            )?;
        }
        let local_metadata = fs::metadata(&guest_local)?;
        let tmp_metadata = fs::metadata(&guest_tmp)?;
        println!(
            "Guest tmp DAC local={}:{}:{:04o} tmp={}:{}:{:04o}",
            local_metadata.uid(),
            local_metadata.gid(),
            local_metadata.mode() & 0o7777,
            tmp_metadata.uid(),
            tmp_metadata.gid(),
            tmp_metadata.mode() & 0o7777
        );
        println!("Guest FD pre-exec: injected Host /data fd={}; root command closes inherited identities and marks later FDs CLOEXEC", sentinel.as_raw_fd());
        let shell_context = ssal::guest_policy::runtime::load(root)?
            .map(|plan| plan.context("shell", true))
            .transpose()?
            .unwrap_or_else(|| "u:r:ssal_guest_probe:s0".into());
        let shell_script = format!(
            r#"set -eu
test "$(getprop ro.build.version.sdk)" = 36
test "$(getprop ro.product.cpu.abilist64)" = arm64-v8a
test "$(getprop ro.zygote.disable_gl_preload)" = 1
test "$(getprop servicemanager.ready)" = false
test -z "$(getprop ro.boot.serialno)"
if test -e /run/ssal/property-service.json; then test -S /dev/socket/property_service; else test ! -e /dev/socket/property_service; fi
for p in /dev/socket/property_service_for_system /dev/socket/init; do test ! -e "$p"; done
for fd in /proc/$$/fd/*; do
    target=$(readlink "$fd") || continue
    echo "Guest post-exec fd=$fd target=$target"
    case "$target" in /dev/null|pipe:*|/system/bin/sh|/system/bin/mksh) ;; *) exit 31;; esac
done
test "$(cat /proc/$$/attr/current)" = "{shell_context}"
umask 077
marker=/data/local/tmp/ssal-launcher-$$
set -C
printf guest > "$marker"
test "$(cat "$marker")" = guest
rm "$marker"
set +e
setprop ctl.start ssal_must_not_reach_host_init
rc=$?
set -e
echo "Guest ctl.start return=$rc"
test "$rc" != 0
echo SSAL_GUEST_SHELL_PROPERTY_FD=PASS
"#
        );
        let shell = run(root, "/system/bin/sh", &["-c", &shell_script], 1000)?;
        if !shell.contains("SSAL_GUEST_SHELL_PROPERTY_FD=PASS") {
            return Err(io::Error::other("shell evidence missing"));
        }
        drop(sentinel);
        let mut manager = Service::start(
            root,
            "/system/bin/servicemanager",
            &[],
            "servicemanager",
            1000,
            Some(GUEST_PROBE_CONTEXT),
            &[],
        )?;
        manager.wait_guest_servicemanager_property(root, "not run")?;
        println!("GUEST_SERVICEMANAGER_PROPERTY=PASS value=true");
        let guest_binder = fs::metadata(root.join("dev/binder"))?.rdev();
        manager.wait_guest_context_manager(root, guest_binder)?;
        let mut server = Service::start(
            root,
            "/system/bin/bootstrap/linker64",
            &["/run/ssal/phase3-ipc", "server"],
            "aidl-server",
            1000,
            Some(GUEST_PROBE_CONTEXT),
            &[],
        )?;
        if let Err(error) = server.wait_text("\"event\":\"registered\"") {
            manager.readiness_diagnostics(
                root,
                "Guest AIDL service registration failed",
                "not run",
            );
            return Err(error);
        }
        let ipc = match run(
            root,
            "/system/bin/bootstrap/linker64",
            &["/run/ssal/phase3-ipc", "client"],
            1000,
        ) {
            Ok(ipc) => ipc,
            Err(error) => {
                manager.readiness_diagnostics(root, "Guest AIDL service lookup failed", "failed");
                return Err(error);
            }
        };
        if !ipc.contains("\"event\":\"ipc_passed\"") {
            manager.readiness_diagnostics(
                root,
                "Guest AIDL service lookup returned no success event",
                "failed",
            );
            return Err(io::Error::other("AIDL IPC success evidence missing"));
        }
        println!("GUEST_SERVICEMANAGER_READINESS=PASS property=servicemanager.ready:true context_manager=Guest_handle_0 service_lookup=aidl_lazy_test_1 private_binder={major}:{minor}");
        println!("PHASE5B=PASS shell=PASS private_aidl=PASS properties=PASS host_control_socket=ABSENT private_binder={major}:{minor}");
        if phase7a {
            let controlled_fork = std::env::var_os("SSAL_PHASE7FB_FORK").is_some();
            let app_trace = std::env::var_os("SSAL_PHASE8B3D_TRACE").is_some();
            if controlled_fork && app_trace {
                fork_probe::prepare(mounts, root, &bin, true)?;
            }
            if std::env::var_os("SSAL_PHASE8B3B_NOOP").is_some() {
                // App trace uses the same overlay as Zygote; startup diagnostic uses stock rules.
                for probe_uid in if app_trace {
                    &[0, 1000, 10000][..]
                } else {
                    &[1000][..]
                } {
                    let output = crate::guest_probe::run_with_timeout(
                        command(
                            root,
                            "/run/ssal/ssal-selinux-startup-probe",
                            *probe_uid,
                            Some(GUEST_PROBE_CONTEXT),
                        )?
                        .env("LD_LIBRARY_PATH", "/run/ssal:/system/lib64")
                        .env("LD_PRELOAD", "/run/ssal/ssal-zygote-selinux-noop.so"),
                        "SELinux startup diagnostic",
                        Duration::from_secs(10),
                    )?;
                    println!(
                        "Guest isolated SELinux startup diagnostic exit={}\n{}{}",
                        output.status,
                        String::from_utf8_lossy(&output.stdout),
                        String::from_utf8_lossy(&output.stderr)
                    );
                    if !output.status.success() {
                        return Err(io::Error::other(
                            "SELinux startup diagnostic failed to execute",
                        ));
                    }
                }
            }
            if controlled_fork && !app_trace {
                fork_probe::prepare(mounts, root, &bin, true)?;
            }
            if system_server_preflight {
                system_server_preflight::run(root, &bin)?;
            }
            if runtime_sid {
                system_server_runtime_sid::prepare(mounts, root, &bin)?;
            }
            crate::guest_mounts::directory(root, "data/dalvik-cache", 0o771)?;
            let binary = run(
                root,
                "/system/bin/sh",
                &[
                    "-c",
                    "set -eu; test -x /system/bin/app_process64; test -x /apex/com.android.sdkext/bin/derive_classpath; test ! -e /dev/socket/zygote; if test -e /run/ssal/property-service.json; then test -S /dev/socket/property_service; else test ! -e /dev/socket/property_service; fi; stat -c '%n %s %a %u %g' /system/bin/app_process64; sha256sum /system/bin/app_process64; getprop ro.product.cpu.abilist64; getprop ro.zygote.disable_gl_preload",
                ],
                0,
            )?;
            println!("Guest Zygote binary preflight:\n{binary}");
            let classpaths = derive_guest_classpath(root)?;
            let boot_classpath = if controlled_fork {
                format!("{}:/system/framework/am.jar", classpaths.boot)
            } else {
                classpaths.boot.clone()
            };
            let mut zygote_env = vec![
                ("ANDROID_BOOTLOGO", "1"),
                ("ANDROID_ASSETS", "/system/app"),
                ("EXTERNAL_STORAGE", "/sdcard"),
                (
                    "LD_LIBRARY_PATH",
                    // Let the generated ART namespace own libart and its runtime singleton.
                    "/run/ssal:/apex/com.android.adbd/lib64:/system/lib64:/apex/com.android.os.statsd/lib64:/apex/com.android.i18n/lib64",
                ),
                ("BOOTCLASSPATH", boot_classpath.as_str()),
                ("SYSTEMSERVERCLASSPATH", classpaths.system_server.as_str()),
            ];
            if let Some(classpath) = classpaths.dex2oat.as_deref() {
                zygote_env.push(("DEX2OATBOOTCLASSPATH", classpath));
            }
            if let Some(jars) = classpaths.standalone_system_server.as_deref() {
                zygote_env.push(("STANDALONE_SYSTEMSERVER_JARS", jars));
            }
            zygote_env.push(("SSAL_PHASE7I_PROPERTIES", "1"));
            if controlled_fork && std::env::var_os("SSAL_PHASE7FC_BYPASS_SETCONTEXT").is_some() {
                zygote_env.push(("SSAL_PHASE7FC_BYPASS_SETCONTEXT", "1"));
            }
            if runtime_sid {
                return system_server_runtime_sid::run(root, &bin, &zygote_env);
            }
            println!(
                "Guest Zygote launch socket=/dev/socket/zygote start_system_server=false private_binder={major}:{minor}"
            );
            let mut zygote = Service::start(
                root,
                "/system/bin/app_process64",
                &if controlled_fork {
                    vec![
                        "-Xzygote",
                        "-XX:ForceJavaZygoteForkLoop=true",
                        "/system/bin",
                        "--zygote",
                        "--socket-name=zygote",
                    ]
                } else {
                    vec![
                        "-Xzygote",
                        "/system/bin",
                        "--zygote",
                        "--socket-name=zygote",
                    ]
                },
                "guest-zygote",
                0,
                Some(GUEST_PROBE_CONTEXT),
                &zygote_env,
            )?;
            zygote.wait_for_socket(&root.join("dev/socket/zygote"))?;
            let pid = zygote.child.id();
            let guest_root = fs::metadata(root)?;
            let process_root = fs::metadata(format!("/proc/{pid}/root"))?;
            if (guest_root.dev(), guest_root.ino()) != (process_root.dev(), process_root.ino()) {
                return Err(io::Error::other("Guest Zygote root identity mismatch"));
            }
            let domain = fs::read_to_string(format!("/proc/{pid}/attr/current"))?;
            let expected = ssal::guest_policy::runtime::load(root)?
                .map(|p| p.context("zygote", true))
                .transpose()?
                .unwrap_or_else(|| "u:r:ssal_guest_probe:s0".into());
            if domain.trim_matches('\0').trim() != expected {
                return Err(io::Error::other(format!(
                    "Guest Zygote domain mismatch: {domain:?}"
                )));
            }
            let status = fs::read_to_string(format!("/proc/{pid}/status"))?;
            let uid = status
                .lines()
                .find(|line| line.starts_with("Uid:"))
                .ok_or_else(|| io::Error::other("Guest Zygote UID missing"))?;
            if uid.split_whitespace().skip(1).any(|value| value != "0") {
                return Err(io::Error::other(format!("Guest Zygote is not root: {uid}")));
            }
            if fs::read_link(format!("/proc/{pid}/ns/net"))? != fs::read_link("/proc/self/ns/net")?
            {
                return Err(io::Error::other(
                    "Guest Zygote left its isolated network namespace",
                ));
            }
            let guest_binder = fs::metadata(root.join("dev/binder"))?.rdev();
            let host_binder = fs::metadata("/dev/binder")?.rdev();
            if guest_binder == host_binder {
                return Err(io::Error::other("Guest Binder resolves to Host Binder"));
            }
            let mut private_binder_fds = 0;
            for fd in fs::read_dir(format!("/proc/{pid}/fd"))? {
                let fd = fd?;
                let target = fs::read_link(fd.path())?;
                if target == Path::new("/dev/binder") {
                    if fs::metadata(fd.path())?.rdev() != guest_binder {
                        return Err(io::Error::other("Guest Zygote opened a non-Guest Binder"));
                    }
                    private_binder_fds += 1;
                }
            }
            println!(
                "Guest Zygote ready pid={pid} root=Guest uid=0 domain={} isolated_netns=true private_binder_fds={private_binder_fds}",
                domain.trim_matches('\0').trim()
            );
            let process_stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
            let starttime = process_stat
                .rsplit_once(") ")
                .and_then(|(_, fields)| fields.split_whitespace().nth(19))
                .ok_or_else(|| io::Error::other("Zygote starttime missing"))?;
            let socket = fs::metadata(root.join("dev/socket/zygote"))?;
            println!(
                "Guest Zygote socket file inode={} uid={} gid={} mode={:o}",
                socket.ino(),
                socket.uid(),
                socket.gid(),
                socket.mode() & 0o777
            );
            let environ = fs::read(format!("/proc/{pid}/environ"))?;
            let standalone_env_matches = match classpaths.standalone_system_server.as_deref() {
                Some(expected) => {
                    guest_env_value(&environ, "STANDALONE_SYSTEMSERVER_JARS")
                        == Some(expected.as_bytes())
                }
                None => guest_env_value(&environ, "STANDALONE_SYSTEMSERVER_JARS").is_none(),
            };
            if guest_env_value(&environ, "SYSTEMSERVERCLASSPATH")
                != Some(classpaths.system_server.as_bytes())
                || !standalone_env_matches
            {
                return Err(io::Error::other(
                    "Guest system-server classpath environment mismatch",
                ));
            }
            println!(
                "Guest Zygote classpath environment verified system_server_entries={} standalone_entries={}",
                classpaths.system_server.split(':').count(),
                classpaths
                    .standalone_system_server
                    .as_deref()
                    .map_or(0, |v| v.split(':').count())
            );
            let inherited_sockets: Vec<_> = environ
                .split(|b| *b == 0)
                .filter_map(|entry| {
                    [
                        b"ANDROID_SOCKET_zygote=".as_slice(),
                        b"ANDROID_SOCKET_usap_pool_primary=".as_slice(),
                    ]
                    .iter()
                    .find_map(|prefix| {
                        entry
                            .strip_prefix(*prefix)
                            .map(|fd| String::from_utf8_lossy(fd).into_owned())
                    })
                })
                .collect();
            if inherited_sockets.len() != 2 {
                return Err(io::Error::other(
                    "Guest inherited socket environment missing",
                ));
            }
            let mut socket_fds = Vec::new();
            for fd in fs::read_dir(format!("/proc/{pid}/fd"))? {
                let fd = fd?;
                if let Ok(target) = fs::read_link(fd.path()) {
                    if target.to_string_lossy().starts_with("socket:[") {
                        println!(
                            "Guest Zygote fd={} target={}",
                            fd.file_name().to_string_lossy(),
                            target.display()
                        );
                        if inherited_sockets
                            .contains(&fd.file_name().to_string_lossy().into_owned())
                        {
                            socket_fds.push((fd.file_name(), target));
                        }
                    }
                }
            }
            if socket_fds.len() != 2 {
                return Err(io::Error::other("Guest inherited socket FDs missing"));
            }
            for entry in environ
                .split(|b| *b == 0)
                .filter(|entry| entry.starts_with(b"ANDROID_SOCKET_"))
            {
                println!("Guest Zygote env={}", String::from_utf8_lossy(entry));
            }
            let deadline = Instant::now() + Duration::from_secs(5);
            while Instant::now() < deadline {
                crate::memory_cgroup::check_interrupted()?;
                if let Some(diagnostics) = &mut zygote.diagnostics {
                    diagnostics.tick()?;
                }
                if zygote.exited()? {
                    return Err(io::Error::other("Guest Zygote exited during residence"));
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            let end_stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
            let end_starttime = end_stat
                .rsplit_once(") ")
                .and_then(|(_, fields)| fields.split_whitespace().nth(19));
            if end_starttime != Some(starttime) {
                return Err(io::Error::other(
                    "Guest Zygote identity changed during residence",
                ));
            }
            if fs::metadata(root.join("dev/socket/zygote"))?.ino() != socket.ino() {
                return Err(io::Error::other(
                    "Guest Zygote socket changed during residence",
                ));
            }
            for (fd, target) in &socket_fds {
                if fs::read_link(format!("/proc/{pid}/fd/{}", fd.to_string_lossy()))
                    .ok()
                    .as_ref()
                    != Some(target)
                {
                    return Err(io::Error::other(
                        "Guest Zygote socket FD changed during residence",
                    ));
                }
            }
            crate::memory_cgroup::verify_guest_membership(pid)?;
            println!("Guest Zygote residence pid={pid} starttime={starttime} seconds=5 membership=verified");
            if controlled_fork {
                fork_probe::run(root, &mut zygote, true)?;
            }
            zygote.stop()?;
            fs::remove_file(root.join("dev/socket/zygote"))?;
            fs::remove_file(root.join("dev/socket/usap_pool_primary"))?;
            println!("PHASE7A_ZYGOTE=PASS preload_complete=true socket_removed=true system_server=not_started");
        }
        if phase6a {
            println!("PHASE6A=START installd/artd through common launcher");
            for path in ["data/misc/user", "data/misc/installd"] {
                crate::guest_mounts::directory(root, path, 0o755)?;
            }
            if phase6b {
                crate::guest_mounts::directory(root, "data/misc/profiles/cur/0", 0o771)?;
            }
            for (exe, name) in [
                ("/system/bin/installd", "installd"),
                ("/apex/com.android.art/bin/artd", "artd"),
            ] {
                let mut service =
                    Service::start(root, exe, &[], name, 0, Some(GUEST_PROBE_CONTEXT), &[])?;
                std::thread::sleep(Duration::from_millis(500));
                if service.exited()? {
                    return Err(io::Error::other(format!(
                        "Phase6A {exe} exited: {}",
                        fs::read_to_string(&service.log)?
                    )));
                }
                println!(
                    "PHASE6A service={name} pid={} alive_after_500ms=true",
                    service.child.id()
                );
                run(
                    root,
                    "/system/bin/bootstrap/linker64",
                    &["/run/ssal/phase3-ipc", "inspect-data-service", name],
                    1000,
                )?;
                if phase6b && name == "installd" {
                    let paths = [
                        "user/0/com.android.ssal.phase2",
                        "user_de/0/com.android.ssal.phase2",
                    ];
                    let profiles = [
                        "misc/profiles/cur/0/com.android.ssal.phase2",
                        "misc/profiles/ref/com.android.ssal.phase2",
                    ];
                    for path in paths.into_iter().chain(profiles) {
                        match fs::symlink_metadata(userdata.join(path)) {
                            Err(e) if e.kind() == io::ErrorKind::NotFound => (),
                            _ => {
                                return Err(io::Error::other("Phase 2 test package already exists"))
                            }
                        }
                    }
                    let major = major.to_string();
                    let minor = minor.to_string();
                    let host_rdev = fs::metadata("/dev/binder")?.rdev().to_string();
                    let call = |role: &str| {
                        run(
                            root,
                            "/system/bin/bootstrap/linker64",
                            &[
                                "/run/ssal/ssal-binder-probe",
                                role,
                                "/dev/binder",
                                &major,
                                &minor,
                                "phase2",
                                &host_rdev,
                            ],
                            1000,
                        )
                    };
                    let create = (|| -> io::Result<()> {
                        let created = call("data-installd-create")?;
                        if !created.contains("\"result\":\"installd_created\"") {
                            return Err(io::Error::other("installd create evidence missing"));
                        }
                        for path in paths {
                            let actual = fs::symlink_metadata(root.join("data").join(path))?;
                            let expected = fs::symlink_metadata(userdata.join(path))?;
                            if !actual.is_dir()
                                || actual.uid() != 10000
                                || (actual.dev(), actual.ino()) != (expected.dev(), expected.ino())
                            {
                                return Err(io::Error::other(
                                    "installd output ownership/backing mismatch",
                                ));
                            }
                        }
                        Ok(())
                    })();
                    let deleted = call("data-installd-delete");
                    for path in profiles {
                        match fs::remove_dir_all(userdata.join(path)) {
                            Ok(()) => (),
                            Err(e) if e.kind() == io::ErrorKind::NotFound => (),
                            Err(e) => return Err(e),
                        }
                    }
                    let deleted = deleted?;
                    if !deleted.contains("\"result\":\"installd_deleted\"") {
                        return Err(io::Error::other("installd delete evidence missing"));
                    }
                    for path in paths {
                        match fs::symlink_metadata(userdata.join(path)) {
                            Err(e) if e.kind() == io::ErrorKind::NotFound => (),
                            _ => return Err(io::Error::other("installd did not remove test data")),
                        }
                    }
                    create?;
                    println!("PHASE6B_INSTALD=PASS create=PASS delete=PASS guest_backing=PASS");
                }
                service.stop()?;
            }
            if phase6b {
                return Err(io::Error::other(
                    "Phase 6B artd dexopt integration not implemented",
                ));
            }
        }
        server.stop()?;
        manager.stop()?;
        if let Some(service) = &mut property_service {
            service.stop()?;
            fs::remove_file(root.join("dev/socket/property_service"))?;
        }
        isolated(root, userdata)?;
        Ok(())
    })();
    let mut cleanup_errors = Vec::new();
    if let Some(service) = &mut property_service {
        if let Err(error) = service.stop() {
            cleanup_errors.push(error.to_string());
        }
        match fs::remove_file(root.join("dev/socket/property_service")) {
            Ok(()) => (),
            Err(error) if error.kind() == io::ErrorKind::NotFound => (),
            Err(error) => cleanup_errors.push(error.to_string()),
        }
    }
    if phase7a && std::env::var_os("SSAL_PHASE7FB_FORK").is_some() {
        if let Err(error) = fork_probe::cleanup(root) {
            cleanup_errors.push(error.to_string());
        }
    }
    if let Err(error) = binder.cleanup() {
        cleanup_errors.push(format!("Private Binder cleanup: {error}"));
    }
    if fs::read_to_string("/sys/fs/selinux/enforce")?.trim() != "1" {
        cleanup_errors.push("Host global Enforcing changed".into());
    }
    let cleanup = if cleanup_errors.is_empty() {
        Ok(())
    } else {
        Err(io::Error::other(cleanup_errors.join("; ")))
    };
    match (result, cleanup) {
        (Err(error), Err(cleanup)) => Err(io::Error::other(format!("{error}; {cleanup}"))),
        (Err(error), _) | (_, Err(error)) => Err(error),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn common_workers_share_live_property_readiness() {
        // Wiring regression: every caller enters this setup before any phase-specific work.
        let source = include_str!("guest_launcher.rs");
        let verify = source.split("pub(crate) fn verify(").nth(1).unwrap();
        let setup = verify
            .split("let mut manager = Service::start(")
            .next()
            .unwrap();
        assert!(setup.contains("\"ssal-property-service\","));
        assert!(setup.contains("property_service = Some(start_property_service("));
        assert!(!setup.contains("if phase7i_properties"));
        assert!(!setup.contains("--initialize-private-properties"));
        assert!(source.contains("\"servicemanager.ready=false\""));
        assert!(!source.contains(concat!("\"servicemanager.ready", "=true\"")));
        let property = verify
            .find("manager.wait_guest_servicemanager_property(")
            .unwrap();
        let context = verify.find("manager.wait_guest_context_manager(").unwrap();
        let aidl = verify.find("\"aidl-server\"").unwrap();
        assert!(property < context && context < aidl);
    }

    #[test]
    fn property_failure_stderr_survives_child_exit() -> io::Result<()> {
        let log = std::env::temp_dir().join(format!("ssal-property-stderr-{}", std::process::id()));
        let output = File::create(&log)?;
        let mut command = Command::new("/bin/sh");
        command
            .args(["-c", "echo 'property startup failure fixture' >&2; exit 1"])
            .stderr(Stdio::piped());
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = command.spawn()?;
        let stream = crate::zygote_diagnostics::Stream::new(child.stderr.take().unwrap(), output)?;
        let mut service = Service {
            child,
            log: log.clone(),
            stopped: false,
            diagnostics: None,
            output: vec![stream],
        };
        let error = service
            .wait_text("guest_property_service_ready")
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("property startup failure fixture"));
        service.stop()?;
        assert_eq!(service.child.wait()?.code(), Some(1));
        fs::remove_file(log)?;
        Ok(())
    }

    #[test]
    fn child_joins_every_hierarchy_before_exec() -> io::Result<()> {
        let directory = std::env::temp_dir().join(format!("ssal-pre-exec-{}", std::process::id()));
        fs::create_dir_all(&directory)?;
        let groups: Vec<_> = ["unified", "memory"]
            .into_iter()
            .map(|name| directory.join(name))
            .collect();
        for group in &groups {
            fs::create_dir(group)?;
            fs::write(group.join("cgroup.procs"), "parent")?;
        }
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "printf %s $$"]);
        let child_groups = groups.clone();
        unsafe {
            command.pre_exec(move || join_cgroups(&child_groups));
        }
        let output = command.output()?;
        assert!(output.status.success());
        for group in &groups {
            assert_eq!(fs::read(group.join("cgroup.procs"))?, output.stdout);
        }
        fs::remove_file(groups[1].join("cgroup.procs"))?;
        std::os::unix::fs::symlink("/dev/null", groups[1].join("cgroup.procs"))?;
        assert!(command.spawn().is_err());
        // A failed join must prevent exec, including when an earlier hierarchy succeeded.
        fs::remove_file(groups[1].join("cgroup.procs"))?;
        fs::remove_dir(&groups[1])?;
        assert!(command.spawn().is_err());
        fs::remove_dir_all(directory)?;
        Ok(())
    }

    #[test]
    fn mapped_helpers_use_their_guest_domains() {
        for executable in [
            "/apex/com.android.runtime/bin/linkerconfig",
            "/system/bin/linkerconfig",
        ] {
            assert_eq!(
                mapped_exec_domain(executable, Some(GUEST_PROBE_CONTEXT)),
                "linkerconfig"
            );
        }
        assert_eq!(
            mapped_exec_domain(
                "/system/bin/bootstrap/linker64",
                Some(PROPERTY_SERVICE_CONTEXT)
            ),
            "init"
        );
        for (executable, domain) in [
            ("/system/bin/app_process64", "zygote"),
            ("/system/bin/servicemanager", "servicemanager"),
            ("/system/bin/sh", "shell"),
        ] {
            assert_eq!(
                mapped_exec_domain(executable, Some(GUEST_PROBE_CONTEXT)),
                domain
            );
        }
    }

    #[test]
    fn abi_query_requires_valid_response() -> io::Result<()> {
        for reply in [
            b"\0\0\0\x09arm64-v8a".as_slice(),
            b"\0\0\0\x09wrong-abi",
            b"\0\0\0\x09arm",
        ] {
            let (mut client, mut server) = UnixStream::pair()?;
            server.write_all(reply)?;
            server.shutdown(std::net::Shutdown::Write)?;
            assert_eq!(
                query_abi(&mut client).is_ok(),
                reply.ends_with(b"arm64-v8a")
            );
            let mut request = [0; 19];
            server.read_exact(&mut request)?;
            assert_eq!(&request, b"1\n--query-abi-list\n");
        }
        Ok(())
    }

    #[test]
    fn zygote_socket_fds_survive_exec() -> io::Result<()> {
        let root = std::env::temp_dir().join(format!("ssal-zygote-sockets-{}", std::process::id()));
        fs::create_dir_all(root.join("dev/socket"))?;
        let mut command = Command::new("/bin/sh");
        unsafe {
            command.pre_exec(ssal::unix::cloexec_unexpected_fds);
        }
        let sockets = zygote_sockets(&mut command, &root.join("dev/socket"))?;
        let status = command.args(["-c", "test -S /proc/self/fd/$ANDROID_SOCKET_zygote && test -S /proc/self/fd/$ANDROID_SOCKET_usap_pool_primary && test \"$ANDROID_SOCKET_zygote\" != \"$ANDROID_SOCKET_usap_pool_primary\""]).status()?;
        assert!(status.success());
        assert!(root.join("dev/socket/zygote").exists());
        drop(sockets);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn classpath_exports_include_guest_system_server_jars() -> io::Result<()> {
        let classpaths = classpath_exports(
            "export SYSTEMSERVERCLASSPATH /system/framework/services.jar\nexport BOOTCLASSPATH /apex/com.android.art/javalib/core-oj.jar:/system/framework/framework.jar\nexport DEX2OATBOOTCLASSPATH /apex/com.android.art/javalib/core-oj.jar\nexport STANDALONE_SYSTEMSERVER_JARS /apex/com.android.os.statsd/javalib/service-statsd.jar\n",
        )?;
        assert_eq!(
            classpaths.boot,
            "/apex/com.android.art/javalib/core-oj.jar:/system/framework/framework.jar"
        );
        assert_eq!(
            classpaths.dex2oat.as_deref(),
            Some("/apex/com.android.art/javalib/core-oj.jar")
        );
        assert_eq!(classpaths.system_server, "/system/framework/services.jar");
        assert_eq!(
            classpaths.standalone_system_server.as_deref(),
            Some("/apex/com.android.os.statsd/javalib/service-statsd.jar")
        );
        assert!(
            classpath_exports("export BOOTCLASSPATH /system/framework/framework.jar\n").is_err()
        );
        assert!(
            classpath_exports("export SYSTEMSERVERCLASSPATH /system/framework/services.jar\n")
                .is_err()
        );
        assert!(classpath_exports(
            "export BOOTCLASSPATH /system/framework/framework.jar\nexport BOOTCLASSPATH /system/framework/framework.jar\nexport SYSTEMSERVERCLASSPATH /system/framework/services.jar\n"
        )
        .is_err());

        let optional_standalone = classpath_exports(
            "export BOOTCLASSPATH /system/framework/framework.jar\nexport SYSTEMSERVERCLASSPATH /system/framework/services.jar\nexport STANDALONE_SYSTEMSERVER_JARS\n",
        )?;
        assert_eq!(optional_standalone.standalone_system_server, None);
        assert!(checked_guest_classpath_paths(&optional_standalone).is_ok());
        let escaped = classpath_exports(
            "export BOOTCLASSPATH /system/../data/host.jar\nexport SYSTEMSERVERCLASSPATH /system/framework/services.jar\n",
        )?;
        assert!(checked_guest_classpath_paths(&escaped).is_err());
        assert_eq!(
            guest_env_value(
                b"BOOTCLASSPATH=/guest.jar\0SYSTEMSERVERCLASSPATH=/guest/services.jar\0",
                "SYSTEMSERVERCLASSPATH"
            ),
            Some(b"/guest/services.jar".as_slice())
        );
        Ok(())
    }

    #[test]
    fn zygote_early_exit_retains_diagnostics_through_service_drop() -> io::Result<()> {
        let directory =
            std::env::temp_dir().join(format!("ssal-7b-service-{}", std::process::id()));
        crate::zygote_diagnostics::Diagnostics::prepare(&directory)?;
        let log = directory.join("legacy.log");
        File::create(&log)?;
        let mut command = Command::new("/bin/sh");
        command
            .args([
                "-c",
                "ulimit -c 0; printf 'zygote fatal fixture' >&2; kill -ABRT $$",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut service = Service {
            child: command.spawn()?,
            log,
            stopped: false,
            diagnostics: None,
            output: Vec::new(),
        };
        service.diagnostics = Some(crate::zygote_diagnostics::Diagnostics::attach(
            &mut service.child,
            &directory,
            &directory.join("missing-cgroup"),
            crate::zygote_diagnostics::launch_time(),
            Instant::now(),
        )?);
        assert!(service
            .wait_for_socket(Path::new("ssal_7b_fixture_absent"))
            .is_err());
        let status = service.exit_status()?.expect("fixture exited");
        assert!(matches!(status.0, libc::CLD_KILLED | libc::CLD_DUMPED));
        assert_eq!(status.1, libc::SIGABRT);
        assert_eq!(service.exit_status()?, Some(status));
        drop(service);
        let metadata = fs::read_to_string(directory.join("metadata.jsonl"))?;
        let exit: serde_json::Value = serde_json::from_str(metadata.lines().last().unwrap())?;
        assert_eq!(exit["signal"], libc::SIGABRT);
        assert!(fs::read_to_string(directory.join("stderr.log"))?.contains("zygote fatal fixture"));
        fs::remove_dir_all(directory)?;
        Ok(())
    }

    #[test]
    fn owned_service_is_reaped_and_stop_is_idempotent() -> io::Result<()> {
        let log = std::env::temp_dir().join(format!("ssal-launcher-test-{}", std::process::id()));
        let output = File::create(&log)?;
        let mut cmd = Command::new("/bin/sh");
        cmd.args(["-c", "sleep 30 & wait"])
            .stdout(output.try_clone()?)
            .stderr(output);
        unsafe {
            cmd.pre_exec(|| {
                if libc::setsid() < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = cmd.spawn()?;
        let pid = child.id();
        let mut service = Service {
            child,
            log: log.clone(),
            stopped: false,
            diagnostics: None,
            output: Vec::new(),
        };
        service.stop()?;
        service.stop()?;
        assert!(service.stopped);
        assert_eq!(unsafe { libc::kill(pid as i32, 0) }, -1);
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::ESRCH));
        fs::remove_file(log)?;
        Ok(())
    }

    #[test]
    fn exited_leader_does_not_leave_its_process_group_running() -> io::Result<()> {
        let log = std::env::temp_dir().join(format!("ssal-exited-leader-{}", std::process::id()));
        let output = File::create(&log)?;
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "sleep 30 & echo $!"]).stdout(output);
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(())
                }
            });
        }
        let mut service = Service {
            child: command.spawn()?,
            log: log.clone(),
            stopped: false,
            diagnostics: None,
            output: Vec::new(),
        };
        let deadline = Instant::now() + Duration::from_secs(3);
        while !service.exited()? {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(10));
        }
        let pid: u32 = fs::read_to_string(&log)?
            .trim()
            .parse()
            .map_err(io::Error::other)?;
        service.stop()?;
        while let Ok(stat) = fs::read_to_string(format!("/proc/{pid}/stat")) {
            if stat.split_whitespace().nth(2) == Some("Z") {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "background process remained alive"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        fs::remove_file(log)?;
        Ok(())
    }
}
