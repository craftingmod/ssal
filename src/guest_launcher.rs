//! Disposable Guest service launcher; shared PID namespace is intentional.
use ssal::namespace_mounts::Mounts;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

mod fork_probe;
pub(crate) use fork_probe::client as fork_client;

pub(crate) fn command(
    root: &Path,
    executable: &str,
    uid: u32,
    guest_domain: bool,
) -> io::Result<Command> {
    crate::memory_cgroup::check_interrupted()?;
    // A real Guest mount root also gives Zygote's FD allowlist Guest-relative proc paths.
    let pivot = executable == "/system/bin/app_process64"
        && std::env::var_os("SSAL_PHASE7FB_FORK").is_some();
    let mut command = crate::guest_probe::root_command(root, executable, pivot)?;
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
            for (_, target) in crate::guest_mounts::GUEST_CGROUPS {
                fs::write(
                    format!("/{target}/cgroup.procs"),
                    std::process::id().to_string(),
                )?;
            }
            crate::memory_cgroup::verify_membership(
                std::process::id(),
                Path::new("/sys/fs/cgroup"),
                Path::new("/sys/fs/cgroup"),
            )?;
            if guest_domain {
                fs::write("/proc/thread-self/attr/exec", b"u:r:ssal_guest_probe:s0\0")?;
            }
            if libc::setgroups(0, std::ptr::null()) != 0
                || libc::setresgid(uid, uid, uid) != 0
                || libc::setresuid(uid, uid, uid) != 0
            {
                return Err(io::Error::last_os_error());
            }
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
    let output = crate::guest_probe::run_with_timeout(
        command(root, exe, uid, true)?.args(args),
        exe,
        Duration::from_secs(20),
    )?;
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
}
impl Service {
    fn exited(&self) -> io::Result<bool> {
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
        Ok(unsafe { info.si_pid() } != 0)
    }
    fn start(
        root: &Path,
        exe: &str,
        args: &[&str],
        name: &str,
        uid: u32,
        env: &[(&str, &str)],
    ) -> io::Result<Self> {
        let log = root.join(format!("run/ssal/{name}.log"));
        let output = File::create(&log)?;
        let mut command = command(root, exe, uid, true)?;
        command.env("LD_PRELOAD", "/run/ssal/ssal-phase2-log.so");
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
        } else if diagnostic {
            command.stdout(Stdio::piped()).stderr(Stdio::piped());
        } else {
            command.stdout(output.try_clone()?).stderr(output);
        }
        let sockets = if is_zygote {
            zygote_sockets(&mut command, Path::new("/dev/socket"))?
        } else {
            Vec::new()
        };
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
        };
        let membership = crate::memory_cgroup::verify_membership(
            service.child.id(),
            Path::new("/sys/fs/cgroup"),
            Path::new(crate::guest_mounts::GUEST_CGROUPS[0].0),
        )?;
        println!(
            "Guest service membership pid={} v2={membership}",
            service.child.id()
        );
        if diagnostic {
            service.diagnostics = Some(crate::zygote_diagnostics::Diagnostics::attach(
                &mut service.child,
                &diagnostic_dir,
                Path::new(crate::guest_mounts::GUEST_CGROUPS[0].0),
                launch_ms,
                started,
            )?);
            println!("Guest diagnostics={}", diagnostic_dir.display());
        }
        Ok(service)
    }
    fn wait_text(&mut self, text: &str) -> io::Result<()> {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            crate::memory_cgroup::check_interrupted()?;
            let log = fs::read_to_string(&self.log)?;
            if self.exited()? {
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
        let subgroup = Path::new(crate::guest_mounts::GUEST_CGROUPS[0].0).join("phase7d_fix");
        fs::write(subgroup.join("cgroup.procs"), pid.to_string())?;
        let before: u64 = crate::memory_cgroup::read(
            Path::new(crate::guest_mounts::GUEST_CGROUPS[0].0).join("memory.current"),
        )?
        .parse()
        .map_err(io::Error::other)?;
        if unsafe { libc::kill(pid as i32, libc::SIGCONT) } != 0 {
            return Err(io::Error::last_os_error());
        }
        if oom_test {
            let events = Path::new(crate::guest_mounts::GUEST_CGROUPS[0].0).join("memory.events");
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
                    let group = Path::new(crate::guest_mounts::GUEST_CGROUPS[0].0);
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
                Path::new("/sys/fs/cgroup"),
                &subgroup,
            )?;
            println!("GUEST_CHILD pid={child} membership={member}");
        }
        let after: u64 = crate::memory_cgroup::read(
            Path::new(crate::guest_mounts::GUEST_CGROUPS[0].0).join("memory.current"),
        )?
        .parse()
        .map_err(io::Error::other)?;
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
    let membership = crate::memory_cgroup::verify_membership(
        pid,
        Path::new("/sys/fs/cgroup"),
        Path::new(crate::guest_mounts::GUEST_CGROUPS[0].0),
    )?;
    let cgroup = Path::new(crate::guest_mounts::GUEST_CGROUPS[0].0);
    let current = crate::memory_cgroup::read(cgroup.join("memory.current"))?
        .parse::<u64>()
        .map_err(io::Error::other)?;
    if current == 0 {
        return Err(io::Error::other("Guest memory accounting is empty"));
    }
    println!("GUEST_MEMORY_PROBE pid={pid} membership={membership} memory.current={current}");
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

fn classpath_exports(content: &str) -> io::Result<(String, Option<String>)> {
    let mut boot = None;
    let mut dex2oat = None;
    for line in content.lines() {
        let mut fields = line.split_whitespace();
        if fields.next() != Some("export") {
            continue;
        }
        let (Some(name), Some(value)) = (fields.next(), fields.next()) else {
            continue;
        };
        if fields.next().is_some() || value.is_empty() {
            return Err(io::Error::other("invalid Guest classpath export"));
        }
        let destination = match name {
            "BOOTCLASSPATH" => &mut boot,
            "DEX2OATBOOTCLASSPATH" => &mut dex2oat,
            _ => continue,
        };
        if destination.replace(value.to_owned()).is_some() {
            return Err(io::Error::other(format!("duplicate Guest {name}")));
        }
    }
    Ok((
        boot.ok_or_else(|| io::Error::other("Guest BOOTCLASSPATH missing"))?,
        dex2oat,
    ))
}

fn derive_guest_classpath(root: &Path) -> io::Result<(String, Option<String>)> {
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
    let (boot, dex2oat) = result?;
    for classpath in std::iter::once(&boot).chain(dex2oat.iter()) {
        for path in classpath.split(':') {
            if !["/apex/", "/product/", "/system/", "/system_ext/"]
                .iter()
                .any(|prefix| path.starts_with(prefix))
            {
                return Err(io::Error::other(format!(
                    "Guest classpath escaped system/APEX roots: {path}"
                )));
            }
        }
    }
    println!(
        "Guest classpath source=derive_classpath(Guest SDK 36, REL) boot_entries={} dex2oat_entries={}",
        boot.split(':').count(),
        dex2oat.as_deref().map_or(0, |v| v.split(':').count())
    );
    Ok((boot, dex2oat))
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
) -> io::Result<()> {
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
    for name in [
        "guest_probe",
        "phase3-ipc",
        "ssal-phase2-log.so",
        "ssal-zygote-diag.so",
    ] {
        if name == "ssal-zygote-diag.so" && !phase7a {
            continue;
        }
        let target = runtime.join(name);
        File::create(&target)?;
        mounts.bind(&bin.join(name), &target, true, false)?;
    }
    let mut binder = crate::binder_probe::Session::new();
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
        let (major, minor, _) = binder.provision(root)?;
        let device = binder.private_device()?;
        if unsafe { libc::fchmod(device.as_raw_fd(), 0o666) } != 0 {
            return Err(io::Error::last_os_error());
        }
        crate::guest_mounts::directory(root, "dev/__properties__", 0o755)?;
        run(
            root,
            "/system/bin/bootstrap/linker64",
            &[
                "/run/ssal/guest_probe",
                "--initialize-private-properties",
                "/dev/guest-properties",
            ],
            0,
        )?;
        fs::remove_dir(root.join("dev/__properties__"))?;
        fs::rename(
            root.join("dev/guest-properties"),
            root.join("dev/__properties__"),
        )?;
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
        println!("Guest FD pre-exec: injected Host /data fd={}; root command closes inherited identities and marks later FDs CLOEXEC", sentinel.as_raw_fd());
        let shell = run(
            root,
            "/system/bin/sh",
            &[
                "-c",
                r#"set -eu
test "$(getprop ro.build.version.sdk)" = 36
test "$(getprop ro.product.cpu.abilist64)" = arm64-v8a
test "$(getprop ro.zygote.disable_gl_preload)" = 1
test -z "$(getprop ro.boot.serialno)"
for p in /dev/socket/property_service /dev/socket/property_service_for_system /dev/socket/init; do test ! -e "$p"; done
for fd in /proc/$$/fd/*; do
    target=$(readlink "$fd") || continue
    echo "Guest post-exec fd=$fd target=$target"
    case "$target" in /dev/null|pipe:*|/system/bin/sh|/system/bin/mksh) ;; *) exit 31;; esac
done
test "$(cat /proc/$$/attr/current)" = u:r:ssal_guest_probe:s0
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
"#,
            ],
            1000,
        )?;
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
            &[],
        )?;
        manager.wait_text("servicemanager")?;
        let mut server = Service::start(
            root,
            "/system/bin/bootstrap/linker64",
            &["/run/ssal/phase3-ipc", "server"],
            "aidl-server",
            1000,
            &[],
        )?;
        server.wait_text("\"event\":\"registered\"")?;
        let ipc = run(
            root,
            "/system/bin/bootstrap/linker64",
            &["/run/ssal/phase3-ipc", "client"],
            1000,
        )?;
        if !ipc.contains("\"event\":\"ipc_passed\"") {
            return Err(io::Error::other("AIDL IPC success evidence missing"));
        }
        println!("PHASE5B=PASS shell=PASS private_aidl=PASS properties=PASS host_control_socket=ABSENT private_binder={major}:{minor}");
        if phase7a {
            server.stop()?;
            let controlled_fork = std::env::var_os("SSAL_PHASE7FB_FORK").is_some();
            if controlled_fork {
                fork_probe::prepare(mounts, root, &bin)?;
            }
            crate::guest_mounts::directory(root, "data/dalvik-cache", 0o771)?;
            let binary = run(
                root,
                "/system/bin/sh",
                &[
                    "-c",
                    "set -eu; test -x /system/bin/app_process64; test -x /apex/com.android.sdkext/bin/derive_classpath; test ! -e /dev/socket/zygote; test ! -e /dev/socket/property_service; stat -c '%n %s %a %u %g' /system/bin/app_process64; sha256sum /system/bin/app_process64; getprop ro.product.cpu.abilist64; getprop ro.zygote.disable_gl_preload",
                ],
                0,
            )?;
            println!("Guest Zygote binary preflight:\n{binary}");
            let (boot_classpath, dex2oat_classpath) = derive_guest_classpath(root)?;
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
            ];
            if let Some(classpath) = dex2oat_classpath.as_deref() {
                zygote_env.push(("DEX2OATBOOTCLASSPATH", classpath));
            }
            if controlled_fork {
                zygote_env.push(("CLASSPATH", "/system/framework/am.jar"));
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
            if domain.trim_matches('\0').trim() != "u:r:ssal_guest_probe:s0" {
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
            crate::memory_cgroup::verify_membership(
                pid,
                Path::new("/sys/fs/cgroup"),
                Path::new(crate::guest_mounts::GUEST_CGROUPS[0].0),
            )?;
            println!("Guest Zygote residence pid={pid} starttime={starttime} seconds=5 membership=verified");
            if controlled_fork {
                fork_probe::run(root, &mut zygote)?;
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
                let mut service = Service::start(root, exe, &[], name, 0, &[])?;
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
        isolated(root, userdata)?;
        Ok(())
    })();
    let cleanup = binder.cleanup();
    if fs::read_to_string("/sys/fs/selinux/enforce")?.trim() != "1" {
        return Err(io::Error::other("Host global Enforcing changed"));
    }
    match (result, cleanup) {
        (Err(e), Err(c)) => Err(io::Error::other(format!("{e}; Binder cleanup: {c}"))),
        (Err(e), _) | (_, Err(e)) => Err(e),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn classpath_exports_keep_guest_runtime_classpaths_only() -> io::Result<()> {
        let (boot, dex2oat) = classpath_exports(
            "export SYSTEMSERVERCLASSPATH /system/framework/services.jar\nexport BOOTCLASSPATH /apex/com.android.art/javalib/core-oj.jar:/system/framework/framework.jar\nexport DEX2OATBOOTCLASSPATH /apex/com.android.art/javalib/core-oj.jar\n",
        )?;
        assert_eq!(
            boot,
            "/apex/com.android.art/javalib/core-oj.jar:/system/framework/framework.jar"
        );
        assert_eq!(
            dex2oat.as_deref(),
            Some("/apex/com.android.art/javalib/core-oj.jar")
        );
        assert!(
            classpath_exports("export SYSTEMSERVERCLASSPATH /system/framework/services.jar\n")
                .is_err()
        );
        assert!(classpath_exports("export BOOTCLASSPATH\n").is_err());
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
