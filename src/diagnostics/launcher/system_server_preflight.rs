//! Opt-in diagnostics only. No system-server launch permission is issued here.
use super::*;
use std::os::fd::OwnedFd;
use std::process::ExitStatus;

const BINS: &[&str] = &[
    "ssal-system-server-gate.so",
    "ssal-system-server-wrapper",
    "ssal-system-server-gate-probe",
    "ssal-system-server-cgroup-probe",
    "ssal-system-server-boundary",
];

pub(crate) fn enabled() -> io::Result<bool> {
    match std::env::var("SSAL_PHASE8B4B1_ONCE") {
        Err(std::env::VarError::NotPresent) => Ok(false),
        Ok(value) if value == "1" => Ok(true),
        _ => Err(io::Error::other("SSAL_PHASE8B4B1_ONCE must be exactly 1")),
    }
}

pub(crate) fn prepare(mounts: &mut Mounts, root: &Path, bin: &Path) -> io::Result<()> {
    for name in BINS {
        let target = root.join("run/ssal").join(name);
        File::create(&target)?;
        mounts.bind(&bin.join(name), &target, true, false)?;
    }
    Ok(())
}

fn starttime(pid: u32) -> io::Result<String> {
    let text = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    text.rsplit_once(") ")
        .and_then(|(_, fields)| fields.split_whitespace().nth(19))
        .map(str::to_owned)
        .ok_or_else(|| io::Error::other("preflight child starttime missing"))
}

struct OwnedChild {
    child: Child,
    fd: OwnedFd,
    start: String,
    reaped: bool,
}

impl OwnedChild {
    fn spawn(command: &mut Command, log: &Path) -> io::Result<Self> {
        let output = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(log)?;
        let mut child = command.stdout(output.try_clone()?).stderr(output).spawn()?;
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, child.id(), 0) } as i32;
        if raw < 0 {
            let error = io::Error::last_os_error();
            // The unreaped direct child pins this numeric PID even on setup failure.
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let start = match starttime(child.id()) {
            Ok(start) => start,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            }
        };
        println!(
            "SSAL_SS_TRACK pid={} starttime={start} pidfd=verified",
            child.id()
        );
        Ok(Self {
            child,
            fd,
            start,
            reaped: false,
        })
    }

    fn stop(&mut self) -> io::Result<ExitStatus> {
        if starttime(self.child.id())? != self.start {
            return Err(io::Error::other("preflight child identity changed"));
        }
        if unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.fd.as_raw_fd(),
                libc::SIGKILL,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        } != 0
            && io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
        {
            return Err(io::Error::last_os_error());
        }
        let status = self.child.wait()?;
        self.reaped = true;
        println!(
            "SSAL_SS_REAP pid={} starttime={} status={status}",
            self.child.id(),
            self.start
        );
        Ok(status)
    }

    fn wait(&mut self, timeout: Duration) -> io::Result<(ExitStatus, bool)> {
        let deadline = Instant::now() + timeout;
        loop {
            crate::guest::process::supervision::check_interrupted()?;
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            if unsafe {
                libc::waitid(
                    3 as libc::idtype_t,
                    self.fd.as_raw_fd() as libc::id_t,
                    &mut info,
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            } != 0
            {
                return Err(io::Error::last_os_error());
            }
            if unsafe { info.si_pid() } != 0 {
                return self.stop().map(|s| (s, false));
            }
            if Instant::now() >= deadline {
                return self.stop().map(|s| (s, true));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for OwnedChild {
    fn drop(&mut self) {
        if !self.reaped {
            if let Err(error) = self.stop() {
                eprintln!("RECOVERY_REQUIRED preflight child: {error}");
            }
        }
    }
}

fn diagnostic(
    root: &Path,
    exe: &str,
    mode: Option<&str>,
    log: &Path,
    timeout: Duration,
) -> io::Result<(ExitStatus, bool)> {
    let mut command = command(root, exe, 0, Some(GUEST_PROBE_CONTEXT))?;
    command.env("LD_LIBRARY_PATH", "/run/ssal:/system/lib64");
    if let Some(mode) = mode {
        command.arg(mode);
    }
    OwnedChild::spawn(&mut command, log)?.wait(timeout)
}

pub(crate) fn run(root: &Path, bin: &Path) -> io::Result<()> {
    // Consuming the flag prevents another invocation in this worker; create_new pins the session.
    std::env::remove_var("SSAL_PHASE8B4B1_ONCE");
    let evidence = root.parent().unwrap().join("phase8b4b1");
    fs::create_dir(&evidence)?;
    let _once = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(evidence.join("consumed"))?;
    let limit = fs::read_to_string(root.join("sys/fs/cgroup/memory.max"))?;
    if limit
        .trim()
        .parse::<u64>()
        .ok()
        .filter(|n| *n > 0)
        .is_none()
    {
        return Err(io::Error::other(
            "preflight requires a finite Guest memory.max",
        ));
    }
    let apps = crate::guest::cgroup::task_cgroup_path()?.join("apps");
    if !apps.exists() {
        fs::create_dir(&apps)?;
    }
    let mut gate_pass = true;
    for (mode, expected) in [
        ("wrapper", 80),
        ("startup", 81),
        ("property-missing", 82),
        ("control-disconnected", 82),
        ("hook-missing", 83),
        ("hook-wrong", 83),
        ("exec-failure", 84),
        ("wrapper-failure", 1),
        ("early-exit", 86),
        ("timeout", -1),
    ] {
        if mode == "property-missing" {
            crate::guest::launcher::run(
                root,
                "/system/bin/sh",
                &[
                    "-c",
                    "setprop wrap.system_server ''; test -z \"$(getprop wrap.system_server)\"",
                ],
                0,
            )?;
        } else if mode == "wrapper" {
            crate::guest::launcher::run(root, "/system/bin/sh", &["-c", "setprop wrap.system_server /run/ssal/ssal-system-server-wrapper; test \"$(getprop wrap.system_server)\" = /run/ssal/ssal-system-server-wrapper"], 0)?;
        }
        let (status, timed_out) = diagnostic(
            root,
            "/run/ssal/ssal-system-server-gate-probe",
            Some(mode),
            &evidence.join(format!("gate-{mode}.log")),
            Duration::from_millis(500),
        )?;
        let passed = if expected == -1 {
            timed_out
        } else {
            !timed_out && status.code() == Some(expected)
        };
        gate_pass &= passed;
        println!("SSAL_SS_GATE_CASE mode={mode} status={status} timeout={timed_out} pass={passed}");
    }
    let (self_test, timeout) = diagnostic(
        root,
        "/run/ssal/ssal-system-server-cgroup-probe",
        Some("--self-test"),
        &evidence.join("cgroup-self-test.log"),
        Duration::from_secs(1),
    )?;
    if timeout || !self_test.success() {
        return Err(io::Error::other(
            "cgroup membership parser self-test failed",
        ));
    }
    let (cgroup, timeout) = diagnostic(
        root,
        "/run/ssal/ssal-system-server-cgroup-probe",
        None,
        &evidence.join("cgroup.log"),
        Duration::from_secs(8),
    )?;
    println!("SSAL_SS_CGROUP_CASE status={cgroup} timeout={timeout}");

    let mut host = Command::new(bin.join("ssal-system-server-boundary"));
    host.env_clear().arg("--canary").stdin(Stdio::null());
    let inherited = ssal::unix::inherited_fds()?;
    let parent = std::process::id() as i32;
    unsafe {
        host.pre_exec(move || {
            ssal::unix::close_inherited_fds(&inherited, &[])?;
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 || libc::getppid() != parent
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let canary_log = evidence.join("host-canary.log");
    let mut canary = OwnedChild::spawn(&mut host, &canary_log)?;
    let deadline = Instant::now() + Duration::from_secs(2);
    let ready = loop {
        if fs::read_to_string(&canary_log)?.contains("SSAL_HOST_CANARY_READY") {
            break true;
        }
        if Instant::now() >= deadline {
            break false;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    if ready {
        let mut probe = command(
            root,
            "/run/ssal/ssal-system-server-boundary",
            0,
            Some(GUEST_PROBE_CONTEXT),
        )?;
        probe
            .arg("--probe")
            .env("SSAL_CANARY_PID", canary.child.id().to_string())
            .env("LD_LIBRARY_PATH", "/run/ssal:/system/lib64");
        let result = OwnedChild::spawn(&mut probe, &evidence.join("boundary.log"))?
            .wait(Duration::from_secs(3))?;
        println!(
            "SSAL_SS_BOUNDARY_CASE status={} timeout={}",
            result.0, result.1
        );
    } else {
        println!("SSAL_SS_BOUNDARY_CASE=UNVERIFIED canary_not_ready");
    }
    canary.stop()?;
    for name in ["host-canary.log", "boundary.log"] {
        let path = evidence.join(name);
        if path.exists() {
            let bytes = fs::read(&path)?;
            let end = bytes
                .iter()
                .position(|byte| *byte == 0)
                .unwrap_or(bytes.len());
            fs::write(&path, &bytes[..end])?;
        }
    }
    println!("SSAL_PHASE8B4B1 gate_harness={gate_pass} actual_gsi_gate=UNVERIFIED forkSystemServer=NOT_RUN next_phase=NO_GO evidence={}", evidence.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pidfd_reaps_early_exit_timeout_and_drop() -> io::Result<()> {
        let log =
            std::env::temp_dir().join(format!("ssal-ss-preflight-{}.log", std::process::id()));
        let mut exited = OwnedChild::spawn(Command::new("/bin/sh").args(["-c", "exit 86"]), &log)?;
        let (status, timeout) = exited.wait(Duration::from_secs(1))?;
        assert_eq!(status.code(), Some(86));
        assert!(!timeout && exited.reaped);
        let mut hanging = OwnedChild::spawn(Command::new("/bin/sleep").arg("10"), &log)?;
        let (status, timeout) = hanging.wait(Duration::from_millis(20))?;
        assert!(!status.success() && timeout && hanging.reaped);
        let abandoned = OwnedChild::spawn(Command::new("/bin/sleep").arg("10"), &log)?;
        let pid = abandoned.child.id();
        drop(abandoned);
        let mut status = 0;
        assert_eq!(
            unsafe { libc::waitpid(pid as i32, &mut status, libc::WNOHANG) },
            -1
        );
        assert_eq!(
            io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
        fs::remove_file(log)?;
        Ok(())
    }
}
