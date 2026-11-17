use std::ffi::CString;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

fn cpath(path: &Path) -> io::Result<CString> {
    CString::new(path.as_os_str().as_bytes()).map_err(io::Error::other)
}
pub(crate) fn command(root: &Path, executable: &str, pivot: bool) -> io::Result<Command> {
    crate::guest::mount::require_guest_exec_admission()?;
    root_command(root, executable, pivot)
}

pub(crate) fn isolate_process_group(zygote: bool) -> io::Result<()> {
    // ZygoteInit calls setpgid itself, which fails for a session leader.
    if unsafe {
        if zygote {
            libc::setpgid(0, 0)
        } else {
            libc::setsid()
        }
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub(crate) fn root_command(root: &Path, executable: &str, pivot: bool) -> io::Result<Command> {
    root_command_at(root, executable, pivot, ".ssal-old-root")
}

pub(crate) fn root_command_at(
    root: &Path,
    executable: &str,
    pivot: bool,
    scratch: &str,
) -> io::Result<Command> {
    let root_c = cpath(root)?;
    let scratch_c = CString::new(scratch).map_err(io::Error::other)?;
    let old_root = format!("/{scratch}");
    let old_root_c = CString::new(old_root.as_str()).map_err(io::Error::other)?;
    let zygote = executable == "/system/bin/app_process64";
    let inherited = ssal::unix::inherited_fds()?;
    let expected = fs::metadata(root)?;
    let pivot_log = if pivot && std::env::var_os("SSAL_PHASE7FB_FORK").is_some() {
        let phase = if std::env::var_os("SSAL_PHASE7I_PROPERTIES").is_some() {
            "phase7fc"
        } else {
            "phase7fb"
        };
        Some(File::create(
            root.parent()
                .unwrap()
                .join(phase)
                .join("pivot-transition.log"),
        )?)
    } else {
        None
    };
    if pivot {
        fs::create_dir(root.join(scratch))?;
    }
    let mut command = Command::new(executable);
    command
        .env_clear()
        .env("PATH", "/system/bin:/apex/com.android.runtime/bin");
    unsafe {
        command.pre_exec(move || {
            ssal::unix::close_inherited_fds(&inherited, &[])?;
            ssal::unix::cloexec_unexpected_fds()?;
            isolate_process_group(zygote)?;
            if pivot {
                if libc::unshare(libc::CLONE_NEWNS) != 0 {
                    return Err(io::Error::last_os_error());
                }
                if libc::mount(
                    std::ptr::null(),
                    c"/".as_ptr(),
                    std::ptr::null(),
                    libc::MS_REC | libc::MS_PRIVATE,
                    std::ptr::null(),
                ) != 0
                {
                    return Err(io::Error::last_os_error());
                }
                if libc::chdir(root_c.as_ptr()) != 0 {
                    return Err(io::Error::last_os_error());
                }
                if libc::syscall(libc::SYS_pivot_root, c".".as_ptr(), scratch_c.as_ptr()) != 0 {
                    return Err(io::Error::other(format!(
                        "Guest pivot_root: {}",
                        io::Error::last_os_error()
                    )));
                }
                if libc::chdir(c"/".as_ptr()) != 0 {
                    return Err(io::Error::last_os_error());
                }
                // Android may stack mounts at /; detach every old-root layer in this private child.
                let layers = fs::read_to_string("/proc/self/mountinfo")?
                    .lines()
                    .filter(|line| line.split_whitespace().nth(4) == Some(old_root.as_str()))
                    .count();
                if layers == 0 {
                    return Err(io::Error::other("old-root mount missing after pivot"));
                }
                for _ in 0..layers {
                    if libc::umount2(old_root_c.as_ptr(), libc::MNT_DETACH) != 0 {
                        return Err(io::Error::last_os_error());
                    }
                }
                if libc::rmdir(old_root_c.as_ptr()) != 0 {
                    return Err(io::Error::last_os_error());
                }
                if let Some(mut log) = pivot_log.as_ref() {
                    writeln!(
                        log,
                        "old_root_layers_detached={layers} old_root_absent=true"
                    )?;
                }
            } else {
                if libc::chroot(root_c.as_ptr()) != 0 {
                    return Err(io::Error::last_os_error());
                }
                if libc::chdir(c"/".as_ptr()) != 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            let mut actual: libc::stat = std::mem::zeroed();
            if libc::stat(c"/".as_ptr(), &mut actual) != 0 {
                return Err(io::Error::last_os_error());
            }
            if actual.st_dev != expected.dev() || actual.st_ino != expected.ino() {
                return Err(io::Error::other("guest root identity mismatch"));
            }
            Ok(())
        });
    }
    Ok(command)
}

#[cfg(feature = "phase2c-diagnostic")]
pub(crate) fn command_for_phase2c(root: &Path, executable: &str) -> io::Result<Command> {
    crate::guest::mount::require_guest_exec_admission()?;
    let root_c = cpath(root)?;
    let expected = fs::metadata(root)?;
    let inherited = ssal::unix::inherited_fds()?;
    let mut command = Command::new(executable);
    command
        .env_clear()
        .env("PATH", "/system/bin:/apex/com.android.runtime/bin");
    unsafe {
        command.pre_exec(move || {
            ssal::unix::close_inherited_fds(&inherited, &[])?;
            ssal::unix::cloexec_unexpected_fds()?;
            if libc::setsid() < 0 {
                return Err(io::Error::last_os_error());
            }
            let context = c"u:r:shell:s0";
            let fd = libc::open(
                c"/proc/thread-self/attr/exec".as_ptr(),
                libc::O_WRONLY | libc::O_CLOEXEC,
            );
            if fd < 0 {
                let error = io::Error::last_os_error();
                return Err(io::Error::new(
                    error.kind(),
                    format!("setexeccon open: {error}"),
                ));
            }
            let written = libc::write(
                fd,
                context.as_ptr().cast(),
                context.to_bytes_with_nul().len(),
            );
            let error = io::Error::last_os_error();
            libc::close(fd);
            if written != context.to_bytes_with_nul().len() as isize {
                return Err(io::Error::new(
                    error.kind(),
                    format!("setexeccon write: {error}"),
                ));
            }
            if libc::chroot(root_c.as_ptr()) != 0 {
                let error = io::Error::last_os_error();
                return Err(io::Error::new(error.kind(), format!("chroot: {error}")));
            }
            if libc::chdir(c"/".as_ptr()) != 0 {
                return Err(io::Error::last_os_error());
            }
            let mut actual: libc::stat = std::mem::zeroed();
            if libc::stat(c"/".as_ptr(), &mut actual) != 0 {
                return Err(io::Error::last_os_error());
            }
            if actual.st_dev != expected.dev() || actual.st_ino != expected.ino() {
                return Err(io::Error::other("guest root identity mismatch"));
            }
            let groups = [3009 as libc::gid_t];
            if libc::setgroups(groups.len(), groups.as_ptr()) != 0
                || libc::setresgid(1000, 1000, 1000) != 0
                || libc::setresuid(1000, 1000, 1000) != 0
                || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    Ok(command)
}
pub(crate) fn run(command: &mut Command, stage: &str) -> io::Result<Output> {
    run_with_timeout(command, stage, Duration::from_secs(20))
}

pub(crate) fn run_with_timeout(
    command: &mut Command,
    stage: &str,
    timeout: Duration,
) -> io::Result<Output> {
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| io::Error::new(e.kind(), format!("{stage}: spawn/root setup: {e}")))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("stdout pipe missing"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("stderr pipe missing"))?;
    let reader = |pipe: Box<dyn Read + Send>| {
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            pipe.take(256 * 1024).read_to_end(&mut bytes).map(|_| bytes)
        })
    };
    let out = reader(Box::new(stdout));
    let err = reader(Box::new(stderr));
    let deadline = Instant::now() + timeout;
    let status = loop {
        if let Err(error) = crate::guest::process::supervision::check_interrupted() {
            unsafe {
                libc::kill(-(child.id() as i32), libc::SIGKILL);
            }
            child.wait()?;
            return Err(error);
        }
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        if unsafe {
            libc::waitid(
                libc::P_PID,
                child.id(),
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        if unsafe { info.si_pid() } != 0 {
            // Keep the leader pinned until its process group is stopped.
            unsafe {
                libc::kill(-(child.id() as i32), libc::SIGKILL);
            }
            break child.wait()?;
        }
        if Instant::now() >= deadline {
            unsafe {
                libc::kill(-(child.id() as i32), libc::SIGKILL);
            }
            child.wait()?;
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("{stage}: exceeded {timeout:?}; probe process group stopped"),
            ));
        }
        std::thread::sleep(Duration::from_millis(25));
    };
    let drain_deadline = Instant::now() + Duration::from_millis(500);
    while !out.is_finished() || !err.is_finished() {
        if Instant::now() >= drain_deadline {
            return Err(io::Error::other(format!(
                "{stage}: output pipe held by descendant"
            )));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    Ok(Output {
        status,
        stdout: out
            .join()
            .map_err(|_| io::Error::other("stdout reader panicked"))??,
        stderr: err
            .join()
            .map_err(|_| io::Error::other("stderr reader panicked"))??,
    })
}
