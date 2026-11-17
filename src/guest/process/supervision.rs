use crate::guest::cgroup::{require, verify_guest_membership};
use std::fs;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};

static INTERRUPTED: AtomicBool = AtomicBool::new(false);
extern "C" fn interrupt(_: libc::c_int) {
    INTERRUPTED.store(true, Ordering::SeqCst);
}
pub(crate) fn install_signal_handlers() {
    INTERRUPTED.store(false, Ordering::SeqCst);
    unsafe {
        for signal in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP] {
            libc::signal(signal, interrupt as *const () as libc::sighandler_t);
        }
    }
}

pub(crate) fn enable_subreaper() -> io::Result<()> {
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, std::process::id(), 0) } as i32;
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    unsafe {
        libc::close(fd);
    }
    if unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub(crate) fn cleanup_descendants(require_guest_cgroup: bool) -> io::Result<()> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    let self_pid = std::process::id();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let mut any: libc::siginfo_t = unsafe { std::mem::zeroed() };
        if unsafe {
            libc::waitid(
                libc::P_ALL,
                0,
                &mut any,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        } != 0
        {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ECHILD) {
                return Ok(());
            }
            return Err(error);
        }
        for entry in fs::read_dir("/proc")? {
            let entry = entry?;
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|s| s.parse::<i32>().ok())
            else {
                continue;
            };
            let Ok(status) = fs::read_to_string(format!("/proc/{pid}/status")) else {
                continue;
            };
            let parent = status
                .lines()
                .find_map(|line| line.strip_prefix("PPid:"))
                .and_then(|p| p.trim().parse::<u32>().ok());
            if parent != Some(self_pid) {
                continue;
            }
            let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32;
            if raw < 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::ESRCH) {
                    continue;
                }
                return Err(error);
            }
            let fd = unsafe { OwnedFd::from_raw_fd(raw) };
            let status = match fs::read_to_string(format!("/proc/{pid}/status")) {
                Ok(status) => status,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error),
            };
            let parent = status
                .lines()
                .find_map(|line| line.strip_prefix("PPid:"))
                .and_then(|p| p.trim().parse::<u32>().ok());
            require(
                parent == Some(self_pid),
                "child ownership changed; preserving Guest cgroup",
            )?;
            let mut exited: libc::siginfo_t = unsafe { std::mem::zeroed() };
            // P_PIDFD binds the wait and reap to the same process identity as the signal.
            if unsafe {
                libc::waitid(
                    3 as libc::idtype_t,
                    fd.as_raw_fd() as libc::id_t,
                    &mut exited,
                    libc::WEXITED | libc::WNOHANG,
                )
            } != 0
            {
                return Err(io::Error::last_os_error());
            }
            if unsafe { exited.si_pid() } != 0 {
                if require_guest_cgroup {
                    println!("Guest descendant reaped pid={pid} pidfd=verified");
                }
                continue;
            }
            if require_guest_cgroup {
                let path = verify_guest_membership(pid as u32)?;
                println!("Guest owned descendant pid={pid} membership={path} pidfd=verified");
            }
            let rc = unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    fd.as_raw_fd(),
                    libc::SIGKILL,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                )
            };
            if rc != 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() != Some(libc::ESRCH) {
                    return Err(error);
                }
            }
        }
        require(
            std::time::Instant::now() < deadline,
            "Guest descendants did not exit; preserve cgroup",
        )?;
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}
pub(crate) fn check_interrupted() -> io::Result<()> {
    require(
        !INTERRUPTED.load(Ordering::SeqCst),
        "Guest worker interrupted",
    )
}
