use std::fs::{self, File};
use std::io;
use std::os::fd::{AsRawFd, RawFd};
#[derive(Clone, Copy)]
pub struct InheritedFd {
    fd: RawFd,
    dev: u64,
    ino: u64,
    mode: u32,
    rdev: u64,
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn cloexec_unexpected_fds() -> io::Result<()> {
    if unsafe { libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 4u32) } < 0 {
        let error = io::Error::last_os_error();
        if matches!(error.raw_os_error(), Some(libc::ENOSYS | libc::EINVAL)) {
            return cloexec_proc_fds();
        }
        return Err(error);
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn cloexec_proc_fds() -> io::Result<()> {
    // Called in the single-threaded pre-exec child; enumerate live FDs, not a parent snapshot.
    for entry in fs::read_dir("/proc/self/fd")? {
        let entry = entry?;
        let Ok(fd) = entry.file_name().to_string_lossy().parse::<RawFd>() else {
            continue;
        };
        if fd < 3 {
            continue;
        }
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

// shortcut: snapshots pre-spawn FDs; replace with coordinated exec admission for multithreaded launchers.
pub fn inherited_fds() -> io::Result<Vec<InheritedFd>> {
    let mut fds = Vec::new();
    for entry in fs::read_dir("/proc/self/fd")? {
        let entry = entry?;
        let Ok(fd) = entry.file_name().to_string_lossy().parse::<RawFd>() else {
            continue;
        };
        if fd <= 2 {
            continue;
        }
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(fd, &mut stat) } == 0 {
            fds.push(InheritedFd {
                fd,
                dev: stat.st_dev,
                ino: stat.st_ino,
                mode: stat.st_mode,
                rdev: stat.st_rdev,
            });
        } else if io::Error::last_os_error().raw_os_error() != Some(libc::EBADF) {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(fds)
}

pub fn close_inherited_fds(fds: &[InheritedFd], allow: &[RawFd]) -> io::Result<()> {
    for inherited in fds {
        if allow.contains(&inherited.fd) {
            continue;
        }
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(inherited.fd, &mut stat) } != 0 {
            if io::Error::last_os_error().raw_os_error() == Some(libc::EBADF) {
                continue;
            }
            return Err(io::Error::last_os_error());
        }
        // Command::spawn may reuse a parent FD number for a child pipe before pre_exec.
        if (stat.st_dev, stat.st_ino, stat.st_mode, stat.st_rdev)
            != (inherited.dev, inherited.ino, inherited.mode, inherited.rdev)
        {
            continue;
        }
        if unsafe { libc::close(inherited.fd) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

pub fn fd_mount_id(file: &File) -> io::Result<u64> {
    fs::read_to_string(format!("/proc/self/fdinfo/{}", file.as_raw_fd()))?
        .lines()
        .find_map(|line| line.strip_prefix("mnt_id:"))
        .ok_or_else(|| io::Error::other("file descriptor has no mount ID"))?
        .trim()
        .parse()
        .map_err(io::Error::other)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::{IntoRawFd, RawFd};
    use std::os::unix::fs::MetadataExt;

    #[cfg(target_os = "linux")]
    #[test]
    fn close_range_marks_fds_in_child_only() {
        for mark in [
            cloexec_unexpected_fds as fn() -> io::Result<()>,
            cloexec_proc_fds,
        ] {
            let file = File::open("/dev/null").unwrap();
            let fd = file.as_raw_fd();
            let pid = unsafe { libc::fork() };
            assert!(pid >= 0);
            if pid == 0 {
                let high = unsafe { libc::fcntl(fd, libc::F_DUPFD, 256) };
                let stdio = unsafe { libc::fcntl(1, libc::F_GETFD) };
                let ok = unsafe { libc::fcntl(fd, libc::F_SETFD, 0) } == 0
                    && high >= 256
                    && mark().is_ok()
                    && unsafe { libc::fcntl(fd, libc::F_GETFD) } & libc::FD_CLOEXEC != 0
                    && unsafe { libc::fcntl(high, libc::F_GETFD) } & libc::FD_CLOEXEC != 0
                    && unsafe { libc::fcntl(1, libc::F_GETFD) } == stdio;
                unsafe { libc::_exit(if ok { 0 } else { 1 }) }
            }
            let mut status = 0;
            assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
            assert!(libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0);
        }
    }

    fn inherited(fd: RawFd, file: &File) -> io::Result<InheritedFd> {
        let metadata = file.metadata()?;
        Ok(InheritedFd {
            fd,
            dev: metadata.dev(),
            ino: metadata.ino(),
            mode: metadata.mode(),
            rdev: metadata.rdev(),
        })
    }

    #[test]
    fn closes_unapproved_fds_and_preserves_allowlisted_or_mismatched_descriptors() -> io::Result<()>
    {
        let closed_path =
            std::env::temp_dir().join(format!("ssal-fd-close-{}", std::process::id()));
        let closed = File::create(&closed_path)?;
        let closed_fd = closed.as_raw_fd();
        let closed_identity = inherited(closed_fd, &closed)?;
        let _ = closed.into_raw_fd();
        close_inherited_fds(&[closed_identity], &[])?;
        assert_eq!(unsafe { libc::fcntl(closed_fd, libc::F_GETFD) }, -1);
        fs::remove_file(closed_path)?;

        let open_path = std::env::temp_dir().join(format!("ssal-fd-open-{}", std::process::id()));
        let open = File::create(&open_path)?;
        let open_fd = open.as_raw_fd();
        let open_identity = inherited(open_fd, &open)?;
        close_inherited_fds(&[open_identity], &[open_fd])?;
        assert_ne!(unsafe { libc::fcntl(open_fd, libc::F_GETFD) }, -1);

        let stale_identity = InheritedFd {
            ino: open_identity.ino.wrapping_add(1),
            ..open_identity
        };
        close_inherited_fds(&[stale_identity], &[])?;
        assert_ne!(unsafe { libc::fcntl(open_fd, libc::F_GETFD) }, -1);
        drop(open);
        fs::remove_file(open_path)?;
        Ok(())
    }
}
