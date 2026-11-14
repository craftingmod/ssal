use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;

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

pub const VERSION: u32 = 2;
pub const ROOT: &str = "/data/local/ssal";
pub const IMAGE_CONTEXT: &str = "u:object_r:ssal_image_file:s0";

pub fn image_context(file: &File) -> io::Result<String> {
    let mut value = [0u8; 256];
    let len = unsafe {
        libc::fgetxattr(
            file.as_raw_fd(),
            c"security.selinux".as_ptr(),
            value.as_mut_ptr().cast(),
            value.len(),
        )
    };
    if len < 0 {
        return Err(io::Error::last_os_error());
    }
    let value = &value[..len as usize];
    let value = value.strip_suffix(&[0]).unwrap_or(value);
    String::from_utf8(value.to_vec()).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

pub fn label_image(file: &File) -> io::Result<()> {
    let context = c"u:object_r:ssal_image_file:s0";
    if unsafe {
        libc::fsetxattr(
            file.as_raw_fd(),
            c"security.selinux".as_ptr(),
            context.as_ptr().cast(),
            context.to_bytes_with_nul().len(),
            0,
        )
    } != 0
    {
        return Err(io::Error::other(format!("cannot label system image with {IMAGE_CONTEXT}: {}; ensure ssal SELinux policy is loaded", io::Error::last_os_error())));
    }
    let actual = image_context(file)?;
    if actual != IMAGE_CONTEXT {
        return Err(io::Error::other(format!(
            "unexpected system image SELinux context: {actual}"
        )));
    }
    Ok(())
}
#[derive(Serialize, Deserialize)]
pub struct Request {
    pub version: u32,
    pub command: String,
    #[serde(default)]
    pub image_name: Option<String>,
    #[serde(default)]
    pub profile_name: Option<String>,
    #[serde(default)]
    pub force_regen: bool,
    #[serde(default)]
    pub native_sepolicy: bool,
}

pub fn valid_image_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}
#[derive(Serialize, Deserialize)]
pub struct Response {
    pub ok: bool,
    pub message: String,
}

pub fn send(stream: &mut UnixStream, request: &Request, fd: Option<RawFd>) -> io::Result<()> {
    let mut bytes = serde_json::to_vec(request)?;
    bytes.push(b'\n');
    if let Some(fd) = fd {
        unsafe {
            let mut iov = libc::iovec {
                iov_base: bytes.as_mut_ptr().cast(),
                iov_len: bytes.len(),
            };
            let mut control = [0usize; 8];
            let mut msg: libc::msghdr = std::mem::zeroed();
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = control.as_mut_ptr().cast();
            msg.msg_controllen = libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as _) as _;
            let cmsg = libc::CMSG_FIRSTHDR(&msg);
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as _) as _;
            std::ptr::write_unaligned(libc::CMSG_DATA(cmsg).cast::<RawFd>(), fd);
            let n = libc::sendmsg(stream.as_raw_fd(), &msg, 0);
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            stream.write_all(&bytes[n as usize..])?;
        }
    } else {
        stream.write_all(&bytes)?;
    }
    Ok(())
}

pub fn receive(stream: &mut UnixStream) -> io::Result<(Request, Option<OwnedFd>)> {
    let mut bytes = [0u8; 4096];
    let mut control = [0usize; 8];
    let (n, fd) = unsafe {
        let mut iov = libc::iovec {
            iov_base: bytes.as_mut_ptr().cast(),
            iov_len: bytes.len(),
        };
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = std::mem::size_of_val(&control) as _;
        let n = libc::recvmsg(stream.as_raw_fd(), &mut msg, libc::MSG_CMSG_CLOEXEC);
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        let fd = if !cmsg.is_null()
            && (*cmsg).cmsg_level == libc::SOL_SOCKET
            && (*cmsg).cmsg_type == libc::SCM_RIGHTS
            && (*cmsg).cmsg_len as usize
                == libc::CMSG_LEN(std::mem::size_of::<RawFd>() as _) as usize
        {
            Some(OwnedFd::from_raw_fd(std::ptr::read_unaligned(
                libc::CMSG_DATA(cmsg).cast::<RawFd>(),
            )))
        } else {
            None
        };
        if msg.msg_flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC) != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated request",
            ));
        }
        (n as usize, fd)
    };
    let mut data = bytes[..n].to_vec();
    while !data.contains(&b'\n') && data.len() < 4096 {
        let mut b = [0];
        if stream.read(&mut b)? == 0 {
            break;
        }
        data.push(b[0]);
    }
    if !data.ends_with(b"\n") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid request",
        ));
    }
    Ok((serde_json::from_slice(&data)?, fd))
}

pub fn reply(stream: &mut UnixStream, ok: bool, message: impl Into<String>) -> io::Result<()> {
    serde_json::to_writer(
        &mut *stream,
        &Response {
            ok,
            message: message.into(),
        },
    )?;
    stream.write_all(b"\n")
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
