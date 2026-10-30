use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;

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
