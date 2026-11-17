pub use crate::ipc::{receive, reply, send, valid_image_name, Request, Response, VERSION};
#[cfg(any(target_os = "linux", target_os = "android"))]
pub use crate::platform::fd::cloexec_unexpected_fds;
pub use crate::platform::fd::{close_inherited_fds, fd_mount_id, inherited_fds, InheritedFd};
use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;
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
