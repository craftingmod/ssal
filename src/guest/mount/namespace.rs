use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub(crate) fn available() -> bool {
    Path::new("/proc/self/ns/mnt").exists()
}

pub(crate) fn current() -> io::Result<PathBuf> {
    fs::read_link("/proc/self/ns/mnt")
}

pub(crate) fn enter() -> io::Result<PathBuf> {
    let host_mount_namespace = current()?;
    if unsafe { libc::unshare(libc::CLONE_NEWNS) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe {
        libc::mount(
            std::ptr::null(),
            c"/".as_ptr(),
            std::ptr::null(),
            libc::MS_REC | libc::MS_PRIVATE,
            std::ptr::null(),
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    let guest_mount_namespace = current()?;
    if host_mount_namespace == guest_mount_namespace {
        return Err(io::Error::other(
            "mount namespace did not separate from Host",
        ));
    }
    println!(
        "host_mount_namespace={} guest_mount_namespace={}",
        host_mount_namespace.display(),
        guest_mount_namespace.display()
    );
    Ok(host_mount_namespace)
}
