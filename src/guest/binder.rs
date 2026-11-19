//! Owns the private Guest Binder device and its mount lifecycle.
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

#[repr(C)]
struct BinderfsDevice {
    name: [u8; 256],
    major: u32,
    minor: u32,
}

fn cpath(path: &Path) -> io::Result<CString> {
    CString::new(path.as_os_str().as_bytes()).map_err(io::Error::other)
}

fn mount_id(file: &File) -> io::Result<u64> {
    let info = fs::read_to_string(format!("/proc/self/fdinfo/{}", file.as_raw_fd()))?;
    info.lines()
        .find_map(|line| line.strip_prefix("mnt_id:"))
        .ok_or_else(|| io::Error::other("Binder fd has no mount ID"))?
        .trim()
        .parse()
        .map_err(io::Error::other)
}

pub(crate) struct Session {
    mounts: Vec<PathBuf>,
    device: Option<File>,
    created_mount: Option<u64>,
}

#[derive(Clone, Copy)]
enum Driver {
    Binder,
    HwBinder,
}

impl Driver {
    fn name(self) -> &'static str {
        match self {
            Self::Binder => "binder",
            Self::HwBinder => "hwbinder",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Binder => "binder_device",
            Self::HwBinder => "hwbinder_device",
        }
    }
}

impl Session {
    pub(crate) fn new() -> Self {
        Self {
            mounts: Vec::new(),
            device: None,
            created_mount: None,
        }
    }

    /// Creates and binds only a private driver; no context manager or IPC.
    pub(crate) fn provision(&mut self, root: &Path) -> io::Result<(u32, u32, i32)> {
        self.provision_with_context(root, None)
    }

    pub(crate) fn provision_with_context(
        &mut self,
        root: &Path,
        label: Option<&str>,
    ) -> io::Result<(u32, u32, i32)> {
        let target = crate::guest::mount::guest_path(root, "dev/binderfs")?;
        self.provision_driver(root, &target, Driver::Binder, label)
    }

    pub(crate) fn provision_hwbinder(&mut self, root: &Path) -> io::Result<(u32, u32)> {
        if !fs::read_to_string("/proc/filesystems")?
            .lines()
            .any(|line| line.split_whitespace().last() == Some("binder"))
        {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "kernel binderfs unavailable",
            ));
        }
        let backing = crate::guest::mount::directory(root, "dev/.ssal-hwbinder/binderfs", 0o700)?;
        // Some kernels populate binder and vndbinder by default. Expose only the HwBinder alias.
        fs::set_permissions(backing.parent().unwrap(), fs::Permissions::from_mode(0o700))?;
        let (major, minor, _) = self.provision_driver(root, &backing, Driver::HwBinder, None)?;
        let device = self
            .device
            .as_ref()
            .ok_or_else(|| io::Error::other("private HwBinder absent"))?;
        device.set_permissions(fs::Permissions::from_mode(0o666))?;
        // Verify binder_mmap on an independent open FD without disturbing the session handle.
        let alias = crate::guest::mount::guest_path(root, "dev/hwbinder")?;
        let mmap_probe = OpenOptions::new().read(true).write(true).open(&alias)?;
        let mapped = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_READ,
                libc::MAP_PRIVATE,
                mmap_probe.as_raw_fd(),
                0,
            )
        };
        if mapped == libc::MAP_FAILED {
            return Err(io::Error::other(format!(
                "private HwBinder mmap: {}",
                io::Error::last_os_error()
            )));
        }
        if unsafe { libc::munmap(mapped, 4096) } != 0 {
            return Err(io::Error::last_os_error());
        }
        println!("GUEST_HWBINDER_MMAP=PASS device={major}:{minor} bytes=4096");
        Ok((major, minor))
    }

    fn provision_driver(
        &mut self,
        root: &Path,
        target: &Path,
        driver: Driver,
        label: Option<&str>,
    ) -> io::Result<(u32, u32, i32)> {
        let name = driver.name();
        let mut host_devices = Vec::new();
        let host_paths: &[_] = match driver {
            Driver::Binder => &["/dev/binder"],
            Driver::HwBinder => &["/dev/binder", "/dev/hwbinder", "/dev/vndbinder"],
        };
        for &host_path in host_paths {
            match fs::metadata(host_path) {
                Ok(meta) if meta.file_type().is_char_device() => {
                    host_devices.push((host_path, meta.rdev()));
                }
                Ok(_) => {
                    return Err(io::Error::other(format!(
                        "{host_path} is not a character device"
                    )))
                }
                Err(error)
                    if error.kind() == io::ErrorKind::NotFound
                        && matches!(driver, Driver::HwBinder) =>
                {
                    ()
                }
                Err(error) => return Err(error),
            }
        }
        if !target.is_dir() {
            return Err(io::Error::other("binderfs mountpoint missing"));
        }
        let mapped = ssal::guest_policy::runtime::load(root)?
            .map(|p| p.context(driver.label(), false))
            .transpose()?;
        if matches!(driver, Driver::HwBinder) && mapped.is_none() {
            return Err(io::Error::other(
                "private HwBinder requires a mapped Guest label",
            ));
        }
        let label = mapped.as_deref().or(label);
        let options = CString::new(match label {
            Some(context)
                if context == "u:object_r:binder_device:s0"
                    || mapped.as_deref() == Some(context) =>
            {
                format!("max=4,context={context}")
            }
            None => "max=4".into(),
            _ => return Err(io::Error::other("unsupported private Binder context")),
        })
        .map_err(io::Error::other)?;
        if unsafe {
            libc::mount(
                c"binder".as_ptr(),
                cpath(target)?.as_ptr(),
                c"binder".as_ptr(),
                libc::MS_NOSUID | libc::MS_NOEXEC,
                options.as_ptr().cast(),
            )
        } != 0
        {
            let e = io::Error::last_os_error();
            return Err(io::Error::new(
                e.kind(),
                format!("mount private binderfs {}: {e}", target.display()),
            ));
        }
        self.mounts.push(target.to_owned());
        let control = OpenOptions::new()
            .read(true)
            .write(true)
            .open(target.join("binder-control"))?;
        let private_mount = mount_id(&control)?;
        self.created_mount = Some(private_mount);
        let mut request = BinderfsDevice {
            name: [0; 256],
            major: 0,
            minor: 0,
        };
        // Inspect the original node before any alias bind hides its genfs label.
        // Only reuse a default node on the fresh mount whose control FD we own.
        let source = target.join(name);
        let created_by = match fs::symlink_metadata(&source) {
            Ok(meta) if meta.file_type().is_char_device() => "kernel_mount_default",
            Ok(_) => {
                return Err(io::Error::other(format!(
                    "private {name} is not a character device"
                )))
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => "BINDER_CTL_ADD",
            Err(e) => return Err(e),
        };
        request.name[..name.len()].copy_from_slice(name.as_bytes());
        // _IOWR('b', 1, struct binderfs_device), size=264 on arm64 and x86_64.
        if created_by == "BINDER_CTL_ADD"
            && unsafe { libc::ioctl(control.as_raw_fd(), 0xc1086201u32 as _, &mut request) } != 0
        {
            return Err(io::Error::other(format!(
                "BINDER_CTL_ADD {name}: {}",
                io::Error::last_os_error()
            )));
        }
        let device = OpenOptions::new().read(true).write(true).open(&source)?;
        let meta = device.metadata()?;
        if created_by == "kernel_mount_default" {
            request.major = libc::major(meta.rdev()) as u32;
            request.minor = libc::minor(meta.rdev()) as u32;
        }
        if !meta.file_type().is_char_device()
            || meta.rdev() != libc::makedev(request.major, request.minor)
            || host_devices.iter().any(|(_, rdev)| *rdev == meta.rdev())
            || mount_id(&device)? != private_mount
        {
            return Err(io::Error::other(
                "private Binder identity verification failed",
            ));
        }
        println!("private Binder original node: created_by={created_by}; dev={} inode={} rdev={} mode=0{:o} uid={} gid={} label={}", meta.dev(), meta.ino(), meta.rdev(), meta.mode() & 0o7777, meta.uid(), meta.gid(), ssal::unix::image_context(&device).unwrap_or_else(|e| format!("unavailable: {e}")));
        let alias = crate::guest::mount::guest_path(root, "dev")?.join(name);
        match fs::symlink_metadata(&alias) {
            Ok(_) if matches!(driver, Driver::HwBinder) => {
                return Err(io::Error::other("Guest HwBinder alias must start absent"));
            }
            Ok(meta) if !meta.file_type().is_symlink() => (),
            Ok(_) => return Err(io::Error::other("Guest Binder alias is a symlink")),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&alias)?;
            }
            Err(error) => return Err(error),
        }
        if fs::metadata(&alias)?.rdev() != meta.rdev() {
            if unsafe {
                libc::mount(
                    cpath(&source)?.as_ptr(),
                    cpath(&alias)?.as_ptr(),
                    std::ptr::null(),
                    libc::MS_BIND,
                    std::ptr::null(),
                )
            } != 0
            {
                return Err(io::Error::other(format!(
                    "bind private /dev/{name}: {}",
                    io::Error::last_os_error()
                )));
            }
            self.mounts.push(alias.clone());
        }
        let alias_file = OpenOptions::new().read(true).write(true).open(&alias)?;
        let alias_meta = alias_file.metadata()?;
        if (alias_meta.dev(), alias_meta.ino(), alias_meta.rdev())
            != (meta.dev(), meta.ino(), meta.rdev())
        {
            return Err(io::Error::other(format!(
                "guest /dev/{name} does not resolve to private device"
            )));
        }
        let mut protocol: i32 = 0;
        if unsafe { libc::ioctl(device.as_raw_fd(), 0xc0046209u32 as _, &mut protocol) } != 0 {
            return Err(io::Error::other(format!(
                "BINDER_VERSION: {}",
                io::Error::last_os_error()
            )));
        }
        if protocol != 8 {
            return Err(io::Error::other(format!(
                "unsupported arm64 Binder protocol {protocol}"
            )));
        }
        let actual_label = ssal::unix::image_context(&device);
        if matches!(driver, Driver::HwBinder) && actual_label.as_deref().ok() != mapped.as_deref() {
            return Err(io::Error::other("private HwBinder SELinux label mismatch"));
        }
        if matches!(driver, Driver::Binder) {
            let host = host_devices[0].1;
            println!("private Binder device: {}:{} mount_id={private_mount}; host device={}:{}; protocol={protocol}; label={}", request.major, request.minor, libc::major(host), libc::minor(host), actual_label.unwrap_or_else(|e| format!("unavailable: {e}")));
        } else {
            let host = host_devices
                .iter()
                .find(|(path, _)| *path == "/dev/hwbinder")
                .map(|(_, rdev)| format!("{}:{}", libc::major(*rdev), libc::minor(*rdev)))
                .unwrap_or_else(|| "absent".into());
            println!("GUEST_HWBINDER_DEVICE=PASS device={}:{} rdev={} mount_id={private_mount} host_hwbinder={host} protocol={protocol} label={}", request.major, request.minor, meta.rdev(), actual_label?);
        }
        self.device = Some(device);
        drop(alias_file);
        drop(control);
        Ok((request.major, request.minor, protocol))
    }

    /// Only the FD allocated by this private session may be modified.
    pub(crate) fn private_device(&self) -> io::Result<&File> {
        let file = self
            .device
            .as_ref()
            .ok_or_else(|| io::Error::other("private Binder absent"))?;
        if Some(mount_id(file)?) != self.created_mount
            || file.metadata()?.rdev() == fs::metadata("/dev/binder")?.rdev()
        {
            return Err(io::Error::other("private Binder ownership guard failed"));
        }
        Ok(file)
    }
    pub(crate) fn cleanup(&mut self) -> io::Result<()> {
        self.device.take();
        let mut errors = Vec::new();
        let mut remaining = Vec::new();
        while let Some(path) = self.mounts.pop() {
            if unsafe { libc::umount2(cpath(&path)?.as_ptr(), 0) } != 0 {
                errors.push(format!(
                    "{}: {}",
                    path.display(),
                    io::Error::last_os_error()
                ));
                remaining.push(path);
            }
        }
        self.mounts = remaining.into_iter().rev().collect();
        if let Some(id) = self.created_mount {
            if fs::read_to_string("/proc/self/mountinfo")?
                .lines()
                .any(|line| {
                    line.split_whitespace()
                        .next()
                        .and_then(|value| value.parse::<u64>().ok())
                        == Some(id)
                })
            {
                errors.push(format!("private Binder mount {id} remains"));
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(io::Error::other(format!(
                "Binder cleanup: {}",
                errors.join("; ")
            )))
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if let Err(e) = self.cleanup() {
            eprintln!("Binder cleanup: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn binderfs_ioctl_layout_matches_uapi() {
        assert_eq!(std::mem::size_of::<BinderfsDevice>(), 264);
        let request = ((3u32 << 30) | (264 << 16) | (u32::from(b'b') << 8) | 1) as u64;
        assert_eq!(request, 0xc1086201);
    }
}
