//! Disposable private binderfs device probe. Never opens host Binder for IPC.
use serde::Serialize;
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};

#[repr(C)]
struct BinderfsDevice {
    name: [u8; 256],
    major: u32,
    minor: u32,
}

#[derive(Serialize, Clone, Copy)]
#[serde(rename_all = "snake_case")]
enum Status {
    NotRun,
    Passed,
    Failed,
    Unavailable,
}

#[derive(Serialize)]
struct Report {
    device_created: Status,
    device_opened: Status,
    driver_protocol: Option<i32>,
    context_manager: Status,
    ipc: Status,
    servicemanager: Status,
    android_service_selinux: Status,
    host_registry_isolation: Status,
    cleanup: Status,
    validation_scope: &'static str,
    failure: Option<String>,
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
        let host = fs::metadata("/dev/binder")?;
        if !host.file_type().is_char_device() {
            return Err(io::Error::other("host binder is not a character device"));
        }
        let target = crate::guest_mounts::guest_path(root, "dev/binderfs")?;
        if !target.is_dir() {
            return Err(io::Error::other("binderfs mountpoint missing"));
        }
        let options = CString::new(match label {
            Some("u:object_r:binder_device:s0") => "max=4,context=u:object_r:binder_device:s0",
            None => "max=4",
            _ => return Err(io::Error::other("unsupported private Binder context")),
        })
        .map_err(io::Error::other)?;
        if unsafe {
            libc::mount(
                c"binder".as_ptr(),
                cpath(&target)?.as_ptr(),
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
        self.mounts.push(target.clone());
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
        // Some Android kernels prepopulate binder/hwbinder/vndbinder on mount.
        // Allocate our own name instead of treating those as an allocation.
        request.name[..10].copy_from_slice(b"ssal-probe");
        // _IOWR('b', 1, struct binderfs_device), size=264 on arm64 and x86_64.
        if unsafe { libc::ioctl(control.as_raw_fd(), 0xc1086201u32 as _, &mut request) } != 0 {
            return Err(io::Error::other(format!(
                "BINDER_CTL_ADD: {}",
                io::Error::last_os_error()
            )));
        }
        let source = target.join("ssal-probe");
        let device = OpenOptions::new().read(true).write(true).open(&source)?;
        let meta = device.metadata()?;
        if !meta.file_type().is_char_device()
            || meta.rdev() != libc::makedev(request.major, request.minor)
            || meta.rdev() == host.rdev()
            || mount_id(&device)? != private_mount
        {
            return Err(io::Error::other(
                "private Binder identity verification failed",
            ));
        }
        let alias = crate::guest_mounts::guest_path(root, "dev/binder")?;
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
                    "bind private /dev/binder: {}",
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
            return Err(io::Error::other(
                "guest /dev/binder does not resolve to private device",
            ));
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
        println!("private Binder device: {}:{} mount_id={private_mount}; host device={}:{}; protocol={protocol}; label={}", request.major, request.minor, libc::major(host.rdev()), libc::minor(host.rdev()), ssal::unix::image_context(&device).unwrap_or_else(|e| format!("unavailable: {e}")));
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

pub fn verify(root: &Path) -> io::Result<()> {
    let mut report = Report {
        device_created: Status::NotRun,
        device_opened: Status::NotRun,
        driver_protocol: None,
        context_manager: Status::NotRun,
        ipc: Status::NotRun,
        servicemanager: Status::NotRun,
        android_service_selinux: Status::NotRun,
        host_registry_isolation: Status::NotRun,
        cleanup: Status::NotRun,
        validation_scope: "private_device_only",
        failure: None,
    };
    let host = fs::metadata("/dev/binder")?;
    if !host.file_type().is_char_device() {
        return Err(io::Error::other(
            "host /dev/binder is not a character device",
        ));
    }
    let mut session = Session::new();
    let result = (|| -> io::Result<()> {
        report.device_created = Status::Failed;
        let (major, minor, protocol) = session.provision(root)?;
        report.device_created = Status::Passed;
        report.device_opened = Status::Passed;
        report.driver_protocol = Some(protocol);
        // A fresh exec is mandatory: no inherited libbinder ProcessState/FDs.
        // The helper is only admitted after exact private device identity checks.
        crate::guest_probe::binder_ipc(root, major, minor, &mut |stage| {
            if stage == "context_manager_attempt" {
                report.context_manager = Status::Failed;
            }
            if stage == "ipc_attempt" {
                report.ipc = Status::Failed;
            }
            if stage == "context_manager" {
                report.context_manager = Status::Passed;
            }
            if stage == "ipc" {
                report.ipc = Status::Passed;
                report.validation_scope = "management_domain_ipc_only";
            }
            if stage == "unavailable" {
                report.context_manager = Status::Unavailable;
                report.ipc = Status::Unavailable;
            }
        })?;
        Ok(())
    })();
    if let Err(e) = &result {
        report.failure = Some(e.to_string());
    }
    let cleanup = session.cleanup();
    if let Err(e) = &cleanup {
        report.failure = Some(match report.failure.take() {
            Some(previous) => format!("{previous}; {e}"),
            None => e.to_string(),
        });
    }
    report.cleanup = if cleanup.is_ok() {
        Status::Passed
    } else {
        Status::Failed
    };
    let current = fs::metadata("/dev/binder")?;
    let host_unchanged =
        (host.dev(), host.ino(), host.rdev()) == (current.dev(), current.ino(), current.rdev());
    println!(
        "host Binder path identity unchanged={host_unchanged}; this probe issued no transactions to the host Binder device"
    );
    println!("Binder probe summary: {}", serde_json::to_string(&report)?);
    if !host_unchanged {
        return Err(io::Error::other(
            "host Binder identity changed during probe",
        ));
    }
    match (result, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(e), Ok(())) | (Ok(()), Err(e)) => Err(e),
        (Err(e), Err(cleanup)) => Err(io::Error::other(format!("{e}; {cleanup}"))),
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
