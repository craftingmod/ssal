use ssal::namespace_mounts::parse_device_number;
#[cfg(target_os = "android")]
use ssal::unix::image_context;
use std::cell::RefCell;
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileExt, FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};

pub(crate) fn cpath(path: &Path) -> io::Result<CString> {
    CString::new(path.as_os_str().as_bytes()).map_err(|_| io::Error::other("invalid path"))
}
#[repr(C)]
struct LoopInfo64 {
    device: u64,
    inode: u64,
    rdevice: u64,
    offset: u64,
    sizelimit: u64,
    number: u32,
    encrypt_type: u32,
    encrypt_key_size: u32,
    flags: u32,
    file_name: [u8; 64],
    crypt_name: [u8; 64],
    encrypt_key: [u8; 32],
    init: [u64; 2],
}

pub(crate) struct LoopNodes {
    path: PathBuf,
    mounted: bool,
    allocated: RefCell<Vec<LoopRecord>>,
    #[cfg(target_os = "android")]
    context: CString,
}

struct LoopRecord {
    path: PathBuf,
    backing_device: u64,
    backing_inode: u64,
}

impl LoopNodes {
    pub(crate) fn new(path: PathBuf) -> io::Result<Self> {
        #[cfg(target_os = "android")]
        let context = {
            let mut reference = None;
            for directory in ["/dev/block", "/dev"] {
                if let Ok(entries) = fs::read_dir(directory) {
                    for entry in entries {
                        let entry = entry?;
                        if !entry.file_name().to_string_lossy().starts_with("loop") {
                            continue;
                        }
                        let meta = entry.metadata()?;
                        if meta.file_type().is_block_device() && libc::major(meta.rdev()) == 7 {
                            reference = Some(entry.path());
                            break;
                        }
                    }
                }
                if reference.is_some() {
                    break;
                }
            }
            let reference = reference.ok_or_else(|| {
                io::Error::other("no host loop block node available as SELinux label reference")
            })?;
            CString::new(image_context(&File::open(&reference)?)?).map_err(io::Error::other)?
        };
        fs::create_dir(&path)?;
        if unsafe {
            libc::mount(
                c"tmpfs".as_ptr(),
                cpath(&path)?.as_ptr(),
                c"tmpfs".as_ptr(),
                libc::MS_NOSUID | libc::MS_NOEXEC,
                c"mode=0700".as_ptr().cast(),
            )
        } != 0
        {
            return Err(io::Error::other(format!(
                "mount private loop-node tmpfs {}: {}",
                path.display(),
                io::Error::last_os_error()
            )));
        }
        Ok(Self {
            path,
            mounted: true,
            allocated: RefCell::new(Vec::new()),
            #[cfg(target_os = "android")]
            context,
        })
    }

    pub(crate) fn cleanup(&mut self) -> io::Result<()> {
        if self.mounted {
            if unsafe { libc::umount2(cpath(&self.path)?.as_ptr(), 0) } != 0 {
                return Err(io::Error::other(format!(
                    "unmount private loop nodes {}: {}",
                    self.path.display(),
                    io::Error::last_os_error()
                )));
            }
            self.mounted = false;
        }
        Ok(())
    }

    pub(crate) fn verify_released(&self) -> io::Result<()> {
        for record in self.allocated.borrow().iter() {
            let device = File::open(&record.path).map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!("verify loop release {}: {e}", record.path.display()),
                )
            })?;
            let mut info: LoopInfo64 = unsafe { std::mem::zeroed() };
            if unsafe { libc::ioctl(device.as_raw_fd(), 0x4c05, &mut info) } != 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::ENXIO) {
                    continue;
                }
                return Err(io::Error::new(
                    error.kind(),
                    format!("LOOP_GET_STATUS64 {}: {error}", record.path.display()),
                ));
            }
            if info.device == record.backing_device && info.inode == record.backing_inode {
                return Err(io::Error::other(format!(
                    "session backing still attached to {}; loop release NOT verified",
                    record.path.display()
                )));
            }
            println!(
                "loop {} now has a different backing; not detached by ssal",
                record.path.display()
            );
        }
        println!(
            "session loop backing release: verified ({} allocations)",
            self.allocated.borrow().len()
        );
        Ok(())
    }

    fn create(&self, number: i32, device_number: libc::dev_t) -> io::Result<PathBuf> {
        let path = self.path.join(format!("loop{number}"));
        if unsafe { libc::mknod(cpath(&path)?.as_ptr(), libc::S_IFBLK | 0o600, device_number) } != 0
        {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::AlreadyExists {
                return Err(io::Error::new(
                    error.kind(),
                    format!("create private loop node {}: {error}", path.display()),
                ));
            }
        }
        let meta = fs::symlink_metadata(&path)?;
        if !meta.file_type().is_block_device() || meta.rdev() != device_number {
            return Err(io::Error::other(format!(
                "private loop node has wrong device number: {}",
                path.display()
            )));
        }
        #[cfg(target_os = "android")]
        if unsafe {
            libc::setxattr(
                cpath(&path)?.as_ptr(),
                c"security.selinux".as_ptr(),
                self.context.as_ptr().cast(),
                self.context.as_bytes_with_nul().len(),
                0,
            )
        } != 0
        {
            return Err(io::Error::other(format!(
                "label private loop node {}: {}",
                path.display(),
                io::Error::last_os_error()
            )));
        }
        println!(
            "created private loop node {} ({}:{})",
            path.display(),
            libc::major(device_number),
            libc::minor(device_number)
        );
        Ok(path)
    }
}

impl Drop for LoopNodes {
    fn drop(&mut self) {
        if let Err(error) = self.cleanup() {
            eprintln!("loop-node cleanup: {error}");
        }
    }
}

pub(crate) fn loop_device(
    image: &Path,
    readonly: bool,
    nodes: &LoopNodes,
) -> io::Result<(File, PathBuf)> {
    let backing = OpenOptions::new()
        .read(true)
        .write(!readonly)
        .open(image)
        .map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("open loop backing {}: {e}", image.display()),
            )
        })?;
    let control_path = if Path::new("/dev/loop-control").exists() {
        "/dev/loop-control"
    } else {
        "/dev/block/loop-control"
    };
    let control = OpenOptions::new()
        .read(true)
        .write(true)
        .open(control_path)
        .map_err(|e| io::Error::new(e.kind(), format!("open loop control {control_path}: {e}")))?;
    for _ in 0..16 {
        let number = unsafe { libc::ioctl(control.as_raw_fd(), 0x4c82) };
        if number < 0 {
            let e = io::Error::last_os_error();
            return Err(io::Error::new(
                e.kind(),
                format!("LOOP_CTL_GET_FREE for {}: {e}", image.display()),
            ));
        }
        let sysfs = format!("/sys/block/loop{number}/dev");
        let device_number = parse_device_number(&fs::read_to_string(&sysfs).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("read allocated loop device number {sysfs}: {e}"),
            )
        })?)?;
        let candidates = [
            PathBuf::from(format!("/dev/block/loop{number}")),
            PathBuf::from(format!("/dev/loop{number}")),
        ];
        let mut selected = None;
        for path in candidates {
            match OpenOptions::new().read(true).write(!readonly).open(&path) {
                Ok(device) => {
                    selected = Some((device, path));
                    break;
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => (),
                Err(e) => {
                    return Err(io::Error::new(
                        e.kind(),
                        format!("open allocated loop node {}: {e}", path.display()),
                    ));
                }
            }
        }
        let (device, path) = match selected {
            Some(pair) => pair,
            None => {
                let path = nodes.create(number, device_number)?;
                let device = OpenOptions::new()
                    .read(true)
                    .write(!readonly)
                    .open(&path)
                    .map_err(|e| {
                        io::Error::new(
                            e.kind(),
                            format!("open private loop node {}: {e}", path.display()),
                        )
                    })?;
                (device, path)
            }
        };
        let meta = device.metadata()?;
        if !meta.file_type().is_block_device() || meta.rdev() != device_number {
            return Err(io::Error::other(format!(
                "loop node {} does not match {sysfs}",
                path.display()
            )));
        }
        if unsafe { libc::ioctl(device.as_raw_fd(), 0x4c00, backing.as_raw_fd()) } != 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EBUSY) {
                continue;
            }
            return Err(io::Error::new(
                error.kind(),
                format!(
                    "LOOP_SET_FD {} <- {}: {error}",
                    path.display(),
                    image.display()
                ),
            ));
        }
        let mut info: LoopInfo64 = unsafe { std::mem::zeroed() };
        info.flags = 4 | if readonly { 1 } else { 0 }; // AUTOCLEAR and READ_ONLY
        if unsafe { libc::ioctl(device.as_raw_fd(), 0x4c04, &info) } != 0 {
            let error = io::Error::last_os_error();
            unsafe {
                libc::ioctl(device.as_raw_fd(), 0x4c01, 0);
            }
            return Err(io::Error::new(
                error.kind(),
                format!("LOOP_SET_STATUS64 {}: {error}", path.display()),
            ));
        }
        let backing_meta = backing.metadata()?;
        nodes.allocated.borrow_mut().push(LoopRecord {
            path: path.clone(),
            backing_device: backing_meta.dev(),
            backing_inode: backing_meta.ino(),
        });
        return Ok((device, path));
    }
    Err(io::Error::other("could not allocate a free loop device"))
}

pub(crate) fn check_loop_read(device: &File, path: &Path, image: &Path) -> io::Result<()> {
    let mut from_image = [0u8; 2048];
    let mut from_loop = [0u8; 2048];
    File::open(image)?.read_exact_at(&mut from_image, 0)?;
    device.read_exact_at(&mut from_loop, 0).map_err(|e| {
        io::Error::other(format!("cannot read {path:?} backed by {}: {e}; check kernel log and SELinux access to the backing file", image.display()))
    })?;
    if from_image != from_loop {
        return Err(io::Error::other(format!(
            "loop device {} does not match its backing image",
            path.display()
        )));
    }
    Ok(())
}
pub(crate) fn mount_image(source: &Path, target: &Path, readonly: bool) -> io::Result<()> {
    let source = cpath(source)?;
    let target = cpath(target)?;
    let filesystem = c"ext4";
    let options = if readonly { c"noload" } else { c"" };
    let flags = libc::MS_NOSUID | libc::MS_NODEV | if readonly { libc::MS_RDONLY } else { 0 };
    if unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            filesystem.as_ptr(),
            flags,
            options.as_ptr().cast(),
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loop_device_number_uses_sysfs_minor() -> io::Result<()> {
        // Device log: loop62 is 7:496, not 7:62 (partition minor layout).
        let device = parse_device_number("7:496\n")?;
        assert_eq!(libc::major(device), 7);
        assert_eq!(libc::minor(device), 496);
        assert!(parse_device_number("loop62").is_err());
        assert!(parse_device_number("7:-1").is_err());
        assert!(parse_device_number("7:496:0").is_err());
        Ok(())
    }
}
