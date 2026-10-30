use sha2::{Digest, Sha256};
use ssal::unix::{image_context, valid_image_name, IMAGE_CONTEXT};
use std::cell::RefCell;
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileExt, FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub struct CheckedProfile {
    pub system: PathBuf,
    pub userdata: PathBuf,
    pub report: String,
}

fn ext4_magic(path: &Path) -> io::Result<bool> {
    let mut file = File::open(path)?;
    file.seek(SeekFrom::Start(1080))?;
    let mut magic = [0; 2];
    file.read_exact(&mut magic)?;
    Ok(magic == [0x53, 0xef])
}

pub fn check(root: &Path, name: &str) -> io::Result<CheckedProfile> {
    if !valid_image_name(name) {
        return Err(io::Error::other("invalid profile name"));
    }
    let dir = root.join("guests").join(name);
    let profile: serde_json::Value = serde_json::from_slice(&fs::read(dir.join("profile.json"))?)?;
    if profile["version"] == 1 {
        return Err(io::Error::other(
            "legacy userdata image profile is unsupported; create a new profile",
        ));
    }
    if profile["version"] != 2
        || profile["name"].as_str() != Some(name)
        || profile["userdata"]["path"] != "userdata"
    {
        return Err(io::Error::other("unsupported or invalid profile"));
    }
    // Existing directory profiles predate this field and use the same default.
    if profile
        .get("mount_profile")
        .is_some_and(|value| value.as_str() != Some(crate::guest_mounts::PROFILE_NAME))
    {
        return Err(io::Error::other("unsupported mount profile"));
    }
    let id = profile["image_id"]
        .as_str()
        .filter(|id| valid_image_name(id))
        .ok_or_else(|| io::Error::other("invalid profile image id"))?;
    let image_dir = root.join("images").join(id);
    let system = image_dir.join("system.img");
    let userdata = dir.join("userdata");
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(image_dir.join("manifest.json"))?)?;
    if manifest["id"].as_str() != Some(id) || manifest["format"] != "raw-ext4" {
        return Err(io::Error::other("invalid image manifest"));
    }
    let mut image = File::open(&system)?;
    let image_label = match image_context(&image) {
        Ok(value) if value == IMAGE_CONTEXT => format!("{value} (expected)"),
        Ok(value) => format!("{value} (expected {IMAGE_CONTEXT}; re-register the image)"),
        Err(error) => format!("unavailable: {error} (expected {IMAGE_CONTEXT})"),
    };
    if !image.metadata()?.is_file() || manifest["size"].as_u64() != Some(image.metadata()?.len()) {
        return Err(io::Error::other("image size does not match manifest"));
    }
    let expected = manifest["sha256"]
        .as_str()
        .ok_or_else(|| io::Error::other("image hash missing"))?;
    let mut hash = Sha256::new();
    let mut buffer = vec![0; 1024 * 1024];
    loop {
        let n = image.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hash.update(&buffer[..n]);
    }
    let actual = hash
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    if actual != expected {
        return Err(io::Error::other("image SHA-256 mismatch"));
    }
    if !ext4_magic(&system)? {
        return Err(io::Error::other("system does not have ext4 magic"));
    }
    let data_meta = fs::symlink_metadata(&userdata)?;
    if !data_meta.is_dir() || profile["userdata"]["format"] != "directory" {
        return Err(io::Error::other("userdata metadata mismatch"));
    }
    let loop_control =
        Path::new("/dev/loop-control").exists() || Path::new("/dev/block/loop-control").exists();
    let namespace = Path::new("/proc/self/ns/mnt").exists();
    let output = std::process::Command::new("/system/bin/getprop")
        .arg("ro.build.fingerprint")
        .output();
    let fingerprint = output
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_owned());
    let recorded = profile["device"]["build_fingerprint"].as_str();
    let device = match (recorded, fingerprint.as_deref()) {
        (Some(a), Some(b)) if !b.is_empty() && a == b => "fingerprint matches",
        (Some(_), Some(b)) if !b.is_empty() => "fingerprint differs",
        _ => "fingerprint unavailable",
    };
    let root_path = cpath(root)?;
    let mut stats: libc::statvfs = unsafe { std::mem::zeroed() };
    let space = if unsafe { libc::statvfs(root_path.as_ptr(), &mut stats) } == 0 {
        format!(
            "{} bytes available",
            stats.f_bavail as u128 * stats.f_frsize as u128
        )
    } else {
        "unavailable".into()
    };
    let report = format!("profile: {name}\nimage: {id}\nimage SELinux context: {image_label}\nimage size and SHA-256: OK\nsystem ext4 magic: OK\nuserdata directory: {}\nspace: {space}\nmount namespace: {}\nloop control: {}\ndevice: {device}\nvendor VINTF manifest: {}\nAndroid version, VINTF, HAL and service compatibility: not verified\n{}", userdata.display(), if namespace { "available" } else { "missing" }, if loop_control { "available" } else { "missing" }, if Path::new("/vendor/etc/vintf/manifest.xml").exists() { "present" } else { "not found at standard path" }, crate::guest_mounts::description()?);
    Ok(CheckedProfile {
        system,
        userdata,
        report,
    })
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
    fn new(path: PathBuf) -> io::Result<Self> {
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

    fn cleanup(&mut self) -> io::Result<()> {
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

    fn verify_released(&self) -> io::Result<()> {
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

fn parse_device_number(value: &str) -> io::Result<libc::dev_t> {
    let (major, minor) = value
        .trim()
        .split_once(':')
        .ok_or_else(|| io::Error::other("invalid sysfs device number"))?;
    let major = major.parse::<u32>().map_err(io::Error::other)?;
    let minor = minor.parse::<u32>().map_err(io::Error::other)?;
    Ok(libc::makedev(major, minor))
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
                    ))
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

fn cpath(path: &Path) -> io::Result<CString> {
    CString::new(path.as_os_str().as_bytes()).map_err(|_| io::Error::other("invalid path"))
}

fn check_loop_read(device: &File, path: &Path, image: &Path) -> io::Result<()> {
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

pub fn worker(system: &Path, userdata: &Path, base: &Path, mode: &str) -> io::Result<()> {
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
    let system_target = base.join("system");
    let mut loop_nodes = LoopNodes::new(base.join("loop-devices"))?;
    let data_target = base.join("data");
    let source = cpath(userdata)?;
    let target = cpath(&data_target)?;
    if unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND,
            std::ptr::null(),
        )
    } != 0
    {
        return Err(io::Error::other(format!(
            "userdata bind mount failed: {}",
            io::Error::last_os_error()
        )));
    }
    let mut system_mounted = false;
    let result = (|| {
        let source_meta = fs::metadata(userdata)?;
        let target_meta = fs::metadata(&data_target)?;
        if (source_meta.dev(), source_meta.ino()) != (target_meta.dev(), target_meta.ino()) {
            return Err(io::Error::other(
                "userdata mount does not refer to the profile directory",
            ));
        }
        let probe_name = format!(".ssal-prepare-probe-{}", std::process::id());
        let probe = data_target.join(&probe_name);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&probe)?;
        let probe_result = (|| {
            file.write_all(b"ssal prepare probe")?;
            file.sync_all()?;
            if fs::read(userdata.join(&probe_name))? != b"ssal prepare probe" {
                return Err(io::Error::other(
                    "userdata probe did not reach backing directory",
                ));
            }
            Ok(())
        })();
        drop(file);
        let remove_result = fs::remove_file(&probe);
        probe_result?;
        remove_result?;
        let data_info = fs::read_to_string("/proc/self/mountinfo")?;
        let data_line = data_info
            .lines()
            .find(|line| line.split_whitespace().nth(4) == Some(data_target.to_str().unwrap_or("")))
            .ok_or_else(|| io::Error::other("userdata mount missing from mountinfo"))?;
        if !data_line
            .split_whitespace()
            .nth(5)
            .is_some_and(|options| options.split(',').any(|option| option == "rw"))
        {
            return Err(io::Error::other("userdata mount is not writable"));
        }
        println!("mount namespace: {}\nuserdata backing: {}\nuserdata bind and write/read probe: OK\nuserdata mountinfo: {data_line}", fs::read_link("/proc/self/ns/mnt")?.display(), userdata.display());
        let (system_loop, system_dev) = loop_device(system, true, &loop_nodes)?;
        check_loop_read(&system_loop, &system_dev, system)?;
        mount_image(&system_dev, &system_target, true)
            .map_err(|e| io::Error::other(format!("system mount failed: {e}")))?;
        system_mounted = true;
        println!(
            "system mounted on {} via {}",
            system_target.display(),
            system_dev.display()
        );
        let build_prop = [
            system_target.join("system/build.prop"),
            system_target.join("build.prop"),
        ]
        .into_iter()
        .find(|path| path.is_file());
        match build_prop.and_then(|path| fs::read_to_string(path).ok()) {
            Some(contents) => println!(
                "image Android release: {}",
                contents
                    .lines()
                    .find_map(|line| line.strip_prefix("ro.build.version.release="))
                    .unwrap_or("not found in build.prop")
            ),
            None => println!("image Android release: build.prop unavailable"),
        }
        let info = fs::read_to_string("/proc/self/mountinfo")?;
        let matches: Vec<&str> = info
            .lines()
            .filter(|line| {
                line.split_whitespace().nth(4).is_some_and(|p| {
                    p == system_target.to_string_lossy() || p == data_target.to_string_lossy()
                })
            })
            .collect();
        if matches.len() != 2 {
            return Err(io::Error::other("could not find both mounts in mountinfo"));
        }
        println!(
            "mount namespace: {}\nsystem backing: {}\nuserdata backing: {}\nmountinfo:\n{}",
            fs::read_link("/proc/self/ns/mnt")?.display(),
            system.display(),
            userdata.display(),
            matches.join("\n")
        );
        crate::guest_mounts::verify(&system_target, userdata, base, &loop_nodes, mode)?;
        Ok(())
    })();
    let mut cleanup = Vec::new();
    if system_mounted && unsafe { libc::umount2(cpath(&system_target)?.as_ptr(), 0) } != 0 {
        cleanup.push(format!("system unmount: {}", io::Error::last_os_error()));
    }
    if unsafe { libc::umount2(cpath(&data_target)?.as_ptr(), 0) } != 0 {
        cleanup.push(format!("userdata unmount: {}", io::Error::last_os_error()));
    }
    if let Err(e) = loop_nodes.verify_released() {
        cleanup.push(e.to_string());
    }
    if let Err(e) = loop_nodes.cleanup() {
        cleanup.push(e.to_string());
    }
    if !cleanup.is_empty() {
        if mode == "--selinux-probe-worker" || mode == "--servicemanager-preflight-worker" {
            println!(
                "SELinux transition resource summary: {}",
                serde_json::json!({"cleanup": "failed", "scope": "system_userdata_mounts_and_loops", "errors": cleanup})
            );
        }
        return Err(io::Error::other(format!(
            "{}; {}",
            result.err().map(|e| e.to_string()).unwrap_or_default(),
            cleanup.join("; ")
        )));
    }
    if mode == "--selinux-probe-worker" || mode == "--servicemanager-preflight-worker" {
        println!(
            "SELinux transition resource summary: {}",
            serde_json::json!({"cleanup": "passed", "scope": "system_userdata_mounts_and_loops"})
        );
    }
    result?;
    println!("mount cleanup and session loop backing release checks: OK");
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

    #[test]
    fn checks_profile_and_rejects_modified_image() -> io::Result<()> {
        let root = std::env::temp_dir().join(format!("ssal-check-{}", std::process::id()));
        fs::create_dir_all(root.join("guests/profile1"))?;
        fs::create_dir_all(root.join("images/id-1"))?;
        let mut bytes = vec![0u8; 2048];
        bytes[1080..1082].copy_from_slice(&[0x53, 0xef]);
        let digest = Sha256::digest(&bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        fs::write(root.join("images/id-1/system.img"), &bytes)?;
        fs::create_dir(root.join("guests/profile1/userdata"))?;
        fs::write(
            root.join("images/id-1/manifest.json"),
            serde_json::to_vec(
                &serde_json::json!({"id":"id-1", "format":"raw-ext4", "size":2048, "sha256":digest}),
            )?,
        )?;
        fs::write(
            root.join("guests/profile1/profile.json"),
            serde_json::to_vec(
                &serde_json::json!({"version":2, "name":"profile1", "image_id":"id-1", "userdata":{"path":"userdata", "format":"directory"}}),
            )?,
        )?;
        assert!(check(&root, "profile1").is_ok());
        bytes[0] = 1;
        fs::write(root.join("images/id-1/system.img"), bytes)?;
        assert!(check(&root, "profile1")
            .unwrap_err()
            .to_string()
            .contains("SHA-256"));
        assert!(check(&root, "../profile1").is_err());
        fs::remove_dir_all(root)?;
        Ok(())
    }
}
