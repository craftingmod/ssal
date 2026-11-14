use sha2::{Digest, Sha256};
use ssal::namespace_mounts::parse_device_number;
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
    // Compatibility resources cannot authorize service execution or migrate data.
    ssal::guest_lock_compat::Config::from_profile(&profile)?.runtime_gate()?;
    if profile["version"] != 3 {
        return Err(io::Error::other(
            "unsupported userdata profile version; remove and recreate the profile (no migration)",
        ));
    }
    if profile["name"].as_str() != Some(name) || profile["userdata"]["path"] != "userdata.img" {
        return Err(io::Error::other("unsupported or invalid profile"));
    }
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
    let userdata = dir.join("userdata.img");
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
    let data_file = crate::userdata::open(&userdata)?;
    if profile["userdata"]["format"] != "raw-ext4"
        || profile["userdata"]["size"].as_u64() != Some(data_file.metadata()?.len())
    {
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
    let report = format!("profile: {name}\nimage: {id}\nimage SELinux context: {image_label}\nimage size and SHA-256: OK\nsystem ext4 magic: OK\nuserdata raw ext4 image: {}\nspace: {space}\nmount namespace: {}\nloop control: {}\ndevice: {device}\nvendor VINTF manifest: {}\nAndroid version, VINTF, HAL and service compatibility: not verified\n{}", userdata.display(), if namespace { "available" } else { "missing" }, if loop_control { "available" } else { "missing" }, if Path::new("/vendor/etc/vintf/manifest.xml").exists() { "present" } else { "not found at standard path" }, crate::guest_mounts::description()?);
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

pub fn worker(
    system: &Path,
    userdata: &Path,
    base: &Path,
    mode: &str,
    force_regen: bool,
) -> io::Result<()> {
    if force_regen && mode != "--prepare-worker" {
        return Err(io::Error::other("--regen is only supported by prepare"));
    }
    crate::selinux_probe::servicemanager::check_recovery()?;
    let host_mount_namespace = fs::read_link("/proc/self/ns/mnt")?;
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
    let guest_mount_namespace = fs::read_link("/proc/self/ns/mnt")?;
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
    let system_target = base.join("system");
    let mut loop_nodes = LoopNodes::new(base.join("loop-devices"))?;
    let data_target = base.join("data");
    let profile_dir = userdata
        .parent()
        .ok_or_else(|| io::Error::other("profile parent missing"))?;
    let data_file = crate::userdata::open(userdata)?;
    crate::userdata::lock(&data_file)?;
    crate::userdata::check_filesystem(userdata)?;
    let mut data_mounted = false;
    let mut system_mounted = false;
    let result = (|| {
        let (data_loop, data_dev) = loop_device(userdata, false, &loop_nodes)?;
        check_loop_read(&data_loop, &data_dev, userdata)?;
        mount_image(&data_dev, &data_target, false)
            .map_err(|e| io::Error::other(format!("userdata mount failed: {e}")))?;
        data_mounted = true;
        let target_meta = fs::metadata(&data_target)?;
        if target_meta.dev() != data_loop.metadata()?.rdev()
            || target_meta.dev() == fs::metadata("/data")?.dev()
        {
            return Err(io::Error::other("userdata filesystem identity mismatch"));
        }
        let probe = data_target.join(format!(".ssal-prepare-probe-{}", std::process::id()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&probe)?;
        let probe_result = (|| {
            file.write_all(b"ssal prepare probe")?;
            file.sync_all()?;
            if fs::read(&probe)? != b"ssal prepare probe" {
                return Err(io::Error::other("userdata write/read mismatch"));
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
            .find(|line| line.split_whitespace().nth(4) == data_target.to_str())
            .ok_or_else(|| io::Error::other("userdata mount missing from mountinfo"))?;
        if !data_line
            .split_once(" - ")
            .is_some_and(|(_, fs)| fs.starts_with("ext4 "))
            || !data_line.split_whitespace().nth(5).is_some_and(|options| {
                ["rw", "nosuid", "nodev"]
                    .iter()
                    .all(|required| options.split(',').any(|o| o == *required))
            })
        {
            return Err(io::Error::other(
                "userdata mount must be ext4 rw,nosuid,nodev",
            ));
        }
        println!("mount namespace: {}\nuserdata backing: {}\nuserdata ext4 write/read probe: OK\nuserdata mountinfo: {data_line}", fs::read_link("/proc/self/ns/mnt")?.display(), userdata.display());
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
        crate::guest_mounts::verify(
            &system_target,
            &data_target,
            profile_dir,
            base,
            &loop_nodes,
            mode,
            &host_mount_namespace,
            force_regen,
        )?;
        Ok(())
    })();
    let mut cleanup = Vec::new();
    if system_mounted && unsafe { libc::umount2(cpath(&system_target)?.as_ptr(), 0) } != 0 {
        cleanup.push(format!("system unmount: {}", io::Error::last_os_error()));
    }
    if data_mounted && unsafe { libc::umount2(cpath(&data_target)?.as_ptr(), 0) } != 0 {
        cleanup.push(format!("userdata unmount: {}", io::Error::last_os_error()));
    }
    if let Err(e) = loop_nodes.verify_released() {
        cleanup.push(e.to_string());
    }
    if let Err(e) = loop_nodes.cleanup() {
        cleanup.push(e.to_string());
    }
    if !cleanup.is_empty() {
        if mode == "--servicemanager-worker"
            || mode == "--guest-data-worker"
            || mode == "--guest-child-worker"
        {
            crate::selinux_probe::servicemanager::mark_recovery(
                &base.display().to_string(),
                &cleanup.join("; "),
            );
        }
        if mode == "--selinux-probe-worker"
            || mode == "--servicemanager-preflight-worker"
            || mode == "--servicemanager-runtime-preflight-worker"
            || mode == "--enforcing-binder-worker"
            || mode == "--servicemanager-worker"
            || mode == "--guest-data-worker"
            || mode == "--guest-child-worker"
        {
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
    if mode == "--selinux-probe-worker"
        || mode == "--servicemanager-preflight-worker"
        || mode == "--servicemanager-runtime-preflight-worker"
        || mode == "--enforcing-binder-worker"
        || mode == "--servicemanager-worker"
        || mode == "--guest-data-worker"
        || mode == "--guest-child-worker"
    {
        println!(
            "SELinux transition resource summary: {}",
            serde_json::json!({"cleanup": "passed", "scope": "system_userdata_mounts_and_loops"})
        );
    }
    if mode == "--guest-data-worker" {
        println!(
            "Phase 2 worker gate: {}",
            serde_json::json!({"phase2_complete":result.is_ok(),"outer_mounts_and_loops_released":true,"launch_enabled":false,"switch_enabled":false})
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
        let data_path = root.join("guests/profile1/userdata.img");
        fs::write(&data_path, &bytes)?;
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&data_path, fs::Permissions::from_mode(0o600))?;
        fs::write(
            root.join("images/id-1/manifest.json"),
            serde_json::to_vec(
                &serde_json::json!({"id":"id-1", "format":"raw-ext4", "size":2048, "sha256":digest}),
            )?,
        )?;
        fs::write(
            root.join("guests/profile1/profile.json"),
            serde_json::to_vec(
                &serde_json::json!({"version":3, "name":"profile1", "image_id":"id-1", "userdata":{"path":"userdata.img", "format":"raw-ext4", "size":2048}}),
            )?,
        )?;
        assert!(check(&root, "profile1").is_ok());
        let profile_path = root.join("guests/profile1/profile.json");
        let original = fs::read(&profile_path)?;
        let mut enabled: serde_json::Value = serde_json::from_slice(&original)?;
        enabled["guest_lock_compat"] = serde_json::json!({"enabled":true});
        fs::write(&profile_path, serde_json::to_vec(&enabled)?)?;
        assert!(check(&root, "profile1")
            .unwrap_err()
            .to_string()
            .contains("offline preparation only"));
        assert_eq!(fs::metadata(&data_path)?.len(), 2048);
        let mut legacy: serde_json::Value = serde_json::from_slice(&original)?;
        for version in [1, 2] {
            legacy["version"] = serde_json::json!(version);
            fs::write(&profile_path, serde_json::to_vec(&legacy)?)?;
            assert!(check(&root, "profile1")
                .unwrap_err()
                .to_string()
                .contains("no migration"));
        }
        fs::write(&profile_path, &original)?;
        let mut invalid: serde_json::Value = serde_json::from_slice(&original)?;
        invalid["userdata"]["size"] = serde_json::json!(4096);
        fs::write(&profile_path, serde_json::to_vec(&invalid)?)?;
        assert!(check(&root, "profile1").is_err());
        fs::write(&profile_path, original)?;
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
    #[test]
    #[ignore = "requires Linux CAP_SYS_ADMIN in a disposable container"]
    fn real_ext4_remount_preserves_data_and_releases_loops() -> io::Result<()> {
        use crate::userdata::{check_filesystem, create, detached, fresh, lock, open};
        use std::ffi::CString;
        use std::io::Write;
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
        let base = std::env::temp_dir().join(format!("ssal-ext4-remount-{}", std::process::id()));
        fs::create_dir(&base)?;
        let path = base.join("userdata.img");
        create(&path, 32 * 1024 * 1024)?;
        let file = open(&path)?;
        lock(&file)?;
        let target = base.join("data");
        fs::create_dir(&target)?;
        let mut nodes = LoopNodes::new(base.join("loop-devices"))?;
        for pass in 0..2 {
            check_filesystem(&path)?;
            let (device, source) = loop_device(&path, false, &nodes)?;
            mount_image(&source, &target, false)?;
            let result: io::Result<()> = (|| {
                assert!(detached(&path).is_err());
                assert!(check_filesystem(&path).is_err());
                assert_eq!(fs::metadata(&target)?.dev(), device.metadata()?.rdev());
                if pass == 0 {
                    assert!(fresh(&target)?);
                    let mut marker = File::create(target.join("persistent"))?;
                    marker.write_all(b"ssal ext4 persistence")?;
                    marker.sync_all()?;
                } else {
                    assert_eq!(
                        fs::read(target.join("persistent"))?,
                        b"ssal ext4 persistence"
                    );
                }
                Ok(())
            })();
            let name = CString::new(target.as_os_str().as_encoded_bytes())?;
            let unmounted = unsafe { libc::umount2(name.as_ptr(), 0) };
            drop(device);
            if unmounted != 0 {
                return Err(io::Error::last_os_error());
            }
            nodes.verify_released()?;
            result?;
        }
        check_filesystem(&path)?;
        nodes.cleanup()?;
        drop(file);
        fs::remove_dir_all(base)
    }
}
