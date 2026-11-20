use super::concurrent::mount_profile;
use sha2::{Digest, Sha256};
use ssal::unix::{image_context, valid_image_name, IMAGE_CONTEXT};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

const BOOT_BINARIES: &[&str] = &[
    "ssal-property-service",
    "ssal-apexservice",
    "ssal-system-suspend",
    "ssal-health",
    "ssal-gatekeeper",
    "ssal-keymint",
    "ssal-virtual-composer",
    "ssal-lmkd",
    "ssal-vold",
    "ssal-netd",
    "ssal-virtual-audio",
    "ssal-audio-host",
];

pub(crate) fn check_boot_binaries(bin: &Path) -> io::Result<()> {
    let unavailable: Vec<_> = BOOT_BINARIES
        .iter()
        .filter(|name| {
            fs::metadata(bin.join(name)).map_or(true, |meta| {
                !meta.is_file() || meta.mode() & 0o111 == 0
            })
        })
        .copied()
        .collect();
    if unavailable.is_empty() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "required Guest boot binaries missing or not executable in {}: {}; rebuild and reinstall the module",
            bin.display(),
            unavailable.join(", ")
        )))
    }
}

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
        .is_some_and(|value| value.as_str() != Some(mount_profile::PROFILE_NAME))
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
    let data_file = crate::guest::userdata::open(&userdata)?;
    if profile["userdata"]["format"] != "raw-ext4"
        || profile["userdata"]["size"].as_u64() != Some(data_file.metadata()?.len())
    {
        return Err(io::Error::other("userdata metadata mismatch"));
    }
    let loop_control =
        Path::new("/dev/loop-control").exists() || Path::new("/dev/block/loop-control").exists();
    let namespace = crate::guest::mount::namespace::available();
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
    let root_path = crate::guest::mount::loop_device::cpath(root)?;
    let mut stats: libc::statvfs = unsafe { std::mem::zeroed() };
    let space = if unsafe { libc::statvfs(root_path.as_ptr(), &mut stats) } == 0 {
        format!(
            "{} bytes available",
            stats.f_bavail as u128 * stats.f_frsize as u128
        )
    } else {
        "unavailable".into()
    };
    let report = format!("profile: {name}\nimage: {id}\nimage SELinux context: {image_label}\nimage size and SHA-256: OK\nsystem ext4 magic: OK\nuserdata raw ext4 image: {}\nspace: {space}\nmount namespace: {}\nloop control: {}\ndevice: {device}\nvendor VINTF manifest: {}\nAndroid version, VINTF, HAL and service compatibility: not verified\n{}", userdata.display(), if namespace { "available" } else { "missing" }, if loop_control { "available" } else { "missing" }, if Path::new("/vendor/etc/vintf/manifest.xml").exists() { "present" } else { "not found at standard path" }, mount_profile::description()?);
    Ok(CheckedProfile {
        system,
        userdata,
        report,
    })
}

pub fn worker(
    system: &Path,
    userdata: &Path,
    base: &Path,
    mode: &str,
    force_regen: bool,
) -> io::Result<()> {
    if mode == "--guest-start-worker" {
        crate::diagnostics::zygote::open_session_log(base)?;
    }
    let admission = if crate::guest::environment::managed(mode) {
        Some(crate::guest::environment::admission(
            userdata
                .parent()
                .ok_or_else(|| io::Error::other("profile parent missing"))?,
        )?)
    } else {
        None
    };
    worker_admitted(system, userdata, base, mode, force_regen, admission)
}

pub(crate) fn worker_admitted(
    system: &Path,
    userdata: &Path,
    base: &Path,
    mode: &str,
    force_regen: bool,
    mut admission: Option<File>,
) -> io::Result<()> {
    if force_regen && mode != "--prepare-worker" {
        return Err(io::Error::other("--regen is only supported by prepare"));
    }
    let installd_probe = crate::guest::launcher::installd_probe_requested();
    if installd_probe && mode != "--guest-start-worker" {
        return Err(io::Error::other("Guest installd probe requires the 7A worker"));
    }
    let _cgroup_lock = crate::guest::cgroup::layout::uses_guest_cgroups(mode)
        .then(crate::guest::cgroup::layout::lock_guest_cgroups)
        .transpose()?;
    crate::diagnostics::selinux::servicemanager::check_recovery()?;
    let host_mount_namespace = crate::guest::mount::namespace::enter()?;
    let system_target = base.join("system");
    let mut loop_nodes =
        crate::guest::mount::loop_device::LoopNodes::new(base.join("loop-devices"))?;
    let data_target = base.join("data");
    let profile_dir = userdata
        .parent()
        .ok_or_else(|| io::Error::other("profile parent missing"))?;
    let data_file = crate::guest::userdata::open(userdata)?;
    if installd_probe || mode == "--guest-hwbinder-worker" {
        let original = fs::metadata(profile_dir.join("userdata.img"))?;
        let copy = data_file.metadata()?;
        if !userdata.file_name().and_then(|name| name.to_str()).is_some_and(|name| {
            name.starts_with(".userdata-") && name.ends_with(".img")
        }) || (copy.dev(), copy.ino()) == (original.dev(), original.ino())
        {
            return Err(io::Error::other("Guest probe requires temporary userdata"));
        }
    }
    crate::guest::userdata::lock(&data_file)?;
    crate::guest::userdata::check_filesystem(userdata)?;
    let mut data_mounted = false;
    let mut system_mounted = false;
    let result = (|| {
        let (data_loop, data_dev) =
            crate::guest::mount::loop_device::loop_device(userdata, false, &loop_nodes)?;
        crate::guest::mount::loop_device::check_loop_read(&data_loop, &data_dev, userdata)?;
        crate::guest::mount::loop_device::mount_image(&data_dev, &data_target, false)
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
        println!(
            "mount namespace: {}\nuserdata backing: {}\nuserdata ext4 write/read probe: OK\nuserdata mountinfo: {data_line}",
            crate::guest::mount::namespace::current()?.display(),
            userdata.display()
        );
        let (system_loop, system_dev) =
            crate::guest::mount::loop_device::loop_device(system, true, &loop_nodes)?;
        crate::guest::mount::loop_device::check_loop_read(&system_loop, &system_dev, system)?;
        crate::guest::mount::loop_device::mount_image(&system_dev, &system_target, true)
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
            crate::guest::mount::namespace::current()?.display(),
            system.display(),
            userdata.display(),
            matches.join("\n")
        );
        crate::guest::mount::verify(
            &system_target,
            &data_target,
            profile_dir,
            base,
            &loop_nodes,
            mode,
            &host_mount_namespace,
            force_regen,
            &mut admission,
            &mount_profile::profile()?,
        )?;
        Ok(())
    })();
    let mut cleanup = Vec::new();
    if system_mounted
        && unsafe {
            libc::umount2(
                crate::guest::mount::loop_device::cpath(&system_target)?.as_ptr(),
                0,
            )
        } != 0
    {
        cleanup.push(format!("system unmount: {}", io::Error::last_os_error()));
    }
    if data_mounted
        && unsafe {
            libc::umount2(
                crate::guest::mount::loop_device::cpath(&data_target)?.as_ptr(),
                0,
            )
        } != 0
    {
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
            crate::diagnostics::selinux::servicemanager::mark_recovery(
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
    fn boot_binaries_require_executable_files() -> io::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let bin =
            std::env::temp_dir().join(format!("ssal-boot-binaries-{}", std::process::id()));
        fs::create_dir(&bin)?;
        let error = check_boot_binaries(&bin).unwrap_err().to_string();
        for name in BOOT_BINARIES {
            assert!(error.contains(name));
            fs::write(bin.join(name), b"test")?;
            fs::set_permissions(bin.join(name), fs::Permissions::from_mode(0o755))?;
        }
        check_boot_binaries(&bin)?;
        let lmkd = bin.join("ssal-lmkd");
        fs::set_permissions(&lmkd, fs::Permissions::from_mode(0o644))?;
        assert!(check_boot_binaries(&bin)
            .unwrap_err()
            .to_string()
            .contains("ssal-lmkd"));
        fs::remove_file(&lmkd)?;
        fs::create_dir(&lmkd)?;
        assert!(check_boot_binaries(&bin).is_err());
        fs::remove_dir_all(bin)
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
        use crate::guest::userdata::{check_filesystem, create, detached, fresh, lock, open};
        use std::ffi::CString;
        use std::io::Write;
        crate::guest::mount::namespace::enter()?;
        let base = std::env::temp_dir().join(format!("ssal-ext4-remount-{}", std::process::id()));
        fs::create_dir(&base)?;
        let path = base.join("userdata.img");
        create(&path, 32 * 1024 * 1024)?;
        let file = open(&path)?;
        lock(&file)?;
        let target = base.join("data");
        fs::create_dir(&target)?;
        let mut nodes =
            crate::guest::mount::loop_device::LoopNodes::new(base.join("loop-devices"))?;
        for pass in 0..2 {
            check_filesystem(&path)?;
            let (device, source) =
                crate::guest::mount::loop_device::loop_device(&path, false, &nodes)?;
            crate::guest::mount::loop_device::mount_image(&source, &target, false)?;
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
