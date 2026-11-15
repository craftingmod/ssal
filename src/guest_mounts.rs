//! Initial mount layout; service execution requires an explicit disposable probe mode.
use serde::Deserialize;
pub(crate) use ssal::namespace_mounts::guest_path;
#[cfg(test)]
use ssal::namespace_mounts::require_private_mounts;
use ssal::namespace_mounts::{inject_compat_file, mount, Mounts};
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{symlink, FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};

fn cpath(path: &Path) -> io::Result<CString> {
    CString::new(path.as_os_str().as_bytes()).map_err(|_| io::Error::other("invalid mount path"))
}

const PROFILE: &str = include_str!("../module/profiles/mounts/initial.json");
pub const PROFILE_NAME: &str = "initial-shared-dev";
const GUEST_DEVICE_NODES: [(&str, u32, u32); 4] = [
    ("null", 1, 3),
    ("zero", 1, 5),
    ("random", 1, 8),
    ("urandom", 1, 9),
];
const GUEST_DEV_ENTRIES: [&str; 7] = [
    "binderfs", "block", "null", "random", "socket", "urandom", "zero",
];

pub(crate) fn require_guest_exec_admission() -> io::Result<()> {
    Err(io::Error::other(
        "Automatic Guest launch is disabled; use the explicit disposable --guest-service-worker launcher",
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Profile {
    version: u32,
    name: String,
    core: std::collections::BTreeMap<String, String>,
    tmpfs: Vec<String>,
    runtime_tmpfs: Vec<RuntimeDirectory>,
    host_readonly: Vec<String>,
    host_runtime: Vec<RuntimeMount>,
    media_views: Vec<String>,
    patches: Vec<Patch>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeDirectory {
    path: String,
    mode: String,
    uid: u32,
    gid: u32,
    readonly: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeMount {
    path: String,
    readonly: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Patch {
    source: String,
    target: String,
}

fn relative(path: &str) -> bool {
    !path.is_empty()
        && Path::new(path)
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
}

fn profile() -> io::Result<Profile> {
    let profile: Profile = serde_json::from_str(PROFILE)?;
    if profile.version != 1
        || profile.name != PROFILE_NAME
        || profile.core
            != [
                ("system", "registered-image-ro"),
                ("data", "profile-userdata-rw"),
                ("dev", "guest-tmpfs-minimal"),
                ("proc", "fresh-proc"),
                ("sys", "fresh-sysfs-ro"),
                ("apex", "payload-ext4-ro"),
                ("linkerconfig", "guest-generated"),
            ]
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value.to_owned()))
            .collect()
        || profile
            .tmpfs
            .iter()
            .chain(&profile.host_readonly)
            .chain(&profile.media_views)
            .any(|path| !relative(path))
        || profile
            .patches
            .iter()
            .any(|p| !relative(&p.source) || !relative(&p.target))
        || profile.host_runtime.iter().any(|p| !relative(&p.path))
        || profile.runtime_tmpfs.iter().any(|p| {
            !relative(&p.path) || u32::from_str_radix(&p.mode, 8).map_or(true, |mode| mode > 0o7777)
        })
    {
        return Err(io::Error::other("invalid built-in mount profile"));
    }
    Ok(profile)
}

pub fn description() -> io::Result<String> {
    let p = profile()?;
    let services = crate::service_contract::blocked_summary()?;
    Ok(format!("mount profile: {} (built-in v{})\nrootfs: composed system RO, profile userdata RW, private mnt/storage/data_mirror\nruntime: tmp/cache RW tmpfs; metadata/config empty RO tmpfs; no host metadata/configfs\ndevices: fresh Guest /dev with null/zero/random/urandom; Guest child/cgroup workers additionally bind Guest-only cgroup subtrees; no Host Binder, properties, sockets, cgroup roots or BPF bind\nAutomatic Guest launch: BLOCKED; preparation restorecon/linkerconfig helpers permitted\nAPEX: guest/vendor payload ext4 RO; Guest linkerconfig generation required\nGuest property service, Android services, FUSE access control, VINTF and SELinux compatibility: not certified\n{services}", p.name, p.version))
}

// Reject symlinks at every directory component, including persistent userdata.
pub(crate) fn directory(root: &Path, relative_path: &str, mode: u32) -> io::Result<PathBuf> {
    if !relative(relative_path) {
        return Err(io::Error::other("invalid directory path"));
    }
    let mut path = root.to_owned();
    for part in Path::new(relative_path).components() {
        path.push(part.as_os_str());
        match fs::symlink_metadata(&path) {
            Ok(meta) if meta.is_dir() => (),
            Ok(_) => {
                return Err(io::Error::other(format!(
                    "not a real directory: {}",
                    path.display()
                )))
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                fs::create_dir(&path)?;
                fs::set_permissions(&path, fs::Permissions::from_mode(mode))?;
            }
            Err(e) => return Err(e),
        }
    }
    Ok(path)
}

fn owned_directory(root: &Path, path: &str, mode: u32, uid: u32, gid: u32) -> io::Result<()> {
    let path = directory(root, path, mode)?;
    if unsafe { libc::chown(cpath(&path)?.as_ptr(), uid, gid) } != 0 {
        return Err(io::Error::last_os_error());
    }
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}

fn same_directory(source: &Path, target: &Path) -> io::Result<()> {
    let a = fs::metadata(source)?;
    let b = fs::metadata(target)?;
    if (a.dev(), a.ino()) != (b.dev(), b.ino()) {
        return Err(io::Error::other(format!(
            "wrong backing directory: {}",
            target.display()
        )));
    }
    Ok(())
}

fn bind_guest_device(
    mounts: &mut Mounts,
    dev: &Path,
    name: &str,
    major: u32,
    minor: u32,
) -> io::Result<()> {
    let source = Path::new("/dev").join(name);
    let source_entry = fs::symlink_metadata(&source)?;
    if !source_entry.file_type().is_char_device()
        || source_entry.rdev() != libc::makedev(major, minor)
        || (
            source_entry.uid(),
            source_entry.gid(),
            source_entry.mode() & 0o7777,
        ) != (0, 0, 0o666)
    {
        return Err(io::Error::other(format!(
            "unsafe Host /dev/{name}: expected char {major}:{minor}, root:root 0666"
        )));
    }
    let source_file = File::open(&source)?;
    let source_mount = ssal::unix::fd_mount_id(&source_file)?;
    let target = dev.join(name);
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&target)?;
    mounts.bind(&source, &target, false, false)?;
    let guest_file = File::open(&target)?;
    let guest = guest_file.metadata()?;
    let host = source_file.metadata()?;
    let guest_mount = ssal::unix::fd_mount_id(&guest_file)?;
    if !guest.file_type().is_char_device()
        || (
            guest.dev(),
            guest.ino(),
            guest.rdev(),
            guest.uid(),
            guest.gid(),
            guest.mode() & 0o7777,
        ) != (
            host.dev(),
            host.ino(),
            host.rdev(),
            host.uid(),
            host.gid(),
            host.mode() & 0o7777,
        )
        || source_mount == guest_mount
    {
        return Err(io::Error::other(format!(
            "Guest /dev/{name} identity, permissions or bind-mount scope mismatch"
        )));
    }
    let label = ssal::unix::image_context(&guest_file)
        .unwrap_or_else(|error| format!("unavailable: {error}"));
    println!(
        "Guest device /dev/{name}: rdev={major}:{minor} uid={} gid={} mode={:o} label={label} host_mount={source_mount} guest_mount={guest_mount}",
        guest.uid(),
        guest.gid(),
        guest.mode() & 0o7777
    );
    Ok(())
}

fn prepare_guest_dev(mounts: &mut Mounts, root: &Path) -> io::Result<()> {
    let dev = root.join("dev");
    mounts.attach(
        Path::new("tmpfs"),
        &dev,
        Some("tmpfs"),
        libc::MS_NOSUID | libc::MS_NOEXEC,
        "mode=0755,size=4m",
    )?;
    for path in ["socket", "block", "binderfs"] {
        directory(&dev, path, 0o755)?;
    }
    for (name, major, minor) in GUEST_DEVICE_NODES {
        bind_guest_device(mounts, &dev, name, major, minor)?;
    }
    let actual: std::collections::BTreeSet<String> = fs::read_dir(&dev)?
        .map(|entry| entry.map(|entry| entry.file_name().to_string_lossy().into_owned()))
        .collect::<io::Result<_>>()?;
    let expected = GUEST_DEV_ENTRIES.into_iter().map(str::to_owned).collect();
    if actual != expected
        || fs::read_dir(dev.join("socket"))?.next().is_some()
        || dev.join("__properties__").exists()
        || dev.join("binder-control").exists()
        || dev.join("binderfs/binder-control").exists()
    {
        return Err(io::Error::other(
            "Guest /dev contains an unapproved entry or Host property endpoint",
        ));
    }
    println!("Guest /dev allowlist verified: null, zero, random, urandom; Host Binder/property/Binder-control/HAL nodes absent");
    Ok(())
}

fn compose_system(mounts: &mut Mounts, system: &Path, root: &Path) -> io::Result<()> {
    if !fs::symlink_metadata(system.join("system")).is_ok_and(|meta| meta.is_dir()) {
        let target = directory(root, "system", 0o755)?;
        mounts.bind(system, &target, true, false)?;
        return Ok(());
    }
    for entry in fs::read_dir(system)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            return Err(io::Error::other("non-UTF8 system root entry"));
        };
        if matches!(
            name_str,
            "data"
                | "dev"
                | "proc"
                | "sys"
                | "mnt"
                | "storage"
                | "data_mirror"
                | "apex"
                | "linkerconfig"
                | "run"
                | "vendor"
                | "odm"
                | "vendor_dlkm"
                | "postinstall"
                | "lost+found"
                | "tmp"
                | "cache"
                | "metadata"
                | "config"
                | ".ssal-old-root"
        ) {
            continue;
        }
        let target = root.join(&name);
        let kind = entry.file_type()?;
        if kind.is_symlink() {
            symlink(fs::read_link(entry.path())?, target)?;
        } else if kind.is_dir() {
            fs::create_dir(&target)?;
            mounts.bind(&entry.path(), &target, true, false)?;
        } else if kind.is_file() {
            File::create(&target)?;
            mounts.bind(&entry.path(), &target, true, false)?;
        }
    }
    Ok(())
}

fn prepare_lock_compat(
    mounts: &mut Mounts,
    root: &Path,
    userdata: &Path,
    profile_dir: &Path,
) -> io::Result<()> {
    let profile_path = profile_dir.join("profile.json");
    let profile: serde_json::Value = serde_json::from_slice(&fs::read(profile_path)?)?;
    let config = ssal::guest_lock_compat::Config::from_profile(&profile)?;
    // This stage is offline-only until the recorded runtime blockers are resolved.
    config.runtime_gate()?;
    let plan = config.plan(
        profile["guest_lock_compat_creation"]["version"] == 1,
        if config.enabled {
            crate::userdata::fresh(userdata)?
        } else {
            false
        },
    )?;
    for entry in plan {
        // Only the built-in XML is certified as a mount input at present. RRO
        // remains a separate blocked result, never silently skipped.
        let bytes = match entry.target {
            ssal::guest_lock_compat::XML_TARGET => ssal::guest_lock_compat::XML.as_bytes(),
            _ => {
                return Err(io::Error::other(
                    "Weaver RRO idmap/immutable activation not certified",
                ))
            }
        };
        inject_compat_file(mounts, root, &entry, bytes)?;
    }
    Ok(())
}

fn unzip(archive: &Path, member: &str, output: &Path) -> io::Result<()> {
    let mut command = if Path::new("/system/bin/unzip").is_file() {
        Command::new("/system/bin/unzip")
    } else if Path::new("/data/adb/ksu/bin/busybox").is_file() {
        let mut command = Command::new("/data/adb/ksu/bin/busybox");
        command.arg("unzip");
        command
    } else {
        Command::new("unzip")
    };
    let result = command
        .args(["-p"])
        .arg(archive)
        .arg(member)
        .stdout(Stdio::from(File::create(output).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("create extraction output {}: {e}", output.display()),
            )
        })?))
        .output()
        .map_err(|e| {
            io::Error::new(
                e.kind(),
                format!(
                    "execute APEX unzip {:?} for {} ({member}): {e}",
                    command.get_program(),
                    archive.display()
                ),
            )
        })?;
    if !result.status.success() {
        return Err(io::Error::other(format!(
            "APEX extraction {} ({member}): {}",
            archive.display(),
            String::from_utf8_lossy(&result.stderr)
        )));
    }
    Ok(())
}

fn varint(bytes: &mut &[u8]) -> io::Result<u64> {
    let mut value = 0;
    for shift in (0..70).step_by(7) {
        let byte = *bytes
            .first()
            .ok_or_else(|| io::Error::other("truncated protobuf varint"))?;
        *bytes = &bytes[1..];
        if shift == 63 && byte > 1 {
            return Err(io::Error::other("protobuf varint overflow"));
        }
        value |= u64::from(byte & 127) << shift;
        if byte & 128 == 0 {
            return Ok(value);
        }
    }
    Err(io::Error::other("invalid protobuf varint"))
}

// AOSP ApexManifest: name = field 1, version = field 2. Other fields are skipped.
fn apex_identity(mut bytes: &[u8]) -> io::Result<(String, u64)> {
    let mut name = None;
    let mut version = 0;
    while !bytes.is_empty() {
        let key = varint(&mut bytes)?;
        if key >> 3 == 0 {
            return Err(io::Error::other("invalid protobuf field"));
        }
        match key & 7 {
            0 => {
                let value = varint(&mut bytes)?;
                if key >> 3 == 2 {
                    version = value;
                }
            }
            1 | 5 => {
                let size = if key & 7 == 1 { 8 } else { 4 };
                bytes = bytes
                    .get(size..)
                    .ok_or_else(|| io::Error::other("truncated protobuf field"))?;
            }
            2 => {
                let size = usize::try_from(varint(&mut bytes)?).map_err(io::Error::other)?;
                let value = bytes
                    .get(..size)
                    .ok_or_else(|| io::Error::other("truncated protobuf string"))?;
                if key >> 3 == 1 {
                    name = Some(
                        std::str::from_utf8(value)
                            .map_err(io::Error::other)?
                            .to_owned(),
                    );
                }
                bytes = &bytes[size..];
            }
            _ => return Err(io::Error::other("unsupported protobuf wire type")),
        }
    }
    let name = name.ok_or_else(|| io::Error::other("APEX module name missing"))?;
    if name.is_empty()
        || matches!(name.as_str(), "." | "..")
        || !name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
        || version > i64::MAX as u64
    {
        return Err(io::Error::other("invalid APEX module identity"));
    }
    Ok((name, version))
}

fn apex(
    mounts: &mut Mounts,
    root: &Path,
    cache: &Path,
    loop_nodes: &crate::prepare::LoopNodes,
    policy: Option<&ssal::guest_policy::Plan>,
) -> io::Result<()> {
    fs::create_dir(cache)?;
    let mut packages = Vec::new();
    for source in [
        "system/apex",
        "system_ext/apex",
        "product/apex",
        "vendor/apex",
    ] {
        let path = match guest_path(root, source) {
            Ok(path) => path,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        };
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                continue;
            }
            let path = entry.path();
            if matches!(
                path.extension().and_then(|x| x.to_str()),
                Some("apex" | "capex")
            ) {
                packages.push(path);
            }
        }
    }
    packages.sort();
    if packages.is_empty() {
        return Err(io::Error::other("no guest APEX packages found"));
    }
    let mut metadata =
        String::from("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<apex-info-list>\n");
    let package_dir = directory(root, "apex/.packages", 0o755)?;
    for (index, package) in packages.iter().enumerate() {
        println!(
            "preparing APEX {}/{}: {}",
            index + 1,
            packages.len(),
            package.display()
        );
        (|| -> io::Result<()> {
        let payload = cache.join(format!("{index}.img"));
        let original = if package.extension().is_some_and(|x| x == "capex") {
            let original = cache.join(format!("{index}.apex"));
            unzip(package, "original_apex", &original)?;
            original
        } else {
            package.clone()
        };
        let manifest_file = cache.join(format!("{index}.pb"));
        unzip(&original, "apex_manifest.pb", &manifest_file)?;
        let (name, version) = apex_identity(&fs::read(&manifest_file)?)?;
        fs::remove_file(manifest_file)?;
        let destination = root.join("apex").join(&name);
        if destination.exists() {
            return Err(io::Error::other(format!("duplicate APEX module {name}")));
        }
        unzip(&original, "apex_payload.img", &payload)?;
        #[cfg(target_os = "android")]
        ssal::unix::label_image(&File::open(&payload)?)?;
        println!("APEX {name}: allocating loop for {}", payload.display());
        let (device, device_path) = crate::prepare::loop_device(&payload, true, loop_nodes)?;
        mounts.loops.push(device);
        let versioned = root.join("apex").join(format!("{name}@{version}"));
        fs::create_dir(&versioned)?;
        crate::prepare::mount_image(&device_path, &versioned, true)
            .map_err(|e| io::Error::new(e.kind(), format!("mount payload {} -> {}: {e}", device_path.display(), versioned.display())))?;
        mounts.paths.push(versioned.clone());
        let payload_manifest = versioned.join("apex_manifest.pb");
        let payload_identity = apex_identity(&fs::read(&payload_manifest)
            .map_err(|e| io::Error::new(e.kind(), format!("read payload manifest {}: {e}", payload_manifest.display())))?)?;
        if payload_identity != (name.clone(), version) {
            return Err(io::Error::other("APEX outer/payload manifest mismatch"));
        }
        if let Some(plan) = policy {
            ssal::guest_policy::runtime::isolate_tree(plan, mounts, &versioned,
                &root.parent().unwrap().join("selinux-overlay").join(format!("apex-{index}")))?;
        }
        fs::create_dir(&destination)?;
        mounts.bind(&versioned, &destination, true, false)?;
        let package_target = package_dir.join(format!("{index}.apex"));
        File::create(&package_target)?;
        mounts.bind(&original, &package_target, true, false)?;
        metadata.push_str(&format!("  <apex-info moduleName=\"{name}\" modulePath=\"/apex/.packages/{index}.apex\" preinstalledModulePath=\"/apex/.packages/{index}.apex\" versionCode=\"{version}\" versionName=\"\" isFactory=\"true\" isActive=\"true\" lastUpdateMillis=\"0\"/>\n"));
        if original != *package {
            fs::remove_file(original)?;
        }
        fs::remove_file(&payload)?;
        println!("guest APEX: {name} <- {} (ro)", package.display());
        Ok(())
        })().map_err(|e| io::Error::new(e.kind(), format!("APEX package {}: {e}", package.display())))?;
    }
    metadata.push_str("</apex-info-list>\n");
    fs::write(root.join("apex/apex-info-list.xml"), metadata)?;
    // Read-only module mounts remain executable. The parent tmpfs becomes RO too.
    mount(
        Path::new("tmpfs"),
        &root.join("apex"),
        None,
        libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV,
        "",
    )?;
    Ok(())
}

pub(crate) fn linkerconfig_binary(root: &Path) -> io::Result<&'static str> {
    for binary in [
        "/apex/com.android.runtime/bin/linkerconfig",
        "/system/bin/linkerconfig",
    ] {
        let path = match guest_path(root, binary.trim_start_matches('/')) {
            Ok(path) => path,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        };
        let metadata = fs::metadata(&path)?;
        if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
            return Err(io::Error::other(format!(
                "guest linkerconfig is not an executable file: {binary}"
            )));
        }
        return Ok(binary);
    }
    Err(io::Error::new(io::ErrorKind::NotFound, "guest linkerconfig not found in runtime APEX or /system/bin; verify guest runtime APEX and system image contents"))
}

fn linkerconfig(root: &Path) -> io::Result<()> {
    let binary = linkerconfig_binary(root)?;
    println!("guest linkerconfig executable: {binary}");
    // This fixed preparation helper does not admit automatic Android service launch.
    let mut command = crate::guest_probe::root_command(root, binary, false)?;
    command.args(["--target", "/linkerconfig"]);
    let output = command.output()
        .map_err(|e| io::Error::new(e.kind(), format!("execute {binary} inside {}: {e}; guest executable was found; check its ELF interpreter path and chroot setup", root.display())))?;
    if !output.status.success()
        || fs::metadata(root.join("linkerconfig/ld.config.txt"))
            .map_or(true, |meta| meta.len() == 0)
    {
        return Err(io::Error::other(format!(
            "guest linkerconfig failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(())
}

fn patches(
    mounts: &mut Mounts,
    profile: &Profile,
    source: &Path,
    root: &Path,
    apex_phase: bool,
) -> io::Result<()> {
    for patch in &profile.patches {
        if patch.target.starts_with("apex/") != apex_phase {
            continue;
        }
        let source = source.join(&patch.source);
        if source.exists() {
            let target = guest_path(root, &patch.target)?;
            if source.is_file() != target.is_file() || source.is_dir() != target.is_dir() {
                return Err(io::Error::other(format!(
                    "patch type mismatch: {}",
                    target.display()
                )));
            }
            ssal::guest_policy::runtime::bind_file(mounts, root, &source, &target)?;
            // Keep the versioned APEX view consistent with the active alias.
            if apex_phase {
                let parts: Vec<_> = patch.target.splitn(3, '/').collect();
                for entry in fs::read_dir(root.join("apex"))? {
                    let entry = entry?;
                    if entry
                        .file_name()
                        .to_string_lossy()
                        .starts_with(&format!("{}@", parts[1]))
                    {
                        let relative =
                            format!("apex/{}/{}", entry.file_name().to_string_lossy(), parts[2]);
                        ssal::guest_policy::runtime::bind_file(
                            mounts,
                            root,
                            &source,
                            &guest_path(root, &relative)?,
                        )?;
                    }
                }
            }
        }
    }
    Ok(())
}

fn permission_controller(mounts: &mut Mounts, patch_dir: &Path, root: &Path) -> io::Result<()> {
    let source = patch_dir.join("PermissionController_patched.apk");
    if !source.exists() {
        return Ok(());
    }
    let mut targets = Vec::new();
    for entry in fs::read_dir(root.join("apex"))? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name != "com.android.permission" && !name.starts_with("com.android.permission@") {
            continue;
        }
        let mut directories = vec![entry.path()];
        while let Some(path) = directories.pop() {
            for child in fs::read_dir(path)? {
                let child = child?;
                if child.file_type()?.is_dir() {
                    directories.push(child.path());
                } else if child.file_type()?.is_file()
                    && child.file_name() == "PermissionController.apk"
                {
                    targets.push(child.path());
                }
            }
        }
    }
    if targets.is_empty() {
        return Err(io::Error::other(
            "PermissionController patch supplied but no target APK found",
        ));
    }
    for target in targets {
        ssal::guest_policy::runtime::bind_file(mounts, root, &source, &target)?;
    }
    Ok(())
}

fn code_bridges(mounts: &mut Mounts, root: &Path, patch_dir: &Path) -> io::Result<()> {
    let code = directory(root, "run/ssal", 0o755)?;
    let daemon = std::env::current_exe()?;
    if let Some(module_bin) = daemon.parent() {
        for name in [
            "ssal",
            "ssald",
            "ssal-enforcing-binder",
            "ssal-binder-probe",
            "ssal-binder-probe.json",
        ] {
            let source = module_bin.join(name);
            if source.is_file() {
                let target = code.join(name);
                File::create(&target)?;
                ssal::guest_policy::runtime::bind_file(mounts, root, &source, &target)?;
            }
        }
    }
    // Opt-in only: an explicit guest bridge binary, never host /data/adb.
    let su = patch_dir.join("su");
    if su.is_file() {
        let xbin = guest_path(root, "system/xbin")?;
        if xbin != root.join("system/xbin") {
            return Err(io::Error::other(
                "su bridge requires a real /system/xbin directory",
            ));
        }
        mounts.tmpfs(&xbin, 0o755)?;
        let target = xbin.join("su");
        File::create(&target)?;
        mounts.bind(&su, &target, true, false)?;
    }
    Ok(())
}

pub(crate) const GUEST_RESOURCE_CGROUPS: [(&str, &str); 3] = [
    ("/dev/cpuctl/ssal_guest", "dev/cpuctl"),
    ("/dev/cpuset/ssal_guest", "dev/cpuset"),
    ("/dev/blkio/ssal_guest", "dev/blkio"),
];

pub(crate) fn guest_cgroup_mounts(
    backend: crate::memory_cgroup::Backend,
) -> Vec<(PathBuf, &'static str)> {
    let mut groups = vec![(crate::memory_cgroup::task_group(backend), "sys/fs/cgroup")];
    if backend == crate::memory_cgroup::Backend::V1 {
        groups.push((crate::memory_cgroup::memory_group(backend), "dev/memcg"));
    }
    groups.extend(
        GUEST_RESOURCE_CGROUPS
            .iter()
            .map(|(source, target)| (PathBuf::from(source), *target)),
    );
    groups
}

pub(crate) fn task_cgroup_path() -> io::Result<PathBuf> {
    Ok(crate::memory_cgroup::task_group(
        crate::memory_cgroup::backend()?,
    ))
}

#[derive(Default)]
struct GuestCgroups {
    created: Vec<PathBuf>,
    memory: Option<crate::memory_cgroup::GuestMemory>,
    preserve: bool,
}

impl GuestCgroups {
    fn create(&mut self, path: &Path) -> io::Result<()> {
        // Never adopt an existing subtree: it may belong to another session.
        fs::create_dir(path)?;
        self.created.push(path.to_owned());
        Ok(())
    }

    fn prepare(&mut self, mounts: &mut Mounts, root: &Path) -> io::Result<()> {
        ssal::namespace_mounts::require_private_mounts(&fs::read_to_string(
            "/proc/self/mountinfo",
        )?)?;
        let backend = self
            .memory
            .as_ref()
            .ok_or_else(|| io::Error::other("Guest memory cgroup was not prepared"))?
            .backend();
        for (source, target) in guest_cgroup_mounts(backend) {
            let parent = source.parent().unwrap();
            if fs::canonicalize(parent)? != parent {
                return Err(io::Error::other("cgroup parent contains a symlink"));
            }
            self.create(&source)?;
            let memory_group = match backend {
                crate::memory_cgroup::Backend::V2 => target == "sys/fs/cgroup",
                crate::memory_cgroup::Backend::V1 => target == "dev/memcg",
            };
            if memory_group {
                self.memory.as_ref().unwrap().configure_group(&source)?;
            }
            if target == "dev/cpuset" {
                for name in ["cpus", "mems"] {
                    let value = fs::read_to_string(parent.join(name))?;
                    if value.trim().is_empty() {
                        return Err(io::Error::other("empty parent cpuset configuration"));
                    }
                    fs::write(source.join(name), value)?;
                }
            }
            // sysfs is read-only; its existing cgroup mountpoint needs no mkdir.
            let target = if target == "sys/fs/cgroup" {
                guest_path(root, target)?
            } else {
                directory(root, target, 0o755)?
            };
            mounts.bind(&source, &target, false, false)?;
            same_directory(&source, &target)?;
            println!(
                "Guest cgroup bind: {} -> {}",
                source.display(),
                target.display()
            );
        }
        Ok(())
    }

    fn cleanup(&mut self) -> io::Result<()> {
        if self.preserve {
            return Err(io::Error::other(
                "unverified descendants; preserve Guest cgroups and controllers",
            ));
        }
        let mut errors = Vec::new();
        for path in std::mem::take(&mut self.created).into_iter().rev() {
            // rmdir only: occupied or unexpected child groups must remain visible as failures.
            if let Err(error) = fs::remove_dir(&path) {
                errors.push(format!("{}: {error}", path.display()));
                self.created.push(path);
            }
        }
        self.created.reverse();
        if errors.is_empty() {
            if let Some(memory) = &mut self.memory {
                if let Err(error) = memory.cleanup() {
                    errors.push(error.to_string());
                }
            }
        }
        if !errors.is_empty() {
            return Err(io::Error::other(errors.join("; ")));
        }
        Ok(())
    }
}

impl Drop for GuestCgroups {
    fn drop(&mut self) {
        if let Err(error) = self.cleanup() {
            eprintln!("Guest cgroup cleanup failed: {error}");
        }
    }
}

// Only rmdir descendants of a subtree this worker created, after all children were reaped.
fn remove_empty_cgroup_children(path: &Path) -> io::Result<()> {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        if entry.file_type()?.is_symlink() {
            return Err(io::Error::other("unexpected symlink in Guest cgroup"));
        }
        if entry.file_type()?.is_dir() {
            remove_empty_cgroup_children(&entry.path())?;
            fs::remove_dir(entry.path())?;
        }
    }
    Ok(())
}

fn memory_limit(value: Option<&str>) -> io::Result<Option<u64>> {
    crate::memory_cgroup::parse_limit(value)
}

fn guest_cgroup_probe(root: &Path) -> io::Result<()> {
    let poc = std::env::var("SSAL_GUEST_CHILD_POC")
        .map_err(|_| io::Error::other("SSAL_GUEST_CHILD_POC is required"))?;
    let inherited = ssal::unix::inherited_fds()?;
    let mut command = Command::new(poc);
    command
        .args(["--cgroup-mount-check"])
        .arg(root)
        .env_clear()
        .stdin(Stdio::null());
    unsafe {
        command.pre_exec(move || {
            ssal::unix::close_inherited_fds(&inherited, &[])?;
            ssal::unix::cloexec_unexpected_fds()
        });
    }
    if !command.status()?.success() {
        return Err(io::Error::other("Guest cgroup read-only diagnostic failed"));
    }
    Ok(())
}

fn processgroup_config(
    mut controllers: serde_json::Value,
    mut profiles: serde_json::Value,
) -> io::Result<(serde_json::Value, serde_json::Value)> {
    let invalid = || io::Error::other("unexpected Guest cgroup/task profile schema");
    let paths: std::collections::BTreeMap<_, _> = controllers["Cgroups"]
        .as_array()
        .ok_or_else(invalid)?
        .iter()
        .map(|entry| {
            (
                entry["Controller"].as_str().unwrap_or(""),
                entry["Path"].as_str().unwrap_or(""),
            )
        })
        .collect();
    if paths
        != [
            ("blkio", "/dev/blkio"),
            ("cpu", "/dev/cpuctl"),
            ("cpuset", "/dev/cpuset"),
        ]
        .into_iter()
        .collect()
        || controllers["Cgroups2"]["Path"] != "/sys/fs/cgroup"
    {
        return Err(invalid());
    }
    // No Host memory-controller delegation; preserve profile names as explicit no-ops.
    controllers["Cgroups2"]["Controllers"]
        .as_array_mut()
        .ok_or_else(invalid)?
        .retain(|entry| entry["Controller"] != "memory");
    let attributes = profiles["Attributes"].as_array_mut().ok_or_else(invalid)?;
    let memory: std::collections::BTreeSet<String> = attributes
        .iter()
        .filter(|entry| entry["Controller"] == "memory")
        .filter_map(|entry| entry["Name"].as_str().map(str::to_owned))
        .collect();
    attributes.retain(|entry| entry["Controller"] != "memory");
    for profile in profiles["Profiles"].as_array_mut().ok_or_else(invalid)? {
        profile["Actions"]
            .as_array_mut()
            .ok_or_else(invalid)?
            .retain(|action| {
                !(action["Name"] == "JoinCgroup" && action["Params"]["Controller"] == "memory"
                    || action["Name"] == "SetAttribute"
                        && memory.contains(action["Params"]["Name"].as_str().unwrap_or("")))
            });
    }
    // Reject traversal before creating any task-profile group.
    for action in profiles["Profiles"]
        .as_array()
        .ok_or_else(invalid)?
        .iter()
        .flat_map(|p| p["Actions"].as_array().into_iter().flatten())
    {
        if action["Name"] == "JoinCgroup" {
            let controller = action["Params"]["Controller"]
                .as_str()
                .ok_or_else(invalid)?;
            let path = action["Params"]["Path"].as_str().ok_or_else(invalid)?;
            if !matches!(controller, "cpu" | "cpuset" | "blkio")
                || (!path.is_empty() && !relative(path))
            {
                return Err(invalid());
            }
        }
    }
    Ok((controllers, profiles))
}

fn processgroup_probe(
    mounts: &mut Mounts,
    cgroups: &mut GuestCgroups,
    root: &Path,
) -> io::Result<()> {
    let helper = std::env::var("SSAL_PROCESSGROUP_PROBE")
        .map_err(|_| io::Error::other("SSAL_PROCESSGROUP_PROBE is required"))?;
    let (controllers, profiles) = processgroup_config(
        serde_json::from_slice(&fs::read(guest_path(root, "system/etc/cgroups.json")?)?)?,
        serde_json::from_slice(&fs::read(guest_path(
            root,
            "system/etc/task_profiles.json",
        )?)?)?,
    )?;
    let runtime = directory(root, "run/ssal/processgroup", 0o755)?;
    for (name, value) in [
        ("cgroups.json", &controllers),
        ("task_profiles.json", &profiles),
    ] {
        let source = runtime.join(name);
        fs::write(&source, serde_json::to_vec_pretty(value)?)?;
        mounts.bind(
            &source,
            &guest_path(root, &format!("system/etc/{name}"))?,
            true,
            false,
        )?;
    }
    let mut groups = std::collections::BTreeSet::new();
    for profile in profiles["Profiles"].as_array().unwrap() {
        for action in profile["Actions"].as_array().unwrap() {
            if action["Name"] == "JoinCgroup" {
                let controller = action["Params"]["Controller"].as_str().unwrap();
                let path = action["Params"]["Path"].as_str().unwrap();
                let source = GUEST_RESOURCE_CGROUPS
                    .iter()
                    .find(|(_, target)| {
                        *target
                            == match controller {
                                "cpu" => "dev/cpuctl",
                                "cpuset" => "dev/cpuset",
                                _ => "dev/blkio",
                            }
                    })
                    .unwrap()
                    .0;
                let mut group = PathBuf::from(source);
                for part in Path::new(path).components() {
                    group.push(part);
                    groups.insert(group.clone());
                }
            }
        }
    }
    for path in groups {
        cgroups.create(&path)?;
        if path.starts_with("/dev/cpuset/ssal_guest") {
            for name in ["cpus", "mems"] {
                fs::write(
                    path.join(name),
                    fs::read(path.parent().unwrap().join(name))?,
                )?;
            }
        }
    }
    for name in ["apps", "system"] {
        cgroups.create(&task_cgroup_path()?.join(name))?;
    }
    for path in &cgroups.created {
        for entry in [
            path.clone(),
            path.join("cgroup.procs"),
            path.join("tasks"),
            path.join("cgroup.threads"),
        ] {
            if entry.exists() {
                if unsafe { libc::chown(cpath(&entry)?.as_ptr(), 1000, 1000) } != 0 {
                    return Err(io::Error::last_os_error());
                }
                fs::set_permissions(
                    &entry,
                    fs::Permissions::from_mode(if entry == *path { 0o755 } else { 0o664 }),
                )?;
            }
        }
    }
    let target = runtime.join("probe");
    File::create(&target)?;
    mounts.bind(Path::new(&helper), &target, true, false)?;
    println!("Guest libprocessgroup config: original image JSON bound with memory actions disabled; Guest-only v1 groups initialized; vendor/property overrides absent; launcher uid/gid=1000");
    let mut command =
        crate::guest_launcher::command(root, "/system/bin/bootstrap/linker64", 1000, None)?;
    command
        .arg("/run/ssal/processgroup/probe")
        .env_clear()
        .env("LD_LIBRARY_PATH", "/system/lib64/bootstrap:/system/lib64")
        .stdin(Stdio::null());
    let status = command.status()?;
    if !status.success() {
        return Err(io::Error::other(format!(
            "Guest libprocessgroup helper: {status}"
        )));
    }
    Ok(())
}

pub fn verify(
    system: &Path,
    userdata: &Path,
    profile_dir: &Path,
    base: &Path,
    loop_nodes: &crate::prepare::LoopNodes,
    mode: &str,
    host_mount_namespace: &Path,
    force_regen: bool,
) -> io::Result<()> {
    let profile = profile()?;
    let root = base.join("rootfs");
    let cache = base.join("apex-cache");
    fs::create_dir(&root)?;
    let mut mounts = Mounts::new();
    let mut cgroups = GuestCgroups::default();
    let overlay_backing = userdata.join(format!(".ssal-overlay-{}", std::process::id()));
    let mut overlay_created = false;
    let mapped_launch = matches!(
        mode,
        "--guest-child-worker"
            | "--guest-service-worker"
            | "--guest-services-6a-worker"
            | "--guest-services-6b-worker"
            | "--guest-zygote-7a-worker"
    );
    let policy = if mode == "--prepare-worker"
        || (mapped_launch && profile_dir.join("selinux/plan.json").is_file())
    {
        Some(ssal::guest_policy::runtime::prepare_mounted(
            system,
            profile_dir,
            force_regen,
        )?)
    } else {
        None
    };
    if matches!(
        mode,
        "--guest-processgroup-worker"
            | "--guest-memory-worker"
            | "--guest-child-worker"
            | "--guest-service-worker"
            | "--guest-services-6a-worker"
            | "--guest-services-6b-worker"
            | "--guest-zygote-7a-worker"
    ) {
        crate::memory_cgroup::install_signal_handlers();
        crate::memory_cgroup::enable_subreaper()?;
    }
    let result = (|| {
        if mode == "--guest-data-worker" {
            crate::guest_data_probe::fresh(userdata)?;
        }
        mounts.tmpfs(&root, 0o755)?;
        compose_system(&mut mounts, system, &root)?;
        if let Some(plan) = &policy {
            fs::create_dir(&overlay_backing)?;
            overlay_created = true;
            fs::set_permissions(&overlay_backing, fs::Permissions::from_mode(0o700))?;
            ssal::guest_policy::runtime::isolate_system(
                plan,
                &mut mounts,
                &root,
                &overlay_backing,
            )?;
        }
        prepare_lock_compat(&mut mounts, &root, userdata, profile_dir)?;
        for name in ["product", "system_ext"] {
            if root.join(name).symlink_metadata().is_err()
                && guest_path(&root, &format!("system/{name}")).is_ok()
            {
                symlink(format!("/system/{name}"), root.join(name))?;
            }
        }
        for path in ["data", "dev", "proc", "sys", "vendor", "odm", "vendor_dlkm"] {
            directory(&root, path, 0o755)?;
        }
        mounts.bind(userdata, &root.join("data"), false, false)?;
        mount(
            Path::new("none"),
            &root.join("data"),
            None,
            libc::MS_BIND | libc::MS_REMOUNT | libc::MS_NOSUID | libc::MS_NODEV,
            "",
        )?;
        if overlay_created {
            // restorecon /data must not relabel the metadata backing the Guest system/APEX views.
            let hidden = root.join("data").join(overlay_backing.file_name().unwrap());
            mounts.tmpfs(&hidden, 0o000)?;
            if fs::read_dir(&hidden)?.next().is_some() {
                return Err(io::Error::other(
                    "Guest overlay backing is visible through /data",
                ));
            }
        }
        prepare_guest_dev(&mut mounts, &root)?;
        if let Some(plan) = &policy {
            let socket = root.join("dev/socket");
            let expected = plan.context("socket_device", false)?;
            ssal::guest_policy::runtime::set_label(&socket, &expected)
                .map_err(|error| io::Error::other(format!("label Guest /dev/socket: {error}")))?;
            let actual = ssal::unix::image_context(&File::open(&socket)?)?;
            if actual != expected {
                return Err(io::Error::other(format!(
                    "Guest /dev/socket label mismatch: expected {expected}, got {actual}"
                )));
            }
            println!("Guest /dev/socket label verified as {actual}");
        }
        for path in &profile.tmpfs {
            directory(&root, path, 0o755)?;
            mounts.tmpfs(&root.join(path), 0o755)?;
        }
        for entry in &profile.runtime_tmpfs {
            let mode = u32::from_str_radix(&entry.mode, 8).map_err(io::Error::other)?;
            let target = directory(&root, &entry.path, mode)?;
            mounts.tmpfs(&target, mode)?;
            owned_directory(&root, &entry.path, mode, entry.uid, entry.gid)?;
            if entry.readonly {
                mount(
                    Path::new("tmpfs"),
                    &target,
                    None,
                    libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV,
                    "",
                )?;
            }
        }
        mounts.attach(
            Path::new("proc"),
            &root.join("proc"),
            Some("proc"),
            libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
            "",
        )?;
        mounts.attach(
            Path::new("sysfs"),
            &root.join("sys"),
            Some("sysfs"),
            libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
            "",
        )?;
        if matches!(
            mode,
            "--guest-cgroup-worker"
                | "--guest-child-worker"
                | "--guest-processgroup-worker"
                | "--guest-memory-worker"
                | "--guest-service-worker"
                | "--guest-services-6a-worker"
                | "--guest-services-6b-worker"
                | "--guest-zygote-7a-worker"
        ) {
            if matches!(
                mode,
                "--guest-processgroup-worker"
                    | "--guest-cgroup-worker"
                    | "--guest-memory-worker"
                    | "--guest-child-worker"
                    | "--guest-service-worker"
                    | "--guest-services-6a-worker"
                    | "--guest-services-6b-worker"
                    | "--guest-zygote-7a-worker"
            ) {
                for key in ["SSAL_MEMORY_HIGH", "SSAL_MEMORY_MAX"] {
                    memory_limit(std::env::var(key).ok().as_deref())?;
                }
                cgroups.memory = Some(crate::memory_cgroup::GuestMemory::prepare()?);
            }
            cgroups.prepare(&mut mounts, &root)?;
        }
        if mode == "--guest-cgroup-worker" {
            return guest_cgroup_probe(&root);
        }
        if mode == "--guest-processgroup-worker" {
            return processgroup_probe(&mut mounts, &mut cgroups, &root);
        }
        for path in &profile.host_readonly {
            let source = Path::new("/").join(path);
            if source.is_dir() {
                mounts.bind(&source, &root.join(path), true, false)?;
            } else {
                println!("optional host mount absent: /{path}");
            }
        }
        for entry in &profile.host_runtime {
            let source = Path::new("/").join(&entry.path);
            if source.is_dir() {
                let target = guest_path(&root, &entry.path)?;
                mounts.bind(&source, &target, entry.readonly, false)?;
            }
        }
        if policy.is_some() {
            // Context validation is a kernel query; policy controls remain read-only.
            mounts.bind(
                Path::new("/sys/fs/selinux/context"),
                &guest_path(&root, "sys/fs/selinux/context")?,
                false,
                false,
            )?;
        }
        for (path, mode, uid, gid) in [
            ("mnt/user", 0o755, 0, 0),
            ("mnt/user/0", 0o755, 0, 0),
            ("mnt/user/0/self", 0o755, 0, 0),
            ("mnt/installer", 0o755, 0, 0),
            ("mnt/androidwritable", 0o755, 0, 0),
            ("mnt/pass_through", 0o700, 0, 0),
            ("mnt/pass_through/0", 0o710, 0, 1023),
            ("mnt/pass_through/0/self", 0o710, 0, 1023),
            ("mnt/pass_through/0/emulated", 0o710, 0, 1023),
            ("mnt/pass_through/0/emulated/0", 0o710, 0, 1023),
            ("mnt/appfuse", 0o711, 0, 0),
            ("mnt/media_rw", 0o750, 0, 1023),
            ("mnt/expand", 0o771, 1000, 1000),
            ("mnt/secure", 0o700, 0, 0),
            ("mnt/secure/asec", 0o700, 0, 0),
            ("mnt/asec", 0o755, 0, 1000),
            ("mnt/obb", 0o755, 0, 1000),
            ("mnt/runtime", 0o700, 0, 0),
        ] {
            owned_directory(&root, path, mode, uid, gid)?;
        }
        for view in ["default", "read", "write", "full"] {
            directory(&root, &format!("mnt/runtime/{view}/self"), 0o755)?;
            symlink(
                "/mnt/user/0/primary",
                root.join(format!("mnt/runtime/{view}/self/primary")),
            )?;
        }
        owned_directory(&root.join("data"), "media", 0o770, 1023, 1023)?;
        owned_directory(&root.join("data"), "media/0", 0o770, 1023, 1023)?;
        let media = root.join("data/media");
        for (source, target) in [
            ("user/0", "data/data"),
            ("user_de/0", "data_mirror/data_de/null/0"),
            ("user/0", "data_mirror/data_ce/null/0"),
            ("misc/profiles/cur", "data_mirror/cur_profiles"),
            ("misc/profiles/ref", "data_mirror/ref_profiles"),
        ] {
            let source = directory(&root.join("data"), source, 0o711)?;
            let target = directory(&root, target, 0o711)?;
            mounts.bind(&source, &target, false, false)?;
        }
        for target in &profile.media_views {
            let target = directory(&root, target, 0o755)?;
            mounts.bind(&media, &target, false, false)?;
            same_directory(&media, &target)?;
        }
        symlink("../emulated/0", root.join("mnt/user/0/self/primary"))?;
        symlink("emulated/0", root.join("mnt/user/0/primary"))?;
        symlink("/mnt/user/0/self", root.join("storage/self"))?;
        same_directory(
            &media.join("0"),
            &guest_path(&root, "storage/self/primary")?,
        )?;
        symlink("/storage/self/primary", root.join("mnt/sdcard"))?;
        if root.join("sdcard").symlink_metadata().is_err() {
            symlink("/storage/self/primary", root.join("sdcard"))?;
        }
        let patch_dir = profile_dir.join("patches");
        if let Some(plan) = &policy {
            ssal::guest_policy::runtime::install(plan, &mut mounts, &root)?;
        }
        patches(&mut mounts, &profile, &patch_dir, &root, false)?;
        code_bridges(&mut mounts, &root, &patch_dir)?;
        println!("guest stage: APEX preparation");
        apex(&mut mounts, &root, &cache, loop_nodes, policy.as_ref())?;
        println!("guest stage: APEX patches");
        patches(&mut mounts, &profile, &patch_dir, &root, true)?;
        permission_controller(&mut mounts, &patch_dir, &root)?;
        if let Some(plan) = &policy {
            let shell = guest_path(&root, "system/bin/sh")?;
            let shell_label = ssal::unix::image_context(&File::open(&shell)?)?;
            let expected = plan.context("system_data_file", false)?;
            let probe = root.join(format!(
                "data/.ssal-restorecon-probe-{}",
                std::process::id()
            ));
            let file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&probe)?;
            let result = (|| {
                let before = ssal::unix::image_context(&file)?;
                if before == expected {
                    return Err(io::Error::other(
                        "restorecon probe already has target label",
                    ));
                }
                let status =
                    crate::guest_probe::root_command(&root, "/system/bin/restorecon", false)?
                        .env("LD_PRELOAD", "/run/ssal/ssal-context-map.so")
                        .args(["-RF", "/data"])
                        .status()
                        .map_err(|e| io::Error::other(format!("execute Guest restorecon: {e}")))?;
                if !status.success() {
                    return Err(io::Error::other(
                        "restorecon Guest userdata using mapped file_contexts failed",
                    ));
                }
                let actual = ssal::unix::image_context(&file)?;
                if actual != expected {
                    return Err(io::Error::other(format!(
                        "Guest restorecon did not relabel userdata probe: expected {expected}, got {actual}"
                    )));
                }
                println!("Guest restorecon: actual userdata probe label changed from {before} to {actual}");
                Ok(())
            })();
            let cleanup = fs::remove_file(&probe);
            result?;
            cleanup?;
            if ssal::unix::image_context(&File::open(&shell)?)? != shell_label {
                return Err(io::Error::other(
                    "Guest restorecon changed the system overlay label",
                ));
            }
        }
        if mode == "--guest-memory-worker" {
            let helper = std::env::var_os("SSAL_PHASE7D_FIX_HELPER");
            if let Some(path) = &helper {
                cgroups.create(&task_cgroup_path()?.join("phase7d_fix"))?;
                let target = directory(&root, "run/ssal", 0o755)?.join("phase7d-fix-probe");
                File::create(&target)?;
                mounts.bind(Path::new(path), &target, true, false)?;
            }
            return crate::guest_launcher::memory_probe(&root, helper.is_some());
        }
        if matches!(
            mode,
            "--guest-child-worker"
                | "--guest-service-worker"
                | "--guest-services-6a-worker"
                | "--guest-services-6b-worker"
                | "--guest-zygote-7a-worker"
        ) {
            return crate::guest_launcher::verify(
                &mut mounts,
                &root,
                userdata,
                mode == "--guest-services-6a-worker" || mode == "--guest-services-6b-worker",
                mode == "--guest-services-6b-worker",
                mode == "--guest-zygote-7a-worker",
                host_mount_namespace,
            );
        }
        {
            println!("guest stage: linkerconfig generation");
            linkerconfig(&root)?;
            let probe = crate::guest_probe::verify(&root, userdata)?;
            crate::service_contract::report(&root, &probe)?;
            if mode == "--binder-probe-worker" {
                crate::binder_probe::verify(&root)?;
            }
            if mode == "--selinux-probe-worker" {
                crate::selinux_probe::verify(&root)?;
            }
            if mode == "--servicemanager-preflight-worker" {
                crate::selinux_probe::preflight::verify(&root)?;
            }
            if mode == "--servicemanager-runtime-preflight-worker" {
                crate::selinux_probe::runtime_preflight::verify(&root)?;
            }
            if mode == "--enforcing-binder-worker" {
                crate::selinux_probe::enforcing::verify(&root)?;
            }
            if mode == "--servicemanager-worker" {
                crate::selinux_probe::servicemanager::verify(&root)?;
            }
            if mode == "--guest-data-worker" {
                crate::selinux_probe::servicemanager::verify_phase2(&root, userdata)?;
            }
        }
        same_directory(userdata, &root.join("data"))?;
        println!("mount profile: {}\nrootfs: {}\nmedia views: verified against guest /data/media\nGuest /dev: isolated tmpfs; only checked pseudo-devices and opt-in Guest cgroup subtrees; Host Binder, property, Binder-control, HAL, cgroup roots and BPF paths absent\nGuest execution: {}\nAPEX activation, full Guest property service, Android services, FUSE permissions, SELinux compatibility: NOT validated", profile.name, root.display(), if mode == "--guest-child-worker" { "limited diagnostic child completed; Android services remain blocked" } else { "blocked pending Host proc/root, exec-FD and signal/ptrace boundary evidence" });
        let info = fs::read_to_string("/proc/self/mountinfo")?;
        for path in &mounts.paths {
            let line = info
                .lines()
                .find(|line| line.split_whitespace().nth(4) == path.to_str())
                .ok_or_else(|| {
                    io::Error::other(format!("mountinfo entry missing: {}", path.display()))
                })?;
            println!("guest mountinfo: {line}");
        }
        Ok(())
    })();
    let result = result.and_then(|()| crate::memory_cgroup::check_interrupted());
    let descendants = if cgroups.memory.is_some() {
        crate::memory_cgroup::cleanup_descendants()
    } else {
        Ok(())
    };
    let descendants = descendants.and_then(|()| {
        if mode == "--guest-zygote-7a-worker" && std::env::var_os("SSAL_PHASE7FB_FORK").is_some() {
            for path in &cgroups.created {
                remove_empty_cgroup_children(path)?;
            }
        }
        Ok(())
    });
    if descendants.is_err() {
        cgroups.preserve = true;
    }
    let cleanup = mounts.cleanup();
    let cgroup_cleanup = cgroups.cleanup();
    println!(
        "Guest cgroup cleanup: {}",
        if cgroup_cleanup.is_ok() {
            "passed"
        } else {
            "failed"
        }
    );
    let residual = fs::read_to_string("/proc/self/mountinfo").and_then(|info| {
        if info
            .lines()
            .filter_map(|line| line.split_whitespace().nth(4))
            .any(|path| Path::new(path).starts_with(&root))
        {
            Err(io::Error::other("guest rootfs mounts remain after cleanup"))
        } else {
            println!("worker rootfs residual mount check: verified absent");
            Ok(())
        }
    });
    let overlay_cleanup = if overlay_created && cleanup.is_ok() && residual.is_ok() {
        fs::remove_dir_all(&overlay_backing)
    } else {
        Ok(())
    };
    let cleanup = [
        descendants,
        cleanup,
        cgroup_cleanup,
        residual,
        overlay_cleanup,
    ]
    .into_iter()
    .filter_map(Result::err)
    .map(|error| error.to_string())
    .collect::<Vec<_>>();
    let cleanup = if cleanup.is_empty() {
        Ok(())
    } else {
        Err(io::Error::other(cleanup.join("; ")))
    };
    if mode == "--servicemanager-worker" || mode == "--guest-data-worker" {
        if let Err(error) = &cleanup {
            crate::selinux_probe::servicemanager::mark_recovery(
                &root.display().to_string(),
                &error.to_string(),
            );
        }
    }
    if mode == "--selinux-probe-worker"
        || mode == "--servicemanager-preflight-worker"
        || mode == "--servicemanager-runtime-preflight-worker"
        || mode == "--enforcing-binder-worker"
        || mode == "--servicemanager-worker"
        || mode == "--guest-data-worker"
    {
        println!(
            "SELinux transition resource summary: {}",
            serde_json::json!({
                "cleanup": if cleanup.is_ok() { "passed" } else { "failed" },
                "scope": "guest_rootfs_mounts", "error": cleanup.as_ref().err().map(ToString::to_string)
            })
        );
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
    fn optional_memory_limits_reject_invalid_values() {
        assert_eq!(memory_limit(None).unwrap(), None);
        assert_eq!(memory_limit(Some("104857600")).unwrap(), Some(104857600));
        for value in ["", "0", "max", "-1", "invalid", "18446744073709551616"] {
            assert!(memory_limit(Some(value)).is_err());
        }
    }

    #[test]
    fn processgroup_config_preserves_profiles_and_rejects_host_path_escape() -> io::Result<()> {
        use serde_json::json;
        let controllers = json!({"Cgroups":[
            {"Controller":"cpu","Path":"/dev/cpuctl"},
            {"Controller":"cpuset","Path":"/dev/cpuset"},
            {"Controller":"blkio","Path":"/dev/blkio"}],
            "Cgroups2":{"Path":"/sys/fs/cgroup","Controllers":[
                {"Controller":"freezer","Path":"."},
                {"Controller":"memory","Path":".","NeedsActivation":true}]}});
        let profiles = json!({"Attributes":[{"Name":"MemLimit","Controller":"memory"}],
            "Profiles":[{"Name":"memory-disabled","Actions":[
                {"Name":"SetAttribute","Params":{"Name":"MemLimit"}},
                {"Name":"JoinCgroup","Params":{"Controller":"memory","Path":"system"}}]},
                {"Name":"cpu-kept","Actions":[{"Name":"JoinCgroup","Params":{"Controller":"cpu","Path":"foreground"}}]}],
            "AggregateProfiles":[{"Name":"CPUSET_SP_FOREGROUND","Profiles":["cpu-kept"]}]});
        let (config, actual) = processgroup_config(controllers.clone(), profiles.clone())?;
        assert_eq!(config["Cgroups"], controllers["Cgroups"]);
        assert_eq!(
            config["Cgroups2"]["Controllers"].as_array().unwrap().len(),
            1
        );
        assert_eq!(actual["Profiles"][0]["Actions"], json!([]));
        assert_eq!(actual["Profiles"][1], profiles["Profiles"][1]);
        assert_eq!(actual["AggregateProfiles"], profiles["AggregateProfiles"]);
        for path in ["../host", "/host", "foreground/../../host"] {
            let mut bad = profiles.clone();
            bad["Profiles"][1]["Actions"][0]["Params"]["Path"] = json!(path);
            assert!(processgroup_config(controllers.clone(), bad).is_err());
        }
        let mut bad = controllers;
        bad["Cgroups"][0]["Path"] = json!("/sys/fs/cgroup/system");
        assert!(processgroup_config(bad, profiles).is_err());
        Ok(())
    }

    #[test]
    fn fork_cgroup_cleanup_uses_rmdir_and_rejects_symlinks() -> io::Result<()> {
        let root = std::env::temp_dir().join(format!("ssal-fork-cgroups-{}", std::process::id()));
        fs::create_dir_all(root.join("uid_10000/pid_42"))?;
        remove_empty_cgroup_children(&root)?;
        assert!(root.is_dir());
        assert!(!root.join("uid_10000").exists());
        fs::create_dir(root.join("occupied"))?;
        fs::write(root.join("occupied/sentinel"), "keep")?;
        assert!(remove_empty_cgroup_children(&root).is_err());
        assert_eq!(fs::read_to_string(root.join("occupied/sentinel"))?, "keep");
        fs::remove_file(root.join("occupied/sentinel"))?;
        fs::remove_dir(root.join("occupied"))?;
        symlink("/", root.join("unexpected"))?;
        assert!(remove_empty_cgroup_children(&root).is_err());
        fs::remove_file(root.join("unexpected"))?;
        fs::remove_dir(root)?;
        Ok(())
    }

    #[test]
    fn cgroup_cleanup_only_removes_owned_empty_directories() -> io::Result<()> {
        let root = std::env::temp_dir().join(format!("ssal-cgroups-{}", std::process::id()));
        fs::create_dir(&root)?;
        let existing = root.join("existing");
        fs::create_dir(&existing)?;
        let mut groups = GuestCgroups::default();
        assert_eq!(
            groups.create(&existing).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        let guest = root.join("ssal_guest");
        groups.create(&guest)?;
        let second = root.join("second_guest");
        groups.create(&second)?;
        fs::create_dir(guest.join("unexpected"))?;
        assert!(groups.cleanup().is_err());
        assert!(!second.exists());
        assert_eq!(groups.created, [guest.clone()]);
        assert!(guest.join("unexpected").is_dir());
        fs::remove_dir(guest.join("unexpected"))?;
        groups.cleanup()?;
        assert!(!guest.exists());
        assert!(existing.is_dir());
        assert!(groups.created.is_empty());
        fs::remove_dir(&existing)?;
        fs::remove_dir(root)
    }

    #[test]
    fn private_propagation_requires_complete_mountinfo() {
        let private = "1 0 0:1 / / rw - tmpfs tmpfs rw\n";
        assert!(require_private_mounts(private).is_ok());
        for input in [
            "",
            "invalid",
            "1 0 0:1 / / rw shared:1 - tmpfs tmpfs rw",
            "1 0 0:1 / / rw master:1 - tmpfs tmpfs rw",
            "1 0 0:1 / / rw unbindable - tmpfs tmpfs rw",
        ] {
            assert!(require_private_mounts(input).is_err());
        }
    }

    #[test]
    fn compat_collisions_abort_before_mount_and_preserve_originals() -> io::Result<()> {
        let root =
            std::env::temp_dir().join(format!("ssal-compat-collision-{}", std::process::id()));
        fs::create_dir(&root)?;
        let result = (|| -> io::Result<()> {
            let parent = directory(&root, "system/etc/sysconfig", 0o755)?;
            let target = parent.join("ssal-lockscreen.xml");
            let config = ssal::guest_lock_compat::Config {
                enabled: true,
                disable_weaver_on_unsecured_users: false,
                ..Default::default()
            };
            let plan = config.plan(true, true)?;
            let before = fs::read_to_string("/proc/self/mountinfo")?;
            let mut mounts = Mounts::new();
            for _ in 0..2 {
                fs::write(&target, b"original")?;
                let error =
                    inject_compat_file(&mut mounts, &root, &plan[0], b"replacement").unwrap_err();
                assert_eq!(error.to_string(), "compatibility target collision");
                assert_eq!(fs::read(&target)?, b"original");
                fs::remove_file(&target)?;
                symlink("missing", &target)?;
                let error =
                    inject_compat_file(&mut mounts, &root, &plan[0], b"replacement").unwrap_err();
                assert_eq!(error.to_string(), "compatibility target collision");
                fs::remove_file(&target)?;
            }
            assert!(mounts.paths.is_empty());
            mounts.cleanup()?;
            assert_eq!(before, fs::read_to_string("/proc/self/mountinfo")?);
            Ok(())
        })();
        fs::remove_dir_all(root)?;
        result
    }

    #[test]
    fn finds_runtime_linkerconfig_and_legacy_system_fallback() -> io::Result<()> {
        let root = std::env::temp_dir().join(format!("ssal-linkerconfig-{}", std::process::id()));
        fs::create_dir_all(root.join("system/bin"))?;
        fs::create_dir_all(root.join("apex/com.android.runtime/bin"))?;
        assert_eq!(
            linkerconfig_binary(&root).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        let legacy = root.join("system/bin/linkerconfig");
        fs::write(&legacy, b"fixture")?;
        fs::set_permissions(&legacy, fs::Permissions::from_mode(0o755))?;
        assert_eq!(linkerconfig_binary(&root)?, "/system/bin/linkerconfig");
        let runtime = root.join("apex/com.android.runtime/bin/linkerconfig");
        fs::write(&runtime, b"fixture")?;
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o755))?;
        assert_eq!(
            linkerconfig_binary(&root)?,
            "/apex/com.android.runtime/bin/linkerconfig"
        );
        fs::remove_file(&legacy)?;
        symlink("/apex/com.android.runtime/bin/linkerconfig", &legacy)?;
        assert_eq!(
            linkerconfig_binary(&root)?,
            "/apex/com.android.runtime/bin/linkerconfig"
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn profile_preserves_data_boundary() -> io::Result<()> {
        let p = profile()?;
        assert_eq!(p.media_views.len(), 4);
        assert_eq!(p.core["dev"], "guest-tmpfs-minimal");
        assert_eq!(
            GUEST_DEVICE_NODES,
            [
                ("null", 1, 3),
                ("zero", 1, 5),
                ("random", 1, 8),
                ("urandom", 1, 9)
            ]
        );
        assert!(p.tmpfs.iter().all(|path| !path.starts_with("dev/")));
        assert!(p
            .host_runtime
            .iter()
            .all(|entry| !matches!(entry.path.as_str(), "sys/fs/cgroup" | "sys/fs/bpf")));
        assert!(p.tmpfs.iter().any(|s| s == "mnt"));
        assert!(GUEST_DEV_ENTRIES.contains(&"socket"));
        assert!(GUEST_DEV_ENTRIES.contains(&"binderfs"));
        assert!(p
            .runtime_tmpfs
            .iter()
            .any(|entry| entry.path == "tmp" && entry.mode == "1777" && !entry.readonly));
        assert!(p
            .runtime_tmpfs
            .iter()
            .any(|entry| entry.path == "cache" && !entry.readonly));
        assert!(p
            .runtime_tmpfs
            .iter()
            .filter(|entry| matches!(entry.path.as_str(), "metadata" | "config"))
            .all(|entry| entry.readonly));
        assert!(p
            .host_readonly
            .iter()
            .all(|s| matches!(s.as_str(), "vendor" | "odm" | "vendor_dlkm")));
        assert!(!relative("../data"));
        assert!(!relative("/data"));
        Ok(())
    }

    #[test]
    fn automatic_launch_requires_explicit_disposable_worker() {
        let error = require_guest_exec_admission().unwrap_err();
        assert!(error.to_string().contains("--guest-service-worker"));
    }

    #[test]
    fn refuses_userdata_symlink_escape() -> io::Result<()> {
        let root = std::env::temp_dir().join(format!("ssal-mount-paths-{}", std::process::id()));
        fs::create_dir(&root)?;
        symlink("/tmp", root.join("media"))?;
        assert!(directory(&root, "media/0", 0o770).is_err());
        fs::remove_file(root.join("media"))?;
        fs::remove_dir(root)?;
        Ok(())
    }

    #[test]
    fn android_absolute_symlinks_stay_inside_guest() -> io::Result<()> {
        let root = std::env::temp_dir().join(format!("ssal-guest-links-{}", std::process::id()));
        fs::create_dir_all(root.join("system/product/apex"))?;
        fs::create_dir_all(root.join("mnt/user/0/emulated/0"))?;
        fs::create_dir_all(root.join("mnt/user/0/self"))?;
        fs::create_dir(root.join("storage"))?;
        symlink("/system/product", root.join("product"))?;
        symlink("/mnt/user/0/self", root.join("storage/self"))?;
        symlink("../emulated/0", root.join("mnt/user/0/self/primary"))?;
        assert_eq!(
            guest_path(&root, "product/apex")?,
            root.join("system/product/apex")
        );
        assert_eq!(
            guest_path(&root, "storage/self/primary")?,
            root.join("mnt/user/0/emulated/0")
        );
        symlink("/tmp", root.join("escape"))?;
        assert!(guest_path(&root, "escape").is_err());
        symlink("loop", root.join("loop"))?;
        assert!(guest_path(&root, "loop").is_err());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn apex_identity_uses_manifest_and_rejects_corruption() -> io::Result<()> {
        let mut manifest = vec![0x0a, 15];
        manifest.extend_from_slice(b"com.android.art");
        manifest.extend_from_slice(&[0x10, 0xac, 0x02, 0x2a, 1, b'v']);
        assert_eq!(apex_identity(&manifest)?, ("com.android.art".into(), 300));
        assert!(apex_identity(&[0x0a, 20, b'x']).is_err());
        assert!(apex_identity(&[0x10, 1]).is_err());
        assert!(apex_identity(&[0x0a, 2, b'.', b'.']).is_err());
        assert!(apex_identity(&[0x0a, 3, b'a', b'/', b'b']).is_err());
        let mut overflowing = [0xff; 10].as_slice();
        assert!(varint(&mut overflowing).is_err());
        Ok(())
    }

    #[test]
    #[ignore = "requires Linux CAP_SYS_ADMIN; run in a disposable privileged container"]
    fn real_mounts_preserve_host_and_cleanup_recursively() -> io::Result<()> {
        if unsafe { libc::unshare(libc::CLONE_NEWNS) } != 0 {
            return Err(io::Error::last_os_error());
        }
        mount(
            Path::new("none"),
            Path::new("/"),
            None,
            libc::MS_REC | libc::MS_PRIVATE,
            "",
        )?;
        let base = std::env::temp_dir().join(format!("ssal-real-mounts-{}", std::process::id()));
        let root = base.join("rootfs");
        let data = base.join("userdata");
        fs::create_dir_all(&root)?;
        fs::create_dir(&data)?;
        fs::create_dir(data.join("media"))?;
        fs::create_dir(data.join("media/0"))?;
        fs::write(data.join("media/0/guest-marker"), b"guest")?;
        let host_dev = fs::metadata("/dev")?;
        let mut mounts = Mounts::new();
        let result: io::Result<()> = (|| {
            mounts.tmpfs(&root, 0o755)?;
            directory(&root, "dev", 0o755)?;
            mounts.bind(Path::new("/dev"), &root.join("dev"), false, true)?;
            directory(&root, "data", 0o755)?;
            mounts.bind(&data, &root.join("data"), false, false)?;
            directory(&root, "mnt", 0o755)?;
            mounts.tmpfs(&root.join("mnt"), 0o755)?;
            directory(&root, "storage", 0o755)?;
            mounts.tmpfs(&root.join("storage"), 0o755)?;
            for view in &profile()?.media_views {
                let target = directory(&root, view, 0o755)?;
                mounts.bind(&root.join("data/media"), &target, false, false)?;
                same_directory(&data.join("media"), &target)?;
                assert_eq!(fs::read(target.join("0/guest-marker"))?, b"guest");
                assert!(!target.join("0/0").exists());
            }
            fs::write(root.join("mnt/user/0/emulated/0/new"), b"new")?;
            assert_eq!(fs::read(data.join("media/0/new"))?, b"new");
            let readonly = root.join("readonly");
            fs::create_dir(&readonly)?;
            mounts.bind(&data, &readonly, true, false)?;
            assert!(fs::write(readonly.join("blocked"), b"blocked").is_err());
            fs::write(data.join("source-still-writable"), b"ok")?;
            assert!(mounts
                .attach(
                    Path::new("/no-such-ssal-source"),
                    &readonly,
                    None,
                    libc::MS_BIND,
                    ""
                )
                .is_err());
            Ok(())
        })();
        let cleanup = mounts.cleanup();
        result?;
        cleanup?;
        assert_eq!(host_dev.ino(), fs::metadata("/dev")?.ino());
        assert!(!fs::read_to_string("/proc/self/mountinfo")?
            .lines()
            .any(|line| line
                .split_whitespace()
                .nth(4)
                .is_some_and(|p| Path::new(p).starts_with(&base))));
        fs::remove_dir_all(base)?;
        Ok(())
    }
}
