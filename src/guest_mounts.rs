//! Initial boot mount layout. No guest service is started by this module.
use serde::Deserialize;
use std::collections::VecDeque;
use std::ffi::CString;
use std::fs::{self, File};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};

const PROFILE: &str = include_str!("../module/profiles/mounts/initial.json");
pub const PROFILE_NAME: &str = "initial-shared-dev";

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
                ("dev", "host-rbind-private"),
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
    Ok(format!("mount profile: {} (built-in v{})\nrootfs: composed system RO, profile userdata RW, private mnt/storage/data_mirror\nruntime: tmp/cache RW tmpfs; metadata/config empty RO tmpfs; no host metadata/configfs\ndevices: shared host /dev, isolated socket/block paths; Binder/properties/cgroups/BPF shared\nAPEX: guest/vendor payload ext4 RO; guest linkerconfig required\nprepare requires chroot/pivot_root shell and profile write/read checks\nguest services, FUSE access control, VINTF and SELinux compatibility: not certified\n{services}", p.name, p.version))
}

fn cpath(path: &Path) -> io::Result<CString> {
    CString::new(path.as_os_str().as_bytes()).map_err(|_| io::Error::other("invalid mount path"))
}

fn mount(
    source: &Path,
    target: &Path,
    kind: Option<&str>,
    flags: libc::c_ulong,
    options: &str,
) -> io::Result<()> {
    let source = cpath(source)?;
    let target_c = cpath(target)?;
    let kind = kind
        .map(CString::new)
        .transpose()
        .map_err(io::Error::other)?;
    let options = CString::new(options).map_err(io::Error::other)?;
    if unsafe {
        libc::mount(
            source.as_ptr(),
            target_c.as_ptr(),
            kind.as_ref().map_or(std::ptr::null(), |k| k.as_ptr()),
            flags,
            options.as_ptr().cast(),
        )
    } != 0
    {
        return Err(io::Error::other(format!(
            "mount {}: {}",
            target.display(),
            io::Error::last_os_error()
        )));
    }
    Ok(())
}

struct Mounts {
    paths: Vec<PathBuf>,
    loops: Vec<File>,
}

impl Mounts {
    fn new() -> Self {
        Self {
            paths: Vec::new(),
            loops: Vec::new(),
        }
    }

    fn attach(
        &mut self,
        source: &Path,
        target: &Path,
        kind: Option<&str>,
        flags: libc::c_ulong,
        options: &str,
    ) -> io::Result<()> {
        mount(source, target, kind, flags, options)?;
        self.paths.push(target.to_owned());
        Ok(())
    }

    fn bind(
        &mut self,
        source: &Path,
        target: &Path,
        readonly: bool,
        recursive: bool,
    ) -> io::Result<()> {
        self.attach(
            source,
            target,
            None,
            libc::MS_BIND | if recursive { libc::MS_REC } else { 0 },
            "",
        )?;
        if recursive {
            // rbind creates child mounts too; each must be released before /dev.
            let info = fs::read_to_string("/proc/self/mountinfo")?;
            let mut children: Vec<PathBuf> = info
                .lines()
                .filter_map(|line| line.split_whitespace().nth(4))
                .map(PathBuf::from)
                .filter(|path| path != target && path.starts_with(target))
                .collect();
            children.sort_by_key(|path| path.components().count());
            self.paths.extend(children);
        }
        if readonly {
            mount(
                Path::new("none"),
                target,
                None,
                libc::MS_BIND
                    | libc::MS_REMOUNT
                    | libc::MS_RDONLY
                    | libc::MS_NOSUID
                    | libc::MS_NODEV,
                "",
            )?;
        }
        Ok(())
    }

    fn tmpfs(&mut self, target: &Path, mode: u32) -> io::Result<()> {
        self.attach(
            Path::new("tmpfs"),
            target,
            Some("tmpfs"),
            libc::MS_NOSUID | libc::MS_NODEV,
            &format!("mode={mode:o}"),
        )
    }

    fn cleanup(&mut self) -> io::Result<()> {
        let mut failures = Vec::new();
        while let Some(path) = self.paths.pop() {
            if unsafe { libc::umount2(cpath(&path)?.as_ptr(), 0) } != 0 {
                failures.push(format!(
                    "{}: {}",
                    path.display(),
                    io::Error::last_os_error()
                ));
            }
        }
        if failures.is_empty() {
            self.loops.clear();
            Ok(())
        } else {
            Err(io::Error::other(format!(
                "guest mount cleanup failed: {}",
                failures.join("; ")
            )))
        }
    }
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

// Resolve absolute Android symlinks against the guest root, not the worker's
// still-active host root. canonicalize(root.join(...)) would escape to the host.
pub(crate) fn guest_path(root: &Path, path: &str) -> io::Result<PathBuf> {
    if !relative(path) {
        return Err(io::Error::other("invalid guest path"));
    }
    let mut pending: VecDeque<_> = Path::new(path)
        .components()
        .map(|p| p.as_os_str().to_owned())
        .collect();
    let mut resolved = PathBuf::new();
    let mut links = 0;
    while let Some(part) = pending.pop_front() {
        if part == "." {
            continue;
        }
        if part == ".." {
            resolved.pop();
            continue;
        }
        let candidate = root.join(&resolved).join(&part);
        let meta = fs::symlink_metadata(&candidate)?;
        if meta.is_symlink() {
            links += 1;
            if links > 40 {
                return Err(io::Error::other("guest symlink loop"));
            }
            let link = fs::read_link(candidate)?;
            if link.is_absolute() {
                resolved.clear();
            }
            let parts: Vec<_> = link
                .components()
                .filter(|p| !matches!(p, Component::RootDir))
                .map(|p| p.as_os_str().to_owned())
                .collect();
            for part in parts.into_iter().rev() {
                pending.push_front(part);
            }
        } else {
            resolved.push(part);
        }
    }
    Ok(root.join(resolved))
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

fn linkerconfig_binary(root: &Path) -> io::Result<&'static str> {
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
    let guest_root = cpath(root)?;
    let mut command = Command::new(binary);
    command.args(["--target", "/linkerconfig"]);
    unsafe {
        command.pre_exec(move || {
            if libc::chroot(guest_root.as_ptr()) != 0 {
                return Err(io::Error::last_os_error());
            }
            std::env::set_current_dir("/")
        });
    }
    let output = command.env_clear().env("PATH", "/system/bin").output()
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
            mounts.bind(&source, &target, true, false)?;
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
                        mounts.bind(&source, &guest_path(root, &relative)?, true, false)?;
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
        mounts.bind(&source, &target, true, false)?;
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
                mounts.bind(&source, &target, true, false)?;
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

pub fn verify(
    system: &Path,
    userdata: &Path,
    base: &Path,
    loop_nodes: &crate::prepare::LoopNodes,
    mode: &str,
) -> io::Result<()> {
    let profile = profile()?;
    let root = base.join("rootfs");
    let cache = base.join("apex-cache");
    fs::create_dir(&root)?;
    let mut mounts = Mounts::new();
    let result = (|| {
        mounts.tmpfs(&root, 0o755)?;
        compose_system(&mut mounts, system, &root)?;
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
        // This intentionally shares devices, properties, Binder and cgroups.
        mounts.bind(Path::new("/dev"), &root.join("dev"), false, true)?;
        mount(
            Path::new("none"),
            &root.join("dev"),
            None,
            libc::MS_PRIVATE | libc::MS_REC,
            "",
        )?;
        // Never mkdir/chmod through the shared /dev tree.
        for path in &profile.tmpfs {
            if path.starts_with("dev/") {
                if !root.join(path).is_dir() {
                    return Err(io::Error::other(format!("host /{path} mountpoint missing")));
                }
            } else {
                directory(&root, path, 0o755)?;
            }
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
        let patch_dir = userdata
            .parent()
            .ok_or_else(|| io::Error::other("userdata parent missing"))?
            .join("patches");
        patches(&mut mounts, &profile, &patch_dir, &root, false)?;
        code_bridges(&mut mounts, &root, &patch_dir)?;
        println!("guest stage: APEX preparation");
        apex(&mut mounts, &root, &cache, loop_nodes)?;
        println!("guest stage: APEX patches");
        patches(&mut mounts, &profile, &patch_dir, &root, true)?;
        permission_controller(&mut mounts, &patch_dir, &root)?;
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
        same_directory(userdata, &root.join("data"))?;
        println!("mount profile: {}\nrootfs: {}\nmedia views: verified against guest /data/media\nshared /dev: Binder/properties/devices shared; sockets and block paths masked\nchroot/pivot_root dynamic shell and userdata write/read: verified\nAPEX activation, guest services, FUSE permissions, SELinux compatibility: NOT validated", profile.name, root.display());
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
    let cleanup = mounts.cleanup();
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
    let cleanup = cleanup.and(residual);
    if mode == "--selinux-probe-worker"
        || mode == "--servicemanager-preflight-worker"
        || mode == "--servicemanager-runtime-preflight-worker"
        || mode == "--enforcing-binder-worker"
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
        assert!(p.tmpfs.iter().any(|s| s == "mnt"));
        assert!(p.tmpfs.iter().any(|s| s == "dev/socket"));
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
