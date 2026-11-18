mod control;
#[cfg(all(test, target_os = "android"))]
mod device_test;
mod persistent;
mod policy;
mod server;
mod services;
mod triggers;

pub use services::ServiceDefinition;

use rsproperties::{MatchKeyword, PropertyInfoEntry, SystemProperties};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

const AREA: &str = "/dev/__properties__";
const SOCKET: &str = "/dev/socket/property_service";
const SYSTEM_SOCKET: &str = "/dev/socket/property_service_for_system";
const PERSIST_DIRECTORY: &str = "/data/property";
const DIRECTORY_CONTEXT: &str = "u:object_r:ssal_guest_property_dir:s0";
const INFO_CONTEXT: &str = "u:object_r:ssal_guest_property_info:s0";
const SERIAL_CONTEXT: &str = "u:object_r:ssal_guest_property_serial:s0";
const SOCKET_CONTEXT: &str = "u:object_r:ssal_guest_property_socket:s0";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub host_mount_namespace: String,
    pub host_property_identity: [u64; 2],
    pub host_data_identity: [u64; 2],
    pub host_persistent_identity: [u64; 2],
    pub host_socket_identity: [u64; 2],
    pub session_owner_pid: i32,
    pub property_contexts: Vec<PathBuf>,
    pub build_props: Vec<PathBuf>,
    #[serde(default)]
    pub selinux_types: BTreeMap<String, String>,
    #[serde(default)]
    pub services: Vec<ServiceDefinition>,
    #[serde(default)]
    pub initrc: bool,
}

impl Config {
    fn context(&self, original: &str, fallback: &str, process: bool) -> io::Result<String> {
        if self.selinux_types.is_empty() {
            return Ok(fallback.into());
        }
        let name = self
            .selinux_types
            .get(original)
            .ok_or_else(|| io::Error::other(format!("missing property service type {original}")))?;
        if !name.starts_with("ssal_p")
            || name.len() > 255
            || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        {
            return Err(io::Error::other("invalid mapped property service type"));
        }
        Ok(format!(
            "u:{}:{name}:s0",
            if process { "r" } else { "object_r" }
        ))
    }
}

struct Properties {
    area: SystemProperties,
    store: persistent::Store,
    policy: policy::Policy,
    socket_context: String,
    initrc: Option<crate::guest_initrc::PropertyTriggers>,
}

impl Properties {
    fn check_write(
        &self,
        name: &str,
        value: &str,
        mut authorize: impl FnMut(&str) -> io::Result<server::PeerCredentials>,
    ) -> io::Result<server::PeerCredentials> {
        rsproperties::wire::validate_property_name(name)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        rsproperties::wire::validate_value_len(name, value)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        if let Some(action) = name.strip_prefix("ctl.") {
            services::validate_control(action, value)?;
            if matches!(action, "start" | "stop" | "restart") {
                let legacy = self.policy.resolve(&format!("ctl.{value}")).0.to_owned();
                if let Ok(peer) = authorize(&legacy) {
                    return Ok(peer);
                }
            }
            return authorize(self.policy.resolve(&format!("{name}${value}")).0);
        }
        if name.starts_with("init.svc.") {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Guest service state is owned by the control dispatcher",
            ));
        }
        let property_name = if let Some(actual) = name.strip_prefix("next_boot.") {
            if !actual.starts_with("persist.") {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "only persistent properties may be staged",
                ));
            }
            actual
        } else {
            name
        };
        if property_name == "selinux.restorecon_recursive" {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Guest restorecon control is disabled",
            ));
        }
        let (context, kind) = self.policy.resolve(property_name);
        let peer = authorize(context)?;
        if !policy::check_type(kind, value) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "property type mismatch",
            ));
        }
        if name.starts_with("ro.") && self.area.find(name).map_err(io::Error::other)?.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "Guest read-only property already set",
            ));
        }
        Ok(peer)
    }

    fn set(&mut self, name: &str, value: &str) -> io::Result<()> {
        // Durability precedes publication. Any I/O/area failure terminates this session's server.
        if name.starts_with("persist.") || name.starts_with("next_boot.persist.") {
            self.store.commit(name, value)?;
        }
        self.area.set(name, value).map_err(io::Error::other)?;
        if let Some(initrc) = &mut self.initrc {
            initrc.changed(name, value);
        }
        Ok(())
    }
}

fn identity(path: &Path) -> io::Result<[u64; 2]> {
    let m = fs::metadata(path)?;
    Ok([m.dev(), m.ino()])
}

fn check_isolation(config: &Config) -> io::Result<()> {
    let namespace = fs::read_link("/proc/thread-self/ns/mnt")?;
    if unsafe { libc::geteuid() } != 0
        || namespace.to_string_lossy() == config.host_mount_namespace
        || !config.host_mount_namespace.starts_with("mnt:[")
        || config.host_property_identity.contains(&0)
        || config.host_data_identity.contains(&0)
        || config.host_persistent_identity.contains(&0)
        || config.host_socket_identity.contains(&0)
        || config.session_owner_pid <= 1
        || unsafe { libc::getppid() } != config.session_owner_pid
        || identity(Path::new(AREA))? == config.host_property_identity
        || identity(Path::new("/data"))? == config.host_data_identity
        || identity(Path::new(PERSIST_DIRECTORY))? == config.host_persistent_identity
        || identity(Path::new("/dev/socket"))? == config.host_socket_identity
        || fs::read_to_string("/sys/fs/selinux/enforce")?.trim() != "1"
        || fs::read_to_string("/proc/self/attr/current")?.trim_matches(['\0', '\n'])
            != config.context("init", "u:r:ssal_property:s0", true)?
    {
        return Err(io::Error::other(
            "Guest property server identity/isolation gate failed",
        ));
    }
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(c"/dev/__properties__".as_ptr(), &mut stat) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if stat.f_type as u64 != libc::TMPFS_MAGIC as u64 {
        return Err(io::Error::other("Guest property area must be tmpfs"));
    }
    for path in [
        Path::new(AREA),
        Path::new("/dev/socket"),
        Path::new(PERSIST_DIRECTORY),
    ] {
        let m = fs::symlink_metadata(path)?;
        if !m.is_dir() || m.uid() != 0 || m.mode() & 0o022 != 0 {
            return Err(io::Error::other("unsafe Guest property directory"));
        }
    }
    if fs::read_dir(AREA)?.next().is_some() {
        return Err(io::Error::other(
            "Guest area must be fresh; restart the whole Guest session",
        ));
    }
    match fs::symlink_metadata("/dev/socket/property_service_for_system") {
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        _ => {
            return Err(io::Error::other(
                "Guest system property socket must be absent",
            ))
        }
    }
    Ok(())
}

fn label(path: &Path, context: &str) -> io::Result<()> {
    let target = std::ffi::CString::new(context).map_err(io::Error::other)?;
    let process_sid = fs::read_to_string("/proc/self/attr/current")
        .unwrap_or_else(|_| "unavailable".into())
        .trim_matches(['\0', '\n'])
        .to_owned();
    let path_identity = fs::symlink_metadata(path)
        .map(|m| {
            format!(
                "uid={} gid={} mode={:o}",
                m.uid(),
                m.gid(),
                m.mode() & 0o7777
            )
        })
        .unwrap_or_else(|e| format!("unavailable({e})"));
    let path_fs_type = std::ffi::CString::new(path.as_os_str().as_bytes())
        .ok()
        .and_then(|path| {
            let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
            (unsafe { libc::statfs(path.as_ptr(), &mut stat) } == 0)
                .then(|| format!("0x{:x}", stat.f_type as u64))
        })
        .unwrap_or_else(|| "unavailable".into());
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(file) => file,
        Err(error) => {
            eprintln!(
                "property_label syscall=open path={} {} fs_type={} process_sid={} target_sid={} error={error}",
                path.display(), path_identity, path_fs_type, process_sid, context
            );
            return Err(error);
        }
    };
    let metadata = file.metadata()?;
    let mut filesystem: libc::statfs = unsafe { std::mem::zeroed() };
    let fs_result = unsafe { libc::fstatfs(file.as_raw_fd(), &mut filesystem) };
    let fs_type = if fs_result == 0 {
        format!("0x{:x}", filesystem.f_type as u64)
    } else {
        format!("unavailable(errno={})", io::Error::last_os_error())
    };
    let identity = format!(
        "uid={} gid={} mode={:o} fs_type={}",
        metadata.uid(),
        metadata.gid(),
        metadata.mode() & 0o7777,
        fs_type
    );
    let mut actual = [0u8; 512];
    let size = unsafe {
        libc::fgetxattr(
            file.as_raw_fd(),
            c"security.selinux".as_ptr(),
            actual.as_mut_ptr().cast(),
            actual.len(),
        )
    };
    if size < 0 {
        let error = io::Error::last_os_error();
        eprintln!(
            "property_label syscall=fgetxattr path={} {identity} process_sid={} target_sid={} error={error}",
            path.display(), process_sid, context
        );
        return Err(error);
    }
    let actual_sid = String::from_utf8_lossy(
        actual[..size as usize]
            .strip_suffix(&[0])
            .unwrap_or(&actual[..size as usize]),
    )
    .into_owned();
    eprintln!(
        "property_label stage=before path={} {identity} process_sid={} actual_sid={} target_sid={}",
        path.display(),
        process_sid,
        actual_sid,
        context
    );
    if actual_sid == context {
        eprintln!(
            "property_label result=already_labeled fsetxattr=skipped path={} actual_sid={}",
            path.display(),
            actual_sid
        );
        return Ok(());
    }
    if unsafe {
        libc::fsetxattr(
            file.as_raw_fd(),
            c"security.selinux".as_ptr(),
            target.as_ptr().cast(),
            target.as_bytes().len() + 1,
            0,
        )
    } != 0
    {
        let error = io::Error::last_os_error();
        eprintln!(
            "property_label syscall=fsetxattr path={} {identity} process_sid={} actual_sid={} target_sid={} error={error}",
            path.display(), process_sid, actual_sid, context
        );
        return Err(error);
    }
    let size = unsafe {
        libc::fgetxattr(
            file.as_raw_fd(),
            c"security.selinux".as_ptr(),
            actual.as_mut_ptr().cast(),
            actual.len(),
        )
    };
    if size < 0 {
        let error = io::Error::last_os_error();
        eprintln!(
            "property_label syscall=fgetxattr_after_fsetxattr path={} {identity} process_sid={} previous_sid={} target_sid={} error={error}",
            path.display(), process_sid, actual_sid, context
        );
        return Err(error);
    }
    let actual_sid = actual[..size as usize]
        .strip_suffix(&[0])
        .unwrap_or(&actual[..size as usize]);
    if actual_sid != context.as_bytes() {
        eprintln!(
            "property_label result=label_mismatch path={} {identity} process_sid={} actual_sid={} target_sid={}",
            path.display(), process_sid, String::from_utf8_lossy(actual_sid), context
        );
        return Err(io::Error::other("Guest property label readback mismatch"));
    }
    eprintln!(
        "property_label result=verified path={} {identity} process_sid={} actual_sid={} target_sid={}",
        path.display(), process_sid, context, context
    );
    Ok(())
}

pub(super) fn label_file(file: &File, context: &str) -> io::Result<()> {
    let target = std::ffi::CString::new(context).map_err(io::Error::other)?;
    let mut actual = [0u8; 512];
    let size = unsafe {
        libc::fgetxattr(
            file.as_raw_fd(),
            c"security.selinux".as_ptr(),
            actual.as_mut_ptr().cast(),
            actual.len(),
        )
    };
    if size < 0 {
        return Err(io::Error::last_os_error());
    }
    if actual[..size as usize]
        .strip_suffix(&[0])
        .unwrap_or(&actual[..size as usize])
        == context.as_bytes()
    {
        return Ok(());
    }
    if unsafe {
        libc::fsetxattr(
            file.as_raw_fd(),
            c"security.selinux".as_ptr(),
            target.as_ptr().cast(),
            target.as_bytes_with_nul().len(),
            0,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    let size = unsafe {
        libc::fgetxattr(
            file.as_raw_fd(),
            c"security.selinux".as_ptr(),
            actual.as_mut_ptr().cast(),
            actual.len(),
        )
    };
    if size < 0 {
        return Err(io::Error::last_os_error());
    }
    if actual[..size as usize]
        .strip_suffix(&[0])
        .unwrap_or(&actual[..size as usize])
        != context.as_bytes()
    {
        return Err(io::Error::other("Guest property label readback mismatch"));
    }
    Ok(())
}

fn load_policy(paths: &[PathBuf]) -> io::Result<policy::Policy> {
    if paths.is_empty() {
        return Err(io::Error::other("Guest property contexts required"));
    }
    let mut entries = Vec::new();
    for path in paths {
        guest_input(path)?;
        let (mut parsed, errors) = PropertyInfoEntry::parse_from_file(path, MatchKeyword::Checked)
            .map_err(io::Error::other)?;
        if !errors.is_empty() {
            return Err(io::Error::other(format!(
                "invalid property contexts: {}",
                path.display()
            )));
        }
        entries.append(&mut parsed);
    }
    Ok(policy::Policy {
        entries,
        default_context: "u:object_r:ssal_guest_property_area:s0".into(),
    })
}

fn guest_input(path: &Path) -> io::Result<()> {
    if !path.is_absolute()
        || !path.components().all(|c| {
            matches!(
                c,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        })
    {
        return Err(io::Error::other(
            "Guest input must be an absolute path without traversal",
        ));
    }
    let resolved = fs::canonicalize(path)?;
    if ![
        "/system",
        "/system_ext",
        "/product",
        "/vendor",
        "/odm",
        "/run/ssal",
    ]
    .iter()
    .any(|root| resolved.starts_with(root))
    {
        return Err(io::Error::other(
            "property input outside Guest partitions/config",
        ));
    }
    Ok(())
}

fn load_seeds(paths: &[PathBuf], policy: &policy::Policy) -> io::Result<BTreeMap<String, String>> {
    if paths.is_empty() {
        return Err(io::Error::other("Guest build properties required"));
    }
    let mut seeds = BTreeMap::new();
    for path in paths {
        guest_input(path)?;
        for line in fs::read_to_string(path)?.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            // shortcut: explicit ordered input files only; implement imports with the image boot rules.
            if line.starts_with("import ") {
                return Err(io::Error::other(
                    "property imports require explicit input expansion",
                ));
            }
            if let Some((name, value)) = line.split_once('=') {
                let (name, value) = (name.trim(), value.trim());
                if name.starts_with("ctl.") || name == "sys.powerctl" {
                    return Err(io::Error::other(
                        "service control properties are not build.prop values",
                    ));
                }
                policy.validate(name, value)?;
                seeds.insert(name.into(), value.into());
            } else {
                return Err(io::Error::other("invalid build property line"));
            }
        }
    }
    seeds.insert("ro.property_service.version".into(), "2".into());
    policy.validate("ro.property_service.version", "2")?;
    Ok(seeds)
}

pub fn serve(config: Config) -> io::Result<()> {
    check_isolation(&config)
        .map_err(|e| io::Error::new(e.kind(), format!("property isolation: {e}")))?;
    let mut policy = load_policy(&config.property_contexts)
        .map_err(|e| io::Error::new(e.kind(), format!("property contexts: {e}")))?;
    policy.default_context = config.context("default_prop", &policy.default_context, false)?;
    let seeds = load_seeds(&config.build_props, &policy)
        .map_err(|e| io::Error::new(e.kind(), format!("property seeds: {e}")))?;
    let persistent_context = config.context("property_data_file", DIRECTORY_CONTEXT, false)?;
    let store = persistent::Store::open(Path::new(PERSIST_DIRECTORY), Some(&persistent_context))
        .map_err(|e| io::Error::new(e.kind(), format!("property persistent store: {e}")))?;
    let mapped_label = |path: &Path, original: &str| {
        let context = match original {
            DIRECTORY_CONTEXT => config.context("properties_device", original, false)?,
            INFO_CONTEXT => config.context("property_info", original, false)?,
            SERIAL_CONTEXT => config.context("properties_serial", original, false)?,
            _ => original.into(),
        };
        label(path, &context).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("label {} as {context}: {e}", path.display()),
            )
        })
    };
    let mut properties = initialize(policy, seeds, store, Path::new(AREA), mapped_label)
        .map_err(|e| io::Error::new(e.kind(), format!("property area initialization: {e}")))?;
    properties.socket_context = config.context("property_socket", SOCKET_CONTEXT, false)?;
    let init_context = config.initrc
        .then(|| config.context("init", "u:r:ssal_property:s0", true))
        .transpose()?;
    let mut services = services::Registry::new(config.services, &config.selinux_types)?;
    services.publish(&mut properties)?;
    if init_context.is_some() {
        let mut values = crate::guest_initrc::Properties::new();
        properties.area.list(|name, value| {
            values.insert(name.to_owned(), value.to_owned());
        }).map_err(io::Error::other)?;
        let plan = crate::guest_initrc::Plan::load(Path::new("/"), &values)?;
        services.apply_restart_options(&plan);
        properties.initrc = Some(crate::guest_initrc::PropertyTriggers::new(plan, values));
    }
    server::serve(&mut properties, config.session_owner_pid, &mut services, init_context.as_deref())
        .map_err(|e| io::Error::new(e.kind(), format!("property socket server: {e}")))
}

fn initialize(
    policy: policy::Policy,
    mut seeds: BTreeMap<String, String>,
    mut store: persistent::Store,
    directory: &Path,
    label: impl Fn(&Path, &str) -> io::Result<()>,
) -> io::Result<Properties> {
    let staged: Vec<_> = store
        .values
        .iter()
        .filter_map(|(name, value)| {
            name.strip_prefix("next_boot.")
                .map(|n| (n.to_owned(), value.clone()))
        })
        .collect();
    for (name, value) in &store.values {
        if !name.starts_with("next_boot.") {
            policy.validate(name, value)?;
            seeds.insert(name.clone(), value.clone());
        }
    }
    for (name, value) in &staged {
        policy.validate(name, value)?;
        seeds.insert(name.clone(), value.clone());
    }
    label(directory, DIRECTORY_CONTEXT)?;
    let info = rsproperties::build_trie(&policy.entries, &policy.default_context, "string")
        .map_err(io::Error::other)?;
    let info_path = directory.join("property_info");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o444)
        .open(&info_path)
        .map_err(|e| io::Error::new(e.kind(), format!("create {}: {e}", info_path.display())))?;
    file.write_all(&info)
        .map_err(|e| io::Error::new(e.kind(), format!("write {}: {e}", info_path.display())))?;
    drop(file);
    label(&info_path, INFO_CONTEXT)?;
    let mut area = SystemProperties::new_area(directory).map_err(|e| {
        io::Error::other(format!("create property area {}: {e}", directory.display()))
    })?;
    label(&directory.join("properties_serial"), SERIAL_CONTEXT)?;
    for context in policy
        .entries
        .iter()
        .map(|e| e.context())
        .chain([policy.default_context.as_str()])
    {
        if !context.is_empty() {
            label(&directory.join(context), context)?;
        }
    }
    for (name, value) in seeds {
        area.add(&name, &value)
            .map_err(|e| io::Error::other(format!("seed property {name}: {e}")))?;
    }
    if !staged.is_empty() {
        store.apply_staged()?;
    }
    Ok(Properties {
        area,
        store,
        policy,
        socket_context: SOCKET_CONTEXT.into(),
        initrc: None,
    })
}

pub fn main() -> io::Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 2 || args[0] != "--config" {
        return Err(io::Error::other(
            "usage: ssal-property-service --config GUEST_CONFIG.json",
        ));
    }
    // This is a dedicated exec worker; inherited Host roots/property/socket FDs must not survive.
    if unsafe { libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 0u32) } != 0 {
        let e = io::Error::last_os_error();
        return Err(io::Error::new(
            e.kind(),
            format!("property inherited FD cleanup: {e}"),
        ));
    }
    let file = File::open(&args[1]).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("property config {}: {e}", Path::new(&args[1]).display()),
        )
    })?;
    let config = serde_json::from_reader(file).map_err(io::Error::other)?;
    serve(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    pub(super) fn temp_dir(name: &str) -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "ssal-properties-{name}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        path
    }

    pub(super) fn fixture(root: &Path) -> Properties {
        use std::os::unix::fs::PermissionsExt;
        let directory = root.join("area");
        fs::create_dir(&directory).unwrap();
        let data = root.join("property");
        if !data.exists() {
            fs::create_dir(&data).unwrap();
        }
        fs::set_permissions(&data, fs::Permissions::from_mode(0o700)).unwrap();
        let policy = policy::Policy {
            default_context: "u:object_r:ssal_guest_property_area:s0".into(),
            entries: vec![PropertyInfoEntry::exact(
                "persist.number",
                "u:object_r:ssal_guest_property_area:s0",
                "uint",
            )
            .unwrap()],
        };
        let seeds = BTreeMap::from([
            ("ro.property_service.version".into(), "2".into()),
            ("persist.number".into(), "1".into()),
        ]);
        initialize(
            policy,
            seeds,
            persistent::Store::open(&data, None).unwrap(),
            &directory,
            |_, _| Ok(()),
        )
        .unwrap()
    }

    fn test_peer() -> server::PeerCredentials {
        server::PeerCredentials {
            pid: 1,
            uid: 0,
            gid: 0,
        }
    }

    #[test]
    fn control_permissions_resolve_service_specific_legacy_and_action_targets() {
        let root = temp_dir("ctl-permissions");
        let mut properties = fixture(&root);
        properties.policy.entries.extend([
            PropertyInfoEntry::exact("ctl.mock", "legacy", "string").unwrap(),
            PropertyInfoEntry::exact("ctl.start$mock", "start_mock", "string").unwrap(),
        ]);
        let mut targets = Vec::new();
        properties
            .check_write("ctl.start", "mock", |target| {
                targets.push(target.to_owned());
                if target == "start_mock" {
                    Ok(test_peer())
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "denied SID",
                    ))
                }
            })
            .unwrap();
        assert_eq!(targets, ["legacy", "start_mock"]);
        targets.clear();
        properties
            .check_write("ctl.stop", "mock", |target| {
                targets.push(target.to_owned());
                Ok(test_peer())
            })
            .unwrap();
        assert_eq!(targets, ["legacy"]);
        assert!(properties
            .check_write("ctl.start", "mock", |_| Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "unauthorized SID"
            )))
            .is_err());
        assert!(properties
            .check_write("init.svc.mock", "running", |_| panic!(
                "state cannot be spoofed"
            ))
            .is_err());
        drop(properties);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn interface_permissions_only_use_original_action_and_interface() {
        let root = temp_dir("ctl-interface-permissions");
        let mut properties = fixture(&root);
        let interface = "aidl/dev.ssal.IMock/default";
        properties.policy.entries.push(
            PropertyInfoEntry::exact(&format!("ctl.{interface}"), "legacy", "string").unwrap(),
        );
        for action in ["start", "stop", "restart"] {
            let property = format!("ctl.interface_{action}");
            let context = format!("interface_{action}");
            properties.policy.entries.push(
                PropertyInfoEntry::exact(&format!("{property}${interface}"), &context, "string")
                    .unwrap(),
            );
            let mut targets = Vec::new();
            properties
                .check_write(&property, interface, |target| {
                    targets.push(target.to_owned());
                    assert_eq!(target, context);
                    Ok(test_peer())
                })
                .unwrap();
            assert_eq!(targets, [context]);
            let mut denied = Vec::new();
            assert!(properties
                .check_write(&property, interface, |target| {
                    denied.push(target.to_owned());
                    if target == "legacy" {
                        Ok(test_peer())
                    } else {
                        Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "denied SID",
                        ))
                    }
                })
                .is_err());
            assert_eq!(
                denied.len(),
                1,
                "interface controls must not try legacy permission"
            );
        }
        drop(properties);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn profile_contexts_do_not_fall_back_to_fixed_guest_types() {
        let mut config: Config = serde_json::from_value(serde_json::json!({
            "host_mount_namespace":"mnt:[1]", "host_property_identity":[1,1],
            "host_data_identity":[1,2], "host_persistent_identity":[1,3],
            "host_socket_identity":[1,4], "session_owner_pid":2,
            "property_contexts":[], "build_props":[],
            "selinux_types":{"init":"ssal_p0001_init", "default_prop":"ssal_p0001_default_prop"}
        }))
        .unwrap();
        assert_eq!(
            config.context("init", "old", true).unwrap(),
            "u:r:ssal_p0001_init:s0"
        );
        assert_eq!(
            config.context("default_prop", "old", false).unwrap(),
            "u:object_r:ssal_p0001_default_prop:s0"
        );
        assert!(config.context("missing", "old", false).is_err());
        config.selinux_types.insert("init".into(), "init".into());
        assert!(config.context("init", "old", true).is_err());
        config.selinux_types.clear();
        assert_eq!(config.context("init", "legacy", true).unwrap(), "legacy");
    }

    #[test]
    fn host_namespace_is_rejected_before_startup_io() {
        let config = Config {
            host_mount_namespace: fs::read_link("/proc/thread-self/ns/mnt")
                .unwrap()
                .to_string_lossy()
                .into(),
            host_property_identity: [1, 1],
            host_data_identity: [1, 2],
            host_persistent_identity: [1, 3],
            host_socket_identity: [1, 4],
            session_owner_pid: unsafe { libc::getppid() },
            property_contexts: vec![],
            build_props: vec![],
            selinux_types: BTreeMap::new(),
            services: vec![],
            initrc: false,
        };
        assert!(check_isolation(&config).is_err());
    }

    #[test]
    fn mmap_update_notification_restore_and_sealing() {
        let root = temp_dir("mmap");
        let mut properties = fixture(&root);
        rsproperties::init(rsproperties::PropertyConfig::new().properties_dir(root.join("area")))
            .unwrap();
        assert_eq!(rsproperties::get::<String>("persist.number").unwrap(), "1");
        let properties_reader = rsproperties::system_properties().unwrap();
        let index = properties_reader.find("persist.number").unwrap().unwrap();
        let serial = properties_reader.serial(index).unwrap();
        let waiter = std::thread::spawn(move || {
            rsproperties::system_properties().unwrap().wait_timeout(
                index,
                serial,
                std::time::Duration::from_secs(2),
            )
        });
        properties
            .check_write("persist.number", "2", |_| Ok(test_peer()))
            .unwrap();
        properties.set("persist.number", "2").unwrap();
        assert!(waiter.join().unwrap().unwrap().is_some());
        assert_eq!(rsproperties::get::<String>("persist.number").unwrap(), "2");
        properties
            .check_write("ro.late", "x", |_| Ok(test_peer()))
            .unwrap();
        properties.set("ro.late", "x").unwrap();
        assert!(properties
            .check_write("ro.late", "y", |_| Ok(test_peer()))
            .is_err());
        assert!(properties
            .check_write("persist.number", "bad", |_| Ok(test_peer()))
            .is_err());
        assert!(properties
            .check_write("persist.number", "3", |_| Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "denied"
            )))
            .is_err());
        assert_eq!(properties.store.values["persist.number"], "2");
        properties
            .store
            .commit("next_boot.persist.number", "4")
            .unwrap();
        drop(properties);
        fs::remove_dir_all(root.join("area")).unwrap();
        let restored = fixture(&root);
        assert_eq!(restored.area.get("persist.number").unwrap(), "4");
        assert_eq!(restored.store.values["persist.number"], "4");
        assert!(!restored
            .store
            .values
            .contains_key("next_boot.persist.number"));
        drop(restored);
        fs::remove_dir_all(root).unwrap();
    }
}
