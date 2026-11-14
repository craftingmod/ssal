#[cfg(all(test, target_os = "android"))]
mod device_test;
mod persistent;
mod policy;
mod server;

use rsproperties::{PropertyInfoEntry, SystemProperties};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

const AREA: &str = "/dev/__properties__";
const SOCKET: &str = "/dev/socket/property_service";
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
    pub property_contexts: Vec<PathBuf>,
    pub build_props: Vec<PathBuf>,
    #[serde(default)]
    pub selinux_types: BTreeMap<String, String>,
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
}

impl Properties {
    fn check_write(
        &self,
        name: &str,
        value: &str,
        authorize: impl FnOnce(&str) -> io::Result<()>,
    ) -> io::Result<()> {
        let context = self.policy.validate(name, value)?;
        authorize(context)?;
        if name.starts_with("ro.") {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Guest read-only properties sealed",
            ));
        }
        Ok(())
    }

    fn set(&mut self, name: &str, value: &str) -> io::Result<()> {
        // Durability precedes publication. Any I/O/area failure terminates this session's server.
        if name.starts_with("persist.") || name.starts_with("next_boot.persist.") {
            self.store.commit(name, value)?;
        }
        self.area.set(name, value).map_err(io::Error::other)
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
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let context = std::ffi::CString::new(context).map_err(io::Error::other)?;
    if unsafe {
        libc::fsetxattr(
            file.as_raw_fd(),
            c"security.selinux".as_ptr(),
            context.as_ptr().cast(),
            context.as_bytes_with_nul().len(),
            0,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
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
        let (mut parsed, errors) =
            PropertyInfoEntry::parse_from_file(path, true).map_err(io::Error::other)?;
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
    check_isolation(&config)?;
    let mut policy = load_policy(&config.property_contexts)?;
    policy.default_context = config.context("default_prop", &policy.default_context, false)?;
    let seeds = load_seeds(&config.build_props, &policy)?;
    let store = persistent::Store::open(Path::new(PERSIST_DIRECTORY))?;
    let mapped_label = |path: &Path, original: &str| {
        let name = match original {
            DIRECTORY_CONTEXT => "properties_device",
            INFO_CONTEXT => "property_info",
            SERIAL_CONTEXT => "properties_serial",
            _ => return label(path, original),
        };
        label(path, &config.context(name, original, false)?)
    };
    let mut properties = initialize(policy, seeds, store, Path::new(AREA), mapped_label)?;
    properties.socket_context = config.context("property_socket", SOCKET_CONTEXT, false)?;
    server::serve(&mut properties)
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
        .open(&info_path)?;
    file.write_all(&info)?;
    drop(file);
    label(&info_path, INFO_CONTEXT)?;
    let mut area = SystemProperties::new_area(directory).map_err(io::Error::other)?;
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
        area.add(&name, &value).map_err(io::Error::other)?;
    }
    if !staged.is_empty() {
        store.apply_staged()?;
    }
    Ok(Properties {
        area,
        store,
        policy,
        socket_context: SOCKET_CONTEXT.into(),
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
        return Err(io::Error::last_os_error());
    }
    let config = serde_json::from_reader(File::open(&args[1])?).map_err(io::Error::other)?;
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
            entries: vec![PropertyInfoEntry::new(
                "persist.number".into(),
                "u:object_r:ssal_guest_property_area:s0".into(),
                "uint",
                true,
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
            persistent::Store::open(&data).unwrap(),
            &directory,
            |_, _| Ok(()),
        )
        .unwrap()
    }

    #[test]
    fn profile_contexts_do_not_fall_back_to_fixed_guest_types() {
        let mut config: Config = serde_json::from_value(serde_json::json!({
            "host_mount_namespace":"mnt:[1]", "host_property_identity":[1,1],
            "host_data_identity":[1,2], "host_persistent_identity":[1,3],
            "host_socket_identity":[1,4], "property_contexts":[], "build_props":[],
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
            property_contexts: vec![],
            build_props: vec![],
            selinux_types: BTreeMap::new(),
        };
        assert!(check_isolation(&config).is_err());
    }

    #[test]
    fn mmap_update_notification_restore_and_sealing() {
        let root = temp_dir("mmap");
        let mut properties = fixture(&root);
        rsproperties::try_init(rsproperties::PropertyConfig::with_properties_dir(
            root.join("area"),
        ))
        .unwrap();
        assert_eq!(rsproperties::get::<String>("persist.number").unwrap(), "1");
        let serial = rsproperties::system_properties().context_serial();
        let waiter = std::thread::spawn(move || {
            rsproperties::system_properties().wait(
                None,
                Some(serial),
                Some(&rsproperties::Timespec {
                    tv_sec: 2,
                    tv_nsec: 0,
                }),
            )
        });
        properties
            .check_write("persist.number", "2", |_| Ok(()))
            .unwrap();
        properties.set("persist.number", "2").unwrap();
        assert!(waiter.join().unwrap().is_some());
        assert_eq!(rsproperties::get::<String>("persist.number").unwrap(), "2");
        assert!(properties.check_write("ro.late", "x", |_| Ok(())).is_err());
        assert!(properties
            .check_write("persist.number", "bad", |_| Ok(()))
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
        assert_eq!(
            restored.area.get_with_result("persist.number").unwrap(),
            "4"
        );
        assert_eq!(restored.store.values["persist.number"], "4");
        assert!(!restored
            .store
            .values
            .contains_key("next_boot.persist.number"));
        drop(restored);
        fs::remove_dir_all(root).unwrap();
    }
}
