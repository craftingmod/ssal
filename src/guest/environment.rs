//! Shared environment resources, independent of Android service lifetime.
use crate::guest::init::Service;
use ssal::namespace_mounts::Mounts;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
const PROPERTY_SERVICE_CONTEXT: &[u8] = b"u:r:ssal_property:s0\0";

fn property_service_definitions(
    root: &Path,
    plan: Option<&ssal::guest_policy::Plan>,
    graphics_system_server: bool,
) -> Vec<ssal::guest_properties::ServiceDefinition> {
    let mut services = Vec::new();
    let has_bootanim_domain = plan.is_some_and(|p| p.types.contains_key("bootanim"));
    if graphics_system_server
        && has_bootanim_domain
        && root.join("system/bin/bootanimation").is_file()
    {
        services.push(ssal::guest_properties::ServiceDefinition {
            name: "bootanim".into(),
            executable: "/system/bin/bootanimation".into(),
            args: Vec::new(),
            interfaces: Vec::new(),
            uid: 1000,
            gid: 1000,
            domain: "bootanim".into(),
            oneshot: Some(true),
            restart_period: None,
            autostart: false,
        });
    }
    let has_adbd_domain = plan.is_some_and(|p| p.types.contains_key("adbd"));
    if has_adbd_domain && root.join("apex/com.android.adbd/bin/adbd").is_file() {
        let autostart = std::env::args_os().nth(1).as_deref()
            == Some(std::ffi::OsStr::new("--guest-start-worker"))
            && crate::guest::system_server_enabled()
            && !crate::guest::disabled("ADBD");
        services.push(ssal::guest_properties::ServiceDefinition {
            name: "adbd".into(),
            executable: "/apex/com.android.adbd/bin/adbd".into(),
            args: Vec::new(),
            interfaces: Vec::new(),
            uid: 0,
            gid: 0,
            domain: "adbd".into(),
            oneshot: Some(false),
            restart_period: Some(5),
            autostart,
        });
    }
    let has_mediaswcodec_domain = plan.is_some_and(|p| p.types.contains_key("mediaswcodec"));
    if has_mediaswcodec_domain
        && root
            .join("apex/com.android.media.swcodec/bin/mediaswcodec")
            .is_file()
    {
        services.push(ssal::guest_properties::ServiceDefinition {
            name: "mediaswcodec".into(),
            executable: "/apex/com.android.media.swcodec/bin/mediaswcodec".into(),
            args: Vec::new(),
            interfaces: vec![
                "android.hardware.media.c2@1.0::IComponentStore/software".into(),
                "android.hardware.media.c2@1.1::IComponentStore/software".into(),
                "android.hardware.media.c2@1.2::IComponentStore/software".into(),
                "aidl/android.hardware.media.c2.IComponentStore/software".into(),
            ],
            uid: 1046,
            gid: 1046,
            domain: "mediaswcodec".into(),
            oneshot: Some(false),
            restart_period: Some(5),
            autostart: false,
        });
    }
    services
}

pub(crate) fn start_property_service(
    mounts: &mut Mounts,
    root: &Path,
    bin: &Path,
    host_mount_namespace: &Path,
    initrc: bool,
) -> io::Result<Service> {
    crate::guest::mount::apex::verify_ready(mounts, root)?;
    // Reuse the established servicemanager view: libselinux rejects an RO root.
    // All control endpoints stay RO; only existing AV/context query files are RW.
    mounts.bind(
        Path::new("/sys/fs/selinux"),
        &root.join("sys/fs/selinux"),
        false,
        false,
    )?;
    for entry in fs::read_dir("/sys/fs/selinux")? {
        let entry = entry?;
        if ["access", "context", "create", "relabel", "member", "user"]
            .contains(&entry.file_name().to_str().unwrap_or(""))
        {
            continue;
        }
        mounts.bind(
            &entry.path(),
            &root.join("sys/fs/selinux").join(entry.file_name()),
            true,
            entry.file_type()?.is_dir(),
        )?;
    }
    let runtime = crate::guest::mount::directory(root, "run/ssal", 0o755)?;
    let contexts = runtime.join("guest_property_contexts");
    fs::write(
        &contexts,
        "persist.ssal_probe u:object_r:ssal_guest_property_area:s0 exact uint\n",
    )?;
    let overrides = runtime.join("guest_build.prop");
    let mut build_props = vec![
        "servicemanager.ready=false",
        // This worker starts only app_process64; ZygoteInit otherwise waits 60s for a secondary.
        "ro.product.cpu.abilist=arm64-v8a",
        "ro.product.cpu.abilist64=arm64-v8a",
        "ro.product.cpu.abilist32=",
        "ro.zygote=zygote64",
        "ro.build.version.codename=REL",
        "dalvik.vm.dex2oat64.enabled=true",
        "ro.zygote.disable_gl_preload=1",
        "service.adb.tcp.port=5555",
        "ro.adb.secure=0",
    ];
    if crate::guest::concurrent::graphics::requested() {
        build_props.extend([
            "ro.hardware.egl=adreno",
            "ro.board.platform=taro",
            "ro.sf.lcd_density=320",
            "ro.vndk.version=32",
            "ro.board.api_level=31",
            "ro.vendor.api_level=31",
            "vendor.gralloc.use_dma_buf_heaps=1",
        ]);
    }
    if crate::guest::launcher::graphics_system_server_requested() {
        // The worker mounts one system image and has no init cppreopt service.
        build_props.push("ro.cp_system_other_odex=0");
    }
    fs::write(&overrides, build_props.join("\n") + "\n")?;
    if !root.join("system/build.prop").is_file() {
        return Err(io::Error::other("Guest /system/build.prop missing"));
    }
    let identity = |path: &Path| -> io::Result<[u64; 2]> {
        let metadata = fs::metadata(path)?;
        Ok([metadata.dev(), metadata.ino()])
    };
    let host_property_identity = identity(Path::new("/dev/__properties__"))?;
    let host_socket_identity = identity(Path::new("/dev/socket"))?;
    let host_data_identity = identity(Path::new("/data"))?;
    let host_persistent_identity = identity(Path::new("/data/property"))?;
    let mut config = serde_json::json!({
        "host_mount_namespace": host_mount_namespace.display().to_string(),
        "session_owner_pid": std::process::id() as i32,
        "host_property_identity": host_property_identity,
        "host_socket_identity": host_socket_identity,
        "host_data_identity": host_data_identity,
        "host_persistent_identity": host_persistent_identity,
        "property_contexts": ["/run/ssal/guest_property_contexts"],
        "build_props": ["/system/build.prop", "/run/ssal/guest_build.prop"],
        "apex_ready": true,
    });
    if initrc {
        config["initrc"] = true.into();
    }
    let plan = ssal::guest_policy::runtime::load(root)?;
    if let Some(plan) = &plan {
        let mut paths = Vec::new();
        for (path, text) in &plan.contexts {
            if path.ends_with("property_contexts") {
                let name = format!("mapped_{}", path.replace('/', "_"));
                fs::write(runtime.join(&name), text)?;
                paths.push(format!("/run/ssal/{name}"));
            }
        }
        config["property_contexts"] = serde_json::to_value(paths)?;
        config["selinux_types"] = serde_json::to_value(&plan.types)?;
    }
    let services = property_service_definitions(
        root,
        plan.as_ref(),
        crate::guest::launcher::graphics_system_server_requested(),
    );
    if !services.is_empty() {
        config["services"] = serde_json::to_value(&services)?;
    }
    fs::write(
        runtime.join("property-service.json"),
        serde_json::to_vec(&config).map_err(io::Error::other)?,
    )?;

    let property_dir = crate::guest::mount::directory(root, "data/property", 0o700)?;
    let metadata = fs::metadata(&property_dir)?;
    if metadata.uid() != 0 || metadata.mode() & 0o077 != 0 {
        return Err(io::Error::other(
            "Guest /data/property must be root-owned mode 0700",
        ));
    }
    let area = crate::guest::mount::directory(root, "dev/__properties__", 0o755)?;
    if fs::read_dir(&area)?.next().is_some() {
        return Err(io::Error::other("Guest property area is not fresh"));
    }
    let executable = runtime.join("property-service");
    File::create(&executable)?;
    ssal::guest_policy::runtime::bind_file(
        mounts,
        root,
        &bin.join("ssal-property-service"),
        &executable,
    )?;
    let log = runtime.join("guest-property-service.log");
    File::create(&log)?;
    let mut command = crate::guest::launcher::command(
        root,
        "/system/bin/bootstrap/linker64",
        0,
        Some(PROPERTY_SERVICE_CONTEXT),
    )?;
    command
        .args([
            "/run/ssal/property-service",
            "--config",
            "/run/ssal/property-service.json",
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    if plan.is_some() {
        command.env("LD_PRELOAD", "/run/ssal/ssal-context-map.so");
    }
    let mut service = Service::from_child(command.spawn()?, log);
    service.output.push(crate::diagnostics::zygote::Stream::new(
        service.child.stdout.take().unwrap(),
        File::options().append(true).open(&service.log)?,
    )?);
    service.output.push(
        crate::diagnostics::zygote::Stream::new(
            service.child.stderr.take().unwrap(),
            File::options().append(true).open(&service.log)?,
        )?
        .with_session_log(),
    );
    service.wait_text("guest_property_service_ready")?;
    let process_context = fs::read_to_string(format!("/proc/{}/attr/current", service.child.id()))?;
    let expected = plan
        .as_ref()
        .map(|p| p.context("init", true))
        .transpose()?
        .unwrap_or_else(|| "u:r:ssal_property:s0".into());
    if process_context.trim_matches('\0').trim() != expected {
        return Err(io::Error::other(format!(
            "Guest property service SID mismatch: {process_context:?}"
        )));
    }
    for (guest, host, name) in [
        (identity(&area)?, host_property_identity, "property area"),
        (
            identity(&root.join("dev/socket"))?,
            host_socket_identity,
            "socket directory",
        ),
        (
            identity(&root.join("data"))?,
            host_data_identity,
            "userdata",
        ),
        (
            identity(&property_dir)?,
            host_persistent_identity,
            "persistent directory",
        ),
    ] {
        if guest == host {
            return Err(io::Error::other(format!("Host {name} selected")));
        }
    }
    let socket_paths = [
        root.join("dev/socket/property_service"),
        root.join("dev/socket/property_service_for_system"),
    ];
    for socket_path in &socket_paths {
        if !fs::symlink_metadata(socket_path)?.file_type().is_socket() {
            return Err(io::Error::other(format!(
                "Guest property-service endpoint is not a Unix socket: {}",
                socket_path.display()
            )));
        }
    }
    if identity(&socket_paths[0])? == identity(Path::new("/dev/socket/property_service"))? {
        return Err(io::Error::other("Host property socket selected"));
    }
    match identity(Path::new("/dev/socket/property_service_for_system")) {
        Ok(host_system_socket) if identity(&socket_paths[1])? == host_system_socket => {
            return Err(io::Error::other("Host system property socket selected"));
        }
        Ok(_) => (),
        Err(error) if error.kind() == io::ErrorKind::NotFound => (),
        Err(error) => return Err(error),
    }
    println!("Guest property sockets type=unix");
    let mut socket_entries = fs::read_dir(root.join("dev/socket"))?
        .map(|entry| entry.map(|entry| entry.file_name().to_string_lossy().into_owned()))
        .collect::<io::Result<Vec<_>>>()?;
    socket_entries.sort();
    if socket_entries != ["property_service", "property_service_for_system"] {
        return Err(io::Error::other(format!(
            "unexpected Guest /dev/socket entries: {socket_entries:?}"
        )));
    }
    for (name, mode, gid) in [
        ("property_service", 0o666, 0),
        ("property_service_for_system", 0o660, 1000),
    ] {
        let metadata = fs::symlink_metadata(root.join("dev/socket").join(name))?;
        if !metadata.file_type().is_socket()
            || metadata.uid() != 0
            || metadata.gid() != gid
            || metadata.mode() & 0o777 != mode
        {
            return Err(io::Error::other(format!(
                "Guest {name} ownership/mode mismatch: uid={} gid={} mode={:o}",
                metadata.uid(),
                metadata.gid(),
                metadata.mode() & 0o777
            )));
        }
    }
    println!("Guest property socket isolation=PASS");
    println!(
        "PHASE7I_PROPERTY_SERVICE=PASS pid={} sid={expected} host_area={host_property_identity:?} guest_area={:?} host_data={host_data_identity:?} guest_data={:?}",
        service.child.id(),
        identity(&area)?,
        identity(&root.join("data"))?
    );
    Ok(service)
}

pub(crate) fn managed(mode: &str) -> bool {
    matches!(
        mode,
        "--shell-worker"
            | "--guest-child-worker"
            | "--guest-service-worker"
            | "--guest-hwbinder-worker"
            | "--guest-services-6a-worker"
            | "--guest-services-6b-worker"
            | "--guest-start-worker"
    )
}

fn lock_file(profile: &Path, name: &str, operation: i32) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(profile.join(name))?;
    flock(&file, operation)?;
    Ok(file)
}

fn flock(file: &File, operation: i32) -> io::Result<()> {
    loop {
        if unsafe { libc::flock(file.as_raw_fd(), operation) } == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

pub(crate) fn admission(profile: &Path) -> io::Result<File> {
    lock_file(profile, "environment.lock", libc::LOCK_EX)
}

#[derive(serde::Serialize, serde::Deserialize)]
struct Record {
    pid: u32,
    start: String,
    boot: String,
    root: PathBuf,
    mount: PathBuf,
    net: PathBuf,
    device: u64,
    inode: u64,
}

fn start_time(pid: u32) -> io::Result<String> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    stat.rsplit_once(") ")
        .and_then(|(_, fields)| fields.split_whitespace().nth(19))
        .map(str::to_owned)
        .ok_or_else(|| io::Error::other("invalid process stat"))
}

pub(crate) struct Published {
    profile: PathBuf,
    leases: File,
}

impl Published {
    pub(crate) fn new(profile: &Path, root: &Path, admission: Option<File>) -> io::Result<Self> {
        let _admission =
            admission.ok_or_else(|| io::Error::other("environment admission lock missing"))?;
        let leases = lock_file(profile, "environment.leases", libc::LOCK_EX | libc::LOCK_NB)?;
        // /proc is still the supervisor's Host proc mount, even in a child PID namespace.
        let pid = fs::read_link("/proc/self")?
            .to_string_lossy()
            .parse::<u32>()
            .map_err(io::Error::other)?;
        let metadata = fs::metadata(root)?;
        let record = Record {
            pid,
            start: start_time(pid)?,
            boot: fs::read_to_string("/proc/sys/kernel/random/boot_id")?,
            root: root.to_owned(),
            mount: fs::read_link("/proc/self/ns/mnt")?,
            net: fs::read_link("/proc/self/ns/net")?,
            device: metadata.dev(),
            inode: metadata.ino(),
        };
        let temp = profile.join("environment.json.tmp");
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temp)?;
        use std::io::Write;
        file.write_all(&serde_json::to_vec(&record)?)?;
        file.sync_all()?;
        fs::rename(temp, profile.join("environment.json"))?;
        // Readers acquire shared leases before entering the published namespaces.
        flock(&leases, libc::LOCK_UN)?;
        Ok(Self {
            profile: profile.to_owned(),
            leases,
        })
    }

    pub(crate) fn finish(self) -> io::Result<File> {
        let admission = admission(&self.profile)?;
        fs::remove_file(self.profile.join("environment.json"))?;
        // Stop new entrants, then retain mounts/properties until every Shell exits.
        flock(&self.leases, libc::LOCK_EX)?;
        Ok(admission)
    }
}

pub(crate) struct Attached {
    pub(crate) root: PathBuf,
    _lease: File,
    _owner: File,
    mount: File,
    net: File,
}

impl Attached {
    pub(crate) fn enter(&self) -> io::Result<()> {
        for (fd, flag) in [
            (&self.net, libc::CLONE_NEWNET),
            (&self.mount, libc::CLONE_NEWNS),
        ] {
            if unsafe { libc::setns(fd.as_raw_fd(), flag) } != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }
}

// Caller holds admission until a shared lease and all namespace FDs are pinned.
pub(crate) fn attach(profile: &Path) -> io::Result<Option<Attached>> {
    let record: Record = match fs::read(profile.join("environment.json")) {
        Ok(bytes) => serde_json::from_slice(&bytes)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if record.boot != fs::read_to_string("/proc/sys/kernel/random/boot_id")? {
        return Ok(None);
    }
    match start_time(record.pid) {
        Ok(start) if start == record.start => (),
        Ok(_) => return Ok(None),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    }
    let lease = lock_file(profile, "environment.leases", libc::LOCK_SH)?;
    let proc = PathBuf::from(format!("/proc/{}", record.pid));
    use std::os::fd::FromRawFd;
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, record.pid, 0) } as i32;
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let owner = unsafe { File::from_raw_fd(fd) };
    let mount = File::open(proc.join("ns/mnt"))?;
    let net = File::open(proc.join("ns/net"))?;
    let metadata = fs::metadata(&record.root)?;
    // root is not mounted in the caller's namespace: verify through the pinned owner.
    let root = proc
        .join("root")
        .join(record.root.strip_prefix("/").map_err(io::Error::other)?);
    let guest_metadata = fs::metadata(&root)?;
    let host_namespace = fs::read_link("/proc/1/ns/mnt")?;
    let mut owner_status = libc::pollfd {
        fd: owner.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    if start_time(record.pid)? != record.start
        || fs::read_link(proc.join("ns/mnt"))? != record.mount
        || fs::read_link(proc.join("ns/net"))? != record.net
        || record.mount == host_namespace
        || (guest_metadata.dev(), guest_metadata.ino()) != (record.device, record.inode)
        || !metadata.is_dir()
        || unsafe { libc::poll(&mut owner_status, 1, 0) } != 0
        || !record.root.starts_with(
            profile
                .parent()
                .and_then(Path::parent)
                .ok_or_else(|| io::Error::other("profile root missing"))?
                .join("mnt"),
        )
    {
        return Err(io::Error::other("Guest environment identity mismatch"));
    }
    Ok(Some(Attached {
        root: record.root,
        _lease: lease,
        _owner: owner,
        mount,
        net,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::Duration;

    #[test]
    fn environment_lives_until_last_shell_and_cleanup_holds_admission() -> io::Result<()> {
        let base = std::env::temp_dir().join(format!("ssal-environment-{}", std::process::id()));
        let profile = base.join("guests/one");
        let root = base.join("mnt/rootfs");
        fs::create_dir_all(&profile)?;
        fs::create_dir_all(&root)?;
        let published = Published::new(&profile, &root, Some(admission(&profile)?))?;
        let lease = lock_file(&profile, "environment.leases", libc::LOCK_SH)?;
        let (sent, received) = mpsc::channel();
        let waiter = std::thread::spawn(move || {
            let lock = published.finish().unwrap();
            sent.send(()).unwrap();
            lock
        });
        assert!(received.recv_timeout(Duration::from_millis(100)).is_err());
        drop(lease);
        received.recv_timeout(Duration::from_secs(2)).unwrap();
        let cleanup_lock = waiter.join().unwrap();
        assert!(!profile.join("environment.json").exists());
        assert!(lock_file(&profile, "environment.lock", libc::LOCK_EX | libc::LOCK_NB).is_err());
        drop(cleanup_lock);
        assert!(attach(&profile)?.is_none());
        fs::remove_dir_all(base)
    }

    #[test]
    fn stale_pid_and_host_namespace_are_never_attached() -> io::Result<()> {
        let base =
            std::env::temp_dir().join(format!("ssal-stale-environment-{}", std::process::id()));
        let profile = base.join("guests/one");
        let root = base.join("mnt/rootfs");
        fs::create_dir_all(&profile)?;
        fs::create_dir_all(&root)?;
        let published = Published::new(&profile, &root, Some(admission(&profile)?))?;
        // A live process in the Host namespace must fail closed.
        assert!(attach(&profile).is_err());
        let path = profile.join("environment.json");
        let mut record: Record = serde_json::from_slice(&fs::read(&path)?)?;
        record.start = "reused-pid".into();
        fs::write(&path, serde_json::to_vec(&record)?)?;
        assert!(attach(&profile)?.is_none());
        drop(published.finish()?);
        fs::remove_dir_all(base)
    }

    #[test]
    fn registers_bootanim_service_only_for_graphics_sessions_with_binary_and_domain() -> io::Result<()>
    {
        let base = std::env::temp_dir().join(format!("ssal-bootanim-svc-{}", std::process::id()));
        let bin_dir = base.join("system/bin");
        fs::create_dir_all(&bin_dir)?;
        let inputs = std::collections::BTreeMap::from([(
            "system/etc/selinux/plat_sepolicy.cil".into(),
            "(type zygote)".into(),
        )]);
        let mut plan = ssal::guest_policy::generate("p0001", &inputs)?;

        assert!(property_service_definitions(&base, Some(&plan), true).is_empty());

        fs::write(bin_dir.join("bootanimation"), b"stub")?;
        assert!(property_service_definitions(&base, Some(&plan), true).is_empty());

        plan.types.insert("bootanim".into(), "ssal_p0001_bootanim".into());
        assert!(property_service_definitions(&base, Some(&plan), false).is_empty());

        let defs = property_service_definitions(&base, Some(&plan), true);
        assert_eq!(defs.len(), 1);
        assert_eq!(defs[0].name, "bootanim");
        assert_eq!(defs[0].executable, "/system/bin/bootanimation");
        assert_eq!(defs[0].domain, "bootanim");
        assert_eq!(defs[0].uid, 1000);
        assert_eq!(defs[0].gid, 1000);
        assert_eq!(defs[0].oneshot, Some(true));

        fs::remove_dir_all(base)
    }

    #[test]
    fn registers_adbd_service_when_binary_and_domain_exist() -> io::Result<()> {
        let base = std::env::temp_dir().join(format!("ssal-adbd-svc-{}", std::process::id()));
        let bin_dir = base.join("apex/com.android.adbd/bin");
        fs::create_dir_all(&bin_dir)?;
        let inputs = std::collections::BTreeMap::from([(
            "system/etc/selinux/plat_sepolicy.cil".into(),
            "(type zygote)".into(),
        )]);
        let mut plan = ssal::guest_policy::generate("p0001", &inputs)?;

        assert!(property_service_definitions(&base, Some(&plan), false).is_empty());

        fs::write(bin_dir.join("adbd"), b"stub")?;
        assert!(property_service_definitions(&base, Some(&plan), false).is_empty());

        plan.types.insert("adbd".into(), "ssal_p0001_adbd".into());
        let defs = property_service_definitions(&base, Some(&plan), false);
        assert_eq!(defs.len(), 1);
        assert_eq!(defs[0].name, "adbd");
        assert_eq!(defs[0].executable, "/apex/com.android.adbd/bin/adbd");
        assert_eq!(defs[0].domain, "adbd");
        assert_eq!(defs[0].uid, 0);
        assert_eq!(defs[0].gid, 0);
        assert_eq!(defs[0].oneshot, Some(false));

        fs::remove_dir_all(base)
    }

    #[test]
    fn registers_mediaswcodec_service_with_c2_software_interfaces() -> io::Result<()> {
        let base = std::env::temp_dir().join(format!("ssal-swcodec-svc-{}", std::process::id()));
        let bin_dir = base.join("apex/com.android.media.swcodec/bin");
        fs::create_dir_all(&bin_dir)?;
        let inputs = std::collections::BTreeMap::from([(
            "system/etc/selinux/plat_sepolicy.cil".into(),
            "(type zygote)".into(),
        )]);
        let mut plan = ssal::guest_policy::generate("p0001", &inputs)?;

        assert!(property_service_definitions(&base, Some(&plan), false).is_empty());

        fs::write(bin_dir.join("mediaswcodec"), b"stub")?;
        assert!(property_service_definitions(&base, Some(&plan), false).is_empty());

        plan.types
            .insert("mediaswcodec".into(), "ssal_p0001_mediaswcodec".into());
        let defs = property_service_definitions(&base, Some(&plan), false);
        assert_eq!(defs.len(), 1);
        assert_eq!(defs[0].name, "mediaswcodec");
        assert_eq!(
            defs[0].executable,
            "/apex/com.android.media.swcodec/bin/mediaswcodec"
        );
        assert_eq!(defs[0].domain, "mediaswcodec");
        assert_eq!(defs[0].uid, 1046);
        assert_eq!(defs[0].gid, 1046);
        assert_eq!(defs[0].oneshot, Some(false));
        assert!(!defs[0].autostart);
        assert!(defs[0]
            .interfaces
            .iter()
            .any(|iface| iface == "android.hardware.media.c2@1.0::IComponentStore/software"));

        fs::remove_dir_all(base)
    }
}
