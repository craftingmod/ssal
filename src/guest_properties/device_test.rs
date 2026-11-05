//! Explicit Android ABI experiment. No production isolation/authorization bypass is exposed.
use super::*;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::process::Command;

fn mount(
    source: &std::ffi::CStr,
    target: &std::ffi::CStr,
    kind: Option<&std::ffi::CStr>,
    flags: libc::c_ulong,
) {
    assert_eq!(
        unsafe {
            libc::mount(
                source.as_ptr(),
                target.as_ptr(),
                kind.map_or(std::ptr::null(), |s| s.as_ptr()),
                flags,
                std::ptr::null(),
            )
        },
        0,
        "mount: {}",
        io::Error::last_os_error()
    );
}

fn initialize_area() -> Properties {
    let policy = policy::Policy {
        default_context: "u:object_r:build_prop:s0".into(),
        entries: vec![PropertyInfoEntry::new(
            "persist.ssal_probe".into(),
            "u:object_r:build_prop:s0".into(),
            "uint",
            true,
        )
        .unwrap()],
    };
    let seeds = BTreeMap::from([
        ("ro.property_service.version".into(), "2".into()),
        ("persist.ssal_probe".into(), "1".into()),
    ]);
    initialize(
        policy,
        seeds,
        persistent::Store::open(Path::new(PERSIST_DIRECTORY)).unwrap(),
        Path::new(AREA),
        |path, context| {
            let actual = match context {
                DIRECTORY_CONTEXT => "u:object_r:properties_device:s0",
                INFO_CONTEXT => "u:object_r:property_info:s0",
                SERIAL_CONTEXT => "u:object_r:properties_serial:s0",
                context => context,
            };
            label(path, actual)
        },
    )
    .unwrap()
}

fn get(name: &str) -> String {
    let output = Command::new("/system/bin/getprop")
        .arg(name)
        .output()
        .unwrap();
    assert!(output.status.success());
    String::from_utf8(output.stdout).unwrap().trim().into()
}

#[test]
#[ignore = "explicit root-only Android mount-namespace experiment; SSAL_PROPERTY_DEVICE_TEST=1"]
fn bionic_set_get_persist_restart() {
    assert_eq!(
        std::env::var("SSAL_PROPERTY_DEVICE_TEST").as_deref(),
        Ok("1")
    );
    assert_eq!(unsafe { libc::geteuid() }, 0);
    assert_eq!(
        fs::read_to_string("/sys/fs/selinux/enforce")
            .unwrap()
            .trim(),
        "1"
    );
    let host_area = identity(Path::new(AREA)).unwrap();
    let host_socket = identity(Path::new("/dev/socket")).unwrap();
    let host_data = identity(Path::new(PERSIST_DIRECTORY)).unwrap();
    let host_namespace = fs::read_link("/proc/thread-self/ns/mnt").unwrap();
    let root = tests::temp_dir("android-abi");
    let backing = root.join("property");
    fs::create_dir(&backing).unwrap();
    fs::set_permissions(&backing, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(unsafe { libc::unshare(libc::CLONE_NEWNS) }, 0);
    mount(c"none", c"/", None, libc::MS_REC | libc::MS_PRIVATE);
    mount(
        c"tmpfs",
        c"/dev/__properties__",
        Some(c"tmpfs"),
        libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
    );
    mount(
        c"tmpfs",
        c"/dev/socket",
        Some(c"tmpfs"),
        libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
    );
    use std::os::unix::ffi::OsStrExt;
    let source = std::ffi::CString::new(backing.as_os_str().as_bytes()).unwrap();
    mount(&source, c"/data/property", None, libc::MS_BIND);
    assert_ne!(
        fs::read_link("/proc/thread-self/ns/mnt").unwrap(),
        host_namespace
    );
    assert_ne!(identity(Path::new(AREA)).unwrap(), host_area);
    assert_ne!(identity(Path::new("/dev/socket")).unwrap(), host_socket);
    assert_ne!(identity(Path::new(PERSIST_DIRECTORY)).unwrap(), host_data);
    let mut properties = initialize_area();
    let listener = UnixListener::bind(SOCKET).unwrap();
    listener.set_nonblocking(true).unwrap();
    assert_eq!(get("persist.ssal_probe"), "1");
    for (name, value, allowed, success) in [
        ("persist.ssal_probe", "7", true, true),
        ("debug.ssal_probe", "volatile", true, true),
        ("persist.ssal_probe", "bad", true, false),
        ("persist.ssal_probe", "8", false, false),
        ("ro.ssal_late", "blocked", true, false),
        ("ctl.start", "ssal_nonexistent_probe", true, false),
        ("sys.powerctl", "ssal_invalid_probe", true, false),
    ] {
        eprintln!("Bionic request: {name}");
        let mut client = Command::new("/system/bin/setprop")
            .args([name, value])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let status = loop {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    server::handle(&mut stream, &mut properties, |stream, _| {
                        let (_, context) = server::peer(stream)?;
                        assert!(!context.is_empty());
                        // shortcut: ABI test uses its real KSU peer but synthetic allow/deny; validate Guest MAC separately.
                        if allowed {
                            Ok(())
                        } else {
                            Err(io::Error::new(
                                io::ErrorKind::PermissionDenied,
                                "test denial",
                            ))
                        }
                    })
                    .unwrap();
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => {
                    let _ = client.kill();
                    let _ = client.wait();
                    panic!("accept: {e}");
                }
            }
            if let Some(status) = client.try_wait().unwrap() {
                break status;
            }
            if std::time::Instant::now() >= deadline {
                client.kill().unwrap();
                let _ = client.wait();
                panic!("{name} response timeout");
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        };
        assert_eq!(status.success(), success, "{name}");
    }
    assert_eq!(get("persist.ssal_probe"), "7");
    assert_eq!(get("debug.ssal_probe"), "volatile");
    assert_eq!(
        fs::metadata("/data/property/persistent_properties")
            .unwrap()
            .mode()
            & 0o777,
        0o600
    );
    drop(listener);
    drop(properties);
    for entry in fs::read_dir(AREA).unwrap() {
        fs::remove_file(entry.unwrap().path()).unwrap();
    }
    let properties = initialize_area();
    assert_eq!(get("persist.ssal_probe"), "7");
    assert_eq!(get("debug.ssal_probe"), "");
    drop(properties);
    for path in [c"/data/property", c"/dev/socket", c"/dev/__properties__"] {
        assert_eq!(unsafe { libc::umount2(path.as_ptr(), 0) }, 0);
    }
    assert_eq!(identity(Path::new(AREA)).unwrap(), host_area);
    assert_eq!(identity(Path::new("/dev/socket")).unwrap(), host_socket);
    assert_eq!(identity(Path::new(PERSIST_DIRECTORY)).unwrap(), host_data);
    assert_eq!(
        fs::read_to_string("/sys/fs/selinux/enforce")
            .unwrap()
            .trim(),
        "1"
    );
    fs::remove_dir_all(root).unwrap();
}
