//! Bounded, disposable userspace checks; never starts Android init or services.
use std::collections::BTreeSet;
use std::ffi::CString;
use std::fs::{self, File};
use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn policy_equality_includes_identifiers_without_logging_them() -> io::Result<()> {
        let mut raw = [0xabu8; 24];
        raw[..8].copy_from_slice(&[2, 1, 4, 10, 0, 0, 0, 0]);
        let a = PolicyState::Encrypted(decode_policy(24, &raw)?);
        let same = PolicyState::Encrypted(decode_policy(24, &raw)?);
        assert_eq!(
            compare_policies(&a, &same),
            PolicyComparison {
                policy_same: Some(true),
                key_identifier_same: Some(true)
            }
        );
        raw[23] = 0xcd;
        let changed_key = PolicyState::Encrypted(decode_policy(24, &raw)?);
        assert_eq!(
            compare_policies(&a, &changed_key),
            PolicyComparison {
                policy_same: Some(false),
                key_identifier_same: Some(false)
            }
        );
        let json = serde_json::to_string(&compare_policies(&a, &changed_key))?;
        assert!(!json.contains("abab"));
        assert!(!policy_description(&a).contains("abab"));
        assert_eq!(
            compare_policies(&a, &PolicyState::Unavailable("unsupported".into())).policy_same,
            None
        );
        assert!(decode_policy(12, &raw).is_err());
        Ok(())
    }

    #[test]
    fn vintf_missing_or_execution_errors_cannot_be_passed() {
        assert_eq!(vintf_status(Some(0)), CheckStatus::Passed);
        assert_eq!(vintf_status(Some(65)), CheckStatus::Failed);
        for code in [Some(64), Some(70), Some(126), Some(127), None] {
            assert_eq!(vintf_status(code), CheckStatus::Error);
        }
        assert_eq!(
            serde_json::to_string(&CheckStatus::Unavailable).unwrap(),
            "\"unavailable\""
        );
    }

    #[test]
    fn linker_summary_rejects_nonempty_but_incomplete_config() -> io::Result<()> {
        let root = std::env::temp_dir().join(format!("ssal-linker-summary-{}", std::process::id()));
        fs::create_dir_all(root.join("linkerconfig"))?;
        let main = root.join("linkerconfig/ld.config.txt");
        fs::write(&main, "# nonempty, but not generated configuration\n")?;
        assert!(linker_summary(&root).is_err());
        fs::write(&main, "dir.system = /system/bin\n[system]\nnamespace.default.search.paths = /system/${LIB}\nnamespace.default.search.paths += /system_ext/${LIB}\nnamespace.runtime.isolated = true\n")?;
        let summary = linker_summary(&root)?;
        assert_eq!(summary.files[0].sections, ["system"]);
        assert_eq!(summary.files[0].namespaces, ["default", "runtime"]);
        assert_eq!(summary.files[0].default_search_paths, 2);
        // A default namespace may resolve only through links to other namespaces.
        fs::write(&main, "dir.system = /system/bin\n[system]\nnamespace.default.links = runtime\nnamespace.runtime.search.paths = /apex/com.android.runtime/${LIB}\n")?;
        assert_eq!(linker_summary(&root)?.files[0].default_search_paths, 0);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn probe_timeout_stops_background_process_group() -> io::Result<()> {
        let mut cmd = Command::new("/bin/sh");
        cmd.args(["-c", "sleep 30 & wait"]);
        unsafe {
            cmd.pre_exec(|| {
                if libc::setsid() < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let started = Instant::now();
        let error =
            run_with_timeout(&mut cmd, "timeout test", Duration::from_millis(50)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(3));
        Ok(())
    }

    #[test]
    #[ignore = "requires Linux root/CAP_SYS_CHROOT; no mount capability needed"]
    fn real_chroot_probe_closes_host_directory_fds() -> io::Result<()> {
        let sentinel =
            std::env::temp_dir().join(format!("ssal-root-probe-fd-{}", std::process::id()));
        fs::create_dir(&sentinel)?;
        let directory = File::open(&sentinel)?;
        let fd = directory.as_raw_fd();
        assert_eq!(unsafe { libc::fcntl(fd, libc::F_SETFD, 0) }, 0);
        let mut cmd = command(Path::new("/"), "/bin/sh", false)?;
        cmd.args(["-c", "test \"$(pwd)\" = /; test ! /proc/self/fd/\"$1\" -ef \"$2\" || exit 1; printf 'root and inherited FD checks OK'", "probe", &fd.to_string(), sentinel.to_str().unwrap()]);
        let output = run(&mut cmd, "chroot FD regression")?;
        drop(directory);
        fs::remove_dir(sentinel)?;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, b"root and inherited FD checks OK");
        Ok(())
    }

    #[test]
    #[ignore = "requires Linux CAP_SYS_ADMIN and CAP_SYS_CHROOT in a disposable container"]
    fn real_pivot_probe_detaches_old_root() -> io::Result<()> {
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
        let root = std::env::temp_dir().join(format!("ssal-pivot-probe-{}", std::process::id()));
        fs::create_dir(&root)?;
        if unsafe {
            libc::mount(
                c"tmpfs".as_ptr(),
                cpath(&root)?.as_ptr(),
                c"tmpfs".as_ptr(),
                libc::MS_NOSUID | libc::MS_NODEV,
                c"mode=0755".as_ptr().cast(),
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        let mut bindings = Vec::new();
        let result = (|| -> io::Result<()> {
            for name in ["usr", "bin", "lib", "lib64"] {
                let source = Path::new("/").join(name);
                let meta = match source.symlink_metadata() {
                    Ok(meta) => meta,
                    Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                    Err(e) => return Err(e),
                };
                let target = root.join(name);
                if meta.file_type().is_symlink() {
                    std::os::unix::fs::symlink(fs::read_link(&source)?, target)?;
                } else {
                    fs::create_dir(&target)?;
                    if unsafe {
                        libc::mount(
                            cpath(&source)?.as_ptr(),
                            cpath(&target)?.as_ptr(),
                            std::ptr::null(),
                            libc::MS_BIND,
                            std::ptr::null(),
                        )
                    } != 0
                    {
                        return Err(io::Error::last_os_error());
                    }
                    bindings.push(target);
                }
            }
            fs::write(root.join("guest-only-marker"), b"guest")?;
            let mut cmd = command(&root, "/bin/sh", true)?;
            cmd.args(["-c", "set -eu; test ! -e /.ssal-old-root; test -f /guest-only-marker; test \"$(pwd)\" = /; printf 'pivot root and old-root detach OK'"]);
            let output = run(&mut cmd, "pivot fixture")?;
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(output.stdout, b"pivot root and old-root detach OK");
            // Child root transition must leave the worker's root unchanged.
            assert!(!Path::new("/guest-only-marker").exists());
            assert!(root.join("guest-only-marker").exists());
            Ok(())
        })();
        for target in bindings.into_iter().rev() {
            if unsafe { libc::umount2(cpath(&target)?.as_ptr(), 0) } != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        if unsafe { libc::umount2(cpath(&root)?.as_ptr(), 0) } != 0 {
            return Err(io::Error::last_os_error());
        }
        fs::remove_dir(root)?;
        result
    }
}

fn cpath(path: &Path) -> io::Result<CString> {
    CString::new(path.as_os_str().as_bytes()).map_err(io::Error::other)
}

fn command(root: &Path, executable: &str, pivot: bool) -> io::Result<Command> {
    let root_c = cpath(root)?;
    // Capture parent descriptors before spawn creates its own CLOEXEC pipes.
    let inherited: Vec<i32> = fs::read_dir("/proc/self/fd")?
        .filter_map(|entry| entry.ok()?.file_name().to_str()?.parse().ok())
        .filter(|fd| *fd > 2)
        .collect();
    let expected = fs::metadata(root)?;
    if pivot {
        fs::create_dir(root.join(".ssal-old-root"))?;
    }
    let mut command = Command::new(executable);
    command
        .env_clear()
        .env("PATH", "/system/bin:/apex/com.android.runtime/bin");
    unsafe {
        command.pre_exec(move || {
            if libc::setsid() < 0 {
                return Err(io::Error::last_os_error());
            }
            for fd in &inherited {
                let flags = libc::fcntl(*fd, libc::F_GETFD);
                if flags >= 0 && libc::fcntl(*fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            if pivot {
                if libc::unshare(libc::CLONE_NEWNS) != 0 {
                    return Err(io::Error::last_os_error());
                }
                if libc::mount(
                    std::ptr::null(),
                    c"/".as_ptr(),
                    std::ptr::null(),
                    libc::MS_REC | libc::MS_PRIVATE,
                    std::ptr::null(),
                ) != 0
                {
                    return Err(io::Error::last_os_error());
                }
                if libc::chdir(root_c.as_ptr()) != 0 {
                    return Err(io::Error::last_os_error());
                }
                if libc::syscall(
                    libc::SYS_pivot_root,
                    c".".as_ptr(),
                    c".ssal-old-root".as_ptr(),
                ) != 0
                {
                    return Err(io::Error::last_os_error());
                }
                if libc::chdir(c"/".as_ptr()) != 0 {
                    return Err(io::Error::last_os_error());
                }
                // Deliberate old-root detachment in this disposable child only.
                // It includes inherited host submounts; this is not cleanup of
                // the worker's tracked guest mounts or a claim of their release.
                if libc::umount2(c"/.ssal-old-root".as_ptr(), libc::MNT_DETACH) != 0 {
                    return Err(io::Error::last_os_error());
                }
                if libc::rmdir(c"/.ssal-old-root".as_ptr()) != 0 {
                    return Err(io::Error::last_os_error());
                }
            } else {
                if libc::chroot(root_c.as_ptr()) != 0 {
                    return Err(io::Error::last_os_error());
                }
                if libc::chdir(c"/".as_ptr()) != 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            let mut actual: libc::stat = std::mem::zeroed();
            if libc::stat(c"/".as_ptr(), &mut actual) != 0 {
                return Err(io::Error::last_os_error());
            }
            if actual.st_dev != expected.dev() || actual.st_ino != expected.ino() {
                return Err(io::Error::other("guest root identity mismatch"));
            }
            Ok(())
        });
    }
    Ok(command)
}

fn run(command: &mut Command, stage: &str) -> io::Result<Output> {
    run_with_timeout(command, stage, Duration::from_secs(20))
}

fn run_with_timeout(command: &mut Command, stage: &str, timeout: Duration) -> io::Result<Output> {
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| io::Error::new(e.kind(), format!("{stage}: spawn/root setup: {e}")))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("stdout pipe missing"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("stderr pipe missing"))?;
    let reader = |pipe: Box<dyn Read + Send>| {
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            pipe.take(256 * 1024).read_to_end(&mut bytes).map(|_| bytes)
        })
    };
    let out = reader(Box::new(stdout));
    let err = reader(Box::new(stderr));
    let deadline = Instant::now() + timeout;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            // No service or background process is part of a successful probe.
            unsafe {
                libc::kill(-(child.id() as i32), libc::SIGKILL);
            }
            break status;
        }
        if Instant::now() >= deadline {
            unsafe {
                libc::kill(-(child.id() as i32), libc::SIGKILL);
            }
            child.wait()?;
            let _ = out.join();
            let _ = err.join();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("{stage}: exceeded {timeout:?}; probe process group stopped"),
            ));
        }
        std::thread::sleep(Duration::from_millis(25));
    };
    Ok(Output {
        status,
        stdout: out
            .join()
            .map_err(|_| io::Error::other("stdout reader panicked"))??,
        stderr: err
            .join()
            .map_err(|_| io::Error::other("stderr reader panicked"))??,
    })
}

#[derive(PartialEq, Eq)]
struct EncryptionPolicy {
    version: u8,
    contents: u8,
    filenames: u8,
    flags: u8,
    // Never Debug/Serialize this type: comparisons must not expose identifiers.
    key_identifier: Vec<u8>,
}

enum PolicyState {
    Encrypted(EncryptionPolicy),
    Unencrypted,
    Unavailable(String),
}

fn decode_policy(size: u64, bytes: &[u8; 24]) -> io::Result<EncryptionPolicy> {
    let key_range = match (bytes[0], size) {
        (0, 12) => 4..12,
        (2, 24) => 8..24,
        _ => return Err(io::Error::other("unsupported fscrypt policy version/size")),
    };
    Ok(EncryptionPolicy {
        version: bytes[0],
        contents: bytes[1],
        filenames: bytes[2],
        flags: bytes[3],
        key_identifier: bytes[key_range].to_vec(),
    })
}

fn read_fscrypt(path: &Path) -> io::Result<PolicyState> {
    #[repr(C)]
    struct Policy {
        size: u64,
        policy: [u8; 24],
    }
    let file = File::open(path)?;
    let mut policy = Policy {
        size: 24,
        policy: [0; 24],
    };
    // linux/fscrypt.h: _IOWR('f', 22, __u8[9]); policy_size + version.
    if unsafe { libc::ioctl(file.as_raw_fd(), 0xc0096616u32 as _, &mut policy) } != 0 {
        let error = io::Error::last_os_error();
        return if error.raw_os_error() == Some(libc::ENODATA) {
            Ok(PolicyState::Unencrypted)
        } else {
            Err(error)
        };
    }
    Ok(PolicyState::Encrypted(decode_policy(
        policy.size,
        &policy.policy,
    )?))
}

fn policy_state(path: &Path) -> PolicyState {
    read_fscrypt(path).unwrap_or_else(|e| PolicyState::Unavailable(e.to_string()))
}

fn policy_description(state: &PolicyState) -> String {
    match state {
        PolicyState::Encrypted(p) => format!(
            "version={}, contents_mode={}, filenames_mode={}, flags=0x{:02x}; identifiers redacted",
            p.version, p.contents, p.filenames, p.flags
        ),
        PolicyState::Unencrypted => "no encryption policy on this directory".into(),
        PolicyState::Unavailable(reason) => format!("unavailable: {reason}"),
    }
}

#[derive(serde::Serialize, Debug, PartialEq, Eq)]
pub struct PolicyComparison {
    policy_same: Option<bool>,
    key_identifier_same: Option<bool>,
}

fn compare_policies(a: &PolicyState, b: &PolicyState) -> PolicyComparison {
    match (a, b) {
        (PolicyState::Encrypted(a), PolicyState::Encrypted(b)) => PolicyComparison {
            policy_same: Some(a == b),
            key_identifier_same: Some(
                a.version == b.version && a.key_identifier == b.key_identifier,
            ),
        },
        (PolicyState::Unencrypted, PolicyState::Unencrypted) => PolicyComparison {
            policy_same: Some(true),
            key_identifier_same: None,
        },
        (PolicyState::Unavailable(_), _) | (_, PolicyState::Unavailable(_)) => PolicyComparison {
            policy_same: None,
            key_identifier_same: None,
        },
        _ => PolicyComparison {
            policy_same: Some(false),
            key_identifier_same: None,
        },
    }
}

fn encryption_diagnostics(root: &Path) -> PolicyComparison {
    let host = policy_state(Path::new("/data"));
    println!(
        "host /data fscrypt reference: {}",
        policy_description(&host)
    );
    let mut states = Vec::new();
    for path in ["data", "data/media", "data/user/0", "data/user_de/0"] {
        let state = match crate::guest_mounts::guest_path(root, path) {
            Ok(path) => policy_state(&path),
            Err(e) => PolicyState::Unavailable(e.to_string()),
        };
        println!("guest fscrypt /{path}: {}", policy_description(&state));
        states.push(state);
    }
    for (label, a, b) in [
        ("host /data vs guest /data", &host, &states[0]),
        ("guest /data vs media", &states[0], &states[1]),
        ("guest /data vs user/0", &states[0], &states[2]),
        ("guest /data vs user_de/0", &states[0], &states[3]),
        ("guest user/0 vs user_de/0", &states[2], &states[3]),
    ] {
        println!(
            "fscrypt comparison {label}: {}",
            serde_json::to_string(&compare_policies(a, b)).expect("comparison serialization")
        );
    }
    println!("fscrypt scope: inherited host filesystem policies only; guest FBE, CE/DE key ownership and lock/unlock lifecycle NOT verified");
    compare_policies(&states[2], &states[3])
}

fn diagnostics(root: &Path) -> io::Result<()> {
    for relative in [
        "data",
        "data/media",
        "data/user/0",
        "data/user_de/0",
        "tmp",
        "cache",
        "metadata",
        "dev/__properties__",
    ] {
        let path = match crate::guest_mounts::guest_path(root, relative) {
            Ok(path) => path,
            Err(e) => {
                println!("guest context /{relative}: unavailable: {e}");
                continue;
            }
        };
        match File::open(&path) {
            Ok(file) => {
                let meta = file.metadata()?;
                let label = ssal::unix::image_context(&file)
                    .unwrap_or_else(|e| format!("unavailable: {e}"));
                println!(
                    "guest context /{relative}: uid={} gid={} mode={:o} label={label}",
                    meta.uid(),
                    meta.gid(),
                    meta.mode() & 0o7777
                );
            }
            Err(e) => println!("guest context /{relative}: unavailable: {e}"),
        }
    }
    for relative in [
        "dev/binder",
        "dev/hwbinder",
        "dev/vndbinder",
        "dev/__properties__",
    ] {
        if let (Ok(host), Ok(guest)) = (
            fs::metadata(Path::new("/").join(relative)),
            crate::guest_mounts::guest_path(root, relative).and_then(fs::metadata),
        ) {
            println!(
                "shared runtime /{relative}: same backing={}",
                (host.dev(), host.ino(), host.rdev()) == (guest.dev(), guest.ino(), guest.rdev())
            );
        }
    }
    println!("property area shared; /dev/socket/property_service masked={}; guest property service is not implemented", !root.join("dev/socket/property_service").exists());
    println!("service gate: Binder/property isolation, guest installd/artd/vold, FUSE permissions and init are NOT validated; no Android services started");
    Ok(())
}

#[derive(serde::Serialize, Debug, PartialEq, Eq, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    Passed,
    Failed,
    Unavailable,
    Error,
}

#[derive(serde::Serialize)]
pub struct RootObservation {
    stage: String,
    selinux_context: Option<String>,
    validation_scope: &'static str,
}

#[derive(serde::Serialize)]
pub struct ProbeReport {
    linkerconfig: LinkerSummary,
    root_probes: Vec<RootObservation>,
    ce_de_policy: PolicyComparison,
    pub vintf: CheckStatus,
    android_service_domains_verified: bool,
    guest_fbe_verified: bool,
}

#[derive(serde::Serialize)]
struct LinkerSummary {
    files: Vec<LinkerFile>,
}

#[derive(serde::Serialize)]
struct LinkerFile {
    path: String,
    sections: Vec<String>,
    namespaces: Vec<String>,
    directory_rules: usize,
    default_search_paths: usize,
}

fn parse_linker_config(path: &str, text: &str) -> io::Result<LinkerFile> {
    if text.trim().is_empty() {
        return Err(io::Error::other(format!(
            "empty linker configuration: {path}"
        )));
    }
    let mut sections = BTreeSet::new();
    let mut namespaces = BTreeSet::new();
    let mut directory_rules = 0;
    let mut default_search_paths = 0;
    for line in text
        .lines()
        .map(str::trim)
        .filter(|line| !line.starts_with('#'))
    {
        if let Some(section) = line
            .strip_prefix('[')
            .and_then(|line| line.strip_suffix(']'))
        {
            if !section.trim().is_empty() {
                sections.insert(section.trim().to_owned());
            }
        }
        if let Some((key, value)) = line.split_once('=') {
            let key = key.trim().trim_end_matches('+').trim();
            if value.trim().is_empty() {
                continue;
            }
            if key.starts_with("dir.") {
                directory_rules += 1;
            }
            if key == "namespace.default.search.paths" {
                default_search_paths += 1;
            }
            if let Some(namespace) = key
                .strip_prefix("namespace.")
                .and_then(|value| value.split_once('.'))
                .map(|(name, _)| name)
            {
                if !namespace.is_empty() {
                    namespaces.insert(namespace.to_owned());
                }
            }
        }
    }
    Ok(LinkerFile {
        path: path.to_owned(),
        sections: sections.into_iter().collect(),
        namespaces: namespaces.into_iter().collect(),
        directory_rules,
        default_search_paths,
    })
}

fn linker_summary(root: &Path) -> io::Result<LinkerSummary> {
    let mut directories = vec![crate::guest_mounts::guest_path(root, "linkerconfig")?];
    let mut files = Vec::new();
    while let Some(directory) = directories.pop() {
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let kind = entry.file_type()?;
            if kind.is_dir() {
                directories.push(entry.path());
            } else if entry.file_name() == "ld.config.txt" {
                let relative = entry
                    .path()
                    .strip_prefix(root)
                    .map_err(io::Error::other)?
                    .to_string_lossy()
                    .into_owned();
                let path = crate::guest_mounts::guest_path(root, &relative)?;
                if fs::metadata(&path)?.len() > 2 * 1024 * 1024 {
                    return Err(io::Error::other("linker configuration exceeds 2 MiB"));
                }
                files.push(parse_linker_config(
                    &format!("/{relative}"),
                    &fs::read_to_string(path)?,
                )?);
            }
        }
    }
    files.sort_by(|a, b| a.path.cmp(&b.path));
    let main = files
        .iter()
        .find(|file| file.path == "/linkerconfig/ld.config.txt")
        .ok_or_else(|| io::Error::other("main linker configuration missing from summary"))?;
    if main.sections.is_empty()
        || !main
            .namespaces
            .iter()
            .any(|namespace| namespace == "default")
        || main.directory_rules == 0
    {
        return Err(io::Error::other(
            "main linkerconfig lacks sections, directory rules or default namespace",
        ));
    }
    println!("guest linkerconfig: {} files, main sections={:?}, main namespaces={:?}, directory_rules={}; structure checked, library loading verified only for executed probes", files.len(), main.sections, main.namespaces, main.directory_rules);
    Ok(LinkerSummary { files })
}

fn vintf_status(code: Option<i32>) -> CheckStatus {
    // AOSP check_vintf: EX_OK=0; EX_DATAERR=65 means incompatible files.
    // EX_USAGE=64, EX_SOFTWARE=70, signals and other failures are errors.
    match code {
        Some(0) => CheckStatus::Passed,
        Some(65) => CheckStatus::Failed,
        _ => CheckStatus::Error,
    }
}

fn vintf_diagnostic(root: &Path) -> io::Result<CheckStatus> {
    let mut inventory = command(root, "/system/bin/sh", false)?;
    inventory.args(["-c", "set -eu; for p in /system/etc/vintf /vendor/etc/vintf /product/etc/vintf /system_ext/etc/vintf; do if test -d \"$p\"; then /system/bin/toybox ls -l \"$p\"; else echo \"VINTF path absent: $p\"; fi; done"]);
    let output = run(&mut inventory, "VINTF inventory")?;
    println!(
        "VINTF inventory (not a compatibility result):\n{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    if !output.status.success() {
        println!("VINTF result: error; inventory failed");
        return Ok(CheckStatus::Error);
    }
    let executable = match crate::guest_mounts::guest_path(root, "system/bin/checkvintf") {
        Ok(path) => path,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            println!(
                "VINTF result: unavailable; checkvintf not installed; compatibility NOT verified"
            );
            return Ok(CheckStatus::Unavailable);
        }
        Err(e) => {
            println!("VINTF result: error; resolve checker: {e}");
            return Ok(CheckStatus::Error);
        }
    };
    let metadata = fs::metadata(executable)?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
        println!("VINTF result: error; checkvintf is not executable");
        return Ok(CheckStatus::Error);
    }
    let mut checker = command(root, "/system/bin/checkvintf", false)?;
    checker.args(["--check-compat", "--rootdir", "/"]);
    match run(&mut checker, "VINTF compatibility checker") {
        Ok(output) => {
            let status = vintf_status(output.status.code());
            println!("VINTF result: {} (checker exit={}); guest property/kernel inputs not validated, complete guest compatibility NOT certified\n{}{}", serde_json::to_string(&status)?, output.status, String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
            Ok(status)
        }
        Err(e) => {
            println!("VINTF result: error; checker execution: {e}");
            Ok(CheckStatus::Error)
        }
    }
}

pub fn verify(root: &Path, userdata: &Path) -> io::Result<ProbeReport> {
    diagnostics(root)?;
    let ce_de_policy = encryption_diagnostics(root);
    let linkerconfig = linker_summary(root)?;
    let mut root_probes = Vec::new();
    let probe = format!(".ssal-runtime-probe-{}", std::process::id());
    let script = r#"
set -eu
echo "Guest root shell OK: $1"
for p in /system /vendor /apex /data /tmp /cache /metadata /config; do
  test -d "$p"
  /system/bin/toybox ls -ld "$p"
done
test -s /linkerconfig/ld.config.txt
test ! -e /.ssal-old-root
for p in /product /system_ext; do
  if test -e "$p"; then /system/bin/toybox readlink -f "$p"; else echo "optional path absent: $p"; fi
done
/system/bin/toybox grep '^ro.build.version.release=' /system/build.prop
context=$(/system/bin/toybox cat "/proc/$$/attr/current" 2>/dev/null) || context=unavailable
printf 'SSAL_PROBE_SELINUX=%s\n' "$context"
umask 077
set -C
printf '%s' "$1" > "/data/$2"
printf '%s' "$1" > "/tmp/$2"
printf '%s' "$1" > "/cache/$2"
test "$(/system/bin/toybox cat "/tmp/$2")" = "$1"
test "$(/system/bin/toybox cat "/cache/$2")" = "$1"
/system/bin/toybox rm "/tmp/$2" "/cache/$2"
echo 'guest runtime paths and write/read checks: OK'
"#;
    for pivot in [false, true] {
        let stage = if pivot { "pivot_root" } else { "chroot" };
        for marker in [
            userdata.join(&probe),
            root.join("tmp").join(&probe),
            root.join("cache").join(&probe),
        ] {
            match marker.symlink_metadata() {
                Ok(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        format!("probe marker already exists: {}", marker.display()),
                    ))
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => (),
                Err(e) => return Err(e),
            }
        }
        println!("guest stage: {stage} dynamic shell probe");
        let result = (|| {
            let mut cmd = command(root, "/system/bin/sh", pivot)?;
            cmd.args(["-c", script, "ssal-probe", stage, &probe]);
            let output = run(&mut cmd, stage)?;
            println!("{}", String::from_utf8_lossy(&output.stdout));
            if !output.status.success() {
                return Err(io::Error::other(format!(
                    "{stage} guest shell failed ({}): {}",
                    output.status,
                    String::from_utf8_lossy(&output.stderr)
                )));
            }
            if fs::read(userdata.join(&probe))? != stage.as_bytes() {
                return Err(io::Error::other(format!(
                    "{stage} write did not reach profile userdata"
                )));
            }
            let selinux_context = String::from_utf8_lossy(&output.stdout)
                .lines()
                .find_map(|line| line.strip_prefix("SSAL_PROBE_SELINUX="))
                .map(|value| value.trim_matches('\0').trim().to_owned())
                .filter(|value| value.starts_with("u:r:"));
            println!("SELinux {stage}: observed={}; validation_scope=probe_only; Android service domains NOT verified", selinux_context.as_deref().unwrap_or("unavailable"));
            root_probes.push(RootObservation {
                stage: stage.to_owned(),
                selinux_context,
                validation_scope: "probe_only",
            });
            Ok(())
        })();
        // Remove only the private marker that this probe successfully created.
        let marker = userdata.join(&probe);
        if marker.exists() {
            fs::remove_file(marker)?;
        }
        for prefix in ["tmp", "cache"] {
            let marker = root.join(prefix).join(&probe);
            if marker.exists() {
                fs::remove_file(marker)?;
            }
        }
        let old = root.join(".ssal-old-root");
        if old.exists() {
            fs::remove_dir(old)?;
        }
        result?;
        println!("guest {stage} probe: root identity, dynamic shell and profile write verified");
    }
    let report = ProbeReport {
        linkerconfig,
        root_probes,
        ce_de_policy,
        vintf: vintf_diagnostic(root).unwrap_or_else(|e| {
            println!("VINTF result: error; diagnostic setup: {e}");
            CheckStatus::Error
        }),
        android_service_domains_verified: false,
        guest_fbe_verified: false,
    };
    println!("guest probe summary: {}", serde_json::to_string(&report)?);
    Ok(report)
}
