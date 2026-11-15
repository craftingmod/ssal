//! Phase 7C root memory controller lifecycle.
use crate::zygote_diagnostics;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

static INTERRUPTED: AtomicBool = AtomicBool::new(false);
extern "C" fn interrupt(_: libc::c_int) {
    INTERRUPTED.store(true, Ordering::SeqCst);
}
pub(crate) fn install_signal_handlers() {
    INTERRUPTED.store(false, Ordering::SeqCst);
    unsafe {
        for signal in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP] {
            libc::signal(signal, interrupt as *const () as libc::sighandler_t);
        }
    }
}

pub(crate) fn enable_subreaper() -> io::Result<()> {
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, std::process::id(), 0) } as i32;
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    unsafe {
        libc::close(fd);
    }
    if unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub(crate) fn cleanup_descendants() -> io::Result<()> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    let self_pid = std::process::id();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let mut any: libc::siginfo_t = unsafe { std::mem::zeroed() };
        if unsafe {
            libc::waitid(
                libc::P_ALL,
                0,
                &mut any,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        } != 0
        {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ECHILD) {
                return Ok(());
            }
            return Err(error);
        }
        for entry in fs::read_dir("/proc")? {
            let entry = entry?;
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|s| s.parse::<i32>().ok())
            else {
                continue;
            };
            let Ok(status) = fs::read_to_string(format!("/proc/{pid}/status")) else {
                continue;
            };
            let parent = status
                .lines()
                .find_map(|line| line.strip_prefix("PPid:"))
                .and_then(|p| p.trim().parse::<u32>().ok());
            if parent != Some(self_pid) {
                continue;
            }
            let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32;
            if raw < 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::ESRCH) {
                    continue;
                }
                return Err(error);
            }
            let fd = unsafe { OwnedFd::from_raw_fd(raw) };
            let status = match fs::read_to_string(format!("/proc/{pid}/status")) {
                Ok(status) => status,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error),
            };
            let parent = status
                .lines()
                .find_map(|line| line.strip_prefix("PPid:"))
                .and_then(|p| p.trim().parse::<u32>().ok());
            require(
                parent == Some(self_pid),
                "child ownership changed; preserving Guest cgroup",
            )?;
            let mut exited: libc::siginfo_t = unsafe { std::mem::zeroed() };
            // P_PIDFD binds the wait and reap to the same process identity as the signal.
            if unsafe {
                libc::waitid(
                    3 as libc::idtype_t,
                    fd.as_raw_fd() as libc::id_t,
                    &mut exited,
                    libc::WEXITED | libc::WNOHANG,
                )
            } != 0
            {
                return Err(io::Error::last_os_error());
            }
            if unsafe { exited.si_pid() } != 0 {
                println!("Guest descendant reaped pid={pid} pidfd=verified");
                continue;
            }
            let path = verify_guest_membership(pid as u32)?;
            println!("Guest owned descendant pid={pid} membership={path} pidfd=verified");
            let rc = unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    fd.as_raw_fd(),
                    libc::SIGKILL,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                )
            };
            if rc != 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() != Some(libc::ESRCH) {
                    return Err(error);
                }
            }
        }
        require(
            std::time::Instant::now() < deadline,
            "Guest descendants did not exit; preserve cgroup",
        )?;
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}
pub(crate) fn check_interrupted() -> io::Result<()> {
    require(
        !INTERRUPTED.load(Ordering::SeqCst),
        "Guest worker interrupted",
    )
}

const ROOT: &str = "/sys/fs/cgroup";
const V1_ROOT: &str = "/dev/memcg";
const GUEST_NAME: &str = "ssal_guest";
const CGROUP2_MAGIC: u64 = 0x63677270;
const CGROUP1_MAGIC: u64 = 0x27e0eb;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Backend {
    V1,
    V2,
}

fn filesystem_magic(path: &Path) -> io::Result<u64> {
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(io::Error::other)?;
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(path.as_ptr(), &mut stat) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(stat.f_type as u64)
}

fn mount_root(mount: &Path, kind: &str, controller: Option<&str>) -> io::Result<String> {
    let text = fs::read_to_string("/proc/self/mountinfo")?;
    text.lines()
        .filter_map(|line| {
            let (before, after) = line.split_once(" - ")?;
            let fields: Vec<_> = before.split_whitespace().collect();
            let tail: Vec<_> = after.split_whitespace().collect();
            if fields.len() < 5 || fields[4] != mount.to_str()? || tail.first() != Some(&kind) {
                return None;
            }
            if controller.is_some_and(|wanted| {
                !tail
                    .get(2..)
                    .unwrap_or_default()
                    .iter()
                    .flat_map(|value| value.split(','))
                    .any(|value| value == wanted)
            }) {
                return None;
            }
            Some(fields[3].to_owned())
        })
        .last()
        .ok_or_else(|| io::Error::other(format!("{} mount missing", kind)))
}

pub(crate) fn backend() -> io::Result<Backend> {
    let root = Path::new(ROOT);
    if filesystem_magic(root).ok() == Some(CGROUP2_MAGIC)
        && mount_root(root, "cgroup2", None).is_ok()
        && root.join("apps").is_dir()
        && fs::read_to_string(root.join("cgroup.controllers")).is_ok_and(|value| has_memory(&value))
    {
        return Ok(Backend::V2);
    }
    let root = Path::new(V1_ROOT);
    if filesystem_magic(root).ok() == Some(CGROUP1_MAGIC)
        && mount_root(root, "cgroup", Some("memory")).is_ok()
    {
        return Ok(Backend::V1);
    }
    Err(io::Error::other(
        "no usable Guest memory cgroup controller (v2 or v1)",
    ))
}

pub(crate) fn task_group(backend: Backend) -> PathBuf {
    match backend {
        Backend::V2 => Path::new(ROOT).join("apps").join(GUEST_NAME),
        Backend::V1 => Path::new(ROOT).join(GUEST_NAME),
    }
}

pub(crate) fn memory_group(backend: Backend) -> PathBuf {
    match backend {
        Backend::V2 => task_group(backend),
        Backend::V1 => Path::new(V1_ROOT).join(GUEST_NAME),
    }
}

pub(crate) fn memory_mount(backend: Backend) -> PathBuf {
    PathBuf::from(match backend {
        Backend::V2 => ROOT,
        Backend::V1 => V1_ROOT,
    })
}

pub(crate) fn require(ok: bool, message: &str) -> io::Result<()> {
    if ok {
        Ok(())
    } else {
        Err(io::Error::other(message))
    }
}
pub(crate) fn read(path: impl AsRef<Path>) -> io::Result<String> {
    Ok(fs::read_to_string(path)?.trim().to_owned())
}
pub(crate) fn change(path: impl AsRef<Path>, value: &str) -> io::Result<()> {
    println!(
        "{} WRITE {}={value}",
        zygote_diagnostics::launch_time(),
        path.as_ref().display()
    );
    fs::write(path, value)
}
pub(crate) fn has_memory(value: &str) -> bool {
    value.split_whitespace().any(|c| c == "memory")
}

fn relative_membership<'a>(membership: &'a str, mount_root: &str) -> io::Result<&'a Path> {
    let path = Path::new(membership);
    let root = Path::new(mount_root);
    for value in [path, root] {
        require(
            value.is_absolute()
                && value.components().all(|part| {
                    matches!(
                        part,
                        std::path::Component::RootDir | std::path::Component::Normal(_)
                    )
                }),
            "invalid cgroup path",
        )?;
    }
    path.strip_prefix(root)
        .map_err(|_| io::Error::other("membership outside cgroup mount"))
}

pub(crate) fn verify_membership(pid: u32, mount: &Path, leaf: &Path) -> io::Result<String> {
    let text = fs::read_to_string(format!("/proc/{pid}/cgroup"))?;
    let (kind, controller, path) = match filesystem_magic(mount)? {
        CGROUP2_MAGIC => (
            "cgroup2",
            None,
            text.lines()
                .find_map(|line| line.strip_prefix("0::"))
                .ok_or_else(|| io::Error::other("v2 membership missing"))?,
        ),
        CGROUP1_MAGIC => {
            let path = text
                .lines()
                .find_map(|line| {
                    let (_, rest) = line.split_once(':')?;
                    let (controllers, path) = rest.split_once(':')?;
                    controllers
                        .split(',')
                        .any(|name| name == "memory")
                        .then_some(path)
                })
                .ok_or_else(|| io::Error::other("v1 memory membership missing"))?;
            ("cgroup", Some("memory"), path)
        }
        _ => return Err(io::Error::other("unsupported cgroup filesystem")),
    };
    let root = mount_root(mount, kind, controller)?;
    let relative = relative_membership(path, &root)?;
    let actual = fs::canonicalize(mount.join(relative))?;
    let expected = fs::canonicalize(leaf)?;
    if !actual.starts_with(&expected) {
        return Err(io::Error::other(format!(
            "Guest memory membership outside subtree: pid={pid} membership={path} actual={} expected={}",
            actual.display(),
            expected.display()
        )));
    }
    Ok(path.to_owned())
}

pub(crate) fn verify_guest_membership(pid: u32) -> io::Result<String> {
    let backend = backend()?;
    verify_membership(pid, &memory_mount(backend), &memory_group(backend))
}

pub(crate) fn verify_guest_mount_membership(pid: u32) -> io::Result<String> {
    let backend = backend()?;
    let mount = memory_mount(backend);
    verify_membership(pid, &mount, &mount)
}

pub(crate) fn usage(group: &Path, backend: Backend) -> io::Result<u64> {
    let name = match backend {
        Backend::V2 => "memory.current",
        Backend::V1 => "memory.usage_in_bytes",
    };
    read(group.join(name))?.parse().map_err(io::Error::other)
}

pub(crate) fn parse_limit(value: Option<&str>) -> io::Result<Option<u64>> {
    value
        .map(|value| {
            value
                .parse::<u64>()
                .ok()
                .filter(|value| *value > 0)
                .ok_or_else(|| io::Error::other("memory limit must be a positive byte count"))
        })
        .transpose()
}

fn page_size() -> u64 {
    let value = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    u64::try_from(value)
        .ok()
        .filter(|size| *size > 0)
        .unwrap_or(4096)
}

#[cfg(test)]
mod membership_tests {
    use super::*;
    #[test]
    fn membership_uses_path_components_and_mount_root() {
        assert_eq!(
            relative_membership(
                "/apps/ssal_guest/system/uid_1000/pid_12",
                "/apps/ssal_guest"
            )
            .unwrap(),
            Path::new("system/uid_1000/pid_12")
        );
        assert_eq!(
            relative_membership("/system/uid_1000", "/").unwrap(),
            Path::new("system/uid_1000")
        );
        assert!(relative_membership("/apps/ssal_guest2", "/apps/ssal_guest").is_err());
        assert!(relative_membership("/apps/ssal_guest/../system", "/apps/ssal_guest").is_err());
    }
}

pub(crate) struct Hierarchy {
    pub(crate) leaf: PathBuf,
    pub(crate) created: bool,
    pub(crate) enabled: bool,
}
impl Hierarchy {
    pub(crate) fn enable(&mut self) -> io::Result<()> {
        require(
            read(format!("{ROOT}/cgroup.subtree_control"))?.is_empty(),
            "root controller state changed",
        )?;
        change(format!("{ROOT}/cgroup.subtree_control"), "+memory")?;
        self.enabled = true;
        require(
            read(format!("{ROOT}/cgroup.subtree_control"))? == "memory",
            "memory enable readback",
        )?;
        // Root delegation exposes files to Host siblings; their limits must remain unlimited.
        for entry in fs::read_dir(ROOT)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                let p = entry.path();
                for (name, expected) in [
                    ("memory.high", "max"),
                    ("memory.max", "max"),
                    ("memory.min", "0"),
                    ("memory.low", "0"),
                ] {
                    require(
                        read(p.join(name))? == expected,
                        "unexpected Host sibling memory policy",
                    )?;
                }
                require(
                    !has_memory(&read(p.join("cgroup.subtree_control"))?),
                    "Host sibling delegated memory concurrently",
                )?;
            }
        }
        Ok(())
    }
    pub(crate) fn cleanup(&mut self) -> io::Result<()> {
        if self.created {
            require(
                read(self.leaf.join("cgroup.procs"))?.is_empty(),
                "occupied Guest cgroup; refusing removal",
            )?;
            fs::remove_dir(&self.leaf)?;
            self.created = false;
            println!(
                "{} RMDIR {}",
                zygote_diagnostics::launch_time(),
                self.leaf.display()
            );
        }
        if self.enabled {
            // Do not revoke a controller another manager started using during this probe.
            for entry in fs::read_dir(ROOT)? {
                let entry = entry?;
                if entry.file_type()?.is_dir() {
                    for (name, expected) in [
                        ("memory.high", "max"),
                        ("memory.max", "max"),
                        ("memory.min", "0"),
                        ("memory.low", "0"),
                    ] {
                        require(
                            read(entry.path().join(name))? == expected,
                            "concurrent sibling memory policy: preserve root for inspection",
                        )?;
                    }
                    require(
                        !has_memory(&read(entry.path().join("cgroup.subtree_control"))?),
                        "concurrent delegation: preserve root memory and report",
                    )?;
                }
            }
            require(
                read(format!("{ROOT}/cgroup.subtree_control"))? == "memory",
                "unexpected root controller state; preserve for inspection",
            )?;
            change(format!("{ROOT}/cgroup.subtree_control"), "-memory")?;
            self.enabled = false;
            require(
                read(format!("{ROOT}/cgroup.subtree_control"))?.is_empty(),
                "root restore readback",
            )?;
        }
        Ok(())
    }
}
impl Drop for Hierarchy {
    fn drop(&mut self) {
        if let Err(e) = self.cleanup() {
            eprintln!("CLEANUP FAILED: {e}; inspect {}", self.leaf.display());
        }
    }
}

/// Guest-only memory limit plus its cgroup task-profile subtree.
pub(crate) struct GuestMemory {
    backend: Backend,
    root: Hierarchy,
    apps_enabled: bool,
}

impl GuestMemory {
    pub(crate) fn prepare() -> io::Result<Self> {
        require(
            read("/sys/fs/selinux/enforce")? == "1",
            "Host must remain Enforcing",
        )?;
        let backend = backend()?;
        let apps = Path::new(ROOT).join("apps");
        require(
            filesystem_magic(Path::new(ROOT))? == CGROUP2_MAGIC,
            "expected cgroup2 mount",
        )?;
        mount_root(Path::new(ROOT), "cgroup2", None)?;
        require(
            fs::canonicalize(ROOT)? == Path::new(ROOT),
            "cgroup path contains symlink",
        )?;
        if backend == Backend::V1 {
            let v1_root = Path::new(V1_ROOT);
            require(
                fs::canonicalize(v1_root)? == v1_root,
                "memory cgroup path contains symlink",
            )?;
            mount_root(v1_root, "cgroup", Some("memory"))?;
            require(
                !task_group(backend).exists() && !memory_group(backend).exists(),
                "Guest cgroup already exists",
            )?;
            println!(
                "Guest memory backend=cgroup v1 memory={} task_groups={} Host controller state unchanged",
                V1_ROOT,
                ROOT
            );
            return Ok(Self {
                backend,
                root: Hierarchy {
                    leaf: memory_group(backend),
                    created: false,
                    enabled: false,
                },
                apps_enabled: false,
            });
        }
        require(
            fs::canonicalize(&apps)? == apps,
            "cgroup path contains symlink",
        )?;
        require(
            has_memory(&read(Path::new(ROOT).join("cgroup.controllers"))?),
            "root memory controller unavailable",
        )?;
        require(
            read(Path::new(ROOT).join("cgroup.subtree_control"))?.is_empty(),
            "root delegation must initially be empty",
        )?;
        require(
            read(apps.join("cgroup.subtree_control"))?.is_empty(),
            "apps delegation must initially be empty",
        )?;
        require(
            read(apps.join("cgroup.procs"))?.is_empty(),
            "apps contains direct processes",
        )?;
        require(
            !memory_group(backend).exists(),
            "Guest cgroup already exists",
        )?;
        let mut session = Self {
            backend,
            root: Hierarchy {
                leaf: memory_group(backend),
                created: false,
                enabled: false,
            },
            apps_enabled: false,
        };
        // First prove the shared ancestors can be restored without a Guest leaf.
        session.enable()?;
        session.cleanup()?;
        println!("Guest memory ancestor roundtrip PASS");
        session.enable()?;
        Ok(session)
    }

    pub(crate) fn backend(&self) -> Backend {
        self.backend
    }

    pub(crate) fn configure_group(&self, group: &Path) -> io::Result<()> {
        match self.backend {
            Backend::V2 => {
                for (name, key) in [
                    ("memory.high", "SSAL_MEMORY_HIGH"),
                    ("memory.max", "SSAL_MEMORY_MAX"),
                ] {
                    if let Some(value) = parse_limit(std::env::var(key).ok().as_deref())? {
                        change(group.join(name), &value.to_string())?;
                        require(
                            read(group.join(name))? == value.to_string(),
                            "Guest memory limit readback",
                        )?;
                    }
                }
            }
            Backend::V1 => {
                let hierarchy = group.join("memory.use_hierarchy");
                require(
                    hierarchy.is_file(),
                    "Guest memory hierarchy control unavailable",
                )?;
                if read(&hierarchy)? != "1" {
                    change(&hierarchy, "1")?;
                }
                require(read(&hierarchy)? == "1", "Guest memory hierarchy readback")?;
                // shortcut: v1 soft limits are advisory, use memory.limit_in_bytes for enforcement.
                if let Some(value) = parse_limit(std::env::var("SSAL_MEMORY_HIGH").ok().as_deref())?
                {
                    let soft = group.join("memory.soft_limit_in_bytes");
                    if soft.exists() {
                        match change(&soft, &value.to_string()).and_then(|_| read(&soft)) {
                            Ok(actual) if actual == value.to_string() => {}
                            Ok(actual) => println!(
                                "Guest cgroup v1 soft limit is advisory/unavailable: requested={value} readback={actual}"
                            ),
                            Err(error) => println!(
                                "Guest cgroup v1 soft limit unavailable: requested={value} error={error}"
                            ),
                        }
                    } else {
                        println!("Guest cgroup v1 soft limit file unavailable; memory.max has no v1 equivalent");
                    }
                }
                if let Some(value) = parse_limit(std::env::var("SSAL_MEMORY_MAX").ok().as_deref())?
                {
                    let hard = group.join("memory.limit_in_bytes");
                    change(&hard, &value.to_string())?;
                    let actual: u64 = read(&hard)?.parse().map_err(io::Error::other)?;
                    require(
                        actual >= value && actual <= value.saturating_add(page_size() - 1),
                        "Guest memory.limit_in_bytes readback",
                    )?;
                }
            }
        }
        Ok(())
    }

    fn enable(&mut self) -> io::Result<()> {
        require(
            self.backend == Backend::V2,
            "v1 memory has no v2 delegation",
        )?;
        check_interrupted()?;
        let apps = Path::new(ROOT).join("apps");
        self.root.enable()?;
        require(
            has_memory(&read(apps.join("cgroup.controllers"))?),
            "apps memory controller unavailable",
        )?;
        require(
            read(apps.join("cgroup.subtree_control"))?.is_empty(),
            "apps delegation changed",
        )?;
        require(
            read(apps.join("cgroup.procs"))?.is_empty(),
            "apps contains direct processes",
        )?;
        change(apps.join("cgroup.subtree_control"), "+memory")?;
        self.apps_enabled = true;
        require(
            read(apps.join("cgroup.subtree_control"))? == "memory",
            "apps memory enable readback",
        )?;
        self.check_apps_children()
    }

    fn check_apps_children(&self) -> io::Result<()> {
        for entry in fs::read_dir(Path::new(ROOT).join("apps"))? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                for (name, expected) in [
                    ("memory.high", "max"),
                    ("memory.max", "max"),
                    ("memory.min", "0"),
                    ("memory.low", "0"),
                ] {
                    require(
                        read(entry.path().join(name))? == expected,
                        "concurrent apps child memory policy",
                    )?;
                }
                require(
                    !has_memory(&read(entry.path().join("cgroup.subtree_control"))?),
                    "concurrent apps child delegation",
                )?;
            }
        }
        Ok(())
    }

    pub(crate) fn cleanup(&mut self) -> io::Result<()> {
        if self.backend == Backend::V1 {
            return Ok(());
        }
        let apps = Path::new(ROOT).join("apps");
        if self.apps_enabled {
            require(
                !apps.join("ssal_guest").exists(),
                "Guest cgroup still exists; preserve controllers",
            )?;
            self.check_apps_children()?;
            require(
                read(apps.join("cgroup.subtree_control"))? == "memory",
                "apps delegation changed; preserve controllers",
            )?;
            change(apps.join("cgroup.subtree_control"), "-memory")?;
            self.apps_enabled = false;
            require(
                read(apps.join("cgroup.subtree_control"))?.is_empty(),
                "apps restore readback",
            )?;
        }
        self.root.cleanup()
    }
}

impl Drop for GuestMemory {
    fn drop(&mut self) {
        if let Err(error) = self.cleanup() {
            eprintln!("Guest memory cleanup failed: {error}");
        }
    }
}
