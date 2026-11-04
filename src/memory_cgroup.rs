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
            let path = verify_membership(
                pid as u32,
                Path::new(ROOT),
                Path::new(ROOT).join("apps/ssal_guest").as_path(),
            )?;
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
    let path = text
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .ok_or_else(|| io::Error::other("v2 membership missing"))?;
    let mounts = fs::read_to_string("/proc/self/mountinfo")?;
    let root = mounts
        .lines()
        .filter_map(|line| {
            let (before, after) = line.split_once(" - ")?;
            let fields: Vec<_> = before.split_whitespace().collect();
            (fields.len() >= 5
                && fields[4] == mount.to_str()?
                && after.split_whitespace().next() == Some("cgroup2"))
            .then_some(fields[3])
        })
        .last()
        .ok_or_else(|| io::Error::other("cgroup2 mount missing"))?;
    let relative = relative_membership(path, root)?;
    let actual = fs::canonicalize(mount.join(relative))?;
    let expected = fs::canonicalize(leaf)?;
    require(
        actual.starts_with(&expected),
        "Guest v2 membership outside subtree",
    )?;
    Ok(path.to_owned())
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

/// Delegation for the launcher's existing apps/ssal_guest leaf.
pub(crate) struct GuestMemory {
    root: Hierarchy,
    apps_enabled: bool,
}

impl GuestMemory {
    pub(crate) fn prepare() -> io::Result<Self> {
        let apps = Path::new(ROOT).join("apps");
        require(
            read("/sys/fs/selinux/enforce")? == "1",
            "Host must remain Enforcing",
        )?;
        require(
            fs::canonicalize(ROOT)? == Path::new(ROOT) && fs::canonicalize(&apps)? == apps,
            "cgroup path contains symlink",
        )?;
        let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
        require(
            unsafe { libc::statfs(c"/sys/fs/cgroup".as_ptr(), &mut stat) } == 0
                && stat.f_type as u64 == 0x63677270,
            "expected cgroup2 mount",
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
            !apps.join("ssal_guest").exists(),
            "Guest cgroup already exists",
        )?;
        let mut session = Self {
            root: Hierarchy {
                leaf: apps.join("ssal_guest"),
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

    fn enable(&mut self) -> io::Result<()> {
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
