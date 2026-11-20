use crate::guest::mount::{cpath, directory, guest_path, same_directory};
use ssal::namespace_mounts::Mounts;
use std::ffi::CString;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

static GUEST_CGROUP_NAMESPACE: Mutex<Option<File>> = Mutex::new(None);

pub(crate) fn namespace_fd() -> Option<RawFd> {
    GUEST_CGROUP_NAMESPACE
        .lock()
        .unwrap()
        .as_ref()
        .map(AsRawFd::as_raw_fd)
}
pub(in crate::guest) const GUEST_RESOURCE_CGROUPS: [(&str, &str); 3] = [
    ("/dev/cpuctl/ssal_guest", "dev/cpuctl"),
    ("/dev/cpuset/ssal_guest", "dev/cpuset"),
    ("/dev/blkio/ssal_guest", "dev/blkio"),
];

pub(crate) fn guest_cgroup_mounts(
    backend: crate::guest::cgroup::Backend,
) -> Vec<(PathBuf, &'static str)> {
    let mut groups = vec![(crate::guest::cgroup::task_group(backend), "sys/fs/cgroup")];
    if backend == crate::guest::cgroup::Backend::V1 {
        groups.push((crate::guest::cgroup::memory_group(backend), "dev/memcg"));
    }
    groups.extend(
        GUEST_RESOURCE_CGROUPS
            .iter()
            .map(|(source, target)| (PathBuf::from(source), *target)),
    );
    groups
}

pub(crate) fn task_cgroup_path() -> io::Result<PathBuf> {
    Ok(crate::guest::cgroup::task_group(
        crate::guest::cgroup::backend()?,
    ))
}

pub(in crate::guest) fn uses_guest_cgroups(mode: &str) -> bool {
    matches!(
        mode,
        "--guest-hwbinder-worker"
            | "--guest-cgroup-worker"
            | "--guest-child-worker"
            | "--guest-processgroup-worker"
            | "--guest-memory-worker"
            | "--guest-service-worker"
            | "--guest-services-6a-worker"
            | "--guest-services-6b-worker"
            | "--guest-start-worker"
    )
}

pub(in crate::guest) fn lock_guest_cgroups() -> io::Result<File> {
    // Lock the same Host directory for every worker using the fixed Guest paths.
    let lock = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(ssal::unix::ROOT)?;
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(io::Error::other(format!(
            "cannot lock Guest cgroups: {}",
            io::Error::last_os_error()
        )));
    }
    Ok(lock)
}

pub(in crate::guest) fn recover_guest_cgroups(backend: super::Backend) -> io::Result<()> {
    let mountinfo = fs::read_to_string("/proc/self/mountinfo")?;
    let mut empty_groups = Vec::new();
    for (path, _) in guest_cgroup_mounts(backend) {
        if !cgroup_exists(&path)? {
            continue;
        }
        validate_cgroup_root(&path, &mountinfo)
            .and_then(|()| collect_empty_cgroups(&path, &mut empty_groups))
            .map_err(|error| io::Error::other(format!("{}: {error}", path.display())))?;
    }
    for path in empty_groups {
        fs::remove_dir(&path)
            .map_err(|error| io::Error::other(format!("rmdir {}: {error}", path.display())))?;
        println!("Removed residual Guest cgroup: {}", path.display());
    }
    for (path, _) in guest_cgroup_mounts(backend) {
        if cgroup_exists(&path)? {
            return Err(io::Error::other(format!(
                "Guest cgroup remains: {}",
                path.display()
            )));
        }
    }
    Ok(())
}

fn validate_cgroup_root(path: &Path, mountinfo: &str) -> io::Result<()> {
    let parent = path.parent().unwrap();
    let (mount, kind, controller) = match parent.to_str() {
        Some("/sys/fs/cgroup" | "/sys/fs/cgroup/apps") => {
            (Path::new("/sys/fs/cgroup"), "cgroup2", None)
        }
        Some("/dev/memcg") => (parent, "cgroup", Some("memory")),
        Some("/dev/cpuctl") => (parent, "cgroup", Some("cpu")),
        Some("/dev/cpuset") => (parent, "cgroup", Some("cpuset")),
        Some("/dev/blkio") => (parent, "cgroup", Some("blkio")),
        _ => return Err(io::Error::other("unexpected cgroup parent")),
    };
    if super::memory::mount_root(mount, kind, controller)? != "/" || fs::canonicalize(path)? != path
    {
        return Err(io::Error::other("unexpected cgroup mount root or symlink"));
    }
    if mountinfo.lines().any(|line| {
        line.split_whitespace().nth(4).is_some_and(|target| {
            let target = Path::new(target);
            target.starts_with(path)
                || (target != mount && target.starts_with(mount) && path.starts_with(target))
        })
    }) {
        return Err(io::Error::other("unexpected mount in Guest cgroup path"));
    }
    Ok(())
}

fn cgroup_populated(events: &Path) -> io::Result<bool> {
    match fs::read_to_string(events)?
        .lines()
        .find_map(|line| line.strip_prefix("populated "))
    {
        Some("0") => Ok(false),
        Some("1") => Ok(true),
        _ => Err(io::Error::other(format!(
            "{}: invalid populated field",
            events.display()
        ))),
    }
}

fn wait_for_empty_cgroup(events: &Path, timeout: Duration) -> io::Result<()> {
    let deadline = Instant::now() + timeout;
    while cgroup_populated(events)? {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("{}: timed out waiting for populated 0", events.display()),
            ));
        }
        std::thread::sleep(remaining.min(Duration::from_millis(20)));
    }
    Ok(())
}

fn cgroup_exists(path: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(io::Error::other(format!("{}: {error}", path.display()))),
    }
}

fn collect_empty_cgroups(path: &Path, groups: &mut Vec<PathBuf>) -> io::Result<()> {
    for control in ["cgroup.procs", "tasks", "cgroup.threads"] {
        let file = path.join(control);
        if control != "cgroup.procs" && !cgroup_exists(&file)? {
            continue;
        }
        let members = fs::read_to_string(&file)
            .map_err(|error| io::Error::other(format!("{}: {error}", file.display())))?;
        if !members.trim().is_empty() {
            return Err(io::Error::other(format!(
                "{} has live members",
                file.display()
            )));
        }
    }
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        if kind.is_symlink() {
            return Err(io::Error::other(format!(
                "unexpected symlink: {}",
                entry.path().display()
            )));
        }
        if kind.is_dir() {
            collect_empty_cgroups(&entry.path(), groups)?;
        }
    }
    groups.push(path.to_owned());
    Ok(())
}

fn chown_system_cgroup(dir: &Path) -> io::Result<()> {
    for entry in [
        dir.to_path_buf(),
        dir.join("cgroup.procs"),
        dir.join("tasks"),
        dir.join("cgroup.threads"),
        dir.join("cgroup.subtree_control"),
        dir.join("cgroup.freeze"),
    ] {
        if entry.exists() {
            let path = cpath(&entry)?;
            if unsafe { libc::chown(path.as_ptr(), 1000, 1000) } != 0 {
                return Err(io::Error::last_os_error());
            }
            fs::set_permissions(
                &entry,
                fs::Permissions::from_mode(if entry == dir { 0o775 } else { 0o664 }),
            )?;
        }
    }
    Ok(())
}

#[derive(Default)]
pub(in crate::guest) struct GuestCgroups {
    pub(in crate::guest) created: Vec<PathBuf>,
    pub(in crate::guest) memory: Option<crate::guest::cgroup::GuestMemory>,
    pub(in crate::guest) preserve: bool,
}

impl GuestCgroups {
    pub(in crate::guest) fn create(&mut self, path: &Path) -> io::Result<()> {
        // Never adopt an existing subtree: it may belong to another session.
        fs::create_dir(path)?;
        self.created.push(path.to_owned());
        Ok(())
    }

    pub(in crate::guest) fn prepare(&mut self, mounts: &mut Mounts, root: &Path) -> io::Result<()> {
        ssal::namespace_mounts::require_private_mounts(&fs::read_to_string(
            "/proc/self/mountinfo",
        )?)?;
        let backend = self
            .memory
            .as_ref()
            .ok_or_else(|| io::Error::other("Guest memory cgroup was not prepared"))?
            .backend();
        let mut root_cgroups = Vec::new();
        for (source, target) in guest_cgroup_mounts(backend) {
            root_cgroups.push(source.clone());
            let parent = source.parent().unwrap();
            if fs::canonicalize(parent)? != parent {
                return Err(io::Error::other("cgroup parent contains a symlink"));
            }
            self.create(&source)?;
            let memory_group = match backend {
                crate::guest::cgroup::Backend::V2 => target == "sys/fs/cgroup",
                crate::guest::cgroup::Backend::V1 => target == "dev/memcg",
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
            // libprocessgroup creates uid_<uid> below system/ and apps/ under this Guest-owned parent.
            let processgroup_parents = if target == "sys/fs/cgroup"
                && crate::guest::system_server_enabled()
            {
                chown_system_cgroup(&source)?;
                let mut created = Vec::with_capacity(2);
                for name in ["system", "apps"] {
                    let dir = source.join(name);
                    fs::create_dir(&dir)?;
                    chown_system_cgroup(&dir)?;
                    created.push((name, dir));
                }
                created
            } else {
                Vec::new()
            };
            // sysfs is read-only; its existing cgroup mountpoint needs no mkdir.
            let target = if target == "sys/fs/cgroup" {
                guest_path(root, target)?
            } else {
                directory(root, target, 0o755)?
            };
            mounts.bind(&source, &target, false, false)?;
            same_directory(&source, &target)?;
            for (name, dir) in processgroup_parents {
                same_directory(&dir, &target.join(name))?;
                println!(
                    "Guest SystemServer cgroup prepared: {} uid=1000 gid=1000",
                    dir.display()
                );
            }
            println!(
                "Guest cgroup bind: {} -> {}",
                source.display(),
                target.display()
            );
        }
        let namespace = create_cgroup_namespace(&root_cgroups)?;
        *GUEST_CGROUP_NAMESPACE.lock().unwrap() = Some(namespace);
        Ok(())
    }

    pub(in crate::guest) fn cleanup(&mut self) -> io::Result<()> {
        if self.preserve {
            return Err(io::Error::other(
                "unverified descendants; preserve Guest cgroups and controllers",
            ));
        }
        *GUEST_CGROUP_NAMESPACE.lock().unwrap() = None;
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

    pub(in crate::guest) fn prepare_stop_cleanup(&mut self) -> io::Result<()> {
        let Some(memory) = &self.memory else {
            return Ok(());
        };
        let backend = memory.backend();
        let task_group = super::task_group(backend);
        let events = self
            .created
            .contains(&task_group)
            .then(|| task_group.join("cgroup.events"));
        if let Some(events) = &events {
            let mountinfo = fs::read_to_string("/proc/self/mountinfo")?;
            validate_cgroup_root(&task_group, &mountinfo)?;
            if cgroup_populated(events)? {
                match fs::OpenOptions::new()
                    .write(true)
                    .custom_flags(libc::O_NOFOLLOW)
                    .open(task_group.join("cgroup.kill"))
                {
                    Ok(mut kill) => kill.write_all(b"1")?,
                    // Older kernels rely on the worker's pidfd-based descendant cleanup.
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error),
                }
            }
            wait_for_empty_cgroup(events, Duration::from_secs(5))?;
        }

        let mountinfo = fs::read_to_string("/proc/self/mountinfo")?;
        let mut groups = Vec::new();
        for (path, _) in guest_cgroup_mounts(backend) {
            if self.created.contains(&path) {
                validate_cgroup_root(&path, &mountinfo)
                    .and_then(|()| collect_empty_cgroups(&path, &mut groups))
                    .map_err(|error| io::Error::other(format!("{}: {error}", path.display())))?;
            }
        }
        if let Some(events) = &events {
            if cgroup_populated(events)? {
                return Err(io::Error::other("Guest task cgroup became populated again"));
            }
        }
        // Cleanup reverses this list, so each directory is removed once, children first.
        self.created = groups.into_iter().rev().collect();
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

fn pipe_cloexec() -> io::Result<(File, File)> {
    let mut fds = [-1; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { (File::from_raw_fd(fds[0]), File::from_raw_fd(fds[1])) })
}

fn format_pid(mut pid: libc::pid_t, buf: &mut [u8; 24]) -> &[u8] {
    let mut idx = buf.len();
    if pid <= 0 {
        return b"0";
    }
    while pid > 0 {
        idx -= 1;
        buf[idx] = b'0' + (pid % 10) as u8;
        pid /= 10;
    }
    &buf[idx..]
}

fn write_all_fd(fd: RawFd, mut data: &[u8]) -> bool {
    while !data.is_empty() {
        let written = unsafe { libc::write(fd, data.as_ptr().cast(), data.len()) };
        if written < 0 {
            if io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return false;
        }
        data = &data[written as usize..];
    }
    true
}

fn create_cgroup_namespace(groups: &[PathBuf]) -> io::Result<File> {
    let procs_paths: Vec<CString> = groups
        .iter()
        .map(|group| cpath(&group.join("cgroup.procs")))
        .collect::<io::Result<_>>()?;
    let host_ns = fs::read_link("/proc/self/ns/cgroup")?;
    let (mut ready_read, ready_write) = pipe_cloexec()?;
    let (done_read, done_write) = pipe_cloexec()?;

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(io::Error::last_os_error());
    }
    if pid == 0 {
        drop(ready_read);
        drop(done_write);
        let mut pid_buf = [0u8; 24];
        let pid_bytes = format_pid(unsafe { libc::getpid() }, &mut pid_buf);
        for path in &procs_paths {
            let fd = unsafe { libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC) };
            if fd < 0 {
                unsafe { libc::_exit(1) };
            }
            let ok = write_all_fd(fd, pid_bytes);
            unsafe { libc::close(fd) };
            if !ok {
                unsafe { libc::_exit(1) };
            }
        }
        if unsafe { libc::unshare(libc::CLONE_NEWCGROUP) } != 0 {
            unsafe { libc::_exit(2) };
        }
        if !write_all_fd(ready_write.as_raw_fd(), b"1") {
            unsafe { libc::_exit(3) };
        }
        drop(ready_write);
        let mut byte = [0u8; 1];
        loop {
            let n = unsafe { libc::read(done_read.as_raw_fd(), byte.as_mut_ptr().cast(), 1) };
            if n == 0 {
                break;
            }
            if n < 0 && io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                unsafe { libc::_exit(4) };
            }
        }
        unsafe { libc::_exit(0) };
    }

    drop(ready_write);
    drop(done_read);
    let mut ready = [0u8; 1];
    let ready_res = loop {
        match ready_read.read(&mut ready) {
            Ok(n) => break Ok(n),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => break Err(e),
        }
    };
    let ns_result = if matches!(ready_res, Ok(1)) {
        let ns_path = PathBuf::from(format!("/proc/{pid}/ns/cgroup"));
        File::open(&ns_path).and_then(|file| Ok((file, fs::read_link(&ns_path)?)))
    } else {
        Err(ready_res.err().unwrap_or_else(|| {
            io::Error::other("Guest cgroup namespace helper exited before signaling")
        }))
    };
    drop(done_write);

    let mut status = 0;
    let waited = loop {
        let rc = unsafe { libc::waitpid(pid, &mut status, 0) };
        if rc < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        break rc;
    };
    if waited != pid {
        return Err(io::Error::last_os_error());
    }
    if !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
        return Err(io::Error::other(format!(
            "Guest cgroup namespace helper failed: status={status}"
        )));
    }
    let (ns_file, guest_ns) = ns_result?;
    if host_ns == guest_ns {
        return Err(io::Error::other(
            "cgroup namespace did not separate from Host",
        ));
    }
    println!(
        "Guest cgroup namespace isolated: Host={} Guest={}",
        host_ns.display(),
        guest_ns.display()
    );
    Ok(ns_file)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssal::namespace_mounts::require_private_mounts;
    use std::os::unix::fs::symlink;

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
    fn cgroup_drain_requires_populated_zero() -> io::Result<()> {
        let events =
            std::env::temp_dir().join(format!("ssal-cgroup-events-{}", std::process::id()));
        let result = (|| {
            fs::write(&events, "populated 1\nfrozen 0\n")?;
            assert_eq!(
                wait_for_empty_cgroup(&events, Duration::from_millis(20))
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::TimedOut
            );
            fs::write(&events, "frozen 0\n")?;
            assert!(wait_for_empty_cgroup(&events, Duration::ZERO).is_err());
            fs::write(&events, "populated 0\nfrozen 0\n")?;
            wait_for_empty_cgroup(&events, Duration::ZERO)
        })();
        result.and(fs::remove_file(events))
    }

    #[test]
    fn stale_cgroup_scan_rejects_live_descendants_and_orders_empty_groups() -> io::Result<()> {
        let root = std::env::temp_dir().join(format!("ssal-stale-cgroups-{}", std::process::id()));
        fs::create_dir(&root)?;
        let result = (|| {
            let child = root.join("child");
            fs::create_dir(&child)?;
            fs::write(root.join("cgroup.procs"), "")?;
            fs::write(child.join("cgroup.procs"), "123\n")?;
            let mut groups = Vec::new();
            assert!(collect_empty_cgroups(&root, &mut groups).is_err());
            assert!(groups.is_empty());

            fs::write(child.join("cgroup.procs"), "")?;
            let unexpected = root.join("unexpected");
            symlink("/", &unexpected)?;
            assert!(collect_empty_cgroups(&root, &mut Vec::new()).is_err());
            fs::remove_file(unexpected)?;
            collect_empty_cgroups(&root, &mut groups)?;
            assert_eq!(groups, [child, root.clone()]);
            Ok(())
        })();
        result.and(fs::remove_dir_all(root))
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
}
