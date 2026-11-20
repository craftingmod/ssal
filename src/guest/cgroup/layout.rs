use crate::guest::mount::{cpath, directory, guest_path, same_directory};
use ssal::namespace_mounts::Mounts;
use std::ffi::CString;
use std::fs::{self, File};
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

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
            // libprocessgroup creates uid_1000 below this Guest-owned parent.
            let system_cgroup = if target == "sys/fs/cgroup"
                && std::env::var_os("SSAL_START_SYSTEM_SERVER").is_some()
            {
                let system = source.join("system");
                fs::create_dir(&system)?;
                for entry in [
                    system.clone(),
                    system.join("cgroup.procs"),
                    system.join("tasks"),
                    system.join("cgroup.threads"),
                ] {
                    if entry.exists() {
                        let path = cpath(&entry)?;
                        if unsafe { libc::chown(path.as_ptr(), 1000, 1000) } != 0 {
                            return Err(io::Error::last_os_error());
                        }
                        fs::set_permissions(
                            &entry,
                            fs::Permissions::from_mode(if entry == system { 0o755 } else { 0o664 }),
                        )?;
                    }
                }
                Some(system)
            } else {
                None
            };
            // sysfs is read-only; its existing cgroup mountpoint needs no mkdir.
            let target = if target == "sys/fs/cgroup" {
                guest_path(root, target)?
            } else {
                directory(root, target, 0o755)?
            };
            mounts.bind(&source, &target, false, false)?;
            same_directory(&source, &target)?;
            if let Some(system) = system_cgroup {
                same_directory(&system, &target.join("system"))?;
                println!(
                    "Guest SystemServer cgroup prepared: {} uid=1000 gid=1000",
                    system.display()
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
}

impl Drop for GuestCgroups {
    fn drop(&mut self) {
        if let Err(error) = self.cleanup() {
            eprintln!("Guest cgroup cleanup failed: {error}");
        }
    }
}

// Only rmdir descendants of a subtree this worker created, after all children were reaped.
pub(in crate::guest) fn remove_empty_cgroup_children(path: &Path) -> io::Result<()> {
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
}
