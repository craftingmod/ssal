use crate::guest::mount::{cpath, directory, guest_path, same_directory};
use ssal::namespace_mounts::Mounts;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
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
        for (source, target) in guest_cgroup_mounts(backend) {
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
        Ok(())
    }

    pub(in crate::guest) fn cleanup(&mut self) -> io::Result<()> {
        if self.preserve {
            return Err(io::Error::other(
                "unverified descendants; preserve Guest cgroups and controllers",
            ));
        }
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
