use ssal::namespace_mounts::Mounts;
use std::fs::{self, File};
use std::io;
use std::os::unix::fs::symlink;
use std::path::Path;

pub(super) fn compose_system(mounts: &mut Mounts, system: &Path, root: &Path) -> io::Result<()> {
    if !fs::symlink_metadata(system.join("system")).is_ok_and(|meta| meta.is_dir()) {
        let target = crate::guest::mount::directory(root, "system", 0o755)?;
        mounts.bind(system, &target, true, false)?;
        return Ok(());
    }
    for entry in fs::read_dir(system)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            return Err(io::Error::other("non-UTF8 system root entry"));
        };
        if matches!(
            name_str,
            "data"
                | "dev"
                | "proc"
                | "sys"
                | "mnt"
                | "storage"
                | "data_mirror"
                | "apex"
                | "linkerconfig"
                | "run"
                | "vendor"
                | "odm"
                | "vendor_dlkm"
                | "postinstall"
                | "lost+found"
                | "tmp"
                | "cache"
                | "metadata"
                | "config"
                | ".ssal-old-root"
        ) {
            continue;
        }
        let target = root.join(&name);
        let kind = entry.file_type()?;
        if kind.is_symlink() {
            symlink(fs::read_link(entry.path())?, target)?;
        } else if kind.is_dir() {
            fs::create_dir(&target)?;
            mounts.bind(&entry.path(), &target, true, false)?;
        } else if kind.is_file() {
            File::create(&target)?;
            mounts.bind(&entry.path(), &target, true, false)?;
        }
    }
    Ok(())
}
