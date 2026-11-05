//! Persistent Guest storage. Never formats an existing image.
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt};
use std::path::{Component, Path};
use std::process::Command;

pub const SIZE: u64 = 8 * 1024 * 1024 * 1024;

fn tool(name: &str) -> Command {
    if cfg!(target_os = "android") {
        Command::new(format!("/system/bin/{name}"))
    } else {
        Command::new(name)
    }
}

pub fn open(path: &Path) -> io::Result<File> {
    if !path.is_absolute() {
        return Err(io::Error::other("userdata image path must be absolute"));
    }
    let mut current = std::path::PathBuf::new();
    for part in path.components() {
        if matches!(part, Component::ParentDir | Component::CurDir) {
            return Err(io::Error::other("userdata path traversal"));
        }
        current.push(part);
        let meta = fs::symlink_metadata(&current)?;
        if current != path && !meta.is_dir() {
            return Err(io::Error::other("userdata parent must be a real directory"));
        }
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() || meta.uid() != 0 || meta.mode() & 0o077 != 0 || meta.nlink() != 1 {
        return Err(io::Error::other(
            "userdata must be a root-owned 0600 regular file with one link",
        ));
    }
    #[cfg(target_os = "android")]
    if ssal::unix::image_context(&file)? != "u:object_r:ssal_userdata_image_file:s0" {
        return Err(io::Error::other(
            "userdata SELinux label mismatch; expected ssal_userdata_image_file",
        ));
    }
    let mut magic = [0; 2];
    file.read_exact_at(&mut magic, 1080)?;
    if magic != [0x53, 0xef] {
        return Err(io::Error::other("userdata is not raw ext4"));
    }
    Ok(file)
}

pub fn lock(file: &File) -> io::Result<()> {
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(io::Error::other(format!(
            "userdata is busy: {}",
            io::Error::last_os_error()
        )));
    }
    Ok(())
}

pub fn check_filesystem(path: &Path) -> io::Result<()> {
    detached(path)?;
    let output = tool("e2fsck")
        .arg("-p")
        .arg(path)
        .output()
        .map_err(|e| io::Error::other(format!("cannot run userdata e2fsck: {e}")))?;
    if !matches!(output.status.code(), Some(0 | 1)) {
        return Err(io::Error::other(format!(
            "userdata e2fsck {}: {}{}; image preserved, offline repair required",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(())
}

pub fn detached(path: &Path) -> io::Result<()> {
    let expected = fs::metadata(path)?;
    for entry in fs::read_dir("/sys/block")? {
        let entry = entry?;
        if !entry.file_name().as_encoded_bytes().starts_with(b"loop") {
            continue;
        }
        let backing = match fs::read_to_string(entry.path().join("loop/backing_file")) {
            Ok(value) => value,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        };
        if let Ok(actual) = fs::metadata(backing.trim()) {
            if (expected.dev(), expected.ino()) == (actual.dev(), actual.ino()) {
                return Err(io::Error::other(
                    "userdata is still attached to a loop device; refusing offline access",
                ));
            }
        }
    }
    Ok(())
}

pub fn create(path: &Path, size: u64) -> io::Result<()> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    let result = (|| {
        let mut stats: libc::statvfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstatvfs(file.as_raw_fd(), &mut stats) } != 0 {
            return Err(io::Error::last_os_error());
        }
        if (stats.f_bavail as u128) * (stats.f_frsize as u128) < size as u128 + 256 * 1024 * 1024 {
            return Err(io::Error::other(
                "insufficient space for userdata and 256 MiB Host reserve",
            ));
        }
        let error = unsafe { libc::posix_fallocate(file.as_raw_fd(), 0, size as libc::off_t) };
        if error != 0 {
            return Err(io::Error::from_raw_os_error(error));
        }
        #[cfg(target_os = "android")]
        {
            let context = c"u:object_r:ssal_userdata_image_file:s0";
            if unsafe {
                libc::fsetxattr(
                    file.as_raw_fd(),
                    c"security.selinux".as_ptr(),
                    context.as_ptr().cast(),
                    context.to_bytes_with_nul().len(),
                    0,
                )
            } != 0
            {
                return Err(io::Error::other(format!(
                    "cannot label Guest userdata: {}; load the updated module policy",
                    io::Error::last_os_error()
                )));
            }
        }
        let output = tool("mke2fs")
            .args(["-q", "-t", "ext4", "-F", "-b", "4096", "-m", "0", "-L", "ssal-data", "-O", "none,has_journal,ext_attr,extent,filetype,sparse_super,large_file,huge_file,dir_nlink,extra_isize", "-E", "nodiscard,lazy_itable_init=0,lazy_journal_init=0"])
            .arg(path).output()
            .map_err(|e| io::Error::other(format!("cannot run userdata mke2fs: {e}")))?;
        if !output.status.success() {
            return Err(io::Error::other(format!(
                "userdata mke2fs {}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            )));
        }
        file.sync_all()?;
        check_filesystem(path)
    })();
    if result.is_err() {
        fs::remove_file(path)?;
    }
    result
}

pub fn fresh(path: &Path) -> io::Result<bool> {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        if entry.file_name() != "lost+found"
            || !entry.file_type()?.is_dir()
            || fs::read_dir(entry.path())?.next().is_some()
        {
            return Ok(false);
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_checks_and_locks_without_overwriting() -> io::Result<()> {
        let dir = std::env::temp_dir().join(format!("ssal-userdata-{}", std::process::id()));
        fs::create_dir(&dir)?;
        let path = dir.join("userdata.img");
        create(&path, 32 * 1024 * 1024)?;
        let file = open(&path)?;
        lock(&file)?;
        assert!(lock(&open(&path)?).is_err());
        assert!(create(&path, 32 * 1024 * 1024).is_err());
        assert_eq!(file.metadata()?.len(), 32 * 1024 * 1024);
        assert!(file.metadata()?.blocks() * 512 >= file.metadata()?.len());
        check_filesystem(&path)?;
        std::os::unix::fs::symlink(&path, dir.join("alias.img"))?;
        assert!(open(&dir.join("alias.img")).is_err());
        let empty = dir.join("empty");
        fs::create_dir(&empty)?;
        assert!(fresh(&empty)?);
        fs::create_dir(empty.join("lost+found"))?;
        assert!(fresh(&empty)?);
        fs::write(empty.join("lost+found/recovered"), b"recovered")?;
        assert!(!fresh(&empty)?);
        fs::hard_link(&path, dir.join("linked.img"))?;
        assert!(open(&path).is_err());
        fs::remove_file(dir.join("linked.img"))?;
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;
        assert!(open(&path).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        file.write_all_at(&[0, 0], 1080)?;
        assert!(open(&path).is_err());
        assert!(check_filesystem(&path).is_err());
        assert!(path.exists());
        assert!(create(&dir.join("failed.img"), 0).is_err());
        assert!(!dir.join("failed.img").exists());
        drop(file);
        fs::remove_dir_all(dir)
    }
}
