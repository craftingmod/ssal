use super::{mount, Path};
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::{fs, io};

struct Entry {
    id: u64,
    device: String,
    path: PathBuf,
    options: String,
    overlay: bool,
}

fn entries(info: &str) -> io::Result<Vec<Entry>> {
    info.lines()
        .map(|line| {
            let (left, right) = line
                .split_once(" - ")
                .ok_or_else(|| io::Error::other("malformed system mountinfo"))?;
            let fields: Vec<_> = left.split_whitespace().collect();
            if fields.len() < 6 || right.split_whitespace().count() < 3 {
                return Err(io::Error::other("malformed system mountinfo fields"));
            }
            let path = fields[4]
                .replace("\\040", " ")
                .replace("\\011", "\t")
                .replace("\\012", "\n")
                .replace("\\134", "\\");
            Ok(Entry {
                id: fields[0].parse().map_err(io::Error::other)?,
                device: fields[2].into(),
                path: path.into(),
                options: fields[5].into(),
                overlay: right.split_whitespace().next() == Some("overlay"),
            })
        })
        .collect()
}

fn system_path(root: &Path, path: &Path) -> bool {
    [
        "system",
        "product",
        "system_ext",
        "vendor",
        "odm",
        "vendor_dlkm",
        "system_dlkm",
        "apex",
    ]
    .iter()
    .any(|name| path.starts_with(root.join(name)))
}

fn selected<'a>(all: &'a [Entry], root: &Path) -> io::Result<Vec<&'a Entry>> {
    let overlays: BTreeSet<_> = all
        .iter()
        .filter(|e| e.overlay && system_path(root, &e.path))
        .map(|e| &e.device)
        .collect();
    let mut result = Vec::new();
    for entry in all {
        let alias = entry.overlay && overlays.contains(&entry.device);
        if alias && !entry.path.starts_with(root) {
            return Err(io::Error::other(format!(
                "system overlay alias outside Guest root: {}",
                entry.path.display()
            )));
        }
        if system_path(root, &entry.path) || alias {
            result.push(entry);
        }
    }
    if !result.iter().any(|e| e.path == root.join("system")) {
        return Err(io::Error::other("Guest /system mount missing"));
    }
    Ok(result)
}

fn is_ro(entry: &Entry) -> bool {
    entry.options.split(',').any(|option| option == "ro")
}

fn flags(options: &str) -> libc::c_ulong {
    let mut flags =
        libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV;
    for option in options.split(',') {
        flags |= match option {
            "noexec" => libc::MS_NOEXEC,
            "noatime" => libc::MS_NOATIME,
            "nodiratime" => libc::MS_NODIRATIME,
            "relatime" => libc::MS_RELATIME,
            "strictatime" => libc::MS_STRICTATIME,
            _ => 0,
        };
    }
    flags
}

pub(super) fn seal(root: &Path) -> io::Result<()> {
    let info = fs::read_to_string("/proc/self/mountinfo")?;
    ssal::namespace_mounts::require_private_mounts(&info)?;
    let all = entries(&info)?;
    let mut targets = selected(&all, root)?;
    targets.sort_by_key(|e| std::cmp::Reverse(e.path.components().count()));
    for entry in &targets {
        if !is_ro(entry) {
            mount(
                Path::new("none"),
                &entry.path,
                None,
                flags(&entry.options),
                "",
            )
            .map_err(|e| {
                io::Error::other(format!(
                    "RO bind remount {} (mount {}): {e}",
                    entry.path.display(),
                    entry.id
                ))
            })?;
        }
    }
    let after = entries(&fs::read_to_string("/proc/self/mountinfo")?)?;
    for entry in selected(&after, root)? {
        if !is_ro(entry) {
            return Err(io::Error::other(format!(
                "writable system mount/alias remains: {} (mount {})",
                entry.path.display(),
                entry.id
            )));
        }
    }
    for entry in targets {
        if !after
            .iter()
            .any(|e| e.id == entry.id && e.path == entry.path && is_ro(e))
        {
            return Err(io::Error::other(format!(
                "system mount changed during RO verification: {}",
                entry.path.display()
            )));
        }
    }
    println!("Guest system mounts: RO verified, including submounts and OverlayFS aliases");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "requires CAP_SYS_ADMIN in a disposable mount namespace; run alone"]
    fn real_overlay_aliases_become_ro_and_userdata_stays_rw() -> io::Result<()> {
        if std::env::var_os("SSAL_RO_MOUNT_TEST_CHILD").is_none() {
            let status = std::process::Command::new("unshare")
                .args(["--mount", "--propagation", "private"])
                .arg(std::env::current_exe()?)
                .args(["--ignored", "--exact", "guest::mount::readonly::tests::real_overlay_aliases_become_ro_and_userdata_stays_rw", "--nocapture"])
                .env("SSAL_RO_MOUNT_TEST_CHILD", "1")
                .status()?;
            assert!(status.success());
            return Ok(());
        }
        let base = std::env::temp_dir().join(format!("ssal-ro-mounts-{}", std::process::id()));
        fs::create_dir(&base)?;
        let mut mounts = super::super::Mounts::new();
        let result: io::Result<()> = (|| {
            mounts.tmpfs(&base, 0o755)?;
            let root = base.join("rootfs");
            for path in [
                "rootfs/system",
                "rootfs/apex/runtime@1",
                "rootfs/apex/runtime",
                "rootfs/run/alias",
                "rootfs/data",
                "lower",
                "upper",
                "work",
            ] {
                fs::create_dir_all(base.join(path))?;
            }
            fs::write(base.join("lower/original"), b"original")?;
            fs::create_dir(base.join("lower/child"))?;
            let options = format!(
                "lowerdir={},upperdir={},workdir={}",
                base.join("lower").display(),
                base.join("upper").display(),
                base.join("work").display()
            );
            mounts.attach(
                Path::new("overlay"),
                &root.join("system"),
                Some("overlay"),
                libc::MS_NOSUID | libc::MS_NODEV,
                &options,
            )?;
            mounts.bind(&root.join("system"), &root.join("run/alias"), false, false)?;
            mounts.tmpfs(&root.join("system/child"), 0o755)?;
            mounts.bind(
                &root.join("system"),
                &root.join("apex/runtime@1"),
                false,
                false,
            )?;
            mounts.bind(
                &root.join("apex/runtime@1"),
                &root.join("apex/runtime"),
                true,
                false,
            )?;
            seal(&root)?;
            seal(&root)?;
            for path in [
                "system/blocked",
                "system/child/blocked",
                "run/alias/blocked",
                "apex/runtime@1/blocked",
                "apex/runtime/blocked",
            ] {
                assert_eq!(
                    fs::write(root.join(path), b"blocked")
                        .unwrap_err()
                        .raw_os_error(),
                    Some(libc::EROFS),
                    "{path}"
                );
            }
            fs::write(root.join("data/writable"), b"ok")?;
            assert_eq!(fs::read(base.join("lower/original"))?, b"original");
            assert!(!base.join("lower/blocked").exists());
            Ok(())
        })();
        let cleanup = mounts.cleanup();
        result?;
        cleanup?;
        fs::remove_dir(base)?;
        Ok(())
    }

    #[test]
    fn includes_submounts_versioned_apex_and_overlay_aliases() -> io::Result<()> {
        let info = "1 0 0:1 / /g/system rw,relatime - overlay overlay rw\n\
2 1 0:2 / /g/system/etc/patch ro - ext4 loop ro\n\
3 0 0:3 / /g/apex/runtime@1 rw - overlay overlay rw\n\
4 0 0:3 / /g/apex/runtime ro - overlay overlay rw\n\
5 0 0:1 /bin/sh /g/run/alias rw - overlay overlay rw\n\
6 0 7:1 / /g/data rw - ext4 loop rw\n\
7 0 0:4 / /g/system_other rw - tmpfs tmpfs rw\n\
8 1 0:5 / /g/system/path\\040with\\134slash rw,noexec - tmpfs tmpfs rw\n";
        let all = entries(info)?;
        let targets = selected(&all, Path::new("/g"))?;
        assert_eq!(
            targets.iter().map(|e| e.id).collect::<Vec<_>>(),
            [1, 2, 3, 4, 5, 8]
        );
        assert_eq!(all[7].path, Path::new("/g/system/path with\\slash"));
        assert!(is_ro(&all[3])); // Per-mount RO even though the superblock is RW.
        assert!(!is_ro(&all[2]));
        assert_ne!(flags(&all[7].options) & libc::MS_NOEXEC, 0);
        assert!(selected(
            &entries(&info.replace("/g/run/alias", "/outside/alias"))?,
            Path::new("/g")
        )
        .is_err());
        assert!(selected(&[], Path::new("/g")).is_err());
        assert!(entries("malformed").is_err());
        Ok(())
    }
}
