//! Phase 2 mounted Guest userdata admission. Never imports Host application data.
use serde_json::{json, Value};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path};

pub const FIELDS: [&str; 5] = [
    "guest_data_isolation",
    "installd",
    "artd",
    "host_unchanged",
    "cleanup",
];

pub fn complete(report: &Value) -> bool {
    FIELDS
        .iter()
        .all(|field| report["checks"][field] == "passed")
}

fn real_directory(path: &Path) -> io::Result<()> {
    if !path.is_absolute() {
        return Err(io::Error::other("userdata must be absolute"));
    }
    let mut current = std::path::PathBuf::new();
    for part in path.components() {
        if matches!(part, Component::ParentDir | Component::CurDir) {
            return Err(io::Error::other("userdata path traversal"));
        }
        current.push(part);
        if !fs::symlink_metadata(&current)?.is_dir() {
            return Err(io::Error::other(
                "userdata path contains a symlink/non-directory",
            ));
        }
    }
    Ok(())
}

pub fn fresh(userdata: &Path) -> io::Result<()> {
    real_directory(userdata)?;
    let meta = fs::metadata(userdata)?;
    if meta.uid() != 0 || meta.mode() & 0o022 != 0 || !crate::guest::userdata::fresh(userdata)? {
        return Err(io::Error::other("Phase 2 requires new empty root-owned userdata, not writable by group/others; create a new profile"));
    }
    Ok(())
}

fn data_mount<'a>(info: &'a str, target: &Path) -> io::Result<&'a str> {
    ssal::namespace_mounts::require_private_mounts(info)?;
    let target = target
        .to_str()
        .ok_or_else(|| io::Error::other("data path encoding"))?;
    let line = info
        .lines()
        .rev()
        .find(|line| line.split_whitespace().nth(4) == Some(target))
        .ok_or_else(|| io::Error::other("Guest /data mount missing"))?;
    let flags = line
        .split_whitespace()
        .nth(5)
        .unwrap_or("")
        .split(',')
        .collect::<Vec<_>>();
    if !["rw", "nosuid", "nodev"]
        .iter()
        .all(|flag| flags.contains(flag))
    {
        return Err(io::Error::other("Guest /data must be rw,nosuid,nodev"));
    }
    Ok(line)
}

pub fn verify_bind(root: &Path, userdata: &Path) -> io::Result<Value> {
    real_directory(userdata)?;
    let data = root.join("data");
    let expected = fs::metadata(userdata)?;
    let actual = fs::symlink_metadata(&data)?;
    let host = fs::metadata("/data")?;
    if !actual.is_dir()
        || (actual.dev(), actual.ino()) != (expected.dev(), expected.ino())
        || actual.dev() == host.dev()
        || fs::read_link("/proc/self/ns/mnt")? == fs::read_link("/proc/1/ns/mnt")?
    {
        return Err(io::Error::other(
            "Guest /data source/namespace identity mismatch",
        ));
    }
    let info = fs::read_to_string("/proc/self/mountinfo")?;
    let line = data_mount(&info, &data)?;
    let marker = data.join(".ssal-phase2-bind-check");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&marker)?;
    let result = (|| {
        file.write_all(b"ssal-phase2-directory-bind\n")?;
        file.sync_all()?;
        let from_profile = File::open(userdata.join(".ssal-phase2-bind-check"))?.metadata()?;
        let written = file.metadata()?;
        if (written.dev(), written.ino()) != (from_profile.dev(), from_profile.ino()) {
            return Err(io::Error::other("write did not reach profile userdata"));
        }
        Ok(())
    })();
    drop(file);
    fs::remove_file(marker)?;
    result?;
    Ok(
        json!({"source":userdata,"identity":[actual.dev(),actual.ino()],"host_identity":[host.dev(),host.ino()],"mountinfo":line,"write_roundtrip":true,"propagation":"private"}),
    )
}

pub fn prepare(root: &Path) -> io::Result<Value> {
    let mut layout = Vec::new();
    let data = File::open(root.join("data"))?;
    if unsafe { libc::fchown(data.as_raw_fd(), 1000, 1000) } != 0 {
        return Err(io::Error::last_os_error());
    }
    data.set_permissions(fs::Permissions::from_mode(0o771))?;
    for (path, mode, uid, gid, label) in [
        ("app", 0o771, 1000, 1000, "apk_data_file"),
        ("app-staging", 0o771, 1000, 1000, "staging_data_file"),
        ("user", 0o711, 1000, 1000, "system_data_file"),
        ("user/0", 0o771, 1000, 1000, "system_data_file"),
        ("user_de", 0o711, 1000, 1000, "system_data_file"),
        ("user_de/0", 0o771, 1000, 1000, "system_data_file"),
        ("misc", 0o1771, 1000, 9998, "system_data_file"),
        ("misc/installd", 0o700, 0, 0, "install_data_file"),
        ("misc/profiles", 0o775, 1000, 1000, "user_profile_root_file"),
        ("misc/profiles/cur", 0o711, 0, 0, "user_profile_root_file"),
        (
            "misc/profiles/cur/0",
            0o771,
            1000,
            1000,
            "user_profile_root_file",
        ),
        (
            "misc/profiles/ref",
            0o770,
            1000,
            1000,
            "user_profile_root_file",
        ),
        ("misc/user", 0o755, 0, 0, "system_data_file"),
        ("dalvik-cache", 0o771, 0, 0, "dalvikcache_data_file"),
        ("dalvik-cache/arm64", 0o771, 0, 0, "dalvikcache_data_file"),
        ("local", 0o751, 0, 0, "shell_data_file"),
        ("local/tmp", 0o755, 0, 0, "shell_data_file"),
    ] {
        let path = crate::guest::mount::directory(&root.join("data"), path, mode)?;
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(&path)?;
        if unsafe { libc::fchown(file.as_raw_fd(), uid, gid) } != 0 {
            return Err(io::Error::last_os_error());
        }
        fs::set_permissions(&path, fs::Permissions::from_mode(mode))?;
        let context = format!("u:object_r:{label}:s0");
        let rc = unsafe {
            libc::fsetxattr(
                file.as_raw_fd(),
                c"security.selinux".as_ptr(),
                context.as_ptr().cast(),
                context.len(),
                0,
            )
        };
        // shortcut: labels are diagnostic in this permissive probe, require policy proof before Enforcing admission.
        layout.push(json!({"path":path,"uid":uid,"gid":gid,"mode":format!("{mode:o}"),"expected_label":context,"actual_label":ssal::unix::image_context(&file).ok(),"label_errno":if rc == 0 {None} else {io::Error::last_os_error().raw_os_error()}}));
    }
    Ok(json!(layout))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn gate_never_accepts_missing_failed_or_unavailable_fields() {
        let mut report = json!({"checks":{}});
        assert!(!complete(&report));
        for field in FIELDS {
            report["checks"][field] = json!("passed");
        }
        assert!(complete(&report));
        for field in FIELDS {
            for status in ["not_run", "failed", "unavailable"] {
                report["checks"][field] = json!(status);
                assert!(!complete(&report));
            }
            report["checks"][field] = json!("passed");
        }
    }
    #[test]
    fn rejects_aliases_existing_data_and_unsafe_mounts() -> io::Result<()> {
        let base = std::env::temp_dir().join(format!("ssal-phase2-{}", std::process::id()));
        fs::create_dir(&base)?;
        let data = base.join("userdata");
        fs::create_dir(&data)?;
        fs::write(data.join("host-data"), b"do not import")?;
        assert!(fresh(&data).is_err());
        std::os::unix::fs::symlink(&data, base.join("alias"))?;
        assert!(real_directory(&base.join("alias")).is_err());
        assert!(data_mount(
            "1 0 8:1 /profile /guest/data rw,nosuid,nodev - ext4 /dev/test rw",
            Path::new("/guest/data")
        )
        .is_ok());
        for text in [
            "1 0 8:1 / /guest/data rw - ext4 /dev/test rw",
            "1 0 8:1 / /guest/data rw,nosuid,nodev shared:2 - ext4 /dev/test rw",
            "",
        ] {
            assert!(data_mount(text, Path::new("/guest/data")).is_err());
        }
        fs::remove_dir_all(base)
    }
}
