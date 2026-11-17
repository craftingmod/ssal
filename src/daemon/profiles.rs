use super::atomic;
use ssal::unix::valid_image_name;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::process::Command;
pub(super) fn create_profile(
    root: &Path,
    image_name: &str,
    requested: Option<&str>,
    userdata_size: u64,
) -> io::Result<String> {
    if !valid_image_name(image_name) || requested.is_some_and(|name| !valid_image_name(name)) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid image or profile name",
        ));
    }
    let id = fs::read_to_string(root.join("state/image-refs").join(image_name))?;
    let id = id.trim();
    if !valid_image_name(id) || !root.join("images").join(id).join("system.img").is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "registered image is missing or invalid",
        ));
    }
    let profiles = root.join("guests");
    let name = match requested {
        Some(name) => name.to_owned(),
        None => (1u64..)
            .map(|i| format!("profile{i}"))
            .find(|name| !profiles.join(name).exists())
            .ok_or_else(|| io::Error::other("no profile name available"))?,
    };
    let destination = profiles.join(&name);
    if destination.exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "profile already exists",
        ));
    }
    let temp = profiles.join(format!(".create-{name}"));
    fs::create_dir(&temp)?;
    let result = (|| {
        let data = temp.join("userdata.img");
        crate::guest::userdata::create(&data, userdata_size)?;
        let property = |key: &str| -> Option<String> {
            let output = Command::new("/system/bin/getprop").arg(key).output().ok()?;
            if !output.status.success() {
                return None;
            }
            let value = String::from_utf8(output.stdout).ok()?.trim().to_owned();
            (!value.is_empty()).then_some(value)
        };
        let manifest = serde_json::json!({"version": 3, "name": name, "image_name": image_name, "image_id": id,
            "selinux_id": ssal::guest_policy::allocate_id(root)?,
            "mount_profile": crate::guest::mount::PROFILE_NAME,
            "guest_lock_compat": ssal::guest_lock_compat::Config::default(),
            "guest_lock_compat_creation": {"version": 1, "userdata_state": "empty-at-creation", "application_phase": "before-first-service", "migration_allowed": false},
            "device": {"product_device": property("ro.product.device"), "product_model": property("ro.product.model"), "build_fingerprint": property("ro.build.fingerprint"), "configuration": null},
            "userdata": {"path": "userdata.img", "format": "raw-ext4", "size": userdata_size}, "compatibility": "unverified"});
        atomic(
            &temp.join("profile.json"),
            serde_json::to_vec_pretty(&manifest)?.as_slice(),
        )?;
        File::open(&temp)?.sync_all()?;
        fs::rename(&temp, &destination)?;
        File::open(&profiles)?.sync_all()?;
        Ok(format!("created profile {name} for {image_name} ({id}); userdata: {userdata_size} bytes ext4 image; device compatibility unverified"))
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&temp);
    }
    result
}

pub(super) fn profile_list(root: &Path) -> io::Result<String> {
    let mut names = Vec::new();
    for entry in fs::read_dir(root.join("guests"))? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if valid_image_name(&name)
            && entry.file_type()?.is_dir()
            && entry.path().join("profile.json").is_file()
        {
            names.push(name);
        }
    }
    names.sort();
    Ok(if names.is_empty() {
        "none".into()
    } else {
        names.join("\n")
    })
}
pub(super) fn remove_profile(root: &Path, name: &str) -> io::Result<()> {
    if !valid_image_name(name) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid profile name",
        ));
    }
    let profiles = root.join("guests");
    let path = profiles.join(name);
    if !fs::symlink_metadata(&path)?.is_dir()
        || !fs::symlink_metadata(path.join("profile.json"))?.is_file()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a profile directory",
        ));
    }
    let data_lock = if path.join("userdata.img").exists() {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(path.join("userdata.img"))?;
        if !file.metadata()?.is_file() {
            return Err(io::Error::other("userdata image is not a regular file"));
        }
        crate::guest::userdata::lock(&file)?;
        crate::guest::userdata::detached(&path.join("userdata.img"))?;
        Some(file)
    } else {
        None
    };
    let mountinfo = fs::read_to_string("/proc/self/mountinfo")?;
    let prefix = format!("{}/", path.display());
    if mountinfo
        .lines()
        .filter_map(|line| line.split_whitespace().nth(4))
        .any(|mount| mount == path.to_string_lossy() || mount.starts_with(&prefix))
    {
        return Err(io::Error::other(
            "profile contains a mount; refusing to remove it",
        ));
    }
    fs::remove_dir_all(&path)?;
    drop(data_lock);
    File::open(profiles)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::now;
    use super::*;
    #[test]
    fn profile_creation_names_and_failure_cleanup() -> io::Result<()> {
        let root = std::env::temp_dir().join(format!(
            "ssal-profiles-test-{}-{}",
            std::process::id(),
            now()
        ));
        fs::create_dir_all(root.join("images/id-1"))?;
        fs::create_dir_all(root.join("state/image-refs"))?;
        fs::create_dir_all(root.join("guests"))?;
        fs::write(root.join("images/id-1/system.img"), b"image")?;
        fs::write(root.join("state/image-refs/lineage"), b"id-1")?;
        create_profile(&root, "lineage", None, 32 * 1024 * 1024)?;
        create_profile(&root, "lineage", None, 32 * 1024 * 1024)?;
        let profile: serde_json::Value =
            serde_json::from_slice(&fs::read(root.join("guests/profile1/profile.json"))?)?;
        assert_eq!(profile["image_id"], "id-1");
        assert_eq!(profile["version"], 3);
        assert_eq!(profile["userdata"]["format"], "raw-ext4");
        assert_eq!(profile["userdata"]["size"], 32 * 1024 * 1024);
        assert_eq!(profile["guest_lock_compat"]["enabled"], false);
        assert_eq!(profile["guest_lock_compat"]["require_fresh_userdata"], true);
        assert_eq!(profile["guest_lock_compat_creation"]["version"], 1);
        assert_eq!(
            profile["guest_lock_compat_creation"]["migration_allowed"],
            false
        );
        assert_eq!(profile["mount_profile"], crate::guest::mount::PROFILE_NAME);
        assert!(crate::guest::userdata::open(&root.join("guests/profile1/userdata.img")).is_ok());
        assert!(root.join("guests/profile2/profile.json").exists());
        assert!(create_profile(&root, "lineage", Some("profile1"), 32 * 1024 * 1024).is_err());
        assert!(create_profile(&root, "missing", Some("other"), 32 * 1024 * 1024).is_err());
        assert!(create_profile(&root, "lineage", Some("../bad"), 32 * 1024 * 1024).is_err());
        assert!(create_profile(&root, "lineage", Some("failed"), 0).is_err());
        assert!(!root.join("guests/failed").exists());
        assert!(!root.join("guests/.create-failed").exists());
        std::os::unix::fs::symlink(root.join("images/id-1"), root.join("guests/profile1/link"))?;
        let active = crate::guest::userdata::open(&root.join("guests/profile1/userdata.img"))?;
        crate::guest::userdata::lock(&active)?;
        assert!(remove_profile(&root, "profile1").is_err());
        drop(active);
        // A damaged filesystem can still be explicitly discarded.
        fs::write(root.join("guests/profile1/userdata.img"), b"damaged")?;
        remove_profile(&root, "profile1")?;
        assert!(!root.join("guests/profile1").exists());
        assert!(root.join("guests/profile2/profile.json").exists());
        assert!(root.join("images/id-1/system.img").exists());
        assert!(remove_profile(&root, "profile1").is_err());
        assert!(remove_profile(&root, "../images").is_err());
        fs::remove_dir_all(root)?;
        Ok(())
    }
}
