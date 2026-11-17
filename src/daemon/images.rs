use super::atomic;
use sha2::{Digest, Sha256};
use ssal::unix::valid_image_name;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::fd::OwnedFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
pub(super) fn register(
    root: &Path,
    fd: OwnedFd,
    id: &str,
    image_name: &str,
    label: impl FnOnce(&File) -> io::Result<()>,
) -> io::Result<String> {
    let mut input = File::from(fd);
    let meta = input.metadata()?;
    if !meta.is_file() || meta.len() < 2048 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "source must be a raw ext4 regular file",
        ));
    }
    let cpath = std::ffi::CString::new(root.join("images").as_os_str().as_encoded_bytes()).unwrap();
    let mut stats: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(cpath.as_ptr(), &mut stats) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if (stats.f_bavail as u128) * (stats.f_frsize as u128) < meta.len() as u128 + 16 * 1024 * 1024 {
        return Err(io::Error::other("insufficient free space"));
    }
    input.seek(SeekFrom::Start(1080))?;
    let mut magic = [0; 2];
    input.read_exact(&mut magic)?;
    if magic != [0x53, 0xef] {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported image: expected raw ext4 (convert sparse or compressed images first)",
        ));
    }
    input.seek(SeekFrom::Start(0))?;
    let temp = root.join("images").join(format!(".tmp-{id}"));
    fs::create_dir(&temp)?;
    let result = (|| {
        let mut out = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(temp.join("system.img"))?;
        label(&out)?;
        let mut hash = Sha256::new();
        let mut buf = vec![0; 1024 * 1024];
        let mut size = 0u64;
        loop {
            let n = input.read(&mut buf)?;
            if n == 0 {
                break;
            }
            out.write_all(&buf[..n])?;
            hash.update(&buf[..n]);
            size += n as u64;
        }
        if size != meta.len() {
            return Err(io::Error::other("source changed during copy"));
        }
        out.sync_all()?;
        let digest = hash
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let manifest = serde_json::json!({"id": id, "image_name": image_name, "format": "raw-ext4", "sha256": digest, "size": size, "android_version": null, "profile": null});
        atomic(
            &temp.join("manifest.json"),
            serde_json::to_string_pretty(&manifest)?.as_bytes(),
        )?;
        File::open(&temp)?.sync_all()?;
        fs::rename(&temp, root.join("images").join(id))?;
        File::open(root.join("images"))?.sync_all()?;
        atomic(
            &root.join("state/image-refs").join(image_name),
            id.as_bytes(),
        )?;
        Ok(format!("registered image {image_name} ({id}, sha256 {digest}); ext4 magic checked, filesystem and Android compatibility not yet verified"))
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&temp);
    }
    result
}
pub(super) fn migrate_legacy_image(root: &Path) -> io::Result<()> {
    let legacy = root.join("state/lineage-image");
    let destination = root.join("state/image-refs/lineage");
    if !destination.exists() {
        match fs::read(legacy) {
            Ok(data) => atomic(&destination, &data)?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => (),
            Err(e) => return Err(e),
        }
    }
    Ok(())
}
pub(super) fn image_list(root: &Path) -> io::Result<String> {
    let mut images = Vec::new();
    for entry in fs::read_dir(root.join("state/image-refs"))? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if valid_image_name(&name) && entry.file_type()?.is_file() {
            images.push(format!(
                "{name}: {}",
                fs::read_to_string(entry.path())?.trim()
            ));
        }
    }
    images.sort();
    Ok(if images.is_empty() {
        "none".into()
    } else {
        images.join("\n")
    })
}

#[cfg(test)]
mod tests {
    use super::super::now;
    use super::*;
    #[test]
    fn names_registration_and_legacy_migration() -> io::Result<()> {
        for name in ["", ".", "..", "../escape", "a/b", "a.b", "space name"] {
            assert!(!valid_image_name(name));
        }
        assert!(valid_image_name("Lineage_23-test"));
        assert!(!valid_image_name(&"a".repeat(65)));

        let root = std::env::temp_dir().join(format!("ssal-test-{}-{}", std::process::id(), now()));
        fs::create_dir_all(root.join("images"))?;
        fs::create_dir_all(root.join("state/image-refs"))?;
        fs::write(root.join("state/lineage-image"), "old-id")?;
        migrate_legacy_image(&root)?;
        assert_eq!(
            fs::read_to_string(root.join("state/image-refs/lineage"))?,
            "old-id"
        );

        let source = root.join("source.img");
        let mut bytes = vec![0u8; 4096];
        bytes[1080..1082].copy_from_slice(&[0x53, 0xef]);
        fs::write(&source, bytes)?;
        register(&root, File::open(&source)?.into(), "first", "alpha", |_| {
            Ok(())
        })?;
        register(&root, File::open(&source)?.into(), "second", "beta", |_| {
            Ok(())
        })?;
        register(&root, File::open(&source)?.into(), "third", "alpha", |_| {
            Ok(())
        })?;
        assert!(register(
            &root,
            File::open(&source)?.into(),
            "failed",
            "alpha",
            |_| Err(io::Error::other("label failed"))
        )
        .is_err());
        assert!(!root.join("images/.tmp-failed").exists());
        assert_eq!(
            fs::read_to_string(root.join("state/image-refs/alpha"))?,
            "third"
        );
        assert_eq!(
            fs::read_to_string(root.join("state/image-refs/beta"))?,
            "second"
        );
        assert_eq!(
            fs::read_to_string(root.join("state/image-refs/lineage"))?,
            "old-id"
        );
        fs::write(root.join("state/image-refs/lineage"), "new-id")?;
        migrate_legacy_image(&root)?;
        assert_eq!(
            fs::read_to_string(root.join("state/image-refs/lineage"))?,
            "new-id"
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }
}
