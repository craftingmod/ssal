use super::{directory, guest_path};
use ssal::namespace_mounts::{mount, Mounts};
use std::fs;
use std::fs::File;
use std::io;
use std::path::Path;
use std::process::{Command, Stdio};
fn unzip(archive: &Path, member: &str, output: &Path) -> io::Result<()> {
    let mut command = if Path::new("/system/bin/unzip").is_file() {
        Command::new("/system/bin/unzip")
    } else if Path::new("/data/adb/ksu/bin/busybox").is_file() {
        let mut command = Command::new("/data/adb/ksu/bin/busybox");
        command.arg("unzip");
        command
    } else {
        Command::new("unzip")
    };
    let result = command
        .args(["-p"])
        .arg(archive)
        .arg(member)
        .stdout(Stdio::from(File::create(output).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("create extraction output {}: {e}", output.display()),
            )
        })?))
        .output()
        .map_err(|e| {
            io::Error::new(
                e.kind(),
                format!(
                    "execute APEX unzip {:?} for {} ({member}): {e}",
                    command.get_program(),
                    archive.display()
                ),
            )
        })?;
    if !result.status.success() {
        return Err(io::Error::other(format!(
            "APEX extraction {} ({member}): {}",
            archive.display(),
            String::from_utf8_lossy(&result.stderr)
        )));
    }
    Ok(())
}

fn varint(bytes: &mut &[u8]) -> io::Result<u64> {
    let mut value = 0;
    for shift in (0..70).step_by(7) {
        let byte = *bytes
            .first()
            .ok_or_else(|| io::Error::other("truncated protobuf varint"))?;
        *bytes = &bytes[1..];
        if shift == 63 && byte > 1 {
            return Err(io::Error::other("protobuf varint overflow"));
        }
        value |= u64::from(byte & 127) << shift;
        if byte & 128 == 0 {
            return Ok(value);
        }
    }
    Err(io::Error::other("invalid protobuf varint"))
}

// AOSP ApexManifest: name = field 1, version = field 2. Other fields are skipped.
fn apex_identity(mut bytes: &[u8]) -> io::Result<(String, u64, Option<String>)> {
    let mut name = None;
    let mut version_name = None;
    let mut version = None;
    while !bytes.is_empty() {
        let key = varint(&mut bytes)?;
        if key >> 3 == 0 {
            return Err(io::Error::other("invalid protobuf field"));
        }
        match key & 7 {
            0 => {
                let value = varint(&mut bytes)?;
                if key >> 3 == 2 {
                    version = Some(value);
                }
            }
            1 | 5 => {
                let size = if key & 7 == 1 { 8 } else { 4 };
                bytes = bytes
                    .get(size..)
                    .ok_or_else(|| io::Error::other("truncated protobuf field"))?;
            }
            2 => {
                let size = usize::try_from(varint(&mut bytes)?).map_err(io::Error::other)?;
                let value = bytes
                    .get(..size)
                    .ok_or_else(|| io::Error::other("truncated protobuf string"))?;
                if key >> 3 == 1 {
                    name = Some(
                        std::str::from_utf8(value)
                            .map_err(io::Error::other)?
                            .to_owned(),
                    );
                }
                if key >> 3 == 5 {
                    version_name = Some(std::str::from_utf8(value).map_err(io::Error::other)?.to_owned());
                }
                bytes = &bytes[size..];
            }
            _ => return Err(io::Error::other("unsupported protobuf wire type")),
        }
    }
    let name = name.ok_or_else(|| io::Error::other("APEX module name missing"))?;
    let version = version.ok_or_else(|| io::Error::other("APEX version missing"))?;
    if name.is_empty()
        || matches!(name.as_str(), "." | "..")
        || !name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
        || version > i64::MAX as u64
    {
        return Err(io::Error::other("invalid APEX module identity"));
    }
    Ok((name, version, version_name))
}

pub(super) fn prepare(
    mounts: &mut Mounts,
    root: &Path,
    cache: &Path,
    loop_nodes: &crate::guest::mount::loop_device::LoopNodes,
    policy: Option<&ssal::guest_policy::Plan>,
) -> io::Result<()> {
    fs::create_dir(cache)?;
    if let Some(plan) = policy {
        ssal::guest_policy::runtime::set_label(
            &root.join("apex"),
            &plan.context("apex_mnt_dir", false)?,
        )?;
    }
    let mut packages = Vec::new();
    for (partition, source) in [
        "system/apex",
        "system_ext/apex",
        "product/apex",
        "vendor/apex",
    ].into_iter().enumerate() {
        let path = match guest_path(root, source) {
            Ok(path) => path,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        };
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                continue;
            }
            let path = entry.path();
            if matches!(
                path.extension().and_then(|x| x.to_str()),
                Some("apex" | "capex")
            ) {
                packages.push((path, partition as i8));
            }
        }
    }
    packages.sort();
    if packages.is_empty() {
        return Err(io::Error::other("no guest APEX packages found"));
    }
    let mut metadata =
        String::from("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<apex-info-list>\n");
    let package_dir = directory(root, "apex/.packages", 0o755)?;
    let mut registry = Vec::new();
    for (index, (package, partition)) in packages.iter().enumerate() {
        println!(
            "preparing APEX {}/{}: {}",
            index + 1,
            packages.len(),
            package.display()
        );
        (|| -> io::Result<()> {
        let payload = cache.join(format!("{index}.img"));
        let original = if package.extension().is_some_and(|x| x == "capex") {
            let original = cache.join(format!("{index}.apex"));
            unzip(package, "original_apex", &original)?;
            if let Some(plan) = policy {
                ssal::guest_policy::runtime::set_label(
                    &original,
                    &plan.context("apex_data_file", false)?,
                )?;
            }
            original
        } else {
            package.clone()
        };
        let manifest_file = cache.join(format!("{index}.pb"));
        unzip(&original, "apex_manifest.pb", &manifest_file)?;
        let (name, version, version_name) = apex_identity(&fs::read(&manifest_file)?)?;
        fs::remove_file(manifest_file)?;
        let destination = root.join("apex").join(&name);
        if destination.exists() {
            return Err(io::Error::other(format!("duplicate APEX module {name}")));
        }
        unzip(&original, "apex_payload.img", &payload)?;
        #[cfg(target_os = "android")]
        ssal::unix::label_image(&File::open(&payload)?)?;
        println!("APEX {name}: allocating loop for {}", payload.display());
        let (device, device_path) =
            crate::guest::mount::loop_device::loop_device(&payload, true, loop_nodes)?;
        mounts.loops.push(device);
        let versioned = root.join("apex").join(format!("{name}@{version}"));
        fs::create_dir(&versioned)?;
        crate::guest::mount::loop_device::mount_image(&device_path, &versioned, true)
            .map_err(|e| io::Error::new(e.kind(), format!("mount payload {} -> {}: {e}", device_path.display(), versioned.display())))?;
        mounts.paths.push(versioned.clone());
        let payload_manifest = versioned.join("apex_manifest.pb");
        let payload_identity = apex_identity(&fs::read(&payload_manifest)
            .map_err(|e| io::Error::new(e.kind(), format!("read payload manifest {}: {e}", payload_manifest.display())))?)?;
        if payload_identity != (name.clone(), version, version_name.clone()) {
            return Err(io::Error::other("APEX outer/payload manifest mismatch"));
        }
        if let Some(plan) = policy {
            ssal::guest_policy::runtime::isolate_tree(plan, mounts, &versioned,
                &root.parent().unwrap().join("selinux-overlay").join(format!("apex-{index}")))?;
        }
        fs::create_dir(&destination)?;
        mounts.bind(&versioned, &destination, true, false)?;
        let package_target = package_dir.join(format!("{index}.apex"));
        File::create(&package_target)?;
        mounts.bind(&original, &package_target, true, false)?;
        let source_path = format!("/{}", package.strip_prefix(root).map_err(io::Error::other)?.to_str().ok_or_else(|| io::Error::other("non UTF-8 APEX path"))?);
        registry.push(ssal::apex_registry::Package {
            module_name: name.clone(), version_code: version as i64, version_name,
            source_path, module_path: format!("/apex/.packages/{index}.apex"),
            mount_path: format!("/apex/{name}@{version}"), partition: *partition, is_active: true,
        });
        metadata.push_str(&format!("  <apex-info moduleName=\"{name}\" modulePath=\"/apex/.packages/{index}.apex\" preinstalledModulePath=\"/apex/.packages/{index}.apex\" versionCode=\"{version}\" versionName=\"\" isFactory=\"true\" isActive=\"true\" lastUpdateMillis=\"0\"/>\n"));
        if original != *package {
            fs::remove_file(original)?;
        }
        fs::remove_file(&payload)?;
        println!("guest APEX: {name} <- {} (ro)", package.display());
        Ok(())
        })().map_err(|e| io::Error::new(e.kind(), format!("APEX package {}: {e}", package.display())))?;
    }
    metadata.push_str("</apex-info-list>\n");
    fs::write(root.join("apex/apex-info-list.xml"), metadata)?;
    ssal::apex_registry::validate(&registry).map_err(io::Error::other)?;
    fs::write(root.join(ssal::apex_registry::PATH.trim_start_matches('/')), serde_json::to_vec(&registry)?)?;
    if let Some(plan) = policy {
        ssal::guest_policy::runtime::set_label(
            &root.join("apex/apex-info-list.xml"),
            &plan.context("apex_info_file", false)?,
        )?;
        ssal::guest_policy::runtime::set_label(
            &root.join(ssal::apex_registry::PATH.trim_start_matches('/')),
            &plan.context("apex_info_file", false)?,
        )?;
    }
    // Read-only module mounts remain executable. The parent tmpfs becomes RO too.
    mount(
        Path::new("tmpfs"),
        &root.join("apex"),
        None,
        libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV,
        "",
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn apex_identity_uses_manifest_and_rejects_corruption() -> io::Result<()> {
        let mut manifest = vec![0x0a, 15];
        manifest.extend_from_slice(b"com.android.art");
        manifest.extend_from_slice(&[0x10, 0xac, 0x02, 0x2a, 1, b'v']);
        assert_eq!(apex_identity(&manifest)?, ("com.android.art".into(), 300, Some("v".into())));
        assert!(apex_identity(&[0x0a, 20, b'x']).is_err());
        assert!(apex_identity(&[0x10, 1]).is_err());
        assert!(apex_identity(&[0x0a, 2, b'.', b'.']).is_err());
        assert!(apex_identity(&[0x0a, 3, b'a', b'/', b'b']).is_err());
        let mut overflowing = [0xff; 10].as_slice();
        assert!(varint(&mut overflowing).is_err());
        Ok(())
    }
}
