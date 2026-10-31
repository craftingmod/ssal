//! v5 diagnostics; all write operations target disposable namespace-local files.
use super::*;
use std::ffi::CString;
use std::io::Write;
use std::io::{Seek, SeekFrom};
use std::os::unix::ffi::OsStrExt;

pub(super) fn context(path: &Path) -> io::Result<String> {
    let name = CString::new(path.as_os_str().as_bytes())?;
    let attr = c"security.selinux";
    let size = unsafe { libc::lgetxattr(name.as_ptr(), attr.as_ptr(), std::ptr::null_mut(), 0) };
    if size < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut bytes = vec![0; size as usize];
    let size = unsafe {
        libc::lgetxattr(
            name.as_ptr(),
            attr.as_ptr(),
            bytes.as_mut_ptr().cast(),
            bytes.len(),
        )
    };
    if size < 0 {
        return Err(io::Error::last_os_error());
    }
    bytes.truncate(size as usize);
    Ok(String::from_utf8(bytes)
        .map_err(io::Error::other)?
        .trim_end_matches('\0')
        .to_owned())
}
fn relabel_temporary_file(path: &Path) -> io::Result<()> {
    let file = File::open(path)?;
    let label = b"u:object_r:system_file:s0\0";
    if unsafe {
        libc::fsetxattr(
            file.as_raw_fd(),
            c"security.selinux".as_ptr(),
            label.as_ptr().cast(),
            label.len(),
            0,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
fn access_transaction(
    file: &mut (impl Read + Write),
    source: &str,
    target: &str,
    index: u32,
    requested: u32,
) -> io::Result<String> {
    // selinuxfs expects one complete request per write. write! may issue
    // several writes for formatting fragments and fails with EINVAL there.
    let request = format!("{source} {target} {index} {requested:x}");
    file.write_all(request.as_bytes())?;
    let mut response = String::new();
    file.read_to_string(&mut response)?;
    Ok(response)
}
fn query(source: &str, target: &str, class: &str, permission: &str) -> Value {
    let result = (|| -> io::Result<Value> {
        let index = fs::read_to_string(format!("/sys/fs/selinux/class/{class}/index"))?
            .trim()
            .parse::<u32>()
            .map_err(io::Error::other)?;
        let bit = fs::read_to_string(format!("/sys/fs/selinux/class/{class}/perms/{permission}"))?
            .trim()
            .parse::<u32>()
            .map_err(io::Error::other)?;
        require((1..=32).contains(&bit), "invalid permission index")?;
        let requested = 1u32 << (bit - 1);
        let mut file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/sys/fs/selinux/access")?;
        let response = access_transaction(&mut file, source, target, index, requested)?;
        let words: Vec<_> = response.split_whitespace().collect();
        require(words.len() == 6, "malformed kernel access response")?;
        let allowed = u32::from_str_radix(words[0], 16).map_err(io::Error::other)?;
        let decided = u32::from_str_radix(words[1], 16).map_err(io::Error::other)?;
        let auditdeny = u32::from_str_radix(words[3], 16).map_err(io::Error::other)?;
        let flags = u32::from_str_radix(words[5], 16).map_err(io::Error::other)?;
        require(
            decided & requested == requested,
            "kernel response did not decide permission",
        )?;
        Ok(
            json!({"status":"passed","allowed":allowed&requested==requested,"requested_mask":requested,"allowed_mask":allowed,"denial_audit_mask":auditdeny,"denial_audited":auditdeny&requested==requested,"source_domain_permissive":flags&1!=0,"raw_response":response,"errno":0}),
        )
    })();
    let mut value = match result {
        Ok(v) => v,
        Err(e) => {
            json!({"status":"blocked","errno":e.raw_os_error(),"error":e.to_string(),"allowed":null})
        }
    };
    value["source"] = json!(source);
    value["target"] = json!(target);
    value["class"] = json!(class);
    value["permission"] = json!(permission);
    value
}
pub(super) fn policy_queries() -> Value {
    let mut result = Vec::new();
    for (source, target, class, permissions) in [
        (
            "u:r:ksu:s0",
            "u:object_r:tmpfs:s0",
            "filesystem",
            vec!["relabelfrom", "mount"],
        ),
        (
            "u:r:ksu:s0",
            "u:object_r:system_file:s0",
            "filesystem",
            vec!["relabelto", "relabelfrom", "mount"],
        ),
        (
            "u:object_r:system_file:s0",
            "u:object_r:system_file:s0",
            "filesystem",
            vec!["associate"],
        ),
        (
            "u:object_r:system_file:s0",
            "u:object_r:tmpfs:s0",
            "filesystem",
            vec!["associate"],
        ),
        (
            "u:object_r:system_file:s0",
            "u:object_r:labeledfs:s0",
            "filesystem",
            vec!["associate"],
        ),
        (
            "u:r:ksu:s0",
            "u:object_r:system_file:s0",
            "dir",
            vec!["mounton"],
        ),
        (
            "u:r:system_server:s0",
            "u:object_r:system_file:s0",
            "dir",
            vec!["search", "open", "read", "getattr"],
        ),
        (
            "u:r:system_server:s0",
            "u:object_r:system_file:s0",
            "file",
            vec!["open", "read", "getattr", "map"],
        ),
        (
            "u:r:kernel:s0",
            "u:object_r:shell_data_file:s0",
            "file",
            vec!["open", "read", "getattr", "map"],
        ),
        (
            "u:r:kernel:s0",
            "u:object_r:ssal_image_file:s0",
            "file",
            vec!["open", "read", "getattr", "map"],
        ),
    ] {
        for permission in permissions {
            result.push(query(source, target, class, permission));
        }
    }
    json!({"scope":"read-only decisions from currently loaded kernel policy via selinuxfs access transaction; no policy change; not actual system_server I/O","queries":result})
}
fn mount_comparison(
    o: &Options,
    mounts: &mut Mounts,
    target: &Path,
    evidence: &mut Value,
) -> io::Result<()> {
    let use_context = o.kind.ends_with("context");
    let options = if use_context {
        "mode=755,uid=0,gid=0,context=u:object_r:system_file:s0"
    } else {
        "mode=755,uid=0,gid=0"
    };
    evidence["target_before_context"] = json!(context(target)?);
    evidence["parent_context"] = json!(context(target.parent().unwrap())?);
    evidence["policy"] = policy_queries();
    evidence["mount_attempt"] = json!({"syscall":"mount","filesystem":"tmpfs","target":target,"flags":["nosuid","nodev","noexec"],"options":options});
    evidence["operation"] = json!("comparison_tmpfs_mount");
    mounts.attach(
        Path::new("tmpfs"),
        target,
        Some("tmpfs"),
        libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
        options,
    )?;
    evidence["mount_success"] = json!(true);
    evidence["mount_root_context"] = json!(context(target)?);
    let file = target.join("ssal-label-test");
    fs::write(&file, b"ssal mount comparison\n")?;
    evidence["created_file_context"] = json!(context(&file)?);
    if o.kind == "lock-mount-relabel" {
        evidence["operation"] = json!("namespace_temporary_file_fsetxattr");
        relabel_temporary_file(&file)?;
    }
    evidence["final_file_context"] = json!(context(&file)?);
    evidence["selinux_label_correct"] = json!(context(&file)? == "u:object_r:system_file:s0");
    require(
        fs::read(&file)? == b"ssal mount comparison\n",
        "comparison read mismatch",
    )?;
    evidence["filesystem_access_valid"] = json!(true);
    evidence["mountinfo"] = json!(fs::read_to_string("/proc/self/mountinfo")?);
    Ok(())
}
pub(super) fn scratch(o: &Options, mounts: &mut Mounts, evidence: &mut Value) -> io::Result<()> {
    let target = Path::new("/mnt/ssal-comparison");
    fs::create_dir(target)?;
    mount_comparison(o, mounts, target, evidence)
}
pub(super) fn target(
    o: &Options,
    mounts: &mut Mounts,
    dir: &Path,
    evidence: &mut Value,
) -> io::Result<()> {
    // A comparison only. This never certifies a new XML or reconstructs the
    // directory: the whole temporary view is discarded at cleanup.
    mount_comparison(o, mounts, dir, evidence)
}
pub(super) fn ext4_input(o: &Options) -> io::Result<File> {
    let path = fs::canonicalize(
        o.sysconfig_image
            .as_ref()
            .ok_or_else(|| io::Error::other("--sysconfig-image required"))?,
    )?;
    require(
        path == Path::new("/data/local/tmp/ssal-lock-v5-sysconfig.ext4"),
        "unexpected alternative image staging path",
    )?;
    let file = open_input(&path)?;
    require(
        file.metadata()?.is_file() && file.metadata()?.len() <= 16 * 1024 * 1024,
        "invalid small ext4 image",
    )?;
    let expected = o
        .sysconfig_sha256
        .as_ref()
        .ok_or_else(|| io::Error::other("--sysconfig-sha256 required"))?;
    require(
        expected.len() == 64 && expected.bytes().all(|c| c.is_ascii_hexdigit()),
        "invalid image digest",
    )?;
    let mut bytes = Vec::new();
    file.try_clone()?.read_to_end(&mut bytes)?;
    require(
        digest(&bytes) == *expected,
        "alternative image digest mismatch",
    )?;
    Ok(file)
}
fn labelled_inventory(dir: &Path) -> io::Result<Value> {
    let mut entries = inventory(dir)?;
    for (name, value) in entries.iter_mut() {
        value["context"] = json!(context(&dir.join(name))?);
    }
    let meta = fs::metadata(dir)?;
    Ok(
        json!({"entries":entries,"root":{"mode":meta.mode(),"uid":meta.uid(),"gid":meta.gid(),"context":context(dir)?}}),
    )
}
pub(super) fn inject_ext4(
    o: &Options,
    mounts: &mut Mounts,
    dir: &Path,
    evidence: &mut Value,
) -> io::Result<()> {
    require(
        fs::symlink_metadata(dir.join("ssal-lockscreen.xml"))
            .is_err_and(|e| e.kind() == io::ErrorKind::NotFound),
        "alternative target collision",
    )?;
    let before = labelled_inventory(dir)?;
    evidence["policy"] = policy_queries();
    let mut source = ext4_input(o)?;
    evidence["host_staged_image_context"] = json!(crate::unix::image_context(&source)?);
    // Never relabel the Host staging file. Copy into the already isolated,
    // private scratch tmpfs and reuse the existing SSAL backing-image type.
    distinct_namespace(&ns("/proc/self/ns/mnt")?, &ns("/proc/1/ns/mnt")?)?;
    require_private_mounts(&fs::read_to_string("/proc/self/mountinfo")?)?;
    let scratch = Path::new("/mnt/ssal-sysconfig-backing.ext4");
    let mut image = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(scratch)?;
    source.seek(SeekFrom::Start(0))?;
    io::copy(&mut source, &mut image)?;
    image.sync_all()?;
    evidence["operation"] = json!("label_namespace_only_backing_image");
    crate::unix::label_image(&image)?;
    evidence["namespace_backing_image_context"] = json!(crate::unix::image_context(&image)?);
    image.seek(SeekFrom::Start(0))?;
    let mut copied = Vec::new();
    image.read_to_end(&mut copied)?;
    require(
        digest(&copied) == *o.sysconfig_sha256.as_ref().unwrap(),
        "namespace image copy digest mismatch",
    )?;
    evidence["namespace_backing_copy_sha256"] = json!(digest(&copied));
    // The loop needs only a read-only FD; the scratch file is never modified
    // after labelling/hash verification and its mount is always ro,noload.
    drop(image);
    let image = open_input(scratch)?;
    let mounted = readonly_image(mounts, &image, evidence, "sysconfig")?;
    evidence["alternative_image_sha256"] = json!(o.sysconfig_sha256);
    evidence["mount_attempt"] = json!({"filesystem":"ext4","flags":["ro","nosuid","nodev","noexec"],"options":"noload","context_option":false});
    fault(o, "after-ext4")?;
    evidence["operation"] = json!("bind_prelabelled_ext4");
    fault(o, "bind")?;
    mounts.bind(&mounted, dir, true, false)?;
    let mut after = labelled_inventory(dir)?;
    let added = after["entries"]
        .as_object_mut()
        .unwrap()
        .remove("ssal-lockscreen.xml")
        .ok_or_else(|| io::Error::other("alternative XML absent"))?;
    require(
        before == after,
        "original names/content/symlinks/labels/DAC or root metadata changed",
    )?;
    require(
        added["context"] == "u:object_r:system_file:s0",
        "alternative XML label mismatch",
    )?;
    evidence["preservation"] = json!({"status":"passed","original_entries":before["entries"].as_object().unwrap().len(),"content_names_symlinks_dac_labels":true,"root_context":context(dir)?});
    evidence["policy"] = policy_queries();
    evidence["method"] = json!("prelabelled-ext4");
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn selinuxfs_access_request_is_a_single_complete_write() -> io::Result<()> {
        struct Transaction {
            writes: Vec<Vec<u8>>,
            response: std::io::Cursor<Vec<u8>>,
        }
        impl Write for Transaction {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.writes.push(bytes.to_vec());
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        impl Read for Transaction {
            fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
                self.response.read(bytes)
            }
        }
        let mut file = Transaction {
            writes: Vec::new(),
            response: std::io::Cursor::new(b"ffffffff ffffffff 0 ffffffff 1 0".to_vec()),
        };
        let response =
            access_transaction(&mut file, "u:r:ksu:s0", "u:object_r:system_file:s0", 3, 64)?;
        assert_eq!(
            file.writes,
            vec![b"u:r:ksu:s0 u:object_r:system_file:s0 3 40".to_vec()]
        );
        assert_eq!(response, "ffffffff ffffffff 0 ffffffff 1 0");
        Ok(())
    }
    #[test]
    fn comparison_is_never_xml_validation() {
        let args: Vec<_> = ["lock-mount-plain"].iter().map(|s| s.to_string()).collect();
        let o = options(&args).unwrap();
        assert!(!o.execute);
        assert!(o.kind.starts_with("lock-mount-"));
    }
    #[test]
    fn alternative_path_and_hash_are_mandatory() {
        let args: Vec<_> = ["lock-sysconfig", "--method", "prelabelled-ext4"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let o = options(&args).unwrap();
        assert!(ext4_input(&o).is_err());
    }
}
