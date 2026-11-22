use super::{cpath, directory};
use crate::guest::concurrent::graphics;
use ssal::namespace_mounts::Mounts;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::Path;

pub(super) const GUEST_DEVICE_NODES: [(&str, u32, u32); 4] = [
    ("null", 1, 3),
    ("zero", 1, 5),
    ("random", 1, 8),
    ("urandom", 1, 9),
];
pub(super) const GUEST_DEV_ENTRIES: [&str; 9] = [
    "binderfs", "block", "null", "ptmx", "pts", "random", "socket", "urandom", "zero",
];

fn bind_guest_device(
    mounts: &mut Mounts,
    dev: &Path,
    name: &str,
    major: u32,
    minor: u32,
    owner: (u32, u32),
    label: Option<&str>,
) -> io::Result<()> {
    let source = Path::new("/dev").join(name);
    let source_entry = fs::symlink_metadata(&source)?;
    if !source_entry.file_type().is_char_device()
        || source_entry.rdev() != libc::makedev(major, minor)
        || (
            source_entry.uid(),
            source_entry.gid(),
            source_entry.mode() & 0o7777,
        ) != (owner.0, owner.1, 0o666)
    {
        return Err(io::Error::other(format!(
            "unsafe Host /dev/{name}: expected char {major}:{minor}, {}:{} 0666",
            owner.0, owner.1
        )));
    }
    let source_file = File::open(&source)?;
    if let Some(label) = label {
        if ssal::unix::image_context(&source_file)? != label {
            return Err(io::Error::other(format!("unexpected Host /dev/{name} label")));
        }
    }
    let source_mount = ssal::unix::fd_mount_id(&source_file)?;
    let target = dev.join(name);
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&target)?;
    mounts.bind(&source, &target, false, false)?;
    let guest_file = File::open(&target)?;
    let guest = guest_file.metadata()?;
    let host = source_file.metadata()?;
    let guest_mount = ssal::unix::fd_mount_id(&guest_file)?;
    if !guest.file_type().is_char_device()
        || (
            guest.dev(),
            guest.ino(),
            guest.rdev(),
            guest.uid(),
            guest.gid(),
            guest.mode() & 0o7777,
        ) != (
            host.dev(),
            host.ino(),
            host.rdev(),
            host.uid(),
            host.gid(),
            host.mode() & 0o7777,
        )
        || source_mount == guest_mount
    {
        return Err(io::Error::other(format!(
            "Guest /dev/{name} identity, permissions or bind-mount scope mismatch"
        )));
    }
    let label = ssal::unix::image_context(&guest_file)
        .unwrap_or_else(|error| format!("unavailable: {error}"));
    println!(
        "Guest device /dev/{name}: rdev={major}:{minor} uid={} gid={} mode={:o} label={label} host_mount={source_mount} guest_mount={guest_mount}",
        guest.uid(),
        guest.gid(),
        guest.mode() & 0o7777
    );
    Ok(())
}

pub(super) fn prepare_guest_dev(
    mounts: &mut Mounts,
    root: &Path,
    y702_graphics: bool,
) -> io::Result<()> {
    let dev = root.join("dev");
    mounts.attach(
        Path::new("tmpfs"),
        &dev,
        Some("tmpfs"),
        libc::MS_NOSUID | libc::MS_NOEXEC,
        "mode=0755,size=4m",
    )?;
    for path in ["socket", "block", "binderfs", "pts"] {
        directory(&dev, path, 0o755)?;
    }
    mounts.attach(
        Path::new("devpts"),
        &dev.join("pts"),
        Some("devpts"),
        libc::MS_NOSUID | libc::MS_NOEXEC,
        "newinstance,ptmxmode=0666,mode=0620",
    )?;
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(dev.join("ptmx"))?;
    mounts.bind(&dev.join("pts/ptmx"), &dev.join("ptmx"), false, false)?;
    for (name, major, minor) in GUEST_DEVICE_NODES {
        bind_guest_device(mounts, &dev, name, major, minor, (0, 0), None)?;
    }
    let mut expected: std::collections::BTreeSet<_> =
        GUEST_DEV_ENTRIES.into_iter().map(str::to_owned).collect();
    if y702_graphics {
        let identity = fs::read_to_string("/sys/class/kgsl/kgsl-3d0/dev")?;
        let (major, minor) = identity
            .trim()
            .split_once(':')
            .ok_or_else(|| io::Error::other("invalid Y702 KGSL device identity"))?;
        bind_guest_device(
            mounts,
            &dev,
            graphics::KGSL,
            major.parse().map_err(io::Error::other)?,
            minor.parse().map_err(io::Error::other)?,
            (1000, 1000),
            Some("u:object_r:gpu_device:s0"),
        )?;
        expected.insert(graphics::KGSL.to_owned());
        let dma_heap = directory(&dev, "dma_heap", 0o755)?;
        for name in ["system", "qcom,system"] {
            let source = Path::new("/dev/dma_heap").join(name);
            if let Ok(meta) = fs::symlink_metadata(&source) {
                if meta.file_type().is_char_device() {
                    let target = dma_heap.join(name);
                    OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(&target)?;
                    mounts.bind(&source, &target, false, false)?;
                }
            }
        }
        expected.insert("dma_heap".to_owned());
    }
    let actual: std::collections::BTreeSet<String> = fs::read_dir(&dev)?
        .map(|entry| entry.map(|entry| entry.file_name().to_string_lossy().into_owned()))
        .collect::<io::Result<_>>()?;
    if actual != expected
        || fs::read_dir(dev.join("socket"))?.next().is_some()
        || dev.join("__properties__").exists()
        || dev.join("binder-control").exists()
        || dev.join("binderfs/binder-control").exists()
    {
        return Err(io::Error::other(
            "Guest /dev contains an unapproved entry or Host property endpoint",
        ));
    }
    println!("Guest /dev allowlist verified: {expected:?}");
    Ok(())
}

pub(super) fn ashmem_device_name(boot_id: &str) -> io::Result<String> {
    let id = boot_id.trim();
    if id.len() != 36
        || !id.bytes().enumerate().all(|(i, c)| {
            if [8, 13, 18, 23].contains(&i) {
                c == b'-'
            } else {
                c.is_ascii_hexdigit()
            }
        })
    {
        return Err(io::Error::other("invalid kernel boot ID for Guest ashmem"));
    }
    Ok(format!("ashmem{id}"))
}

pub(super) fn prepare_guest_ashmem(root: &Path, plan: &ssal::guest_policy::Plan) -> io::Result<()> {
    let name = ashmem_device_name(&fs::read_to_string("/proc/sys/kernel/random/boot_id")?)?;
    let host = fs::symlink_metadata(Path::new("/dev").join(&name))?;
    let legacy = fs::symlink_metadata("/dev/ashmem")?;
    if !host.file_type().is_char_device()
        || !legacy.file_type().is_char_device()
        || host.rdev() == 0
        || host.rdev() != legacy.rdev()
        || (host.uid(), host.gid(), host.mode() & 0o7777) != (0, 0, 0o666)
    {
        return Err(io::Error::other(
            "unsafe Host ashmem device identity or permissions",
        ));
    }
    for (node_name, label_name) in [(name.as_str(), "ashmem_libcutils_device"), ("ashmem", "ashmem_device")] {
        let target = root.join("dev").join(node_name);
        // A private inode allows Guest labeling without relabeling either Host ashmem node.
        if unsafe { libc::mknod(cpath(&target)?.as_ptr(), libc::S_IFCHR | 0o666, host.rdev()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        fs::set_permissions(&target, fs::Permissions::from_mode(0o666))?;
        let context = plan.context(label_name, false)?;
        ssal::guest_policy::runtime::set_label(&target, &context)?;
        let guest = fs::symlink_metadata(&target)?;
        if !guest.file_type().is_char_device()
            || guest.rdev() != host.rdev()
            || (guest.dev(), guest.ino()) == (host.dev(), host.ino())
            || (guest.uid(), guest.gid(), guest.mode() & 0o7777) != (0, 0, 0o666)
        {
            return Err(io::Error::other(
                "Guest ashmem identity or permissions mismatch",
            ));
        }
        println!(
            "Guest /dev/{node_name}: private ashmem node label={context} rdev={}",
            guest.rdev()
        );
    }
    Ok(())
}
