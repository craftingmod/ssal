//! Shared namespace mount and compatibility projection primitives.
use std::collections::VecDeque;
use std::ffi::CString;
use std::fs::{self, File};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
fn cpath(path: &Path) -> io::Result<CString> {
    CString::new(path.as_os_str().as_bytes()).map_err(|_| io::Error::other("invalid mount path"))
}

pub fn mount(
    source: &Path,
    target: &Path,
    kind: Option<&str>,
    flags: libc::c_ulong,
    options: &str,
) -> io::Result<()> {
    let source = cpath(source)?;
    let target_c = cpath(target)?;
    let kind = kind
        .map(CString::new)
        .transpose()
        .map_err(io::Error::other)?;
    let options = CString::new(options).map_err(io::Error::other)?;
    if unsafe {
        libc::mount(
            source.as_ptr(),
            target_c.as_ptr(),
            kind.as_ref().map_or(std::ptr::null(), |k| k.as_ptr()),
            flags,
            options.as_ptr().cast(),
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub struct Mounts {
    pub paths: Vec<PathBuf>,
    pub loops: Vec<File>,
}
impl Default for Mounts {
    fn default() -> Self {
        Self::new()
    }
}

impl Mounts {
    pub fn new() -> Self {
        Self {
            paths: Vec::new(),
            loops: Vec::new(),
        }
    }

    pub fn attach(
        &mut self,
        source: &Path,
        target: &Path,
        kind: Option<&str>,
        flags: libc::c_ulong,
        options: &str,
    ) -> io::Result<()> {
        mount(source, target, kind, flags, options)?;
        self.paths.push(target.to_owned());
        Ok(())
    }

    pub fn bind(
        &mut self,
        source: &Path,
        target: &Path,
        readonly: bool,
        recursive: bool,
    ) -> io::Result<()> {
        self.attach(
            source,
            target,
            None,
            libc::MS_BIND | if recursive { libc::MS_REC } else { 0 },
            "",
        )?;
        if recursive {
            // rbind creates child mounts too; each must be released before /dev.
            let info = fs::read_to_string("/proc/self/mountinfo")?;
            let mut children: Vec<PathBuf> = info
                .lines()
                .filter_map(|line| line.split_whitespace().nth(4))
                .map(PathBuf::from)
                .filter(|path| path != target && path.starts_with(target))
                .collect();
            children.sort_by_key(|path| path.components().count());
            self.paths.extend(children);
        }
        if readonly {
            mount(
                Path::new("none"),
                target,
                None,
                libc::MS_BIND
                    | libc::MS_REMOUNT
                    | libc::MS_RDONLY
                    | libc::MS_NOSUID
                    | libc::MS_NODEV,
                "",
            )?;
        }
        Ok(())
    }

    pub fn tmpfs(&mut self, target: &Path, mode: u32) -> io::Result<()> {
        self.attach(
            Path::new("tmpfs"),
            target,
            Some("tmpfs"),
            libc::MS_NOSUID | libc::MS_NODEV,
            &format!("mode={mode:o}"),
        )
    }

    pub fn cleanup(&mut self) -> io::Result<()> {
        let mut failures = Vec::new();
        while let Some(path) = self.paths.pop() {
            if unsafe { libc::umount2(cpath(&path)?.as_ptr(), 0) } != 0 {
                failures.push(format!(
                    "{}: {}",
                    path.display(),
                    io::Error::last_os_error()
                ));
            }
        }
        if failures.is_empty() {
            self.loops.clear();
            Ok(())
        } else {
            Err(io::Error::other(format!(
                "guest mount cleanup failed: {}",
                failures.join("; ")
            )))
        }
    }
}

// Resolve absolute Android symlinks against the guest root, not the worker's
// still-active host root. canonicalize(root.join(...)) would escape to the host.
pub fn guest_path(root: &Path, path: &str) -> io::Result<PathBuf> {
    if !relative(path) {
        return Err(io::Error::other("invalid guest path"));
    }
    let mut pending: VecDeque<_> = Path::new(path)
        .components()
        .map(|p| p.as_os_str().to_owned())
        .collect();
    let mut resolved = PathBuf::new();
    let mut links = 0;
    while let Some(part) = pending.pop_front() {
        if part == "." {
            continue;
        }
        if part == ".." {
            resolved.pop();
            continue;
        }
        let candidate = root.join(&resolved).join(&part);
        let meta = fs::symlink_metadata(&candidate)?;
        if meta.is_symlink() {
            links += 1;
            if links > 40 {
                return Err(io::Error::other("guest symlink loop"));
            }
            let link = fs::read_link(candidate)?;
            if link.is_absolute() {
                resolved.clear();
            }
            let parts: Vec<_> = link
                .components()
                .filter(|p| !matches!(p, Component::RootDir))
                .map(|p| p.as_os_str().to_owned())
                .collect();
            for part in parts.into_iter().rev() {
                pending.push_front(part);
            }
        } else {
            resolved.push(part);
        }
    }
    Ok(root.join(resolved))
}

pub fn require_private_mounts(info: &str) -> io::Result<()> {
    let mut count = 0;
    for line in info.lines() {
        let (prefix, suffix) = line
            .split_once(" - ")
            .ok_or_else(|| io::Error::other("malformed mountinfo; cannot verify propagation"))?;
        let fields: Vec<_> = prefix.split_whitespace().collect();
        if fields.len() < 6 || suffix.split_whitespace().count() < 3 {
            return Err(io::Error::other(
                "malformed mountinfo; cannot verify propagation",
            ));
        }
        if fields[6..].iter().any(|field| {
            field.starts_with("shared:")
                || field.starts_with("master:")
                || field.starts_with("propagate_from:")
                || *field == "unbindable"
        }) {
            return Err(io::Error::other(
                "compatibility injection requires private mount propagation",
            ));
        }
        count += 1;
    }
    if count == 0 {
        return Err(io::Error::other(
            "empty mountinfo; cannot verify propagation",
        ));
    }
    Ok(())
}

// Project the original directory into namespace-local tmpfs and add exactly one
// new file. Original inodes are bound read-only, rather than copied or modified.
// All mounts use the existing reverse-order cleanup stack.
pub fn inject_compat_file(
    mounts: &mut Mounts,
    root: &Path,
    entry: &crate::guest_lock_compat::Injection,
    bytes: &[u8],
) -> io::Result<()> {
    inject_compat_file_with_hook(mounts, root, entry, bytes, |_| Ok(()))
}
pub fn inject_compat_file_with_hook(
    mounts: &mut Mounts,
    root: &Path,
    entry: &crate::guest_lock_compat::Injection,
    bytes: &[u8],
    mut hook: impl FnMut(&str) -> io::Result<()>,
) -> io::Result<()> {
    let target = Path::new(entry.target);
    let parent = target
        .parent()
        .and_then(Path::to_str)
        .ok_or_else(|| io::Error::other("invalid compatibility target"))?;
    let name = target
        .file_name()
        .ok_or_else(|| io::Error::other("missing compatibility filename"))?;
    let directory = guest_path(root, parent)?;
    // Includes symlinks and identical files: never silently overwrite/reapply.
    match fs::symlink_metadata(directory.join(name)) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => (),
        Err(e) => return Err(e),
        Ok(_) => return Err(io::Error::other("compatibility target collision")),
    }
    // Worker must already have made every inherited mount recursively private.
    let info = fs::read_to_string("/proc/self/mountinfo")?;
    require_private_mounts(&info)?;
    let metadata = fs::metadata(&directory)?;
    if !metadata.is_dir()
        || metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.mode() & 0o7777 != 0o755
    {
        return Err(io::Error::other("unexpected compatibility directory DAC"));
    }
    let original = File::open(&directory)?;
    let original_path = PathBuf::from(format!("/proc/self/fd/{}", original.as_raw_fd()));
    // Validate all entries before mounting. Preserve symlinks verbatim.
    let entries: Vec<_> = fs::read_dir(&directory)?.collect::<Result<_, _>>()?;
    for item in &entries {
        let kind = item.file_type()?;
        if !(kind.is_file() || kind.is_dir() || kind.is_symlink()) {
            return Err(io::Error::other(
                "unsupported entry in compatibility directory",
            ));
        }
    }
    hook("context")?;
    mounts.attach(
        Path::new("tmpfs"),
        &directory,
        Some("tmpfs"),
        libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
        "mode=755,uid=0,gid=0,context=u:object_r:system_file:s0",
    )?;
    for item in entries {
        let source = original_path.join(item.file_name());
        let destination = directory.join(item.file_name());
        let kind = item.file_type()?;
        if kind.is_symlink() {
            symlink(fs::read_link(source)?, destination)?;
        } else {
            if kind.is_dir() {
                fs::create_dir(&destination)?;
            } else {
                File::create(&destination)?;
            }
            hook("bind")?;
            mounts.bind(&source, &destination, true, kind.is_dir())?;
        }
    }
    let destination = directory.join(name);
    hook("create")?;
    fs::write(&destination, bytes)?;
    fs::set_permissions(&destination, fs::Permissions::from_mode(entry.mode))?;
    let actual = crate::unix::image_context(&File::open(&destination)?)?;
    if actual != entry.context {
        return Err(io::Error::other(format!(
            "compatibility file SELinux label mismatch: actual {actual}, expected {}",
            entry.context
        )));
    }
    mount(
        Path::new("tmpfs"),
        &directory,
        None,
        libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
        "",
    )
}

fn relative(path: &str) -> bool {
    !path.is_empty()
        && Path::new(path)
            .components()
            .all(|p| matches!(p, Component::Normal(_)))
}
pub fn parse_device_number(value: &str) -> io::Result<libc::dev_t> {
    let (major, minor) = value
        .trim()
        .split_once(':')
        .ok_or_else(|| io::Error::other("invalid sysfs device number"))?;
    let major = major.parse::<u32>().map_err(io::Error::other)?;
    let minor = minor.parse::<u32>().map_err(io::Error::other)?;
    Ok(libc::makedev(major, minor))
}
