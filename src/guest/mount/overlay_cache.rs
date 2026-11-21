//! Persistent sparse ext4 cache for relabeled Guest /system and APEX overlays.
use crate::guest::mount::loop_device::{loop_device, mount_image, LoopNodes};
use serde::{Deserialize, Serialize};
use ssal::guest_policy::{Plan, MULTI_GUEST_SUPPORT};
use ssal::namespace_mounts::Mounts;
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

const CACHE_SCHEMA_VERSION: u32 = 1;
const CACHE_IMAGE_SIZE: u64 = 6 * 1024 * 1024 * 1024;
const MIN_HOST_RESERVE: u64 = 4 * 1024 * 1024 * 1024;
const META_FILENAME: &str = "cache-meta.json";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct OverlayCacheMeta {
    pub version: u32,
    pub system_image_key: String,
    pub policy_fingerprint: String,
    pub completed: bool,
}

fn system_image_key(system: &Path) -> String {
    system
        .parent()
        .and_then(|parent| parent.file_name())
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| system.display().to_string())
}

impl OverlayCacheMeta {
    pub(crate) fn for_inputs(system: &Path, plan: &Plan) -> Self {
        Self {
            version: CACHE_SCHEMA_VERSION,
            system_image_key: system_image_key(system),
            policy_fingerprint: policy_fingerprint(plan),
            completed: false,
        }
    }
}

fn policy_fingerprint(plan: &Plan) -> String {
    // FNV-1a 128-bit over policy version, id, input_hash, and sorted type mappings.
    let mut hash: u128 = 0x6c62_272e_07bb_0142_62b8_2175_6295_c58d;
    let prime: u128 = 0x0000_0000_0100_0000_0000_0000_0000_013b;
    let feed = |h: &mut u128, bytes: &[u8]| {
        for &b in bytes {
            *h ^= b as u128;
            *h = h.wrapping_mul(prime);
        }
        *h ^= 0xff;
        *h = h.wrapping_mul(prime);
    };
    feed(&mut hash, &plan.version.to_le_bytes());
    feed(&mut hash, plan.id.as_bytes());
    feed(&mut hash, plan.input_hash.as_bytes());
    let sorted: BTreeMap<&str, &str> = plan
        .types
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    for (k, v) in sorted {
        feed(&mut hash, k.as_bytes());
        feed(&mut hash, v.as_bytes());
    }
    format!("{hash:032x}")
}

pub(crate) fn cache_image_path(system: &Path, profile_dir: &Path) -> PathBuf {
    if let Some(dir) = std::env::var_os("SSAL_OVERLAY_CACHE_DIR") {
        return PathBuf::from(dir).join("overlay-cache.img");
    }
    system
        .parent()
        .unwrap_or(profile_dir)
        .join("overlay-cache.img")
}

fn mke2fs(path: &Path) -> io::Result<()> {
    let bin = if cfg!(target_os = "android") {
        "/system/bin/mke2fs"
    } else {
        "mke2fs"
    };
    let output = Command::new(bin)
        .args([
            "-q",
            "-t",
            "ext4",
            "-F",
            "-b",
            "4096",
            "-m",
            "0",
            "-L",
            "ssal-ovl-cache",
            "-O",
            "none,has_journal,ext_attr,extent,filetype,sparse_super,large_file,huge_file,dir_nlink,extra_isize",
            "-E",
            "nodiscard,lazy_itable_init=0,lazy_journal_init=0",
        ])
        .arg(path)
        .output()
        .map_err(|e| io::Error::other(format!("cannot run overlay-cache mke2fs: {e}")))?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "overlay-cache mke2fs {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(())
}

fn create_sparse_ext4(path: &Path, size: u64) -> io::Result<()> {
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
        let avail = (stats.f_bavail as u128) * (stats.f_frsize as u128);
        if avail < MIN_HOST_RESERVE as u128 {
            return Err(io::Error::other(
                "insufficient Host space for overlay cache image (need 4 GiB free)",
            ));
        }
        file.set_len(size)?;
        #[cfg(target_os = "android")]
        ssal::unix::label_userdata_image(&file)?;
        mke2fs(path)?;
        file.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(path);
    }
    result
}

fn flock_file(file: &File, exclusive: bool) -> io::Result<()> {
    let op = if exclusive {
        libc::LOCK_EX
    } else {
        libc::LOCK_SH
    };
    loop {
        if unsafe { libc::flock(file.as_raw_fd(), op) } == 0 {
            return Ok(());
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
}

pub(crate) struct OverlayCache {
    mount_point: PathBuf,
    hit: bool,
    _lock_file: File,
    pending_meta: Option<OverlayCacheMeta>,
}

impl OverlayCache {
    pub(crate) fn open_or_create(
        system: &Path,
        profile_dir: &Path,
        base: &Path,
        plan: &Plan,
        mounts: &mut Mounts,
        loop_nodes: &LoopNodes,
    ) -> io::Result<Self> {
        let _multi_guest_mode = MULTI_GUEST_SUPPORT;
        let img_path = cache_image_path(system, profile_dir);
        let lock_path = img_path.with_extension("lock");
        let lock_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(&lock_path)?;
        let expected = OverlayCacheMeta::for_inputs(system, plan);
        let mount_point = base.join("overlay-cache");
        fs::create_dir(&mount_point)?;

        if img_path.is_file() {
            flock_file(&lock_file, false)?;
            if let Ok((loop_dev, loop_path)) = loop_device(&img_path, true, loop_nodes) {
                if mount_image(&loop_path, &mount_point, true).is_ok() {
                    let meta_ok = fs::read(mount_point.join(META_FILENAME))
                        .ok()
                        .and_then(|bytes| serde_json::from_slice::<OverlayCacheMeta>(&bytes).ok())
                        .is_some_and(|meta| {
                            meta.completed
                                && meta.version == expected.version
                                && meta.system_image_key == expected.system_image_key
                                && meta.policy_fingerprint == expected.policy_fingerprint
                        });
                    if meta_ok {
                        mounts.paths.push(mount_point.clone());
                        mounts.loops.push(loop_dev);
                        println!(
                            "Guest overlay cache hit: {} (ro)",
                            img_path.display()
                        );
                        return Ok(Self {
                            mount_point,
                            hit: true,
                            _lock_file: lock_file,
                            pending_meta: None,
                        });
                    }
                    let c_mp = crate::guest::mount::cpath(&mount_point)?;
                    unsafe { libc::umount2(c_mp.as_ptr(), libc::MNT_DETACH) };
                }
                drop(loop_dev);
            }
            unsafe { libc::flock(lock_file.as_raw_fd(), libc::LOCK_UN) };
        }

        flock_file(&lock_file, true)?;
        if img_path.exists() {
            fs::remove_file(&img_path)?;
        }
        println!(
            "Guest overlay cache miss: creating sparse ext4 at {}",
            img_path.display()
        );
        create_sparse_ext4(&img_path, CACHE_IMAGE_SIZE)?;
        let (loop_dev, loop_path) = loop_device(&img_path, false, loop_nodes)?;
        mounts.loops.push(loop_dev);
        mount_image(&loop_path, &mount_point, false)?;
        mounts.paths.push(mount_point.clone());

        let mut incomplete = expected.clone();
        incomplete.completed = false;
        fs::write(
            mount_point.join(META_FILENAME),
            serde_json::to_vec(&incomplete)?,
        )?;

        Ok(Self {
            mount_point,
            hit: false,
            _lock_file: lock_file,
            pending_meta: Some(expected),
        })
    }

    pub(crate) fn cached_root(&self) -> Option<&Path> {
        self.hit.then_some(self.mount_point.as_path())
    }

    pub(crate) fn write_root(&self) -> Option<&Path> {
        (!self.hit).then_some(self.mount_point.as_path())
    }

    pub(crate) fn finish(&mut self) -> io::Result<()> {
        if self.hit {
            return Ok(());
        }
        if let Some(mut meta) = self.pending_meta.take() {
            meta.completed = true;
            let meta_path = self.mount_point.join(META_FILENAME);
            let file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&meta_path)?;
            serde_json::to_writer(&file, &meta)?;
            file.sync_all()?;
            println!("Guest overlay cache populated and sealed");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};

    fn dummy_plan(id: &str, types: &[(&str, &str)]) -> Plan {
        Plan {
            version: 1,
            id: id.into(),
            input_hash: "hash".into(),
            inputs: Vec::new(),
            types: types
                .iter()
                .map(|(k, v)| ((*k).into(), (*v).into()))
                .collect::<BTreeMap<_, _>>()
                .into_iter()
                .collect(),
            attributes: BTreeMap::new(),
            shared_types: BTreeSet::new(),
            placeholders: BTreeSet::new(),
            contexts: BTreeMap::new(),
            declarations: Vec::new(),
            rules: BTreeSet::new(),
            native_rules: BTreeMap::new(),
            unsupported: Vec::new(),
            unsupported_source: BTreeMap::new(),
            retained_host: Vec::new(),
        }
    }

    #[test]
    fn policy_fingerprint_changes_when_types_or_prefix_change() {
        let a = dummy_plan("ssal_p0001_", &[("system_file", "ssal_p0001_system_file")]);
        let b = dummy_plan("ssal_p0001_", &[("system_file", "ssal_p0001_system_file")]);
        let c = dummy_plan("ssal_p0002_", &[("system_file", "ssal_p0002_system_file")]);
        assert_eq!(policy_fingerprint(&a), policy_fingerprint(&b));
        assert_ne!(policy_fingerprint(&a), policy_fingerprint(&c));
    }

    #[test]
    fn cache_image_path_places_cache_beside_system_image() {
        let system = Path::new("/data/local/ssal/images/1794661103681-12276/system.img");
        let profile = Path::new("/data/local/ssal/guests/y702");
        assert_eq!(
            cache_image_path(system, profile),
            PathBuf::from("/data/local/ssal/images/1794661103681-12276/overlay-cache.img")
        );
        assert_eq!(system_image_key(system), "1794661103681-12276");
    }
}
