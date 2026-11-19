//! Mount profile for the existing Concurrent Mode worker.
use crate::guest::mount::profile::{relative, Profile};
use std::io;

const PROFILE: &str = include_str!("../../../module/profiles/concurrent/mounts/initial.json");
pub const PROFILE_NAME: &str = "initial-shared-dev";

pub(in crate::guest) fn profile() -> io::Result<Profile> {
    let profile: Profile = serde_json::from_str(PROFILE)?;
    if profile.version != 1
        || profile.name != PROFILE_NAME
        || profile.core
            != [
                ("system", "registered-image-ro"),
                ("data", "profile-userdata-rw"),
                ("dev", "guest-tmpfs-minimal"),
                ("proc", "fresh-proc"),
                ("sys", "fresh-sysfs-ro"),
                ("apex", "payload-ext4-ro"),
                ("linkerconfig", "guest-generated"),
            ]
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value.to_owned()))
            .collect()
        || profile
            .tmpfs
            .iter()
            .chain(&profile.host_readonly)
            .chain(&profile.media_views)
            .any(|path| !relative(path))
        || profile
            .patches
            .iter()
            .any(|p| !relative(&p.source) || !relative(&p.target))
        || profile.host_runtime.iter().any(|p| !relative(&p.path))
        || profile.runtime_tmpfs.iter().any(|p| {
            !relative(&p.path) || u32::from_str_radix(&p.mode, 8).map_or(true, |mode| mode > 0o7777)
        })
    {
        return Err(io::Error::other("invalid built-in mount profile"));
    }
    Ok(profile)
}

pub fn description() -> io::Result<String> {
    let p = profile()?;
    let services = crate::service_contract::blocked_summary()?;
    Ok(format!("mount profile: {} (built-in v{})\nrootfs: composed system RO, profile userdata RW, private mnt/storage/data_mirror\nruntime: tmp/cache RW tmpfs; metadata/config empty RO tmpfs; no host metadata/configfs\ndevices: fresh Guest /dev with null/zero/random/urandom; Guest child/cgroup workers additionally bind Guest-only cgroup subtrees; no Host Binder, properties, sockets, cgroup roots or BPF bind\nAutomatic Guest launch: BLOCKED; preparation restorecon/linkerconfig helpers permitted\nAPEX: guest/vendor payload ext4 RO; Guest linkerconfig generation required\nGuest property service, Android services, FUSE access control, VINTF and SELinux compatibility: not certified\n{services}", p.name, p.version))
}
