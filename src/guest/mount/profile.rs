use crate::guest::compat::patches::Patch;
use serde::Deserialize;
use std::io;
use std::path::{Component, Path};

const PROFILE: &str = include_str!("../../../module/profiles/mounts/initial.json");
pub const PROFILE_NAME: &str = "initial-shared-dev";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Profile {
    pub(super) version: u32,
    pub(super) name: String,
    pub(super) core: std::collections::BTreeMap<String, String>,
    pub(super) tmpfs: Vec<String>,
    pub(super) runtime_tmpfs: Vec<RuntimeDirectory>,
    pub(super) host_readonly: Vec<String>,
    pub(super) host_runtime: Vec<RuntimeMount>,
    pub(super) media_views: Vec<String>,
    pub(super) patches: Vec<Patch>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RuntimeDirectory {
    pub(super) path: String,
    pub(super) mode: String,
    pub(super) uid: u32,
    pub(super) gid: u32,
    pub(super) readonly: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RuntimeMount {
    pub(super) path: String,
    pub(super) readonly: bool,
}

pub(super) fn relative(path: &str) -> bool {
    !path.is_empty()
        && Path::new(path)
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
}

pub(super) fn profile() -> io::Result<Profile> {
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
