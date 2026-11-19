//! Mount configuration consumed by the Core Runtime.
use crate::guest::compat::patches::Patch;
use serde::Deserialize;
use std::path::{Component, Path};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::guest) struct Profile {
    pub(in crate::guest) version: u32,
    pub(in crate::guest) name: String,
    pub(in crate::guest) core: std::collections::BTreeMap<String, String>,
    pub(in crate::guest) tmpfs: Vec<String>,
    pub(in crate::guest) runtime_tmpfs: Vec<RuntimeDirectory>,
    pub(in crate::guest) host_readonly: Vec<String>,
    pub(in crate::guest) host_runtime: Vec<RuntimeMount>,
    pub(in crate::guest) media_views: Vec<String>,
    pub(in crate::guest) patches: Vec<Patch>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::guest) struct RuntimeDirectory {
    pub(in crate::guest) path: String,
    pub(in crate::guest) mode: String,
    pub(in crate::guest) uid: u32,
    pub(in crate::guest) gid: u32,
    pub(in crate::guest) readonly: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::guest) struct RuntimeMount {
    pub(in crate::guest) path: String,
    pub(in crate::guest) readonly: bool,
}

pub(in crate::guest) fn relative(path: &str) -> bool {
    !path.is_empty()
        && Path::new(path)
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
}
