//! Guest cgroup APIs split by layout, task profiles, and memory-controller lifecycle.
pub(crate) mod layout;
mod memory;
pub(crate) mod task_profiles;

pub(crate) use layout::{guest_cgroup_mounts, task_cgroup_path};
pub(in crate::guest) use layout::{
    remove_empty_cgroup_children, GuestCgroups, GUEST_RESOURCE_CGROUPS,
};
pub(crate) use memory::{
    backend, change, has_memory, memory_group, memory_mount, parse_limit, read, require,
    task_group, usage, verify_guest_membership, verify_guest_mount_membership, verify_membership,
    Backend, GuestMemory, Hierarchy,
};
pub(in crate::guest) use task_profiles::{guest_cgroup_probe, memory_limit, processgroup_probe};
