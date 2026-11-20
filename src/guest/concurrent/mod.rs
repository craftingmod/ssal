//! Concurrent Mode profiles and adapters for the existing Host-preserving Guest path.

pub(in crate::guest) mod device_vintf;
pub(in crate::guest) mod gatekeeper;
pub(in crate::guest) mod graphics;
pub(in crate::guest) mod health;
pub(in crate::guest) mod keymint;
pub(crate) mod mount_profile;
pub(crate) mod service_contract;
pub(in crate::guest) mod system_suspend;
