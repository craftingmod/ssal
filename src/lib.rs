#[path = "guest/compat/lockscreen.rs"]
pub mod guest_lock_compat;
#[path = "guest/selinux/mod.rs"]
pub mod guest_policy;
#[cfg(any(target_os = "linux", target_os = "android"))]
#[path = "guest/properties/mod.rs"]
pub mod guest_properties;
#[cfg(unix)]
pub mod ipc;
#[cfg(unix)]
pub mod unix;
#[cfg(unix)]
#[path = "shell_client.rs"]
pub mod shell_transport;

#[cfg(unix)]
#[path = "diagnostics/lock_namespace/mod.rs"]
pub mod lock_namespace_probe;
#[cfg(unix)]
pub mod platform;
#[cfg(unix)]
pub use platform::mount as namespace_mounts;
