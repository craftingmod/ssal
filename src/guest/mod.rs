//! SSAL Core Runtime and the existing Guest worker composition.

#[cfg(unix)]
pub(crate) mod binder;
#[cfg(unix)]
pub(crate) mod cgroup;
#[cfg(unix)]
pub(crate) mod compat;
#[cfg(unix)]
pub(crate) mod concurrent;
#[cfg(unix)]
pub(crate) mod environment;
#[cfg(unix)]
mod hwbinder;
#[cfg(unix)]
pub(crate) mod init;
#[cfg(unix)]
pub(crate) mod launcher;
#[cfg(unix)]
pub(crate) mod mount;
#[cfg(unix)]
pub(crate) mod prepare;
#[cfg(unix)]
pub(crate) mod process;
#[cfg(unix)]
pub(crate) mod runtime;
#[cfg(unix)]
pub(crate) mod shell;
pub(crate) mod userdata;

#[cfg(unix)]
pub(crate) fn disabled(feature: &str) -> bool {
    std::env::var_os("SSAL_DISABLE").is_some_and(|value| {
        value
            .to_string_lossy()
            .split(',')
            .any(|item| item.trim().eq_ignore_ascii_case(feature))
    })
}

#[cfg(unix)]
pub(crate) fn system_server_enabled() -> bool {
    !disabled("SYSTEM_SERVER")
}
