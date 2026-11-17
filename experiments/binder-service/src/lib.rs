//! Guest-only Binder registration. Call before creating any other Binder state.
use rsbinder::{hub, Interface, ProcessState, Strong};
use std::fs;
use std::os::unix::fs::{FileTypeExt, MetadataExt};

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub fn init(expected_device: u64, expected_context: &str) -> Result<()> {
    let binder = fs::metadata("/dev/binder")?;
    let context = fs::read_to_string("/proc/self/attr/current")?;
    if !binder.file_type().is_char_device()
        || binder.rdev() != expected_device
        || context.trim_end_matches(['\0', '\n']) != expected_context
        || !expected_context.starts_with("u:r:ssal_p")
    {
        return Err("Guest Binder device/domain admission failed".into());
    }
    // The launcher closes inherited FDs; also refuse another Binder device alias.
    for name in ["/dev/hwbinder", "/dev/vndbinder", "/dev/binderfs/binder"] {
        if fs::metadata(name)
            .is_ok_and(|m| m.file_type().is_char_device() && m.rdev() != expected_device)
        {
            return Err(format!("unexpected Binder device accessible: {name}").into());
        }
    }
    ProcessState::init("/dev/binder", 4)?;
    if !fs::read_dir("/proc/self/fd")?
        .filter_map(|e| e.ok())
        .any(|e| {
            fs::metadata(e.path())
                .is_ok_and(|m| m.file_type().is_char_device() && m.rdev() == expected_device)
        })
    {
        return Err("Binder driver FD does not match Guest device".into());
    }
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    ProcessState::start_thread_pool();
    Ok(())
}

pub fn register<T: Interface + rsbinder::FromIBinder + ?Sized>(
    name: &str,
    service: Strong<T>,
) -> Result<()> {
    if hub::default()?.check_service(name).is_some() {
        return Err(format!("Guest service already registered: {name}").into());
    }
    hub::add_service(name, service)?;
    println!("guest_binder_registered={name}");
    Ok(())
}

pub fn join() -> Result<()> {
    ProcessState::join_thread_pool()?;
    Err("Guest Binder thread pool exited".into())
}
