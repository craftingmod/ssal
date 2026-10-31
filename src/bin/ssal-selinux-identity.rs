//! Disposable identity reporter. No Binder, properties, mounts, or child processes.
#[cfg(unix)]
fn mark_main_entry() {
    #[repr(C)]
    struct Event {
        stage: u32,
        errno: i32,
    }
    unsafe {
        let value = libc::getenv(c"SSAL_STAGE_FD".as_ptr());
        if !value.is_null() {
            let fd = libc::atoi(value);
            if fd >= 0 {
                let event = Event {
                    stage: 10,
                    errno: 0,
                };
                libc::write(
                    fd,
                    (&event as *const Event).cast(),
                    std::mem::size_of::<Event>(),
                );
            }
        }
    }
}

#[cfg(unix)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    mark_main_entry();
    use std::os::unix::fs::MetadataExt;
    fn path_error(path: &str, e: std::io::Error) -> std::io::Error {
        std::io::Error::new(e.kind(), format!("{path}: {e}"))
    }
    let meta = std::fs::metadata("/proc/self/exe").map_err(|e| path_error("/proc/self/exe", e))?;
    let mut namespaces = serde_json::Map::new();
    for entry in std::fs::read_dir("/proc/self/ns").map_err(|e| path_error("/proc/self/ns", e))? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let path = entry.path();
        namespaces.insert(
            name,
            serde_json::json!(std::fs::read_link(&path)
                .map_err(|e| path_error(&path.display().to_string(), e))?),
        );
    }
    println!(
        "{}",
        serde_json::json!({
            "protocol": 1, "pid": std::process::id(),
            "context": std::fs::read_to_string("/proc/self/attr/current").map_err(|e| path_error("/proc/self/attr/current", e))?.trim_matches('\0').trim(),
            "uid": unsafe { libc::getuid() }, "euid": unsafe { libc::geteuid() },
            "gid": unsafe { libc::getgid() }, "egid": unsafe { libc::getegid() },
            "namespaces": namespaces, "executable": std::fs::read_link("/proc/self/exe").map_err(|e| path_error("/proc/self/exe", e))?,
            "executable_dev": meta.dev(), "executable_ino": meta.ino(),
            "status": std::fs::read_to_string("/proc/self/status").map_err(|e| path_error("/proc/self/status", e))?
        })
    );
    Ok(())
}
#[cfg(not(unix))]
fn main() {
    std::process::exit(1);
}
