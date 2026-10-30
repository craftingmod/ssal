//! Disposable identity reporter. No Binder, properties, mounts, or child processes.
#[cfg(unix)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata("/proc/self/exe")?;
    let mut namespaces = serde_json::Map::new();
    for entry in std::fs::read_dir("/proc/self/ns")? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        namespaces.insert(name, serde_json::json!(std::fs::read_link(entry.path())?));
    }
    println!(
        "{}",
        serde_json::json!({
            "protocol": 1, "pid": std::process::id(),
            "context": std::fs::read_to_string("/proc/self/attr/current")?.trim_matches('\0').trim(),
            "uid": unsafe { libc::getuid() }, "euid": unsafe { libc::geteuid() },
            "gid": unsafe { libc::getgid() }, "egid": unsafe { libc::getegid() },
            "namespaces": namespaces, "executable": std::fs::read_link("/proc/self/exe")?,
            "executable_dev": meta.dev(), "executable_ino": meta.ino(),
            "status": std::fs::read_to_string("/proc/self/status")?
        })
    );
    Ok(())
}
#[cfg(not(unix))]
fn main() {
    std::process::exit(1);
}
