use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

pub(in crate::guest) fn linkerconfig_binary(root: &Path) -> io::Result<&'static str> {
    for binary in [
        "/apex/com.android.runtime/bin/linkerconfig",
        "/system/bin/linkerconfig",
    ] {
        let path = match crate::guest::mount::guest_path(root, binary.trim_start_matches('/')) {
            Ok(path) => path,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        };
        let metadata = fs::metadata(&path)?;
        if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
            return Err(io::Error::other(format!(
                "guest linkerconfig is not an executable file: {binary}"
            )));
        }
        return Ok(binary);
    }
    Err(io::Error::new(io::ErrorKind::NotFound, "guest linkerconfig not found in runtime APEX or /system/bin; verify guest runtime APEX and system image contents"))
}

pub(in crate::guest) fn linkerconfig(root: &Path) -> io::Result<()> {
    let binary = linkerconfig_binary(root)?;
    println!("guest linkerconfig executable: {binary}");
    // This fixed preparation helper does not admit automatic Android service launch.
    let mut command = crate::guest::process::command::root_command(root, binary, false)?;
    command.args(["--target", "/linkerconfig"]);
    let output = command.output().map_err(|e| {
        io::Error::new(
            e.kind(),
            format!(
                "execute {binary} inside {}: {e}; guest executable was found; check its ELF interpreter path and chroot setup",
                root.display()
            ),
        )
    })?;
    if !output.status.success()
        || fs::metadata(root.join("linkerconfig/ld.config.txt"))
            .map_or(true, |meta| meta.len() == 0)
    {
        return Err(io::Error::other(format!(
            "guest linkerconfig failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(())
}
