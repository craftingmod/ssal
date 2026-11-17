use std::fs;
use std::io;
use std::path::PathBuf;

/// Join and verify the already isolated Guest cgroup mounts before exec.
pub fn join_cgroups(groups: &[PathBuf]) -> io::Result<()> {
    let pid = std::process::id().to_string();
    for group in groups {
        fs::write(group.join("cgroup.procs"), &pid)?;
    }
    for group in groups {
        let members = fs::read_to_string(group.join("cgroup.procs"))?;
        if !members.split_whitespace().any(|member| member == pid) {
            return Err(io::Error::other(format!(
                "Guest pre-exec membership missing: pid={pid} group={}",
                group.display()
            )));
        }
    }
    Ok(())
}
