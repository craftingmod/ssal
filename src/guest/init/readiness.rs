use super::service::Service;
use std::collections::HashSet;
use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::{Duration, Instant};
pub(in crate::guest) fn wait_for_system_server(
    root: &Path,
    zygote: &mut Service,
) -> io::Result<u32> {
    let parent = zygote.child.id();
    let expected = ssal::guest_policy::runtime::load(root)?
        .ok_or_else(|| io::Error::other("SystemServer requires Guest policy"))?
        .context("system_server", true)?;
    let group = crate::guest::cgroup::memory_group(crate::guest::cgroup::backend()?);
    let deadline = Instant::now() + Duration::from_secs(180);
    let mut last_candidate = None;
    let mut observed_children = HashSet::new();
    loop {
        crate::guest::process::supervision::check_interrupted()?;
        if let Some(diagnostics) = &mut zygote.diagnostics {
            diagnostics.tick()?;
        }
        if zygote.exited()? {
            return Err(io::Error::other(
                "Guest Zygote exited during SystemServer startup",
            ));
        }
        let members = match fs::read_to_string(group.join("cgroup.procs")) {
            Ok(members) => members,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        for pid in members
            .split_whitespace()
            .filter_map(|pid| pid.parse::<u32>().ok())
        {
            let process = Path::new("/proc").join(pid.to_string());
            let status = match fs::read_to_string(process.join("status")) {
                Ok(status) => status,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error),
            };
            let child_parent = status
                .lines()
                .find_map(|line| line.strip_prefix("PPid:"))
                .and_then(|parent| parent.trim().parse::<u32>().ok());
            if child_parent != Some(parent) {
                continue;
            }
            let domain = fs::read_to_string(process.join("attr/current")).unwrap_or_default();
            let domain = domain.trim_matches('\0').trim();
            if observed_children.insert(pid) {
                println!("Guest SystemServer child pid={pid} domain={domain} expected={expected}");
            }
            if domain != expected {
                continue;
            }
            if last_candidate != Some(pid) {
                println!("Guest SystemServer candidate pid={pid} domain={expected}");
                last_candidate = Some(pid);
            }
            for key in ["Uid:", "Gid:"] {
                if status
                    .lines()
                    .find_map(|line| line.strip_prefix(key))
                    .map(|ids| ids.split_whitespace().all(|id| id == "1000"))
                    != Some(true)
                {
                    return Err(io::Error::other("Guest SystemServer credentials mismatch"));
                }
            }
            let guest = fs::metadata(root)?;
            let actual = match fs::metadata(process.join("root")) {
                Ok(actual) => actual,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error),
            };
            let network = match fs::read_link(process.join("ns/net")) {
                Ok(network) => network,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error),
            };
            if (guest.dev(), guest.ino()) != (actual.dev(), actual.ino())
                || network != fs::read_link("/proc/self/ns/net")?
            {
                return Err(io::Error::other(
                    "Guest SystemServer root/network namespace mismatch",
                ));
            }
            match crate::guest::cgroup::verify_guest_membership(pid) {
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error),
            }
            let stderr = fs::read_to_string(root.parent().unwrap().join("phase7b/stderr.log"))?;
            if stderr.contains("Entered the Android system server!") {
                println!("Guest SystemServer ready pid={pid} parent={parent} uid=1000 domain={expected} root=Guest isolated_netns=true framework_entry=true");
                return Ok(pid);
            }
        }
        if Instant::now() >= deadline {
            return Err(io::Error::other(
                "Guest SystemServer Framework entry timeout",
            ));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}
