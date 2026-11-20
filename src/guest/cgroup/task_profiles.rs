use crate::guest::mount::{cpath, directory, guest_path, relative};
use ssal::namespace_mounts::Mounts;
use std::fs::{self, File};
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
pub(in crate::guest) fn memory_limit(value: Option<&str>) -> io::Result<Option<u64>> {
    crate::guest::cgroup::parse_limit(value)
}

pub(in crate::guest) fn guest_cgroup_probe(root: &Path) -> io::Result<()> {
    let poc = std::env::var("SSAL_GUEST_CHILD_POC")
        .map_err(|_| io::Error::other("SSAL_GUEST_CHILD_POC is required"))?;
    let inherited = ssal::unix::inherited_fds()?;
    let mut command = Command::new(poc);
    command
        .args(["--cgroup-mount-check"])
        .arg(root)
        .env_clear()
        .stdin(Stdio::null());
    unsafe {
        command.pre_exec(move || {
            ssal::unix::close_inherited_fds(&inherited, &[])?;
            ssal::unix::cloexec_unexpected_fds()
        });
    }
    if !command.status()?.success() {
        return Err(io::Error::other("Guest cgroup read-only diagnostic failed"));
    }
    Ok(())
}

fn processgroup_config(
    mut controllers: serde_json::Value,
    mut profiles: serde_json::Value,
) -> io::Result<(serde_json::Value, serde_json::Value)> {
    let invalid = || io::Error::other("unexpected Guest cgroup/task profile schema");
    let paths: std::collections::BTreeMap<_, _> = controllers["Cgroups"]
        .as_array()
        .ok_or_else(invalid)?
        .iter()
        .map(|entry| {
            (
                entry["Controller"].as_str().unwrap_or(""),
                entry["Path"].as_str().unwrap_or(""),
            )
        })
        .collect();
    if paths
        != [
            ("blkio", "/dev/blkio"),
            ("cpu", "/dev/cpuctl"),
            ("cpuset", "/dev/cpuset"),
        ]
        .into_iter()
        .collect()
        || controllers["Cgroups2"]["Path"] != "/sys/fs/cgroup"
    {
        return Err(invalid());
    }
    // No Host memory-controller delegation; preserve profile names as explicit no-ops.
    controllers["Cgroups2"]["Controllers"]
        .as_array_mut()
        .ok_or_else(invalid)?
        .retain(|entry| entry["Controller"] != "memory");
    let attributes = profiles["Attributes"].as_array_mut().ok_or_else(invalid)?;
    let memory: std::collections::BTreeSet<String> = attributes
        .iter()
        .filter(|entry| entry["Controller"] == "memory")
        .filter_map(|entry| entry["Name"].as_str().map(str::to_owned))
        .collect();
    attributes.retain(|entry| entry["Controller"] != "memory");
    for profile in profiles["Profiles"].as_array_mut().ok_or_else(invalid)? {
        profile["Actions"]
            .as_array_mut()
            .ok_or_else(invalid)?
            .retain(|action| {
                !(action["Name"] == "JoinCgroup" && action["Params"]["Controller"] == "memory"
                    || action["Name"] == "SetAttribute"
                        && memory.contains(action["Params"]["Name"].as_str().unwrap_or("")))
            });
    }
    // Reject traversal before creating any task-profile group.
    for action in profiles["Profiles"]
        .as_array()
        .ok_or_else(invalid)?
        .iter()
        .flat_map(|p| p["Actions"].as_array().into_iter().flatten())
    {
        if action["Name"] == "JoinCgroup" {
            let controller = action["Params"]["Controller"]
                .as_str()
                .ok_or_else(invalid)?;
            let path = action["Params"]["Path"].as_str().ok_or_else(invalid)?;
            if !matches!(controller, "cpu" | "cpuset" | "blkio")
                || (!path.is_empty() && !relative(path))
            {
                return Err(invalid());
            }
        }
    }
    Ok((controllers, profiles))
}

pub(in crate::guest) fn prepare_processgroup(
    mounts: &mut Mounts,
    cgroups: &mut crate::guest::cgroup::GuestCgroups,
    root: &Path,
) -> io::Result<PathBuf> {
    let (controllers, profiles) = processgroup_config(
        serde_json::from_slice(&fs::read(guest_path(root, "system/etc/cgroups.json")?)?)?,
        serde_json::from_slice(&fs::read(guest_path(
            root,
            "system/etc/task_profiles.json",
        )?)?)?,
    )?;
    let runtime = directory(root, "run/ssal/processgroup", 0o755)?;
    for (name, value) in [
        ("cgroups.json", &controllers),
        ("task_profiles.json", &profiles),
    ] {
        let source = runtime.join(name);
        fs::write(&source, serde_json::to_vec_pretty(value)?)?;
        fs::set_permissions(&source, fs::Permissions::from_mode(0o644))?;
        ssal::guest_policy::runtime::bind_file(
            mounts,
            root,
            &source,
            &guest_path(root, &format!("system/etc/{name}"))?,
        )?;
    }
    let mut groups = std::collections::BTreeSet::new();
    for profile in profiles["Profiles"].as_array().unwrap() {
        for action in profile["Actions"].as_array().unwrap() {
            if action["Name"] == "JoinCgroup" {
                let controller = action["Params"]["Controller"].as_str().unwrap();
                let path = action["Params"]["Path"].as_str().unwrap();
                let source = crate::guest::cgroup::GUEST_RESOURCE_CGROUPS
                    .iter()
                    .find(|(_, target)| {
                        *target
                            == match controller {
                                "cpu" => "dev/cpuctl",
                                "cpuset" => "dev/cpuset",
                                _ => "dev/blkio",
                            }
                    })
                    .unwrap()
                    .0;
                let mut group = PathBuf::from(source);
                for part in Path::new(path).components() {
                    group.push(part);
                    groups.insert(group.clone());
                }
            }
        }
    }
    for path in groups {
        cgroups.create(&path)?;
        if path.starts_with("/dev/cpuset/ssal_guest") {
            for name in ["cpus", "mems"] {
                fs::write(
                    path.join(name),
                    fs::read(path.parent().unwrap().join(name))?,
                )?;
            }
        }
    }
    for name in ["apps", "system"] {
        let dir = crate::guest::cgroup::task_cgroup_path()?.join(name);
        if !dir.exists() {
            cgroups.create(&dir)?;
        }
    }
    for path in &cgroups.created {
        for entry in [
            path.clone(),
            path.join("cgroup.procs"),
            path.join("tasks"),
            path.join("cgroup.threads"),
        ] {
            if entry.exists() {
                if unsafe { libc::chown(cpath(&entry)?.as_ptr(), 1000, 1000) } != 0 {
                    return Err(io::Error::last_os_error());
                }
                fs::set_permissions(
                    &entry,
                    fs::Permissions::from_mode(if entry == *path { 0o775 } else { 0o664 }),
                )?;
            }
        }
    }
    Ok(runtime)
}

pub(in crate::guest) fn processgroup_probe(
    mounts: &mut Mounts,
    cgroups: &mut crate::guest::cgroup::GuestCgroups,
    root: &Path,
) -> io::Result<()> {
    let helper = std::env::var("SSAL_PROCESSGROUP_PROBE")
        .map_err(|_| io::Error::other("SSAL_PROCESSGROUP_PROBE is required"))?;
    let runtime = prepare_processgroup(mounts, cgroups, root)?;
    let target = runtime.join("probe");
    File::create(&target)?;
    mounts.bind(Path::new(&helper), &target, true, false)?;
    println!(
        "Guest libprocessgroup config: original image JSON bound with memory actions disabled; Guest-only v1 groups initialized; vendor/property overrides absent; launcher uid/gid=1000"
    );
    let mut command =
        crate::guest::launcher::command(root, "/system/bin/bootstrap/linker64", 1000, None)?;
    command
        .arg("/run/ssal/processgroup/probe")
        .env_clear()
        .env("LD_LIBRARY_PATH", "/system/lib64/bootstrap:/system/lib64")
        .stdin(Stdio::null());
    let status = command.status()?;
    if !status.success() {
        return Err(io::Error::other(format!(
            "Guest libprocessgroup helper: {status}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn optional_memory_limits_reject_invalid_values() {
        assert_eq!(memory_limit(None).unwrap(), None);
        assert_eq!(memory_limit(Some("104857600")).unwrap(), Some(104857600));
        for value in ["", "0", "max", "-1", "invalid", "18446744073709551616"] {
            assert!(memory_limit(Some(value)).is_err());
        }
    }

    #[test]
    fn processgroup_config_preserves_profiles_and_rejects_host_path_escape() -> io::Result<()> {
        use serde_json::json;
        let controllers = json!({"Cgroups":[
            {"Controller":"cpu","Path":"/dev/cpuctl"},
            {"Controller":"cpuset","Path":"/dev/cpuset"},
            {"Controller":"blkio","Path":"/dev/blkio"}],
            "Cgroups2":{"Path":"/sys/fs/cgroup","Controllers":[
                {"Controller":"freezer","Path":"."},
                {"Controller":"memory","Path":".","NeedsActivation":true}]}});
        let profiles = json!({"Attributes":[{"Name":"MemLimit","Controller":"memory"}],
            "Profiles":[{"Name":"memory-disabled","Actions":[
                {"Name":"SetAttribute","Params":{"Name":"MemLimit"}},
                {"Name":"JoinCgroup","Params":{"Controller":"memory","Path":"system"}}]},
                {"Name":"cpu-kept","Actions":[{"Name":"JoinCgroup","Params":{"Controller":"cpu","Path":"foreground"}}]}],
            "AggregateProfiles":[{"Name":"CPUSET_SP_FOREGROUND","Profiles":["cpu-kept"]}]});
        let (config, actual) = processgroup_config(controllers.clone(), profiles.clone())?;
        assert_eq!(config["Cgroups"], controllers["Cgroups"]);
        assert_eq!(
            config["Cgroups2"]["Controllers"].as_array().unwrap().len(),
            1
        );
        assert_eq!(actual["Profiles"][0]["Actions"], json!([]));
        assert_eq!(actual["Profiles"][1], profiles["Profiles"][1]);
        assert_eq!(actual["AggregateProfiles"], profiles["AggregateProfiles"]);
        for path in ["../host", "/host", "foreground/../../host"] {
            let mut bad = profiles.clone();
            bad["Profiles"][1]["Actions"][0]["Params"]["Path"] = json!(path);
            assert!(processgroup_config(controllers.clone(), bad).is_err());
        }
        let mut bad = controllers;
        bad["Cgroups"][0]["Path"] = json!("/sys/fs/cgroup/system");
        assert!(processgroup_config(bad, profiles).is_err());
        Ok(())
    }
}
