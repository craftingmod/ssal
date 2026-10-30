//! Target execution contract, not a service launcher. Never derives service
//! readiness from successful probes in the management SELinux domain.
use serde::Deserialize;
use std::collections::BTreeSet;
use std::fs::File;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path};

const CONTRACT: &str = include_str!("../module/profiles/services/initial.json");

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Contract {
    version: u32,
    name: String,
    launch_enabled: bool,
    supervisor: String,
    properties: Properties,
    binder: Binder,
    selinux: Selinux,
    lifecycle: Lifecycle,
    services: Vec<Service>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Properties {
    mode: String,
    initial_values: String,
    persistent_directory: String,
    host_read_allowlist: Vec<String>,
    host_write_allowlist: Vec<String>,
    forward_ctl: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Binder {
    framework: String,
    host_hal: String,
    hal_allowlist: Vec<String>,
    register_on_host: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Selinux {
    permissive: bool,
    proof: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Lifecycle {
    stop: String,
    timeout: String,
    restore: String,
    failure: String,
    writes: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Service {
    name: String,
    launch: String,
    executable: Option<String>,
    domain: String,
    depends_on: Vec<String>,
    write_paths: Vec<String>,
    requires: Vec<String>,
}

const CHECKS: &[&str] = &[
    "root_and_userdata",
    "journal",
    "execution_spec",
    "selinux_transition",
    "private_property_storage",
    "property_access_policy",
    "properties_ready",
    "private_framework_binder",
    "userdata_labels",
    "userdata_crypto_policy",
    "storage_ownership",
    "guest_metadata_policy",
    "device_vintf",
    "hal_bridge",
    "app_storage_permissions",
];

fn guest_absolute(value: &str) -> bool {
    value.starts_with('/')
        && value != "/"
        && Path::new(value)
            .components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
}

fn startup_order(contract: &Contract) -> io::Result<Vec<&Service>> {
    let mut remaining: Vec<_> = contract.services.iter().collect();
    let mut result: Vec<&Service> = Vec::new();
    while !remaining.is_empty() {
        let position = remaining
            .iter()
            .position(|service| {
                service
                    .depends_on
                    .iter()
                    .all(|dependency| result.iter().any(|done| &done.name == dependency))
            })
            .ok_or_else(|| {
                io::Error::other("service contract dependency cycle or missing dependency")
            })?;
        result.push(remaining.remove(position));
    }
    Ok(result)
}

fn validate(contract: &Contract) -> io::Result<()> {
    let bad = || io::Error::other("unsupported service contract; launch remains disabled");
    if contract.version != 1
        || contract.name != "isolated-userspace-v1"
        || contract.launch_enabled
        || contract.supervisor != "explicit-services-no-android-init"
        || contract.properties.mode != "private-area-and-service"
        || contract.properties.initial_values != "guest-partition-files"
        || contract.properties.persistent_directory != "/data/property"
        || !contract.properties.host_read_allowlist.is_empty()
        || !contract.properties.host_write_allowlist.is_empty()
        || contract.properties.forward_ctl
        || contract.binder.framework != "private-context"
        || contract.binder.host_hal != "per-interface-bridge"
        || !contract.binder.hal_allowlist.is_empty()
        || contract.binder.register_on_host
        || contract.selinux.permissive
        || contract.selinux.proof != "per-service-transition-and-runtime-domain"
        || contract.lifecycle.stop != "reverse-dependency-order"
        || contract.lifecycle.timeout != "term-then-kill-owned-processes"
        || contract.lifecycle.restore != "journaled-host-changes-only"
        || contract.lifecycle.failure != "recovery-required"
        || contract.lifecycle.writes != "quiesce-before-unmount"
        || contract.services.is_empty()
    {
        return Err(bad());
    }
    let mut names = BTreeSet::new();
    for service in &contract.services {
        let fields: Vec<_> = service.domain.split(':').collect();
        if !names.insert(&service.name)
            || service.name.is_empty()
            || fields.len() != 4
            || fields[0] != "u"
            || fields[1] != "r"
            || fields[3] != "s0"
            || matches!(fields[2], "" | "ksu" | "su" | "magisk" | "init")
            || service
                .requires
                .iter()
                .any(|check| !CHECKS.contains(&check.as_str()))
            || [
                "root_and_userdata",
                "journal",
                "execution_spec",
                "selinux_transition",
            ]
            .iter()
            .any(|check| !service.requires.iter().any(|required| required == check))
            || service.write_paths.iter().any(|path| {
                !guest_absolute(path)
                    || ![
                        "/data",
                        "/data_mirror",
                        "/dev",
                        "/mnt",
                        "/storage",
                        "/run",
                        "/tmp",
                        "/cache",
                    ]
                    .iter()
                    .any(|allowed| Path::new(path).starts_with(allowed))
            })
        {
            return Err(bad());
        }
        match (service.launch.as_str(), service.executable.as_deref()) {
            ("exec", Some(path)) if guest_absolute(path) => (),
            ("zygote-child", None)
                if service.name == "system_server"
                    && service.depends_on.iter().any(|name| name == "zygote") => {}
            _ => return Err(bad()),
        }
    }
    startup_order(contract)?;
    Ok(())
}

fn load() -> io::Result<Contract> {
    let contract = serde_json::from_str(CONTRACT)?;
    validate(&contract)?;
    Ok(contract)
}

pub fn blocked_summary() -> io::Result<String> {
    let contract = load()?;
    Ok(format!("service contract {}: launch DISABLED; requires private properties/framework Binder, per-service execution/SELinux proof, device HAL and restore plan; contract specified, runtime backends not implemented", contract.name))
}

pub fn report(root: &Path, probe: &crate::guest_probe::ProbeReport) -> io::Result<()> {
    let contract = load()?;
    println!("{}", blocked_summary()?);
    println!("target property contract: guest initial values, private area+service, guest /data/property, no host reads/writes or ctl forwarding; current shared probe environment does NOT implement this contract");
    println!("target Binder contract: private framework context; per-interface host HAL bridge (allowlist empty); no registration on host contexts");
    println!("service admission: blocked; probe VINTF={}; root shell/fscrypt observations do not satisfy service domain, guest FBE or HAL prerequisites", serde_json::to_string(&probe.vintf)?);
    let order = startup_order(&contract)?;
    println!(
        "planned start order: {}",
        order
            .iter()
            .map(|service| service.name.as_str())
            .collect::<Vec<_>>()
            .join(" -> ")
    );
    println!(
        "planned stop order: {}",
        order
            .iter()
            .rev()
            .map(|service| service.name.as_str())
            .collect::<Vec<_>>()
            .join(" -> ")
    );
    for service in order {
        let entrypoint = match service.executable.as_deref() {
            None => "zygote-managed child; no direct exec".into(),
            Some(executable) => {
                match crate::guest_mounts::guest_path(root, executable).and_then(File::open) {
                    Ok(file) => format!(
                        "{executable}; regular_file_with_execute_bits={}; file_label={}",
                        file.metadata().is_ok_and(
                            |meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0
                        ),
                        ssal::unix::image_context(&file)
                            .unwrap_or_else(|e| format!("unavailable: {e}"))
                    ),
                    Err(e) => format!("{executable}; unavailable: {e}"),
                }
            }
        };
        println!("service {}: may_spawn=false; expected_domain={}; actual_service_domain=not_started; entrypoint={entrypoint}; required_before_spawn={}", service.name, service.domain, service.requires.join(","));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dependency_order_and_fail_closed_contract() -> io::Result<()> {
        let mut contract = load()?;
        let order: Vec<_> = startup_order(&contract)?
            .iter()
            .map(|service| service.name.as_str())
            .collect();
        assert!(
            order.iter().position(|name| *name == "property_service")
                < order.iter().position(|name| *name == "zygote")
        );
        assert!(
            order.iter().position(|name| *name == "zygote")
                < order.iter().position(|name| *name == "system_server")
        );
        contract.launch_enabled = true;
        assert!(validate(&contract).is_err());
        contract.launch_enabled = false;
        contract.properties.forward_ctl = true;
        assert!(validate(&contract).is_err());
        Ok(())
    }

    #[test]
    fn rejects_missing_dependencies_management_domain_and_path_escape() -> io::Result<()> {
        let mut contract = load()?;
        contract.services[0].depends_on.push("missing".into());
        assert!(validate(&contract).is_err());
        contract.services[0].depends_on.clear();
        contract.services[0].depends_on.push("system_server".into());
        assert!(validate(&contract).is_err());
        contract.services[0].depends_on.clear();
        contract.services[0].domain = "u:r:ksu:s0".into();
        assert!(validate(&contract).is_err());
        contract.services[0].domain = "u:r:ssal_property:s0".into();
        contract.services[0]
            .write_paths
            .push("/data/../metadata".into());
        assert!(validate(&contract).is_err());
        Ok(())
    }
}
