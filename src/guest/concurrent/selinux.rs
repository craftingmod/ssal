//! Guest SELinux rules for Concurrent Mode services.
use super::{native, BTreeMap, Plan};

pub(super) const SYSTEM_SUSPEND_DOMAIN: &str = "system_suspend";

// Add the Health domain after GSI policy expansion so it inherits no HAL attributes.
pub(super) fn add_health_rules(
    plan: &mut Plan,
    native_rules: &mut BTreeMap<String, Vec<native::PolicyCommand>>,
) -> std::io::Result<()> {
    let [Some(manager), Some(server), Some(service), Some(binder), Some(system_file)] = [
        "servicemanager",
        "system_server",
        "hal_health_service",
        "binder_device",
        "system_file",
    ]
    .map(|name| plan.types.get(name).cloned()) else {
        return Ok(());
    };
    let owned = format!("ssal_{}_owned", plan.id);
    let mut declare = |original: &str| -> std::io::Result<String> {
        let name = format!("ssal_{}_{original}", plan.id);
        if plan.attributes.contains_key(original)
            || plan.types.insert(original.into(), name.clone()).is_some()
        {
            return Err(std::io::Error::other(format!(
                "Guest Health policy name collision: {original}"
            )));
        }
        let declaration = format!("type {name} {owned}");
        native::record(native_rules, declaration.clone(), 4, 0, &[&name, &owned]);
        plan.declarations.push(declaration);
        Ok(name)
    };
    let health = declare("ssal_health")?;
    let exec = declare("ssal_health_exec")?;
    let mut rules: Vec<(&str, &str, &str, &[&str])> = vec![
        (&exec, "labeledfs", "filesystem", &["associate"]),
        (&exec, "tmpfs", "filesystem", &["associate"]),
        (
            &health,
            &exec,
            "file",
            &["entrypoint", "execute", "read", "open", "getattr", "map"],
        ),
        (&health, &system_file, "dir", &["search", "getattr"]),
        (
            &health,
            &system_file,
            "file",
            &["execute", "read", "open", "getattr", "map"],
        ),
        (&health, "rootfs", "dir", &["search"]),
        (&health, "rootfs", "lnk_file", &["read", "getattr"]),
        (&health, "tmpfs", "dir", &["search"]),
        (&health, "device", "dir", &["search"]),
        (&health, "proc", "dir", &["search"]),
        (&health, "proc", "lnk_file", &["read"]),
        (
            &health,
            &health,
            "dir",
            &["read", "open", "getattr", "search"],
        ),
        (&health, &health, "file", &["read", "open", "getattr"]),
        (&health, &health, "lnk_file", &["read", "getattr"]),
        (
            &health,
            &health,
            "process",
            &["fork", "getattr", "getsched"],
        ),
        (&health, "labeledfs", "filesystem", &["getattr"]),
        (&health, "ksu", "fd", &["use"]),
        (&health, "ksu", "fifo_file", &["read", "write", "getattr"]),
        (
            &health,
            "null_device",
            "chr_file",
            &["read", "write", "open", "getattr"],
        ),
        (
            &health,
            "random_device",
            "chr_file",
            &["read", "open", "getattr"],
        ),
        (
            &health,
            &binder,
            "chr_file",
            &["read", "write", "open", "getattr", "ioctl", "map"],
        ),
        (&health, &binder, "dir", &["search"]),
        (&health, &manager, "binder", &["call", "transfer"]),
        (&manager, &health, "binder", &["call", "transfer"]),
        (&health, &server, "binder", &["call", "transfer"]),
        (&server, &health, "binder", &["call", "transfer"]),
        (&health, &service, "service_manager", &["add", "find"]),
        (&server, &service, "service_manager", &["find"]),
    ];
    for (target, class, permissions) in [
        (
            "system_linker_exec",
            "file",
            &["execute", "read", "open", "getattr", "map"][..],
        ),
        ("system_linker_exec", "lnk_file", &["read", "getattr"]),
        ("system_lib_file", "dir", &["search", "getattr"]),
        (
            "system_lib_file",
            "file",
            &["execute", "read", "open", "getattr", "map"],
        ),
        ("system_lib_file", "lnk_file", &["read", "getattr"]),
        ("apex_mnt_dir", "dir", &["search", "getattr"]),
        ("apex_mnt_dir", "lnk_file", &["read", "getattr"]),
        ("linkerconfig_file", "dir", &["search"]),
        ("linkerconfig_file", "file", &["read", "open", "getattr"]),
        (
            "system_linker_config_file",
            "file",
            &["read", "open", "getattr"],
        ),
        ("properties_device", "dir", &["search", "getattr"]),
        ("build_prop", "file", &["read", "open", "getattr", "map"]),
        ("property_info", "file", &["read", "open", "getattr", "map"]),
        (
            "properties_serial",
            "file",
            &["read", "open", "getattr", "map"],
        ),
        (
            "properties_device",
            "file",
            &["read", "open", "getattr", "map"],
        ),
        (
            "bionic_linker_16kb_app_compat_prop",
            "file",
            &["read", "open", "getattr", "map"],
        ),
    ] {
        if let Some(target) = plan.types.get(target) {
            rules.push((&health, target, class, permissions));
        }
    }
    for (source, target, class, permissions) in rules {
        let rule = format!(
            "allow {source} {target} {class} {{ {} }}",
            permissions.join(" ")
        );
        for permission in permissions {
            native::record(
                native_rules,
                rule.clone(),
                1,
                1,
                &[source, target, class, permission],
            );
        }
        plan.rules.insert(rule);
    }
    Ok(())
}

pub(super) fn add_system_suspend_rules(
    plan: &mut Plan,
    native_rules: &mut BTreeMap<String, Vec<native::PolicyCommand>>,
) {
    // Only the launcher supplies the connected broker socket to this Guest domain.
    if let Some(domain) = plan.types.get(SYSTEM_SUSPEND_DOMAIN) {
        let rule = format!("allow {domain} ksu unix_stream_socket {{ read write shutdown }}");
        for permission in ["read", "write", "shutdown"] {
            native::record(
                native_rules,
                rule.clone(),
                1,
                1,
                &[domain, "ksu", "unix_stream_socket", permission],
            );
        }
        plan.rules.insert(rule);
    }
}
