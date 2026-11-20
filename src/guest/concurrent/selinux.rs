//! Guest SELinux rules for Concurrent Mode services.
use super::{native, BTreeMap, Plan};

pub(super) const SYSTEM_SUSPEND_DOMAIN: &str = "system_suspend";

// Add private Guest HAL domains after GSI policy expansion so they inherit no Host HAL attributes.
fn add_private_hal_rules(
    plan: &mut Plan,
    native_rules: &mut BTreeMap<String, Vec<native::PolicyCommand>>,
    domain_name: &str,
    exec_name: &str,
    service_types: &[&str],
    client_domains: &[&str],
) -> std::io::Result<()> {
    let [Some(manager), Some(binder), Some(system_file)] =
        ["servicemanager", "binder_device", "system_file"].map(|name| plan.types.get(name).cloned())
    else {
        return Ok(());
    };
    let resolved_services: Vec<String> = service_types
        .iter()
        .filter_map(|name| plan.types.get(*name).cloned())
        .collect();
    if resolved_services.is_empty() {
        return Ok(());
    }
    let resolved_clients: Vec<String> = client_domains
        .iter()
        .filter_map(|name| plan.types.get(*name).cloned())
        .collect();
    let owned = format!("ssal_{}_owned", plan.id);
    let mut declare = |original: &str| -> std::io::Result<String> {
        let name = format!("ssal_{}_{original}", plan.id);
        if plan.attributes.contains_key(original)
            || plan.types.insert(original.into(), name.clone()).is_some()
        {
            return Err(std::io::Error::other(format!(
                "Guest HAL policy name collision: {original}"
            )));
        }
        let declaration = format!("type {name} {owned}");
        native::record(native_rules, declaration.clone(), 4, 0, &[&name, &owned]);
        plan.declarations.push(declaration);
        Ok(name)
    };
    let domain = declare(domain_name)?;
    let exec = declare(exec_name)?;
    let mut rules: Vec<(String, String, &'static str, &'static [&'static str])> = vec![
        (exec.clone(), "labeledfs".into(), "filesystem", &["associate"]),
        (exec.clone(), "tmpfs".into(), "filesystem", &["associate"]),
        (
            domain.clone(),
            exec,
            "file",
            &["entrypoint", "execute", "read", "open", "getattr", "map"],
        ),
        (domain.clone(), system_file.clone(), "dir", &["search", "getattr"]),
        (
            domain.clone(),
            system_file,
            "file",
            &["execute", "read", "open", "getattr", "map"],
        ),
        (domain.clone(), "rootfs".into(), "dir", &["search"]),
        (domain.clone(), "rootfs".into(), "lnk_file", &["read", "getattr"]),
        (domain.clone(), "tmpfs".into(), "dir", &["search"]),
        (domain.clone(), "device".into(), "dir", &["search"]),
        (domain.clone(), "proc".into(), "dir", &["search"]),
        (domain.clone(), "proc".into(), "lnk_file", &["read"]),
        (
            domain.clone(),
            domain.clone(),
            "dir",
            &["read", "open", "getattr", "search"],
        ),
        (domain.clone(), domain.clone(), "file", &["read", "open", "getattr"]),
        (domain.clone(), domain.clone(), "lnk_file", &["read", "getattr"]),
        (
            domain.clone(),
            domain.clone(),
            "process",
            &["fork", "getattr", "getsched"],
        ),
        (domain.clone(), "labeledfs".into(), "filesystem", &["getattr"]),
        (domain.clone(), "ksu".into(), "fd", &["use"]),
        (domain.clone(), "ksu".into(), "fifo_file", &["read", "write", "getattr"]),
        (
            domain.clone(),
            "null_device".into(),
            "chr_file",
            &["read", "write", "open", "getattr"],
        ),
        (
            domain.clone(),
            "random_device".into(),
            "chr_file",
            &["read", "open", "getattr"],
        ),
        (
            domain.clone(),
            binder.clone(),
            "chr_file",
            &["read", "write", "open", "getattr", "ioctl", "map"],
        ),
        (domain.clone(), binder, "dir", &["search"]),
        (domain.clone(), manager.clone(), "binder", &["call", "transfer"]),
        (manager, domain.clone(), "binder", &["call", "transfer"]),
    ];
    for service in &resolved_services {
        rules.push((
            domain.clone(),
            service.clone(),
            "service_manager",
            &["add", "find"],
        ));
    }
    for client in &resolved_clients {
        rules.push((domain.clone(), client.clone(), "binder", &["call", "transfer"]));
        rules.push((client.clone(), domain.clone(), "binder", &["call", "transfer"]));
        for service in &resolved_services {
            rules.push((client.clone(), service.clone(), "service_manager", &["find"]));
        }
    }
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
        ("device", "dir", &["search"]),
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
            rules.push((domain.clone(), target.clone(), class, permissions));
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
                &[&source, &target, class, permission],
            );
        }
        plan.rules.insert(rule);
    }
    Ok(())
}

pub(super) fn add_health_rules(
    plan: &mut Plan,
    native_rules: &mut BTreeMap<String, Vec<native::PolicyCommand>>,
) -> std::io::Result<()> {
    add_private_hal_rules(
        plan,
        native_rules,
        "ssal_health",
        "ssal_health_exec",
        &["hal_health_service"],
        &["system_server"],
    )
}

pub(super) fn add_gatekeeper_rules(
    plan: &mut Plan,
    native_rules: &mut BTreeMap<String, Vec<native::PolicyCommand>>,
) -> std::io::Result<()> {
    add_private_hal_rules(
        plan,
        native_rules,
        "ssal_gatekeeper",
        "ssal_gatekeeper_exec",
        &["hal_gatekeeper_service"],
        &["system_server", "gatekeeperd", "keystore"],
    )
}

pub(super) fn add_keymint_rules(
    plan: &mut Plan,
    native_rules: &mut BTreeMap<String, Vec<native::PolicyCommand>>,
) -> std::io::Result<()> {
    add_private_hal_rules(
        plan,
        native_rules,
        "ssal_keymint",
        "ssal_keymint_exec",
        &[
            "hal_keymint_service",
            "hal_sharedsecret_service",
            "hal_secureclock_service",
        ],
        &["system_server", "keystore", "vold", "credstore"],
    )
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
