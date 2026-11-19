use crate::diagnostics::selinux;
use ssal::namespace_mounts::Mounts;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

pub(in crate::guest) const KGSL: &str = "kgsl-3d0";

const VENDOR_ACCESS: [(&str, &str, &[&str]); 4] = [
    ("vendor_file", "dir", &["search", "getattr"]),
    ("vendor_hal_file", "dir", &["search", "getattr"]),
    ("same_process_hal_file", "dir", &["search", "getattr"]),
    ("same_process_hal_file", "file", &["read", "open"]),
];

pub(in crate::guest) fn requested() -> bool {
    std::env::var("SSAL_Y702_GRAPHICS").as_deref() == Ok("1")
}

pub(in crate::guest) fn require_y702() -> io::Result<()> {
    let product = Command::new("/system/bin/getprop")
        .arg("ro.product.device")
        .output()?;
    if !product.status.success() || product.stdout.trim_ascii() != b"TB320FC" {
        return Err(io::Error::other("SSAL_Y702_GRAPHICS requires Lenovo TB320FC"));
    }
    Ok(())
}

fn vendor_rule(domain: &str, target: &str, class: &str, permissions: &[&str]) -> String {
    format!("allow {domain} {target} {class} {{ {} }}", permissions.join(" "))
}

pub(in crate::guest) fn apply_vendor_access(
    plan: &ssal::guest_policy::Plan,
    applied_only: bool,
) -> io::Result<()> {
    let shell = plan.context("shell", true)?;
    selinux::require_enforcing_domain(&shell)?;
    let domain = &plan.types["shell"];
    for (target, class, permissions) in VENDOR_ACCESS {
        let context = format!("u:object_r:{target}:s0");
        let allowed = || {
            permissions.iter().try_fold(true, |all, permission| {
                Ok::<_, io::Error>(
                    selinux::access_allowed(&shell, &context, class, permission)? && all,
                )
            })
        };
        if allowed()? {
            continue;
        }
        let rule = vendor_rule(domain, target, class, permissions);
        if applied_only {
            return Err(io::Error::other(format!("Y702 graphics requires an applied rule: {rule}")));
        }
        let status = Command::new("/data/adb/ksu/bin/ksud")
            .args(["sepolicy", "patch", &rule])
            .status()?;
        if !status.success() || !allowed()? {
            return Err(io::Error::other(format!("Y702 Guest graphics rule failed: {rule}")));
        }
    }
    println!("Y702 Guest vendor graphics permissions verified for {shell}");
    Ok(())
}

const SURFACEFLINGER_GRAPHICS_ACCESS: [(&str, &str, &[&str]); 7] = [
    ("vendor_file", "dir", &["search", "getattr", "read", "open"]),
    ("vendor_file", "file", &["read", "open", "getattr", "map", "execute"]),
    ("vendor_hal_file", "dir", &["search", "getattr", "read", "open"]),
    ("vendor_hal_file", "file", &["read", "open", "getattr", "map", "execute"]),
    ("same_process_hal_file", "dir", &["search", "getattr", "read", "open"]),
    (
        "same_process_hal_file",
        "file",
        &["read", "open", "getattr", "map", "execute"],
    ),
    (
        "gpu_device",
        "chr_file",
        &["read", "write", "open", "ioctl", "getattr", "map"],
    ),
];

pub(in crate::guest) fn apply_surfaceflinger_graphics_access(
    plan: &ssal::guest_policy::Plan,
) -> io::Result<()> {
    let sf = plan.context("surfaceflinger", true)?;
    selinux::require_enforcing_domain(&sf)?;
    let domain = plan
        .types
        .get("surfaceflinger")
        .ok_or_else(|| io::Error::other("Guest surfaceflinger type missing"))?;
    for (target, class, permissions) in SURFACEFLINGER_GRAPHICS_ACCESS {
        let context = format!("u:object_r:{target}:s0");
        let allowed = || {
            permissions.iter().try_fold(true, |all, permission| {
                Ok::<_, io::Error>(
                    selinux::access_allowed(&sf, &context, class, permission)? && all,
                )
            })
        };
        if allowed()? {
            continue;
        }
        let rule = vendor_rule(domain, target, class, permissions);
        let status = Command::new("/data/adb/ksu/bin/ksud")
            .args(["sepolicy", "patch", &rule])
            .status()?;
        if !status.success() || !allowed()? {
            return Err(io::Error::other(format!(
                "Y702 Guest SurfaceFlinger graphics rule failed: {rule}"
            )));
        }
    }
    println!("Y702 Guest SurfaceFlinger graphics permissions verified for {sf}");
    Ok(())
}

const VIRTUAL_COMPOSER_VINTF: &str = r#"<manifest version="1.0" type="framework">
    <hal format="aidl">
        <name>android.hardware.graphics.composer3</name>
        <version>2</version>
        <interface>
            <name>IComposer</name>
            <instance>default</instance>
        </interface>
    </hal>
    <hal format="hidl">
        <name>android.hardware.graphics.allocator</name>
        <transport>hwbinder</transport>
        <version>4.0</version>
        <interface>
            <name>IAllocator</name>
            <instance>default</instance>
        </interface>
    </hal>
    <hal format="hidl">
        <name>vendor.qti.hardware.display.allocator</name>
        <transport>hwbinder</transport>
        <version>4.0</version>
        <interface>
            <name>IQtiAllocator</name>
            <instance>default</instance>
        </interface>
    </hal>
    <hal format="hidl">
        <name>android.hardware.graphics.mapper</name>
        <transport arch="32+64">passthrough</transport>
        <version>4.0</version>
        <interface>
            <name>IMapper</name>
            <instance>default</instance>
        </interface>
    </hal>
    <hal format="hidl">
        <name>vendor.qti.hardware.display.mapper</name>
        <transport arch="32+64">passthrough</transport>
        <version>4.0</version>
        <interface>
            <name>IQtiMapper</name>
            <instance>default</instance>
        </interface>
    </hal>
</manifest>
"#;

pub(in crate::guest) fn install_virtual_composer_vintf(
    mounts: &mut Mounts,
    root: &Path,
    plan: &ssal::guest_policy::Plan,
) -> io::Result<()> {
    let manifest_dir = crate::guest::mount::guest_path(root, "system/system_ext/etc/vintf/manifest")
        .or_else(|_| crate::guest::mount::guest_path(root, "system/etc/vintf/manifest"))?;
    let staging = root.parent().unwrap().join("vintf-manifest-overlay");
    if staging.exists() {
        fs::remove_dir_all(&staging)?;
    }
    fs::create_dir_all(&staging)?;
    fs::set_permissions(&staging, fs::Permissions::from_mode(0o755))?;
    let file_context = plan.context("system_file", false)?;
    ssal::guest_policy::runtime::set_label(&staging, &file_context)?;
    for entry in fs::read_dir(&manifest_dir)? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            let dest = staging.join(entry.file_name());
            fs::copy(entry.path(), &dest)?;
            fs::set_permissions(&dest, fs::Permissions::from_mode(0o644))?;
            ssal::guest_policy::runtime::set_label(&dest, &file_context)?;
        }
    }
    let fragment = staging.join("ssal_virtual_composer.xml");
    fs::write(&fragment, VIRTUAL_COMPOSER_VINTF)?;
    fs::set_permissions(&fragment, fs::Permissions::from_mode(0o644))?;
    ssal::guest_policy::runtime::set_label(&fragment, &file_context)?;
    mounts.bind(&staging, &manifest_dir, true, true)?;
    println!(
        "GUEST_VIRTUAL_COMPOSER_VINTF=PASS dir={} fragment=ssal_virtual_composer.xml",
        manifest_dir.display()
    );
    Ok(())
}

pub(in crate::guest) fn apply_virtual_composer_access(
    plan: &ssal::guest_policy::Plan,
) -> io::Result<()> {
    let composer_sid = plan.context("hal_graphics_composer_default", true)?;
    selinux::require_enforcing_domain(&composer_sid)?;
    let composer = plan
        .types
        .get("hal_graphics_composer_default")
        .ok_or_else(|| io::Error::other("Guest hal_graphics_composer_default type missing"))?;
    let sf = plan
        .types
        .get("surfaceflinger")
        .ok_or_else(|| io::Error::other("Guest surfaceflinger type missing"))?;
    let sm = plan
        .types
        .get("servicemanager")
        .ok_or_else(|| io::Error::other("Guest servicemanager type missing"))?;
    let sys_file = plan
        .types
        .get("system_file")
        .ok_or_else(|| io::Error::other("Guest system_file type missing"))?;
    let binder_dev = plan
        .types
        .get("binder_device")
        .ok_or_else(|| io::Error::other("Guest binder_device type missing"))?;
    let comp_svc = plan
        .types
        .get("hal_graphics_composer_service")
        .ok_or_else(|| io::Error::other("Guest hal_graphics_composer_service type missing"))?;
    let rules: [(&str, &str, &str, &str, &[&str]); 11] = [
        (composer, "r", sys_file, "file", &["entrypoint", "execute", "execute_no_trans", "read", "open", "getattr", "map"]),
        (composer, "r", "ksu", "fd", &["use"]),
        (composer, "r", "ksu", "fifo_file", &["write"]),
        (composer, "r", binder_dev, "chr_file", &["read", "write", "open", "ioctl", "map", "getattr"]),
        (composer, "r", sm, "binder", &["call", "transfer"]),
        (sm, "r", composer, "binder", &["call", "transfer"]),
        (composer, "r", comp_svc, "service_manager", &["add", "find"]),
        (composer, "r", sf, "binder", &["call", "transfer"]),
        (composer, "r", sf, "fd", &["use"]),
        (sf, "r", composer, "binder", &["call", "transfer"]),
        (sf, "r", comp_svc, "service_manager", &["find"]),
    ];
    for (src, _src_role, dst, class, perms) in rules {
        let src_ctx = format!("u:r:{src}:s0");
        let dst_role = if matches!(class, "binder" | "fd" | "fifo_file") && (dst == "ksu" || dst == sf || dst == sm || dst == composer) {
            "r"
        } else {
            "object_r"
        };
        let dst_ctx = format!("u:{dst_role}:{dst}:s0");
        let allowed = || {
            perms.iter().try_fold(true, |all, p| {
                Ok::<_, io::Error>(selinux::access_allowed(&src_ctx, &dst_ctx, class, p)? && all)
            })
        };
        if allowed()? {
            continue;
        }
        let rule = vendor_rule(src, dst, class, perms);
        let status = Command::new("/data/adb/ksu/bin/ksud")
            .args(["sepolicy", "patch", &rule])
            .status()?;
        if !status.success() || !allowed()? {
            return Err(io::Error::other(format!(
                "Guest Virtual Composer SELinux rule failed: {rule}"
            )));
        }
    }
    println!("Guest Virtual Composer SELinux rules verified for {composer_sid}");
    Ok(())
}

pub(in crate::guest) fn apply_graphics_allocator_access(
    plan: &ssal::guest_policy::Plan,
) -> io::Result<()> {
    let alloc_sid = plan.context("hal_graphics_allocator_default", true)?;
    selinux::require_enforcing_domain(&alloc_sid)?;
    let alloc = plan
        .types
        .get("hal_graphics_allocator_default")
        .ok_or_else(|| io::Error::other("Guest hal_graphics_allocator_default type missing"))?;
    let sf = plan
        .types
        .get("surfaceflinger")
        .ok_or_else(|| io::Error::other("Guest surfaceflinger type missing"))?;
    let hwsm = plan
        .types
        .get("hwservicemanager")
        .ok_or_else(|| io::Error::other("Guest hwservicemanager type missing"))?;
    let hwbinder_dev = plan
        .types
        .get("hwbinder_device")
        .ok_or_else(|| io::Error::other("Guest hwbinder_device type missing"))?;
    let alloc_hwsvc = plan
        .types
        .get("hal_graphics_allocator_hwservice")
        .ok_or_else(|| io::Error::other("Guest hal_graphics_allocator_hwservice type missing"))?;
    let hwsm_prop = plan
        .types
        .get("hwservicemanager_prop")
        .ok_or_else(|| io::Error::other("Guest hwservicemanager_prop type missing"))?;
    let default_hwsvc = plan
        .types
        .get("default_android_hwservice")
        .ok_or_else(|| io::Error::other("Guest default_android_hwservice type missing"))?;
    let hidl_base_hwsvc = plan
        .types
        .get("hidl_base_hwservice")
        .ok_or_else(|| io::Error::other("Guest hidl_base_hwservice type missing"))?;
    let rules: [(&str, &str, &str, &[&str]); 25] = [
        (alloc, "hal_graphics_allocator_default_exec", "file", &["entrypoint", "execute", "execute_no_trans", "read", "open", "getattr", "map"]),
        (alloc, "vendor_file", "dir", &["search", "getattr", "read", "open"]),
        (alloc, "vendor_file", "file", &["read", "open", "getattr", "map", "execute"]),
        (alloc, "vendor_hal_file", "dir", &["search", "getattr", "read", "open"]),
        (alloc, "vendor_hal_file", "file", &["read", "open", "getattr", "map", "execute"]),
        (alloc, "same_process_hal_file", "dir", &["search", "getattr", "read", "open"]),
        (alloc, "same_process_hal_file", "file", &["read", "open", "getattr", "map", "execute"]),
        (alloc, "gpu_device", "chr_file", &["read", "write", "open", "ioctl", "getattr", "map"]),
        (alloc, "ksu", "fd", &["use"]),
        (alloc, "ksu", "fifo_file", &["write"]),
        (alloc, hwbinder_dev, "chr_file", &["read", "write", "open", "ioctl", "map", "getattr"]),
        (alloc, hwsm, "binder", &["call", "transfer"]),
        (hwsm, alloc, "binder", &["call", "transfer"]),
        (alloc, alloc_hwsvc, "hwservice_manager", &["add", "find"]),
        (alloc, default_hwsvc, "hwservice_manager", &["add", "find"]),
        (alloc, hidl_base_hwsvc, "hwservice_manager", &["add"]),
        (alloc, hwsm_prop, "file", &["read", "open", "getattr", "map"]),
        (alloc, "dmabuf_system_heap_device", "chr_file", &["read", "open", "ioctl", "getattr"]),
        (alloc, "vendor_dmabuf_system_heap_device", "chr_file", &["read", "open", "ioctl", "getattr"]),
        (sf, alloc, "binder", &["call", "transfer"]),
        (sf, alloc, "fd", &["use"]),
        (alloc, sf, "binder", &["call", "transfer"]),
        (alloc, sf, "fd", &["use"]),
        (sf, alloc_hwsvc, "hwservice_manager", &["find"]),
        (sf, default_hwsvc, "hwservice_manager", &["find"]),
    ];
    for (src, dst, class, perms) in rules {
        let src_ctx = format!("u:r:{src}:s0");
        let dst_role = if matches!(class, "binder" | "fd" | "fifo_file")
            && (dst == "ksu" || dst == sf || dst == hwsm || dst == alloc)
        {
            "r"
        } else {
            "object_r"
        };
        let dst_ctx = format!("u:{dst_role}:{dst}:s0");
        let allowed = || {
            perms.iter().try_fold(true, |all, p| {
                Ok::<_, io::Error>(selinux::access_allowed(&src_ctx, &dst_ctx, class, p)? && all)
            })
        };
        if allowed()? {
            continue;
        }
        let rule = vendor_rule(src, dst, class, perms);
        let status = Command::new("/data/adb/ksu/bin/ksud")
            .args(["sepolicy", "patch", &rule])
            .status()?;
        if !status.success() || !allowed()? {
            return Err(io::Error::other(format!(
                "Guest Graphics Allocator SELinux rule failed: {rule}"
            )));
        }
    }
    println!("Guest Graphics Allocator SELinux rules verified for {alloc_sid}");
    Ok(())
}

pub(in crate::guest) fn apply_hwbinder_vintf_access(
    plan: &ssal::guest_policy::Plan,
) -> io::Result<()> {
    let manager = plan.context("hwservicemanager", true)?;
    selinux::require_enforcing_domain(&manager)?;
    let domain = plan
        .types
        .get("hwservicemanager")
        .ok_or_else(|| io::Error::other("Guest hwservicemanager type missing"))?;
    for target in ["vendor_file", "vendor_hal_file", "same_process_hal_file"] {
        let context = format!("u:object_r:{target}:s0");
        let allowed = || {
            ["search", "getattr"].iter().try_fold(true, |all, permission| {
                Ok::<_, io::Error>(
                    selinux::access_allowed(&manager, &context, "dir", permission)? && all,
                )
            })
        };
        if allowed()? {
            continue;
        }
        let rule = format!("allow {domain} {target} dir {{ search getattr }}");
        let status = Command::new("/data/adb/ksu/bin/ksud")
            .args(["sepolicy", "patch", &rule])
            .status()?;
        if !status.success() || !allowed()? {
            return Err(io::Error::other(format!(
                "Y702 Guest HwBinder VINTF permission failed: {rule}"
            )));
        }
    }
    for (name, class, permissions) in [
        ("apex_mnt_dir", "dir", &["getattr", "open", "read", "search"][..]),
        ("apex_info_file", "file", &["getattr", "map", "open", "read"][..]),
        ("apex_ready_prop", "file", &["getattr", "map", "open", "read"][..]),
    ] {
        let target = plan
            .types
            .get(name)
            .ok_or_else(|| io::Error::other(format!("Guest {name} type missing")))?;
        let context = format!("u:object_r:{target}:s0");
        let allowed = || {
            permissions.iter().try_fold(true, |all, permission| {
                Ok::<_, io::Error>(
                    selinux::access_allowed(&manager, &context, class, permission)? && all,
                )
            })
        };
        if allowed()? {
            continue;
        }
        let rule = format!(
            "allow {domain} {target} {class} {{ {} }}",
            permissions.join(" ")
        );
        let status = Command::new("/data/adb/ksu/bin/ksud")
            .args(["sepolicy", "patch", &rule])
            .status()?;
        if !status.success() || !allowed()? {
            return Err(io::Error::other(format!(
                "Y702 Guest HwBinder APEX/VINTF permission failed: {rule}"
            )));
        }
    }
    println!("Y702 Guest HwBinder VINTF search verified for {manager}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_y702_avc_rules() {
        let rules: Vec<_> = VENDOR_ACCESS
            .map(|(target, class, permissions)| {
                vendor_rule("ssal_p0001_shell", target, class, permissions)
            })
            .into();
        let observed: Vec<_> = include_str!("../../../scripts/guest-graphics-y702.rule")
            .lines()
            .filter(|line| line.starts_with("allow "))
            .collect();
        assert_eq!(rules, observed);
    }
}
