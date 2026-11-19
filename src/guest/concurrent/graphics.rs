use crate::diagnostics::selinux;
use std::io;
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
