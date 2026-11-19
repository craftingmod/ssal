//! Guest SELinux rules for the Concurrent Mode Power Broker connection.
use super::{native, BTreeMap, Plan};

pub(super) const SYSTEM_SUSPEND_DOMAIN: &str = "system_suspend";

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
