//! Offline compatibility contract. This is not a guest launch authorization.
use serde::{Deserialize, Serialize};
use std::io;

pub const XML: &str = include_str!("../../../guest-compat/lockscreen/ssal-lockscreen.xml");
pub const XML_TARGET: &str = "system/etc/sysconfig/ssal-lockscreen.xml";
pub const APK_TARGET: &str = "product/overlay/SSALWeaverOverlay.apk";

/// Diagnostic evidence only. These values never grant permission to launch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ValidationStage {
    Disabled,
    OfflineValidated,
    NamespaceProbeReady,
    NamespaceValidated,
    FrameworkValidationBlocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ValidationStatus {
    pub sysconfig: ValidationStage,
    pub rro: ValidationStage,
    pub framework: ValidationStage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub enabled: bool,
    pub disable_secure_lockscreen: bool,
    pub disable_weaver_on_unsecured_users: bool,
    pub require_fresh_userdata: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            enabled: false,
            disable_secure_lockscreen: true,
            disable_weaver_on_unsecured_users: true,
            require_fresh_userdata: true,
        }
    }
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct Injection {
    pub source: &'static str,
    /// Always relative to the composed guest root, never the host root.
    pub target: &'static str,
    pub mode: u32,
    pub context: &'static str,
}

impl Config {
    /// Current built-in evidence, not editable profile data. Namespace and
    /// framework results are deliberately not inferred from offline evidence.
    pub fn validation_status(&self) -> ValidationStatus {
        let sysconfig = if self.enabled && self.disable_secure_lockscreen {
            ValidationStage::OfflineValidated
        } else {
            ValidationStage::Disabled
        };
        let rro = if self.enabled && self.disable_weaver_on_unsecured_users {
            ValidationStage::FrameworkValidationBlocked
        } else {
            ValidationStage::Disabled
        };
        ValidationStatus {
            sysconfig,
            rro,
            framework: if self.enabled {
                ValidationStage::FrameworkValidationBlocked
            } else {
                ValidationStage::Disabled
            },
        }
    }
    pub fn from_profile(profile: &serde_json::Value) -> io::Result<Self> {
        profile.get("guest_lock_compat").cloned().map_or_else(
            || Ok(Self::default()),
            |value| serde_json::from_value(value).map_err(io::Error::other),
        )
    }

    pub fn plan(
        &self,
        created_with_contract: bool,
        userdata_empty: bool,
    ) -> io::Result<Vec<Injection>> {
        if !self.enabled {
            return Ok(Vec::new());
        }
        if !self.require_fresh_userdata || !created_with_contract || !userdata_empty {
            return Err(io::Error::other(
                "guest lock compatibility requires a newly created, empty independent userdata with a creation contract; migration is unsupported",
            ));
        }
        let mut plan = Vec::new();
        if self.disable_secure_lockscreen {
            plan.push(Injection {
                source: "ssal-lockscreen.xml",
                target: XML_TARGET,
                mode: 0o644,
                context: "u:object_r:system_file:s0",
            });
        }
        if self.disable_weaver_on_unsecured_users {
            plan.push(Injection {
                source: "overlay/SSALWeaverOverlay.apk",
                target: APK_TARGET,
                mode: 0o644,
                context: "u:object_r:system_file:s0",
            });
        }
        Ok(plan)
    }

    /// Fail closed until actual feature removal, immutable overlay and HAL isolation
    /// have been certified. Editing JSON cannot authorize a Framework boot.
    pub fn runtime_gate(&self) -> io::Result<()> {
        if self.enabled {
            return Err(io::Error::other(
                format!("guest_lock_compat blocked: {:?}; runtime feature removal, immutable overlay, Enforcing and Host authentication HAL isolation not certified; offline preparation only", self.validation_status()),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_profiles_are_disabled_and_unknown_configuration_is_rejected() {
        let config = Config::from_profile(&serde_json::json!({})).unwrap();
        assert!(!config.enabled);
        assert!(config.plan(false, false).unwrap().is_empty());
        assert!(config.runtime_gate().is_ok());
        assert!(
            Config::from_profile(&serde_json::json!({"guest_lock_compat":{"enable":true}}))
                .is_err()
        );
    }

    #[test]
    fn fresh_contract_and_empty_userdata_are_mandatory() {
        let mut config = Config {
            enabled: true,
            ..Config::default()
        };
        for (contract, empty) in [(false, false), (false, true), (true, false)] {
            assert!(config.plan(contract, empty).is_err());
        }
        let plan = config.plan(true, true).unwrap();
        assert_eq!(plan.len(), 2);
        assert_eq!(plan[0].target, XML_TARGET);
        assert_eq!(plan[1].target, APK_TARGET);
        assert!(config.runtime_gate().is_err());
        config.require_fresh_userdata = false;
        assert!(config.plan(true, true).is_err());
    }

    #[test]
    fn features_are_independent() {
        let mut config = Config {
            enabled: true,
            disable_weaver_on_unsecured_users: false,
            ..Config::default()
        };
        assert_eq!(config.plan(true, true).unwrap().len(), 1);
        config.disable_secure_lockscreen = false;
        config.disable_weaver_on_unsecured_users = true;
        assert_eq!(config.plan(true, true).unwrap()[0].target, APK_TARGET);
    }

    #[test]
    fn diagnostic_stages_do_not_authorize_launch_and_stay_independent() {
        let mut config = Config {
            enabled: true,
            ..Config::default()
        };
        let status = config.validation_status();
        assert_eq!(status.sysconfig, ValidationStage::OfflineValidated);
        assert_eq!(status.rro, ValidationStage::FrameworkValidationBlocked);
        assert!(config.runtime_gate().is_err());
        config.disable_secure_lockscreen = false;
        assert_eq!(
            config.validation_status().sysconfig,
            ValidationStage::Disabled
        );
        assert!(config.runtime_gate().is_err());
        config.disable_weaver_on_unsecured_users = false;
        assert!(config.runtime_gate().is_err());
        config.enabled = false;
        assert!(config.runtime_gate().is_ok());
    }
}
