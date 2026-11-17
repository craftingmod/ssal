//! Facts captured by the SSAL mount manager, before the APEX tmpfs becomes read-only.
use serde::{Deserialize, Serialize};

pub const PATH: &str = "/apex/ssal-registry.json";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Package {
    pub module_name: String,
    pub version_code: i64,
    pub version_name: Option<String>,
    pub source_path: String,
    pub module_path: String,
    pub mount_path: String,
    pub partition: i8,
    pub is_active: bool,
}

pub fn validate(packages: &[Package]) -> Result<(), String> {
    if packages.is_empty() {
        return Err("Guest APEX registry is empty".into());
    }
    let mut names = std::collections::BTreeSet::new();
    for p in packages {
        if p.module_name.is_empty()
            || !p
                .module_name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            || matches!(p.module_name.as_str(), "." | "..")
            || !names.insert(&p.module_name)
            || p.version_code < 0
            || !(0..=3).contains(&p.partition)
            || !p.module_path.starts_with("/apex/.packages/")
            || p.mount_path != format!("/apex/{}@{}", p.module_name, p.version_code)
            || !match p.partition {
                0 => p.source_path.starts_with("/system/"),
                1 => {
                    p.source_path.starts_with("/system_ext/")
                        || p.source_path.starts_with("/system/system_ext/")
                }
                2 => {
                    p.source_path.starts_with("/product/")
                        || p.source_path.starts_with("/system/product/")
                }
                3 => {
                    p.source_path.starts_with("/vendor/")
                        || p.source_path.starts_with("/system/vendor/")
                }
                _ => false,
            }
            || [&p.source_path, &p.module_path]
                .iter()
                .any(|s| s.split('/').any(|c| matches!(c, "." | "..")))
        {
            return Err(format!(
                "invalid or duplicate Guest APEX: {}",
                p.module_name
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn registry_rejects_empty_and_invented_paths() {
        assert!(validate(&[]).is_err());
        let p = Package {
            module_name: "com.android.art".into(),
            version_code: 42,
            version_name: None,
            source_path: "/system/apex/art.capex".into(),
            module_path: "/apex/.packages/0.apex".into(),
            mount_path: "/apex/com.android.art@42".into(),
            partition: 0,
            is_active: true,
        };
        assert!(validate(&[p.clone()]).is_ok());
        assert!(validate(&[p.clone(), p.clone()]).is_err());
        let mut bad = p;
        bad.module_path = "/apex/.packages/../host".into();
        assert!(validate(&[bad]).is_err());
    }
}
