use rsproperties::PropertyInfoEntry;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};

pub(super) struct Policy {
    pub entries: Vec<PropertyInfoEntry>,
    pub default_context: String,
}

impl Policy {
    pub fn resolve(&self, name: &str) -> (&str, &str) {
        let mut context = self.default_context.as_str();
        let mut kind = "string";
        let mut node = String::new();
        let mut remaining = name;
        loop {
            if let Some(entry) = self
                .entries
                .iter()
                .find(|e| !e.exact_match() && e.name() == node)
            {
                let (c, t) = (entry.context(), entry.type_str());
                if !c.is_empty() {
                    context = c;
                }
                if !t.is_empty() {
                    kind = t;
                }
            }
            if let Some(entry) = self
                .entries
                .iter()
                .filter(|e| {
                    !e.exact_match() && !e.name().ends_with('.') && e.name().starts_with(&node)
                })
                .filter(|e| {
                    let tail = &e.name()[node.len()..];
                    !tail.contains('.') && remaining.starts_with(tail)
                })
                .max_by_key(|e| e.name().len())
            {
                let (c, t) = (entry.context(), entry.type_str());
                if !c.is_empty() {
                    context = c;
                }
                if !t.is_empty() {
                    kind = t;
                }
            }
            let Some((segment, rest)) = remaining.split_once('.') else {
                break;
            };
            let child = format!("{node}{segment}.");
            if !self.entries.iter().any(|e| e.name().starts_with(&child)) {
                break;
            }
            node = child;
            remaining = rest;
        }
        if let Some(entry) = self
            .entries
            .iter()
            .find(|e| e.exact_match() && e.name() == name)
        {
            if !entry.context().is_empty() {
                context = entry.context();
            }
            if !entry.type_str().is_empty() {
                kind = entry.type_str();
            }
        }
        (context, kind)
    }

    pub fn validate(&self, name: &str, value: &str) -> io::Result<&str> {
        rsproperties::wire::validate_property_name(name)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        rsproperties::wire::validate_value_len(name, value)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        if let Some(actual) = name.strip_prefix("next_boot.") {
            if !actual.starts_with("persist.") {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "only persistent properties may be staged",
                ));
            }
            return self.validate(actual, value);
        }
        if name.starts_with("ctl.")
            || matches!(name, "sys.powerctl" | "selinux.restorecon_recursive")
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Guest control property disabled",
            ));
        }
        let (context, kind) = self.resolve(name);
        if !check_type(kind, value) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "property type mismatch",
            ));
        }
        Ok(context)
    }
}

pub(super) fn check_access(source: &str, target: &str) -> io::Result<()> {
    // Never let a context become another token in the selinuxfs transaction.
    if [source, target]
        .iter()
        .any(|s| s.is_empty() || s.bytes().any(|b| b.is_ascii_whitespace() || b == 0))
    {
        return Err(io::Error::other("invalid SELinux context"));
    }
    let class: u32 = fs::read_to_string("/sys/fs/selinux/class/property_service/index")?
        .trim()
        .parse()
        .map_err(io::Error::other)?;
    let bit: u32 = fs::read_to_string("/sys/fs/selinux/class/property_service/perms/set")?
        .trim()
        .parse()
        .map_err(io::Error::other)?;
    let mask = bit
        .checked_sub(1)
        .and_then(|b| 1u32.checked_shl(b))
        .ok_or_else(|| io::Error::other("invalid SELinux permission bit"))?;
    let mut access = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/sys/fs/selinux/access")?;
    access.write_all(format!("{source} {target} {class} {mask:x}").as_bytes())?;
    let mut reply = String::new();
    access.read_to_string(&mut reply)?;
    let fields: Vec<_> = reply.split_whitespace().collect();
    if fields.len() != 6 {
        return Err(io::Error::other("incomplete SELinux access decision"));
    }
    let allowed = u32::from_str_radix(fields[0], 16).map_err(io::Error::other)?;
    let decided = u32::from_str_radix(fields[1], 16).map_err(io::Error::other)?;
    // Guest-only permissive domains collect AVCs; this server still requires an explicit allow.
    if decided & mask != mask || allowed & mask != mask {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "property_service:set denied",
        ));
    }
    Ok(())
}

fn integer(value: &str, signed: bool) -> bool {
    let value = value.trim_start_matches(|c: char| c.is_ascii_whitespace());
    let (negative, digits) = if let Some(s) = value.strip_prefix('-') {
        if !signed {
            return false;
        }
        (true, s)
    } else {
        (false, value.strip_prefix('+').unwrap_or(value))
    };
    let (radix, digits) = if let Some(s) = digits
        .strip_prefix("0x")
        .or_else(|| digits.strip_prefix("0X"))
    {
        (16, s)
    } else {
        (10, digits)
    };
    let Ok(number) = u64::from_str_radix(digits, radix) else {
        return false;
    };
    !signed
        || if negative {
            number <= (i64::MAX as u64) + 1
        } else {
            number <= i64::MAX as u64
        }
}

fn check_type(kind: &str, value: &str) -> bool {
    if value.is_empty() {
        return true;
    }
    let mut parts = kind.split_whitespace();
    match parts.next() {
        Some("string") => true,
        Some("bool") => matches!(value, "true" | "false" | "1" | "0"),
        Some("int") => integer(value, true),
        Some("uint") => integer(value, false),
        Some("double") => value
            .trim_start()
            .parse::<f64>()
            .is_ok_and(|v| v.is_finite()),
        Some("size") => value
            .strip_suffix(['k', 'm', 'g'])
            .is_some_and(|s| !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit())),
        Some("enum") => parts.any(|p| p == value),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn entry(name: &str, context: &str, kind: &str, exact: bool) -> PropertyInfoEntry {
        PropertyInfoEntry::new(name.into(), context.into(), kind, exact).unwrap()
    }
    #[test]
    fn exact_prefix_and_inherited_type() {
        let policy = Policy {
            default_context: "default".into(),
            entries: vec![
                entry("persist.", "persist", "bool", false),
                entry("persist.test", "partial", "", false),
                entry("persist.test.", "child", "uint", false),
                entry("persist.test.exact", "exact", "enum a b", true),
                entry("persist.short", "short", "uint", false),
                entry("persist.shorter", "long", "", false),
            ],
        };
        assert_eq!(policy.resolve("unknown"), ("default", "string"));
        assert_eq!(policy.resolve("persist.tested"), ("partial", "bool"));
        assert_eq!(policy.resolve("persist.test.any"), ("child", "uint"));
        assert_eq!(policy.resolve("persist.test.exact"), ("exact", "enum a b"));
        assert_eq!(policy.resolve("persist.shorter"), ("long", "bool"));
        assert!(policy.validate("ctl.start", "x").is_err());
        assert!(policy.validate("sys.powerctl", "reboot").is_err());
        assert!(policy.validate("persist.test.any", "bad").is_err());
        assert!(policy.validate("persist.test.any", "").is_ok());
        assert_eq!(
            policy.validate("next_boot.persist.test.any", "3").unwrap(),
            "child"
        );
        assert!(policy
            .validate("next_boot.persist.test.any", "bad")
            .is_err());
        assert!(policy.validate("next_boot.sys.powerctl", "reboot").is_err());
    }
    #[test]
    fn aosp_value_types() {
        for (kind, good, bad) in [
            ("bool", "1", "yes"),
            ("int", "-0x10", "9223372036854775808"),
            ("uint", "0xffffffffffffffff", "-1"),
            ("double", "1.25", "NaN"),
            ("size", "128m", "128M"),
            ("enum a b", "b", "c"),
        ] {
            assert!(check_type(kind, good), "{kind}");
            assert!(!check_type(kind, bad), "{kind}");
        }
    }
}
