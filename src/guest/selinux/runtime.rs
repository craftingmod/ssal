use super::*;
use crate::namespace_mounts::Mounts;
use std::ffi::CString;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::process::Command;

#[derive(Default, Serialize, Deserialize)]
struct Applied {
    boot_id: String,
    symbols: BTreeSet<String>,
    #[serde(default)]
    placeholders: BTreeSet<String>,
    statements: BTreeSet<String>,
    pending: bool,
    result: String,
    #[serde(default)]
    native_batches: Vec<NativeBatchResult>,
    #[serde(default)]
    rule_readback_verified: bool,
}

#[derive(Serialize, Deserialize)]
struct NativeBatchResult {
    batch: usize,
    expected: usize,
    succeeded: Option<usize>,
    error: Option<String>,
    partial_or_uncertain: bool,
}

impl NativeBatchResult {
    fn complete(&mut self, result: io::Result<usize>) {
        match result {
            Ok(count) => {
                self.succeeded = Some(count);
                self.partial_or_uncertain = count != self.expected;
                if self.partial_or_uncertain {
                    self.error = Some(format!("partial batch: {count}/{}; failed commands cannot be identified from the count", self.expected));
                }
            }
            Err(e) => self.error = Some(e.to_string()),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    Ksud,
    KernelSuNative,
}

fn select_backend(plan: &Plan, requested: Backend) -> Backend {
    if plan.rules.iter().any(|rule| {
        plan.native_rules.get(rule).is_some_and(|commands| {
            commands.iter().any(|c| {
                c.cmd == 7
                    && c.args
                        .get(4)
                        .is_some_and(|name| !name.is_empty() && !symbol(name))
            })
        })
    }) {
        Backend::KernelSuNative
    } else {
        requested
    }
}

pub fn encode_native(plan: &Plan) -> io::Result<Vec<native::EncodedBatch>> {
    let mut ordered = delta(plan, &Applied::default())?;
    if !plan.permissive {
        return native::encode(plan, &ordered);
    }
    let mut plan = plan.clone();
    add_domain_mode_commands(&mut plan, &mut ordered, &BTreeSet::new(), &BTreeSet::new());
    native::encode(&plan, &ordered)
}

/// Offline validation only: never acquires a driver FD or calls an ioctl.
pub fn check_native(plan: &Plan) -> io::Result<()> {
    encode_native(plan).map(|_| ())
}

fn enforcing() -> io::Result<()> {
    if fs::read_to_string("/sys/fs/selinux/enforce")?.trim() != "1" {
        return Err(invalid(
            "Phase 8C requires Host SELinux Enforcing; mode was not changed",
        ));
    }
    Ok(())
}

fn read_policy_with_recovery(
    mut read: impl FnMut() -> io::Result<Vec<u8>>,
    recover: impl FnOnce() -> io::Result<()>,
) -> io::Result<Vec<u8>> {
    match read() {
        Err(error) if error.raw_os_error() == Some(libc::EINVAL) => {
            recover().map_err(|e| {
                invalid(format!(
                    "active SELinux policy read returned EINVAL; export recovery failed: {e}"
                ))
            })?;
            read().map_err(|e| {
                invalid(format!(
                    "active SELinux policy read after export recovery failed: {e}"
                ))
            })
        }
        result => result,
    }
}

fn explicit_read_permission(reply: &str, requested: u32) -> io::Result<bool> {
    let fields: Vec<_> = reply.split_whitespace().collect();
    if fields.len() != 6 {
        return Err(invalid(
            "incomplete SELinux access response during export recovery",
        ));
    }
    let allowed = u32::from_str_radix(fields[0], 16).map_err(io::Error::other)?;
    let decided = u32::from_str_radix(fields[1], 16).map_err(io::Error::other)?;
    Ok(allowed & requested == requested && decided & requested == requested)
}

fn recover_policy_export() -> io::Result<()> {
    enforcing()?;
    let class = fs::read_to_string("/sys/fs/selinux/class/file/index")?;
    let class: u32 = class.trim().parse().map_err(io::Error::other)?;
    let bit = fs::read_to_string("/sys/fs/selinux/class/file/perms/read")?;
    let bit: u32 = bit.trim().parse().map_err(io::Error::other)?;
    let requested = bit
        .checked_sub(1)
        .and_then(|b| 1u32.checked_shl(b))
        .ok_or_else(|| invalid("invalid SELinux file read permission index"))?;
    let mut access = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/sys/fs/selinux/access")?;
    access.write_all(
        format!("u:r:ksu:s0 u:object_r:ssal_image_file:s0 {class} {requested:x}").as_bytes(),
    )?;
    let mut reply = String::new();
    std::io::Read::read_to_string(&mut access, &mut reply)?;
    if !explicit_read_permission(&reply, requested)? {
        return Err(invalid("export recovery requires existing ksu -> ssal_image_file:file read permission; no rule applied"));
    }
    // Reapplying an existing allow can refresh KernelSU's stale serialized policy length.
    println!("Guest SELinux: active policy read EINVAL; reapplying verified existing SSAL read rule once to recover export");
    let output = Command::new("/data/adb/ksu/bin/ksud")
        .args(["sepolicy", "patch", "allow ksu ssal_image_file file read"])
        .output()?;
    if !output.status.success() {
        return Err(invalid(format!(
            "KernelSU export recovery failed ({}): {}{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    enforcing()
}

fn split_allow_rule(rule: &str) -> io::Result<Vec<String>> {
    // 1. 주석과 끝의 세미콜론 제거
    let line = rule.split('#').next().unwrap_or("").trim();
    let line = line.strip_suffix(';').unwrap_or(line).trim();

    // 2. 중괄호 주변 공백 정규화
    let normalized = line.replace('{', " { ").replace('}', " } ");

    let fields: Vec<&str> = normalized.split_whitespace().collect();

    let Some(&action) = fields.first() else {
        return Ok(vec![rule.into()]);
    };

    if !matches!(action, "allow" | "auditallow" | "dontaudit") {
        return Ok(vec![rule.into()]);
    }

    let error = || invalid(format!("invalid serialized allow rule: {rule:?}"));

    // 3. 헤더 파싱
    // KernelSU: allow source target class permission
    // SELinux:  allow source target:class permission
    let (source, target, class, perm_start) = match fields.as_slice() {
        [_, source, target_class, ..] if target_class.contains(':') => {
            let (target, class) = target_class.split_once(':').ok_or_else(error)?;
            (*source, target, class, 3)
        }
        [_, source, target, class, ..] => (*source, *target, *class, 4),
        _ => return Err(error()),
    };

    if [source, target, class]
        .iter()
        .any(|s| s.is_empty() || s.contains(['{', '}', ';']))
    {
        return Err(error());
    }

    // 4. Permission 추출
    let tail = &fields[perm_start..];

    let permissions: &[&str] = match tail {
        ["{", middle @ .., "}"] if !middle.is_empty() => middle,
        [single] if *single != "{" && *single != "}" => tail,
        _ => return Err(error()),
    };

    if permissions
        .iter()
        .any(|p| p.is_empty() || p.contains(['{', '}', ';']))
    {
        return Err(error());
    }

    // 5. 기존 분할 로직 사용
    let groups = [permissions_text(permissions)];

    // 6. KernelSU 형식으로 정규화
    Ok(groups
        .into_iter()
        .map(|perms| format!("{action} {source} {target} {class} {{ {perms} }}"))
        .collect())
}

fn split_xperm_rule(rule: &str) -> io::Result<Vec<String>> {
    let line = rule.split('#').next().unwrap_or("").trim();
    let line = line.strip_suffix(';').unwrap_or(line).trim();
    let normalized = line.replace('{', " { ").replace('}', " } ");
    let fields: Vec<&str> = normalized.split_whitespace().collect();
    let Some(&action) = fields.first() else {
        return Ok(vec![rule.into()]);
    };
    if !matches!(action, "allowxperm" | "auditallowxperm" | "dontauditxperm") {
        return Ok(vec![rule.into()]);
    }

    let error = || invalid(format!("invalid serialized xperm rule: {rule:?}"));
    let (source, target, class, tail_start) = match fields.as_slice() {
        [_, source, target_class, ..] if target_class.contains(':') => {
            let (target, class) = target_class.split_once(':').ok_or_else(error)?;
            (*source, target, class, 3)
        }
        [_, source, target, class, ..] => (*source, *target, *class, 4),
        _ => return Err(error()),
    };
    if [source, target, class]
        .iter()
        .any(|s| s.is_empty() || s.contains(['{', '}', ';', ':']))
    {
        return Err(error());
    }

    let tail = &fields[tail_start..];
    let [operation, xperms @ ..] = tail else {
        return Err(error());
    };
    if *operation != "ioctl" {
        return Err(error());
    }
    let ranges: &[&str] = match xperms {
        ["{", values @ .., "}"] if !values.is_empty() => values,
        [single] if *single != "{" && *single != "}" => xperms,
        _ => return Err(error()),
    };

    ranges
        .iter()
        .map(|range| {
            let parse = |value: &str| u16::from_str_radix(value.strip_prefix("0x")?, 16).ok();
            let valid = match range.split_once('-') {
                Some((low, high)) => match (parse(low), parse(high)) {
                    (Some(low), Some(high)) => low <= high,
                    _ => false,
                },
                None => parse(range).is_some(),
            };
            if !valid {
                return Err(error());
            }
            Ok(format!(
                "{action} {source} {target} {class} {operation} {range}"
            ))
        })
        .collect()
}

fn delta(plan: &Plan, applied: &Applied) -> io::Result<Vec<String>> {
    if applied.pending {
        return Err(invalid(
            "previous KernelSU apply outcome uncertain; reboot before prepare (no live deletion)",
        ));
    }
    let mut rules = BTreeSet::new();
    for rule in &plan.rules {
        let action = rule.split_whitespace().next().unwrap_or("");
        if matches!(action, "allowxperm" | "auditallowxperm" | "dontauditxperm") {
            rules.extend(split_xperm_rule(rule)?);
        } else {
            rules.extend(split_allow_rule(rule)?);
        }
    }
    // KernelSU cannot remove policy statements already applied to this Guest ID.
    Ok(plan
        .declarations
        .iter()
        .chain(rules.iter().filter(|r| r.starts_with("typeattribute ")))
        .chain(rules.iter().filter(|r| !r.starts_with("typeattribute ")))
        .filter(|r| !applied.statements.contains(*r))
        .cloned()
        .collect())
}

fn domain_mode_changes<'a>(
    plan: &'a Plan,
    current: &'a BTreeSet<String>,
    owned: &'a BTreeSet<String>,
) -> impl Iterator<Item = (&'a String, bool)> {
    let prefix = format!("ssal_{}_", plan.id);
    current
        .intersection(owned)
        .filter(move |name| name.starts_with(&prefix))
        .filter(|name| !plan.permissive || !plan.domains.contains(*name))
        .map(|name| (name, false))
        .chain(
            plan.domains
                .difference(current)
                .filter(|_| plan.permissive)
                .map(|name| (name, true)),
        )
}

fn add_domain_mode_commands(
    plan: &mut Plan,
    ordered: &mut Vec<String>,
    current: &BTreeSet<String>,
    owned: &BTreeSet<String>,
) {
    let commands: Vec<_> = domain_mode_changes(plan, current, owned)
        .map(|(name, permissive)| {
            let action = if permissive { "permissive" } else { "enforce" };
            let subcmd = if permissive { 1 } else { 2 };
            (format!("{action} {name}"), name.clone(), subcmd)
        })
        .collect();
    for (statement, name, subcmd) in commands {
        native::record(&mut plan.native_rules, statement.clone(), 3, subcmd, &[&name]);
        ordered.push(statement);
    }
}

fn compatible_plan(
    plan: &Plan,
    symbols: &BTreeSet<String>,
    applied: &Applied,
    class_root: &Path,
) -> io::Result<(Plan, Vec<String>)> {
    let mut classes = BTreeMap::new();
    for entry in fs::read_dir(class_root)? {
        let entry = entry?;
        let perms = entry.path().join("perms");
        if !perms.is_dir() {
            continue;
        }
        let names = fs::read_dir(perms)?
            .map(|e| e.map(|e| e.file_name().to_string_lossy().into_owned()))
            .collect::<io::Result<BTreeSet<String>>>()?;
        classes.insert(entry.file_name().to_string_lossy().into_owned(), names);
    }
    let mut result = plan.clone();
    result.placeholders = plan
        .shared_types
        .iter()
        .filter(|name| !symbols.contains(*name) || applied.placeholders.contains(*name))
        .cloned()
        .collect();
    if !result.placeholders.is_empty() {
        let attribute = format!("ssal_{}_placeholders", plan.id);
        if plan
            .declarations
            .iter()
            .any(|d| d.split_whitespace().nth(1) == Some(&attribute))
        {
            return Err(invalid(
                "placeholder attribute collides with Guest declaration",
            ));
        }
        let text = format!("attribute {attribute}");
        let index = result
            .declarations
            .iter()
            .position(|d| d.starts_with("type "))
            .unwrap_or(result.declarations.len());
        result.declarations.insert(index, text.clone());
        native::record(&mut result.native_rules, text, 6, 0, &[&attribute]);
        for name in &result.placeholders {
            if !symbol(name) || !plan.types.contains_key(name) {
                return Err(invalid(format!("invalid placeholder type: {name}")));
            }
            let text = format!("type {name} {attribute}");
            result.declarations.push(text.clone());
            native::record(&mut result.native_rules, text, 4, 0, &[name, &attribute]);
        }
    }
    let declared: BTreeSet<_> = result
        .declarations
        .iter()
        .filter_map(|s| s.split_whitespace().nth(1).map(str::to_owned))
        .collect();
    let mut omitted = Vec::new();
    let mut narrowed = Vec::new();
    result.rules.retain(|rule| {
        let f: Vec<_> = rule.split_whitespace().collect();
        let reason = (|| -> Option<String> {
            // Placeholders must not inherit grants through Guest target attributes.
            for name in &f[1..3] {
                if result.placeholders.contains(*name) {
                    return Some(format!("permissionless placeholder: {name}"));
                }
            }
            for name in &f[1..3] {
                if *name != "self" && !declared.contains(*name) && !symbols.contains(*name) {
                    return Some(format!("Host symbol missing: {name}"));
                }
            }
            if f[0] == "typeattribute" {
                return None;
            }
            let Some(perms) = classes.get(f[3]) else {
                return Some(format!("Host class missing: {}", f[3]));
            };
            if matches!(f[0], "allow" | "auditallow" | "dontaudit") {
                let requested: Vec<_> = f[4..]
                    .iter()
                    .copied()
                    .filter(|p| !matches!(*p, "{" | "}"))
                    .collect();
                let valid: Vec<_> = requested
                    .iter()
                    .copied()
                    .filter(|p| perms.contains(*p))
                    .collect();
                if valid.len() != requested.len() {
                    if !valid.is_empty() {
                        let text = format!(
                            "{} {} {} {} {{ {} }}",
                            f[0],
                            f[1],
                            f[2],
                            f[3],
                            valid.join(" ")
                        );
                        if let Some(commands) = plan.native_rules.get(rule) {
                            result.native_rules.insert(
                                text.clone(),
                                commands
                                    .iter()
                                    .filter(|c| {
                                        c.cmd == 1
                                            && c.args
                                                .get(3)
                                                .is_some_and(|p| valid.contains(&p.as_str()))
                                    })
                                    .cloned()
                                    .collect(),
                            );
                        }
                        narrowed.push(text);
                    }
                    return Some(format!(
                        "Host permissions missing: {}: {}",
                        f[3],
                        requested
                            .into_iter()
                            .filter(|p| !perms.contains(*p))
                            .collect::<Vec<_>>()
                            .join(" ")
                    ));
                }
            } else if f[0].ends_with("xperm") && !perms.contains("ioctl") {
                return Some(format!("Host ioctl permission missing: {}", f[3]));
            }
            None
        })();
        if let Some(reason) = reason {
            omitted.push(format!("{reason}: {rule}"));
            false
        } else {
            true
        }
    });
    result.rules.extend(narrowed);
    Ok((result, omitted))
}

pub fn apply(profile: &Path, plan: &Plan) -> io::Result<()> {
    apply_with_backend(profile, plan, Backend::Ksud)
}

pub fn apply_with_backend(profile: &Path, plan: &Plan, backend: Backend) -> io::Result<()> {
    enforcing()?;
    plan.usable()?;
    check_native(plan)?;
    let directory = profile.join("selinux");
    let lock = File::create(directory.join("apply.lock"))?;
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(invalid("profile SELinux application already running"));
    }
    let boot_id = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    let path = directory.join("applied.json");
    let mut applied: Applied = match fs::read(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes)?,
        Err(e) if e.kind() == io::ErrorKind::NotFound => Applied::default(),
        Err(e) => return Err(e),
    };
    if applied.boot_id != boot_id {
        applied = Applied {
            boot_id,
            ..Applied::default()
        };
    }
    if plan.audit
        && applied
            .statements
            .iter()
            .any(|s| s.starts_with("dontaudit ") || s.starts_with("dontauditxperm "))
    {
        return Err(invalid(
            "Guest SELinux dontaudit rules were already applied in this boot; reboot before prepare --audit (no live deletion)",
        ));
    }
    let policy =
        read_policy_with_recovery(|| fs::read("/sys/fs/selinux/policy"), recover_policy_export)?;
    let symbols = super::symbols::read(&policy)?;
    let (mut compatible, omitted) = compatible_plan(
        plan,
        &symbols.names,
        &applied,
        Path::new("/sys/fs/selinux/class"),
    )?;
    let backend = select_backend(&compatible, backend);
    let compatible_bytes = serde_json::to_vec_pretty(&compatible)?;
    atomic(&directory.join("compatible-plan.json"), &compatible_bytes)?;
    atomic(
        &directory.join("compatibility.json"),
        &serde_json::to_vec_pretty(
            &serde_json::json!({"boot_id":applied.boot_id,"omitted":omitted,"placeholders":compatible.placeholders,"backend":if backend == Backend::KernelSuNative {"native"} else {"ksud"},"gsi_unsupported":plan.unsupported,
                "desired_plan_sha256":digest(&serde_json::to_vec_pretty(plan)?),
                "compatible_plan_sha256":digest(&compatible_bytes),
                "applied_evidence":"applied.json is a cumulative backend acknowledgement ledger for this boot; additions are not removed",
                "rule_readback_verified":false}),
        )?,
    )?;
    let mut ordered = delta(&compatible, &applied)?;
    let rule_count = ordered.len();
    add_domain_mode_commands(
        &mut compatible,
        &mut ordered,
        &symbols.permissive,
        &applied.symbols,
    );
    applied.rule_readback_verified = false;
    for declaration in &compatible.declarations {
        let name = declaration.split_whitespace().nth(1).unwrap();
        if symbols.names.contains(name) && !applied.symbols.contains(name) {
            return Err(invalid(format!(
                "unowned active policy symbol collision: {name}"
            )));
        }
    }
    let ksud = Path::new("/data/adb/ksu/bin/ksud");
    native::encode(&compatible, &ordered)?;
    if !ordered.is_empty() {
        let native = if backend == Backend::KernelSuNative {
            let batches = native::encode(&compatible, &ordered)?;
            let driver = native::KernelSuNative::open()?;
            driver.validate_uapi()?;
            Some((driver, batches))
        } else {
            None
        };
        let delta_path = directory.join("delta.rule");
        atomic(&delta_path, (ordered.join("\n") + "\n").as_bytes())?;
        applied.pending = true;
        applied.result = "applying".into();
        applied.native_batches.clear();
        atomic(&path, &serde_json::to_vec_pretty(&applied)?)?;
        if let Some((driver, batches)) = native {
            for (index, batch) in batches.iter().enumerate() {
                applied.native_batches.push(NativeBatchResult {
                    batch: index,
                    expected: batch.commands,
                    succeeded: None,
                    error: None,
                    partial_or_uncertain: true,
                });
                atomic(&path, &serde_json::to_vec_pretty(&applied)?)?;
                let result = driver.inject(batch);
                let report = applied.native_batches.last_mut().unwrap();
                report.complete(result);
                let failed = report.partial_or_uncertain;
                applied.result = if failed {
                    format!("Native batch {index} failed/partial; prior additions may remain; no rollback or automatic fallback; reboot required")
                } else {
                    format!(
                        "Native batch {index}: {}/{} commands succeeded",
                        batch.commands, batch.commands
                    )
                };
                atomic(&path, &serde_json::to_vec_pretty(&applied)?)?;
                if failed {
                    return Err(invalid(&applied.result));
                }
            }
        } else {
            let output = Command::new(ksud)
                .args(["sepolicy", "apply"])
                .arg(&delta_path)
                .output()?;
            fs::write(directory.join("apply-stdout.txt"), &output.stdout)?;
            fs::write(directory.join("apply-stderr.txt"), &output.stderr)?;
            if !output.status.success() {
                applied.result = format!(
                    "KernelSU apply failed (partial additions may remain): {}{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
                atomic(&path, &serde_json::to_vec_pretty(&applied)?)?;
                return Err(invalid(&applied.result));
            }
        }
        // Domain modes can change again this boot, so only ledger additive rules.
        for statement in &ordered[..rule_count] {
            applied.statements.insert(statement.clone());
            if statement.starts_with("type ") || statement.starts_with("attribute ") {
                applied
                    .symbols
                    .insert(statement.split_whitespace().nth(1).unwrap().into());
            }
        }
        if ordered.len() != rule_count {
            let policy = read_policy_with_recovery(
                || fs::read("/sys/fs/selinux/policy"),
                recover_policy_export,
            )?;
            let active = super::symbols::read(&policy)?;
            if domain_mode_changes(plan, &active.permissive, &applied.symbols)
                .next()
                .is_some()
            {
                return Err(invalid("Guest SELinux domain mode readback failed; reboot before prepare"));
            }
        }
        applied.pending = false;
        applied
            .placeholders
            .extend(compatible.placeholders.iter().cloned());
        applied.result =
            "backend acknowledged delta; rule readback not verified; Host Enforcing retained"
                .into();
        atomic(&path, &serde_json::to_vec_pretty(&applied)?)?;
        enforcing()?;
    }
    for original in ["zygote", "system_server", "init", "servicemanager"] {
        let context = CString::new(plan.context(original, true)?).map_err(invalid_cstring)?;
        let mut query = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/sys/fs/selinux/context")?;
        query.write_all(context.as_bytes_with_nul())?;
    }
    applied.result =
        "required process contexts verified; rule readback not verified; Host Enforcing retained"
            .into();
    atomic(&path, &serde_json::to_vec_pretty(&applied)?)?;
    enforcing()
}

fn invalid_cstring(e: std::ffi::NulError) -> io::Error {
    invalid(e.to_string())
}

pub fn load_applied_for_probe(system: &Path, profile: &Path) -> io::Result<Plan> {
    enforcing()?;
    let dir = profile.join("selinux");
    let desired = fs::read(dir.join("plan.json"))?;
    let compatible = fs::read(dir.join("compatible-plan.json"))?;
    let evidence: serde_json::Value =
        serde_json::from_slice(&fs::read(dir.join("compatibility.json"))?)?;
    let applied: Applied = serde_json::from_slice(&fs::read(dir.join("applied.json"))?)?;
    let plan: Plan = serde_json::from_slice(&desired)?;
    let compatible_plan: Plan = serde_json::from_slice(&compatible)?;
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    let hashes: Vec<_> = inputs(system)?
        .iter()
        .map(|(path, text)| Input {
            path: path.clone(),
            sha256: digest(text.as_bytes()),
        })
        .collect();
    if plan.version != VERSION
        || plan.input_hash != digest(&serde_json::to_vec(&hashes)?)
        || evidence["desired_plan_sha256"] != digest(&desired)
        || evidence["compatible_plan_sha256"] != digest(&compatible)
        || evidence["boot_id"] != boot
        || applied.boot_id != boot
        || applied.pending
        || !delta(&compatible_plan, &applied)?.is_empty()
    {
        return Err(invalid("Guest probe requires an already applied plan for this image and boot"));
    }
    plan.usable()?;
    if plan.permissive {
        let active = super::symbols::read(&fs::read("/sys/fs/selinux/policy")?)?;
        if domain_mode_changes(&plan, &active.permissive, &applied.symbols)
            .next()
            .is_some()
        {
            return Err(invalid("Guest probe requires the prepared SELinux domain mode"));
        }
    }
    Ok(plan)
}

pub fn prepare_mounted(
    system: &Path,
    system_image: &Path,
    profile: &Path,
    force_regen: bool,
    permissive: Option<bool>,
    audit: Option<bool>,
) -> io::Result<Plan> {
    fs::create_dir_all(profile.join("selinux"))?;
    let prepare_lock = File::create(profile.join("selinux/prepare.lock"))?;
    if unsafe { libc::flock(prepare_lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(invalid("profile SELinux preparation already running"));
    }
    let root = profile
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| invalid("profile root missing"))?;
    let registry_lock = File::create(root.join("state/selinux-ids.lock"))?;
    if unsafe { libc::flock(registry_lock.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let id = if MULTI_GUEST_SUPPORT == "single" {
        let image_dir = system_image
            .parent()
            .ok_or_else(|| invalid("system image directory missing"))?;
        system_image_id(root, image_dir)?
    } else {
        profile_id(root, profile)?
    };
    drop(registry_lock);
    let files = inputs(system)?;
    let (plan, regenerated) = prepare(profile, &id, &files, force_regen, permissive, audit)?;
    for original in ["init", "servicemanager", "socket_device", "property_socket"] {
        plan.context(original, false)?;
    }
    println!(
        "Guest SELinux: id={} input_hash={} regenerated={} types={} rules={} unsupported={}",
        plan.id,
        plan.input_hash,
        regenerated,
        plan.types.len(),
        plan.rules.len(),
        plan.unsupported.len()
    );
    let backend = match std::env::var("SSAL_PREPARE_SEPOLICY_BACKEND").as_deref() {
        Ok("native") => Backend::KernelSuNative,
        Ok("ksud") | Err(_) => Backend::Ksud,
        Ok(value) => return Err(invalid(format!("unknown prepare SELinux backend: {value}"))),
    };
    apply_with_backend(profile, &plan, backend)?;
    if plan.permissive {
        println!("Guest SELinux permissive=1; Guest Enforcing guards excluded");
    }
    if plan.audit {
        println!("Guest SELinux audit=1; Guest dontaudit rules excluded");
    }
    Ok(plan)
}

/// A private overlay copies up labels without modifying the registered read-only image.
pub fn isolate_system(
    plan: &Plan,
    mounts: &mut Mounts,
    root: &Path,
    backing: &Path,
) -> io::Result<()> {
    isolate_system_with_cache(plan, mounts, root, backing, None, None)
}

pub fn isolate_system_with_cache(
    plan: &Plan,
    mounts: &mut Mounts,
    root: &Path,
    session_backing: &Path,
    cached_root: Option<&Path>,
    cache_write_root: Option<&Path>,
) -> io::Result<()> {
    plan.usable()?;
    let scratch = root.parent().unwrap().join("selinux-overlay");
    fs::create_dir(&scratch)?;
    // Android tmpfs can lack trusted xattrs; use the already mounted Guest ext4 userdata.
    mounts.bind(session_backing, &scratch, false, false)?;
    for partition in ["system", "product", "system_ext"] {
        let target = root.join(partition);
        if !fs::symlink_metadata(&target).is_ok_and(|m| m.is_dir()) {
            continue;
        }
        if let Some(cache_root) = cached_root {
            let cached_upper = cache_root.join(partition).join("upper");
            if cached_upper.is_dir() {
                isolate_tree_cached(
                    plan,
                    mounts,
                    &target,
                    &cached_upper,
                    &scratch.join(partition),
                )?;
                continue;
            }
        }
        let target_scratch = cache_write_root
            .unwrap_or(&scratch)
            .join(partition);
        isolate_tree(plan, mounts, &target, &target_scratch)?;
    }
    Ok(())
}

pub fn isolate_tree_cached(
    plan: &Plan,
    mounts: &mut Mounts,
    target: &Path,
    cached_upper: &Path,
    session_scratch: &Path,
) -> io::Result<()> {
    fs::create_dir(session_scratch)?;
    let lower = File::open(target)?;
    let original = crate::unix::image_context(&lower)?;
    let mut parts: Vec<_> = original.split(':').collect();
    let mapped = context_type(&original)
        .and_then(|t| plan.types.get(t))
        .ok_or_else(|| {
            invalid(format!(
                "unmapped lower root label {}: {original}",
                target.display()
            ))
        })?;
    parts[2] = mapped;
    create_upper_root(&lower, &session_scratch.join("upper"), |upper| {
        let expected = parts.join(":");
        set_label(upper, &expected)?;
        let actual = crate::unix::image_context(&File::open(upper)?)?;
        if actual != expected {
            return Err(invalid(format!(
                "upper label mismatch: expected {expected}, got {actual}"
            )));
        }
        Ok(())
    })?;
    fs::create_dir(session_scratch.join("work"))?;
    if [target, cached_upper, session_scratch]
        .iter()
        .any(|p| p.as_os_str().as_bytes().iter().any(|b| b",:\\".contains(b)))
    {
        return Err(invalid("overlay path contains option separators"));
    }
    let options = format!(
        "lowerdir={}:{},upperdir={},workdir={},metacopy=off",
        cached_upper.display(),
        target.display(),
        session_scratch.join("upper").display(),
        session_scratch.join("work").display()
    );
    mounts
        .attach(
            Path::new("overlay"),
            target,
            Some("overlay"),
            libc::MS_NOSUID | libc::MS_NODEV,
            &options,
        )
        .map_err(|e| {
            io::Error::other(format!(
                "Guest cached metadata overlay mount {}: {e}",
                target.display()
            ))
        })?;
    Ok(())
}

pub fn isolate_tree(
    plan: &Plan,
    mounts: &mut Mounts,
    target: &Path,
    scratch: &Path,
) -> io::Result<()> {
    fs::create_dir(scratch)?;
    let lower = File::open(target)?;
    let original = crate::unix::image_context(&lower)?;
    let mut parts: Vec<_> = original.split(':').collect();
    let mapped = context_type(&original)
        .and_then(|t| plan.types.get(t))
        .ok_or_else(|| {
            invalid(format!(
                "unmapped lower root label {}: {original}",
                target.display()
            ))
        })?;
    parts[2] = mapped;
    create_upper_root(&lower, &scratch.join("upper"), |upper| {
        let expected = parts.join(":");
        set_label(upper, &expected)?;
        let actual = crate::unix::image_context(&File::open(upper)?)?;
        if actual != expected {
            return Err(invalid(format!(
                "upper label mismatch: expected {expected}, got {actual}"
            )));
        }
        Ok(())
    })?;
    fs::create_dir(scratch.join("work"))?;
    if [target, scratch]
        .iter()
        .any(|p| p.as_os_str().as_bytes().iter().any(|b| b",:\\".contains(b)))
    {
        return Err(invalid("overlay path contains option separators"));
    }
    let options = format!(
        // mprotect checks the backing inode; metadata-only copy-up leaves its Host label active.
        "lowerdir={},upperdir={},workdir={},metacopy=off",
        target.display(),
        scratch.join("upper").display(),
        scratch.join("work").display()
    );
    mounts
        .attach(
            Path::new("overlay"),
            target,
            Some("overlay"),
            libc::MS_NOSUID | libc::MS_NODEV,
            &options,
        )
        .map_err(|e| {
            io::Error::other(format!(
                "Guest metadata overlay mount {}: {e}",
                target.display()
            ))
        })?;
    relabel_tree(target, plan)?;
    Ok(())
}

fn create_upper_root(
    lower: &File,
    upper: &Path,
    label: impl FnOnce(&Path) -> io::Result<()>,
) -> io::Result<()> {
    let result = (|| {
        let metadata = lower.metadata()?;
        if !metadata.is_dir() {
            return Err(invalid("lower root is not a directory"));
        }
        // Refuse existing uppers: their metadata and contents belong to an earlier session.
        fs::DirBuilder::new()
            .mode(0o700)
            .create(upper)
            .map_err(|e| {
                io::Error::new(e.kind(), format!("create new upper (reuse refused): {e}"))
            })?;
        let file = File::open(upper)?;
        if unsafe { libc::fchown(file.as_raw_fd(), metadata.uid(), metadata.gid()) } != 0 {
            return Err(io::Error::other(format!(
                "chown: {}",
                io::Error::last_os_error()
            )));
        }
        // chown may clear special mode bits; restore the complete mode afterwards.
        if unsafe { libc::fchmod(file.as_raw_fd(), metadata.mode() & 0o7777) } != 0 {
            return Err(io::Error::other(format!(
                "chmod: {}",
                io::Error::last_os_error()
            )));
        }
        label(upper).map_err(|e| io::Error::other(format!("setxattr security.selinux: {e}")))?;
        Ok(())
    })();
    result.map_err(|e: io::Error| {
        io::Error::new(
            e.kind(),
            format!("initialize Guest upper {}: {e}", upper.display()),
        )
    })
}

pub fn install(plan: &Plan, mounts: &mut Mounts, root: &Path) -> io::Result<()> {
    // New linkerconfig files inherit this Guest-only tmpfs directory's mapped type.
    set_label(
        &root.join("linkerconfig"),
        &plan.context("linkerconfig_file", false)?,
    )?;
    let scratch = root.parent().unwrap().join("selinux-overlay");
    let runtime = root.join("run/ssal");
    fs::create_dir_all(&runtime)?;
    fs::set_permissions(&runtime, fs::Permissions::from_mode(0o755))?;
    let file_context = plan.context("system_file", false)?;
    // compose_system creates these links on the Guest tmpfs, outside the system overlay.
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        if entry.file_type()?.is_symlink() {
            set_label(&entry.path(), &file_context)?;
        }
    }
    set_label(&root.join("run"), &file_context)?;
    set_label(&runtime, &file_context)?;
    let mut runtime_plan = plan.clone();
    runtime_plan.declarations.clear();
    runtime_plan.rules.clear();
    runtime_plan.inputs.clear();
    runtime_plan
        .contexts
        .retain(|p, _| p.ends_with("property_contexts"));
    atomic(
        &runtime.join("selinux-plan.json"),
        &serde_json::to_vec(&runtime_plan)?,
    )?;
    set_label(&runtime.join("selinux-plan.json"), &file_context)?;
    let mapping: String = plan
        .types
        .iter()
        .map(|(a, b)| format!("{a} {b}\n"))
        .collect();
    let types = runtime.join("selinux-types");
    fs::write(&types, mapping)?;
    fs::set_permissions(&types, fs::Permissions::from_mode(0o644))?;
    set_label(&types, &file_context)?;
    let library = runtime.join("ssal-context-map.so");
    File::create(&library)?;
    bind_file(
        mounts,
        root,
        &std::env::current_exe()?.with_file_name("ssal-context-map.so"),
        &library,
    )?;
    for (path, text) in &plan.contexts {
        let target = crate::namespace_mounts::guest_path(root, path)?;
        if path.ends_with("file_contexts") {
            let binary = target.with_file_name(format!(
                "{}.bin",
                target.file_name().unwrap().to_string_lossy()
            ));
            if binary.is_file() {
                fs::remove_file(binary)?;
            }
        }
        let source = scratch.join(path.replace('/', "_"));
        fs::write(&source, text)?;
        fs::set_permissions(&source, fs::Permissions::from_mode(0o644))?;
        set_label(&source, &file_context)?;
        mounts.bind(&source, &target, true, false)?;
    }
    Ok(())
}

/// Copy Guest-only helpers/patches before labeling; never relabel a Host bind source.
pub fn bind_file(mounts: &mut Mounts, root: &Path, source: &Path, target: &Path) -> io::Result<()> {
    let Some(plan) = load(root)? else {
        return mounts.bind(source, target, true, false);
    };
    if !source.is_file() {
        // shortcut: copy individual patches; add private tree copies for directory patches.
        return Err(invalid(format!(
            "mapped Guest policy requires file patches, not directory bind sources: {} -> {}",
            source.display(),
            target.display()
        )));
    }
    let existing = crate::unix::image_context(&File::open(target)?).ok();
    let mapped = existing
        .as_deref()
        .and_then(context_type)
        .filter(|t| plan.types.values().any(|v| v == t));
    let context = match mapped {
        Some(_) => existing.unwrap(),
        None => plan.context(
            if target.extension().is_some_and(|s| s == "so") {
                "system_lib_file"
            } else {
                "shell_exec"
            },
            false,
        )?,
    };
    let private = root
        .parent()
        .unwrap()
        .join("selinux-overlay")
        .join(format!("private-{}", mounts.paths.len()));
    fs::copy(source, &private)?;
    set_label(&private, &context)?;
    mounts.bind(&private, target, true, false)
}

pub fn set_label(path: &Path, context: &str) -> io::Result<()> {
    let path = CString::new(path.as_os_str().as_bytes()).map_err(invalid_cstring)?;
    let context = CString::new(context).map_err(invalid_cstring)?;
    if unsafe {
        libc::lsetxattr(
            path.as_ptr(),
            c"security.selinux".as_ptr(),
            context.as_ptr().cast(),
            context.as_bytes_with_nul().len(),
            0,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub fn relabel_tree(path: &Path, plan: &Plan) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    let name = CString::new(path.as_os_str().as_bytes()).map_err(invalid_cstring)?;
    let mut buffer = [0u8; 1024];
    let size = unsafe {
        libc::lgetxattr(
            name.as_ptr(),
            c"security.selinux".as_ptr(),
            buffer.as_mut_ptr().cast(),
            buffer.len(),
        )
    };
    if size < 0 {
        return Err(io::Error::other(format!(
            "read Guest label {}: {}",
            path.display(),
            io::Error::last_os_error()
        )));
    }
    let original = std::str::from_utf8(&buffer[..size as usize])
        .map_err(|e| invalid(e.to_string()))?
        .trim_end_matches('\0');
    if let Some(mapped) = context_type(original).and_then(|t| plan.types.get(t)) {
        let mut parts: Vec<_> = original.split(':').collect();
        parts[2] = mapped;
        set_label(path, &parts.join(":")).map_err(|e| {
            io::Error::other(format!("label Guest overlay {}: {e}", path.display()))
        })?;
    }
    if metadata.is_dir() {
        for entry in fs::read_dir(path)? {
            relabel_tree(&entry?.path(), plan)?;
        }
    }
    Ok(())
}

pub fn load(root: &Path) -> io::Result<Option<Plan>> {
    match fs::read(root.join("run/ssal/selinux-plan.json")) {
        Ok(bytes) => {
            let plan: Plan = serde_json::from_slice(&bytes)?;
            plan.usable()?;
            Ok(Some(plan))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_mode_delta_can_restore_only_owned_guest_types() -> io::Result<()> {
        let mut plan = generate("p0001", &BTreeMap::from([(
            "test.cil".into(),
            "(type init) (typeattribute domain) (typeattributeset domain (init))".into(),
        )]))?;
        let current = BTreeSet::from(["ssal_p0001_init".into(), "ssal_p0002_init".into(), "ksu".into()]);
        let mut ordered = Vec::new();
        add_domain_mode_commands(&mut plan, &mut ordered, &current, &BTreeSet::new());
        assert!(ordered.is_empty());
        add_domain_mode_commands(&mut plan, &mut ordered, &current, &current);
        assert_eq!(ordered, ["enforce ssal_p0001_init"]);
        native::encode(&plan, &ordered)?;
        Ok(())
    }
    #[test]
    fn upper_root_copies_metadata_and_refuses_reuse() -> io::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let root = std::env::temp_dir().join(format!("ssal-upper-root-{}", std::process::id()));
        fs::create_dir(&root)?;
        let lower = root.join("lower");
        fs::create_dir(&lower)?;
        fs::set_permissions(&lower, fs::Permissions::from_mode(0o2751))?;
        let lower = File::open(lower)?;
        let upper = root.join("upper");
        let expected = lower.metadata()?;
        create_upper_root(&lower, &upper, |_| Ok(()))?;
        let actual = fs::metadata(&upper)?;
        assert_eq!(
            (actual.uid(), actual.gid(), actual.mode() & 0o7777),
            (expected.uid(), expected.gid(), expected.mode() & 0o7777)
        );
        let error =
            create_upper_root(&lower, &upper, |_| panic!("existing upper relabeled")).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        let error = create_upper_root(&lower, &root.join("failed-label"), |_| {
            Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP))
        })
        .unwrap_err();
        assert!(error.to_string().contains("setxattr security.selinux"));
        assert!(error.to_string().contains("failed-label"));
        fs::remove_dir_all(root)?;
        Ok(())
    }
    #[test]
    fn special_transition_names_select_native() -> io::Result<()> {
        let plan = generate(
            "p0001",
            &BTreeMap::from([(
                "policy.cil".into(),
                "(type app) (type file) (typetransition app app anon_inode \"[aaa]\" file)".into(),
            )]),
        )?;
        assert!(select_backend(&plan, Backend::Ksud) == Backend::KernelSuNative);
        assert!(encode_native(&plan)?
            .iter()
            .any(|b| b.payload.windows(5).any(|w| w == b"[aaa]")));
        let mut ordinary = plan.clone();
        ordinary.rules.clear();
        assert!(select_backend(&ordinary, Backend::Ksud) == Backend::Ksud);
        assert!(select_backend(&ordinary, Backend::KernelSuNative) == Backend::KernelSuNative);
        Ok(())
    }

    #[test]
    fn missing_shared_types_are_permissionless_placeholders_and_stay_so_on_retry() -> io::Result<()>
    {
        let plan = generate(
            "p0001",
            &BTreeMap::from([(
                "policy.cil".into(),
                r#"
            (type app) (type iso9660) (type vfat)
            (typeattribute files) (typeattributeset files (iso9660 vfat))
            (genfscon iso9660 / (u object_r iso9660 (s0 s0)))
            (genfscon vfat / (u object_r vfat (s0 s0)))
            (allow app iso9660 (file (read)))
            (allow app files (file (read)))
        "#
                .into(),
            )]),
        )?;
        let root =
            std::env::temp_dir().join(format!("ssal-placeholder-classes-{}", std::process::id()));
        fs::create_dir_all(root.join("file/perms"))?;
        fs::write(root.join("file/perms/read"), "1")?;
        let mut symbols = BTreeSet::from(["vfat".into()]);
        let (live, omitted) = compatible_plan(&plan, &symbols, &Applied::default(), &root)?;
        assert_eq!(live.placeholders, BTreeSet::from(["iso9660".into()]));
        assert!(live
            .declarations
            .contains(&"type iso9660 ssal_p0001_placeholders".into()));
        assert!(!live
            .declarations
            .iter()
            .any(|d| d.starts_with("type vfat ")));
        assert!(live
            .rules
            .iter()
            .all(|r| !r.split_whitespace().any(|w| w == "iso9660")));
        assert!(live
            .rules
            .contains("typeattribute vfat ssal_p0001_targets_files"));
        assert!(live
            .rules
            .contains("allow ssal_p0001_app ssal_p0001_iso9660 file { read }"));
        assert!(omitted
            .iter()
            .any(|r| r.contains("permissionless placeholder: iso9660")));
        encode_native(&live)?;
        let statements = delta(&live, &Applied::default())?;
        let applied = Applied {
            statements: statements.into_iter().collect(),
            placeholders: live.placeholders.clone(),
            ..Applied::default()
        };
        symbols.insert("iso9660".into());
        let (retry, _) = compatible_plan(&plan, &symbols, &applied, &root)?;
        assert!(delta(&retry, &applied)?.is_empty());
        assert_eq!(retry.rules, live.rules);

        let mut unsafe_plan = live.clone();
        let text = "allow ssal_p0001_app iso9660 file { read }".to_owned();
        unsafe_plan.rules.insert(text.clone());
        native::record(
            &mut unsafe_plan.native_rules,
            text,
            1,
            1,
            &["ssal_p0001_app", "iso9660", "file", "read"],
        );
        assert!(encode_native(&unsafe_plan)
            .unwrap_err()
            .to_string()
            .contains("placeholder may only"));
        let (existing, _) = compatible_plan(&plan, &symbols, &Applied::default(), &root)?;
        assert!(existing.placeholders.is_empty());
        assert!(existing
            .rules
            .contains("allow ssal_p0001_app iso9660 file { read }"));
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn policy_read_recovers_only_einval_once() -> io::Result<()> {
        for errno in [libc::EINVAL, libc::EACCES, libc::ENOENT] {
            let mut reads = 0;
            let mut recoveries = 0;
            let result = read_policy_with_recovery(
                || {
                    reads += 1;
                    if reads == 1 {
                        Err(io::Error::from_raw_os_error(errno))
                    } else {
                        Ok(vec![1, 2, 3])
                    }
                },
                || {
                    recoveries += 1;
                    Ok(())
                },
            );
            if errno == libc::EINVAL {
                assert_eq!(result?, [1, 2, 3]);
                assert_eq!((reads, recoveries), (2, 1));
            } else {
                assert_eq!(result.unwrap_err().raw_os_error(), Some(errno));
                assert_eq!((reads, recoveries), (1, 0));
            }
        }
        assert_eq!(
            read_policy_with_recovery(|| Ok(vec![4]), || panic!("unnecessary recovery"))?,
            [4]
        );
        let mut reads = 0;
        let error = read_policy_with_recovery(
            || {
                reads += 1;
                Err(io::Error::from_raw_os_error(libc::EINVAL))
            },
            || Ok(()),
        )
        .unwrap_err();
        assert_eq!(reads, 2);
        assert!(error.to_string().contains("after export recovery"));
        let mut reads = 0;
        let error = read_policy_with_recovery(
            || {
                reads += 1;
                Err(io::Error::from_raw_os_error(libc::EINVAL))
            },
            || Err(io::Error::other("ksud failed")),
        )
        .unwrap_err();
        assert_eq!(reads, 1);
        assert!(error.to_string().contains("ksud failed"));
        Ok(())
    }

    #[test]
    fn export_recovery_requires_explicit_allowed_and_decided_read() -> io::Result<()> {
        assert!(explicit_read_permission("2 ffffffff 0 0 1 0", 2)?);
        assert!(!explicit_read_permission("0 ffffffff 0 0 1 1", 2)?);
        assert!(!explicit_read_permission("2 0 0 0 1 0", 2)?);
        assert!(explicit_read_permission("2", 2).is_err());
        assert!(explicit_read_permission("invalid ffffffff 0 0 1 0", 2).is_err());
        Ok(())
    }

    #[test]
    fn native_preencodes_complete_policy_and_rejects_missing_or_tampered_commands() -> io::Result<()>
    {
        let files = BTreeMap::from([(
            "policy.cil".into(),
            r#"
            (type app) (type file)
            (allow app self (process (fork getattr)))
            (auditallow app file (file (read))) (dontaudit app file (file (write)))
            (allowx app self (ioctl file (0x8b01 (range 0x8b11 0x8b13))))
            (typetransition app app anon_inode "[userfaultfd]" file)
            (typetransition app app anon_inode "[io_uring]" file)
            (typetransition app file process app)
            (typechange app file file file) (typemember app file file file)
        "#
            .into(),
        )]);
        let mut plan = generate("p0001", &files)?;
        let ordered = delta(&plan, &Applied::default())?;
        let batches = encode_native(&plan)?;
        assert_eq!(
            batches
                .iter()
                .flat_map(|b| b.statements.clone())
                .collect::<Vec<_>>(),
            ordered
        );
        assert_eq!(batches.iter().map(|b| b.commands).sum::<usize>(), 14);
        assert!(batches
            .iter()
            .any(|b| b.payload.windows(10).any(|w| w == b"[io_uring]")));
        let mut reversed = ordered.clone();
        reversed.reverse();
        assert!(native::encode(&plan, &reversed)
            .unwrap_err()
            .to_string()
            .contains("ordering"));
        let key = ordered.last().unwrap();
        let original = plan.native_rules.remove(key).unwrap();
        assert!(encode_native(&plan).unwrap_err().to_string().contains(key));
        plan.native_rules.insert(key.clone(), original);
        plan.native_rules.get_mut(key).unwrap()[0].args[0] = "system_server".into();
        assert!(encode_native(&plan)
            .unwrap_err()
            .to_string()
            .contains("non-Guest"));
        Ok(())
    }

    #[test]
    fn native_batch_report_keeps_partial_and_error_outcomes_uncertain() {
        for (result, succeeded, uncertain) in [
            (Ok(3), Some(3), false),
            (Ok(2), Some(2), true),
            (Err(io::Error::from_raw_os_error(libc::EINVAL)), None, true),
        ] {
            let mut report = NativeBatchResult {
                batch: 0,
                expected: 3,
                succeeded: None,
                error: None,
                partial_or_uncertain: true,
            };
            report.complete(result);
            assert_eq!(report.succeeded, succeeded);
            assert_eq!(report.partial_or_uncertain, uncertain);
            assert_eq!(report.error.is_some(), uncertain);
        }
    }

    #[test]
    fn application_delta_is_idempotent_and_preserves_applied_rules() -> io::Result<()> {
        let plan = generate("p0001", &BTreeMap::from([("policy.cil".into(), "(type foo) (typeattribute domain) (typeattributeset domain (foo)) (allow domain self (process (fork)))".into())]))?;
        let mut applied = Applied::default();
        let first = delta(&plan, &applied)?;
        let membership = first
            .iter()
            .position(|r| r.starts_with("typeattribute "))
            .unwrap();
        let allow = first.iter().position(|r| r.starts_with("allow ")).unwrap();
        assert!(membership < allow);
        applied.statements.extend(first);
        assert!(delta(&plan, &applied)?.is_empty());
        let mut legacy = serde_json::to_value(&applied)?;
        legacy
            .as_object_mut()
            .unwrap()
            .remove("rule_readback_verified");
        let legacy: Applied = serde_json::from_value(legacy)?;
        assert!(!legacy.rule_readback_verified);
        assert_eq!(legacy.statements, applied.statements);
        assert!(delta(&plan, &legacy)?.is_empty());
        let mut removed = plan.clone();
        removed.rules.retain(|r| !r.starts_with("allow "));
        assert!(delta(&removed, &applied)?.is_empty());
        applied.pending = true;
        assert!(delta(&plan, &applied)
            .unwrap_err()
            .to_string()
            .contains("uncertain"));
        assert!(!delta(&plan, &Applied::default())?.is_empty());
        Ok(())
    }
    #[test]
    fn delta_preserves_long_allow_permission_sets() -> io::Result<()> {
        let permissions = [
            "ioctl",
            "read",
            "write",
            "create",
            "getattr",
            "setattr",
            "lock",
            "rename",
            "open",
            "watch",
            "watch_reads",
            "add_name",
            "remove_name",
            "reparent",
            "search",
            "rmdir",
        ];
        let cil = format!(
            "(type aconfigd) (type aconfig_storage_flags_metadata_file) (allow aconfigd aconfig_storage_flags_metadata_file (dir ({})))",
            permissions.join(" ")
        );
        let mut plan = generate("p0001", &BTreeMap::from([("policy.cil".into(), cil)]))?;
        plan.rules.clear();
        plan.rules.insert(format!(
            "allow ssal_p0001_aconfigd ssal_p0001_aconfig_storage_flags_metadata_file dir {{ {} }}",
            permissions.join(" ")
        ));

        let statements = delta(&plan, &Applied::default())?;
        let rules = statements
            .iter()
            .filter(|rule| {
                rule.starts_with(
                    "allow ssal_p0001_aconfigd ssal_p0001_aconfig_storage_flags_metadata_file dir { ",
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(rules.len(), 1);
        let mut observed = BTreeSet::new();
        for rule in rules {
            let fields = rule.split_whitespace().collect::<Vec<_>>();
            assert_eq!(
                &fields[..4],
                &[
                    "allow",
                    "ssal_p0001_aconfigd",
                    "ssal_p0001_aconfig_storage_flags_metadata_file",
                    "dir"
                ]
            );
            assert_eq!(fields[4], "{");
            assert_eq!(fields.last(), Some(&"}"));
            let body = &fields[5..fields.len() - 1];
            assert!(body.join(" ").len() > 90);
            for permission in body {
                assert!(
                    observed.insert(*permission),
                    "duplicate permission: {permission}"
                );
            }
        }
        assert_eq!(observed, permissions.into_iter().collect());
        Ok(())
    }

    #[test]
    fn delta_splits_xperm_sets_into_kernelsu_rules() -> io::Result<()> {
        let mut plan = generate(
            "p0001",
            &BTreeMap::from([("policy.cil".into(), "(type app)".into())]),
        )?;
        plan.rules.clear();
        plan.rules.insert(
            "allowxperm ssal_p0001_app self rawip_socket ioctl { 0x8b01 0x8b11-0x8b13 }".into(),
        );

        let statements = delta(&plan, &Applied::default())?;
        assert!(
            statements.contains(&"allowxperm ssal_p0001_app self rawip_socket ioctl 0x8b01".into())
        );
        assert!(statements
            .contains(&"allowxperm ssal_p0001_app self rawip_socket ioctl 0x8b11-0x8b13".into()));
        assert!(!statements.iter().any(|statement| statement.contains('{')));
        Ok(())
    }

    #[test]
    fn missing_host_capabilities_are_recorded_without_dropping_supported_permissions(
    ) -> io::Result<()> {
        let plan = generate("p0001", &BTreeMap::from([("policy.cil".into(), "(type foo) (type target) (allow foo target (file (read watch))) (allow foo self (process (fork)))".into())]))?;
        let root = std::env::temp_dir().join(format!("ssal-policy-classes-{}", std::process::id()));
        fs::create_dir_all(root.join("file/perms"))?;
        fs::write(root.join("file/perms/read"), "1")?;
        let desired = serde_json::to_vec(&plan)?;
        let (live, omitted) = compatible_plan(&plan, &BTreeSet::new(), &Applied::default(), &root)?;
        assert_eq!(serde_json::to_vec(&plan)?, desired);
        assert!(live
            .rules
            .contains("allow ssal_p0001_foo ssal_p0001_target file { read }"));
        assert_eq!(live.rules.len(), 1);
        assert_eq!(omitted.len(), 2);
        assert!(omitted.iter().any(|s| s.contains("watch")));
        assert!(omitted
            .iter()
            .any(|s| s.contains("Host class missing: process")));
        let encoded = encode_native(&live)?;
        assert_eq!(encoded.iter().map(|b| b.commands).sum::<usize>(), 4);
        fs::remove_dir_all(root)?;
        Ok(())
    }
}
