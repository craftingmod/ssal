//! Profile-owned, additive CIL -> KernelSU policy and Android context mapping.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;

#[path = "../concurrent/selinux.rs"]
mod concurrent;
pub mod native;
#[cfg(unix)]
pub mod runtime;
mod symbols;

const VERSION: u32 = 69;

type Names = BTreeMap<String, String>;

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

pub fn atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let tmp = path.with_extension("tmp");
    let mut file = File::create(&tmp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(tmp, path)?;
    #[cfg(unix)]
    File::open(path.parent().unwrap())?.sync_all()?;
    Ok(())
}

fn symbol(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && (name.as_bytes()[0].is_ascii_alphabetic() || name.as_bytes()[0] == b'_')
        && name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
}

fn permissions_text(permissions: &[&str]) -> String {
    let mut seen = BTreeSet::new();
    permissions
        .iter()
        .copied()
        .filter(|p| seen.insert(*p))
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn valid_id(id: &str) -> bool {
    id.strip_prefix('p').is_some_and(|n| {
        n.len() >= 4
            && n.bytes().all(|b| b.is_ascii_digit())
            && n.parse::<u64>()
                .is_ok_and(|n| n > 0 && format!("p{n:04}") == id)
    })
}

/// Reservations live outside profiles and are never deleted, including on failed creation.
pub fn allocate_id(root: &Path) -> io::Result<String> {
    let reservations = root.join("state/selinux-ids");
    fs::create_dir_all(&reservations)?;
    for n in 1..u64::MAX {
        let id = format!("p{n:04}");
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(reservations.join(&id))
        {
            Ok(file) => {
                file.sync_all()?;
                #[cfg(unix)]
                File::open(&reservations)?.sync_all()?;
                return Ok(id);
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
    }
    Err(invalid("profile IDs exhausted"))
}

/// Compile-time guest concurrency mode ("single" | "multi").
/// In "single" mode, SELinux policy IDs are allocated per system image rather than per profile.
pub const MULTI_GUEST_SUPPORT: &str = "single";

pub fn system_image_id(root: &Path, system_image_dir: &Path) -> io::Result<String> {
    let path = system_image_dir.join("selinux-id");
    if path.is_file() {
        let id = fs::read_to_string(&path)?;
        let id = id.trim();
        if valid_id(id) && root.join("state/selinux-ids").join(id).is_file() {
            return Ok(id.to_owned());
        }
    }
    let id = allocate_id(root)?;
    atomic(&path, id.as_bytes())?;
    Ok(id)
}

pub fn profile_id(root: &Path, profile: &Path) -> io::Result<String> {
    let path = profile.join("profile.json");
    let mut value: serde_json::Value = serde_json::from_slice(&fs::read(&path)?)?;
    if let Some(id) = value.get("selinux_id") {
        let id = id
            .as_str()
            .filter(|id| valid_id(id))
            .ok_or_else(|| invalid("invalid SELinux ID"))?;
        if !root.join("state/selinux-ids").join(id).is_file() {
            return Err(invalid("SELinux ID reservation missing"));
        }
        for entry in fs::read_dir(root.join("guests"))? {
            let entry = entry?;
            if entry.path() == profile || !entry.file_type()?.is_dir() {
                continue;
            }
            let other = entry.path().join("profile.json");
            if other.is_file() {
                let other: serde_json::Value = serde_json::from_slice(&fs::read(other)?)?;
                if other["selinux_id"].as_str() == Some(id) {
                    return Err(invalid(format!("duplicate profile SELinux ID {id}")));
                }
            }
        }
        return Ok(id.into());
    }
    let id = allocate_id(root)?;
    value["selinux_id"] = id.clone().into();
    atomic(&path, &serde_json::to_vec_pretty(&value)?)?;
    Ok(id)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Input {
    pub path: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Plan {
    pub version: u32,
    pub id: String,
    pub input_hash: String,
    pub inputs: Vec<Input>,
    pub types: Names,
    pub attributes: Names,
    pub shared_types: BTreeSet<String>,
    #[serde(default)]
    pub placeholders: BTreeSet<String>,
    pub contexts: BTreeMap<String, String>,
    pub declarations: Vec<String>,
    pub rules: BTreeSet<String>,
    #[serde(default)]
    pub native_rules: BTreeMap<String, Vec<native::PolicyCommand>>,
    pub unsupported: Vec<String>,
    #[serde(default)]
    pub unsupported_source: BTreeMap<String, String>,
    pub retained_host: Vec<String>,
}

impl Plan {
    fn ensure_kernel_av_access(&mut self) -> io::Result<()> {
        // selinuxfs computes decisions against the live kernel SID, not its Guest copy.
        for original in ["init", "servicemanager"] {
            let domain = self
                .types
                .get(original)
                .ok_or_else(|| invalid(format!("GSI type missing: {original}")))?;
            let rule = format!("allow {domain} kernel security {{ compute_av }}");
            self.rules.insert(rule.clone());
            native::record(
                &mut self.native_rules,
                rule,
                1,
                1,
                &[domain, "kernel", "security", "compute_av"],
            );
        }
        for original in ["hwservicemanager", "keystore"] {
            if let Some(domain) = self.types.get(original) {
                let rule = format!("allow {domain} kernel security {{ compute_av }}");
                self.rules.insert(rule.clone());
                native::record(
                    &mut self.native_rules,
                    rule,
                    1,
                    1,
                    &[domain, "kernel", "security", "compute_av"],
                );
            }
        }
        for original in ["zygote", "installd"] {
            if let Some(domain) = self.types.get(original) {
                let rule = format!("allow {domain} kernel security {{ check_context }}");
                self.rules.insert(rule.clone());
                native::record(
                    &mut self.native_rules,
                    rule,
                    1,
                    1,
                    &[domain, "kernel", "security", "check_context"],
                );
            }
        }
        Ok(())
    }

    pub fn context(&self, original: &str, process: bool) -> io::Result<String> {
        let name = self
            .types
            .get(original)
            .ok_or_else(|| invalid(format!("GSI type missing: {original}")))?;
        Ok(format!(
            "u:{}:{name}:s0",
            if process { "r" } else { "object_r" }
        ))
    }

    fn ensure_property_socket_transition(&mut self) -> io::Result<()> {
        let init = self
            .types
            .get("init")
            .ok_or_else(|| invalid("GSI type missing: init"))?
            .clone();
        let socket_device = self
            .types
            .get("socket_device")
            .ok_or_else(|| invalid("GSI type missing: socket_device"))?
            .clone();
        let property_socket = self
            .types
            .get("property_socket")
            .ok_or_else(|| invalid("GSI type missing: property_socket"))?
            .clone();
        let rule = format!("type_transition {init} {socket_device} sock_file {property_socket}");
        self.rules.insert(rule.clone());
        native::record(
            &mut self.native_rules,
            rule,
            7,
            0,
            &[&init, &socket_device, "sock_file", &property_socket, ""],
        );
        Ok(())
    }

    pub fn usable(&self) -> io::Result<()> {
        if self.types.len() >= 8192 {
            return Err(invalid(
                "GSI exceeds native context-map capacity (8191 types)",
            ));
        }
        // shortcut: omit nlmsg grants until KernelSU supports that xperm operation.
        if let Some(issue) = self
            .unsupported
            .iter()
            .find(|s| !s.ends_with("unsupported xperm operation: nlmsg"))
        {
            return Err(invalid(format!(
                "unsupported policy statement; see selinux/plan.json: {issue}"
            )));
        }
        Ok(())
    }
}

fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Only GSI-owned policy directories; never recursively read Host /vendor.
pub fn inputs(system: &Path) -> io::Result<BTreeMap<String, String>> {
    fn plain_directory(root: &Path, relative: &str) -> bool {
        let mut path = root.to_owned();
        relative.split('/').filter(|s| !s.is_empty()).all(|part| {
            path.push(part);
            fs::symlink_metadata(&path).is_ok_and(|m| m.is_dir())
        })
    }
    let prefix = if plain_directory(system, "system/etc/selinux") {
        "system/"
    } else {
        ""
    };
    let mut result = BTreeMap::new();
    for partition in ["system", "system_ext", "product"] {
        let candidates = if partition == "system" {
            vec![format!("{prefix}etc/selinux")]
        } else {
            vec![
                format!("{prefix}{partition}/etc/selinux"),
                format!("{partition}/etc/selinux"),
            ]
        };
        if let Some(relative) = candidates.iter().find(|p| plain_directory(system, p)) {
            collect(
                &system.join(relative),
                &format!("{partition}/etc/selinux"),
                &mut result,
            )?;
        }
    }
    if !result.keys().any(|p| p.ends_with(".cil")) {
        return Err(invalid("GSI contains no CIL policy"));
    }
    Ok(result)
}

fn collect(dir: &Path, relative: &str, result: &mut BTreeMap<String, String>) -> io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let path = format!("{relative}/{name}");
        let kind = entry.file_type()?;
        // Versioned mapping/compat CIL is not an active GSI partition policy.
        if kind.is_file() && (name.ends_with(".cil") || name.ends_with("_contexts")) {
            result.insert(path, fs::read_to_string(entry.path())?);
        }
    }
    Ok(())
}

#[derive(Debug, Clone)]
enum Expr {
    Atom(String),
    List(Vec<Expr>),
}
impl Expr {
    fn atom(&self) -> io::Result<&str> {
        match self {
            Self::Atom(a) => Ok(a),
            _ => Err(invalid("expected CIL symbol")),
        }
    }
    fn list(&self) -> io::Result<&[Expr]> {
        match self {
            Self::List(a) => Ok(a),
            _ => Err(invalid("expected CIL list")),
        }
    }
}

fn parse(text: &str) -> io::Result<Vec<(usize, Expr)>> {
    let mut stack: Vec<(usize, Vec<Expr>)> = Vec::new();
    let mut result = Vec::new();
    let mut chars = text.chars().peekable();
    let mut line = 1;
    while let Some(c) = chars.next() {
        match c {
            '\n' => line += 1,
            ';' => {
                for c in chars.by_ref() {
                    if c == '\n' {
                        line += 1;
                        break;
                    }
                }
            }
            '(' => {
                if stack.len() >= 128 {
                    return Err(invalid("CIL nesting limit"));
                }
                stack.push((line, Vec::new()));
            }
            ')' => {
                let (start, list) = stack.pop().ok_or_else(|| invalid("unbalanced CIL close"))?;
                let expr = Expr::List(list);
                if let Some((_, parent)) = stack.last_mut() {
                    parent.push(expr);
                } else {
                    result.push((start, expr));
                }
            }
            c if c.is_whitespace() => {}
            _ => {
                let mut token = String::new();
                if c == '"' {
                    let mut closed = false;
                    while let Some(c) = chars.next() {
                        if c == '"' {
                            closed = true;
                            break;
                        }
                        if c == '\n' {
                            line += 1;
                        }
                        if c == '\\' {
                            token.push(chars.next().ok_or_else(|| invalid("CIL escape"))?);
                        } else {
                            token.push(c);
                        }
                    }
                    if !closed {
                        return Err(invalid("unterminated CIL string"));
                    }
                } else {
                    token.push(c);
                    while chars
                        .peek()
                        .is_some_and(|c| !c.is_whitespace() && !matches!(c, '(' | ')' | ';'))
                    {
                        token.push(chars.next().unwrap());
                    }
                }
                stack
                    .last_mut()
                    .ok_or_else(|| invalid("CIL atom outside list"))?
                    .1
                    .push(Expr::Atom(token));
            }
        }
    }
    if !stack.is_empty() {
        return Err(invalid("unclosed CIL list"));
    }
    Ok(result)
}

fn members(
    expr: &Expr,
    sets: &BTreeMap<String, BTreeSet<String>>,
    universe: &BTreeSet<String>,
) -> io::Result<BTreeSet<String>> {
    match expr {
        Expr::Atom(a) => sets
            .get(a)
            .cloned()
            .or_else(|| universe.contains(a).then(|| BTreeSet::from([a.clone()])))
            .ok_or_else(|| invalid(format!("unresolved CIL type/attribute: {a}"))),
        Expr::List(items) => {
            let op = items.first().and_then(|e| e.atom().ok()).unwrap_or("");
            if matches!(op, "not" | "and" | "or" | "xor" | "all") {
                if op == "all" && items.len() == 1 {
                    return Ok(universe.clone());
                }
                let args: Vec<_> = items[1..]
                    .iter()
                    .map(|e| members(e, sets, universe))
                    .collect::<io::Result<_>>()?;
                if args.is_empty() || (op == "not" && args.len() != 1) {
                    return Err(invalid("invalid CIL set operator"));
                }
                if op == "not" {
                    return Ok(universe.difference(&args[0]).cloned().collect());
                }
                let mut value = args[0].clone();
                for arg in &args[1..] {
                    value = match op {
                        "and" => value.intersection(arg).cloned().collect(),
                        "xor" => value.symmetric_difference(arg).cloned().collect(),
                        _ => value.union(arg).cloned().collect(),
                    };
                }
                Ok(value)
            } else {
                let mut result = BTreeSet::new();
                for e in items {
                    result.extend(members(e, sets, universe)?);
                }
                Ok(result)
            }
        }
    }
}

fn resolve_attribute(
    name: &str,
    expressions: &BTreeMap<String, Vec<Expr>>,
    universe: &BTreeSet<String>,
    sets: &mut BTreeMap<String, BTreeSet<String>>,
    visiting: &mut BTreeSet<String>,
) -> io::Result<()> {
    if visiting.len() >= 128 {
        return Err(invalid("CIL attribute dependency depth limit"));
    }
    if sets.contains_key(name) {
        return Ok(());
    }
    if !visiting.insert(name.into()) {
        return Err(invalid(format!("cyclic attribute {name}")));
    }
    let mut value = BTreeSet::new();
    if let Some(exprs) = expressions.get(name) {
        fn dependencies(
            e: &Expr,
            expressions: &BTreeMap<String, Vec<Expr>>,
            out: &mut BTreeSet<String>,
        ) {
            match e {
                Expr::Atom(a) if expressions.contains_key(a) => {
                    out.insert(a.clone());
                }
                Expr::List(l) => {
                    for e in l {
                        dependencies(e, expressions, out);
                    }
                }
                _ => {}
            }
        }
        for expr in exprs {
            let mut deps = BTreeSet::new();
            dependencies(expr, expressions, &mut deps);
            for dep in deps {
                resolve_attribute(&dep, expressions, universe, sets, visiting)?;
            }
            value.extend(members(expr, sets, universe)?);
        }
    }
    visiting.remove(name);
    sets.insert(name.into(), value);
    Ok(())
}

fn shared_path(pattern: &str) -> bool {
    ["/vendor", "/odm", "/vendor_dlkm", "/dev", "/proc", "/sys"]
        .iter()
        .any(|prefix| {
            pattern
                .strip_prefix(prefix)
                .is_some_and(|s| s.is_empty() || s.starts_with(['/', '(', '$']))
        })
        && !["/dev/binder", "/dev/socket", "/dev/__properties__"]
            .iter()
            .any(|p| pattern.starts_with(p))
}

fn context_type(context: &str) -> Option<&str> {
    let mut parts = context.split(':');
    parts.next()?;
    parts.next()?;
    parts.next()
}

fn rewrite(text: &str, names: &Names, seapp: bool, files: bool) -> io::Result<String> {
    let mut out = String::new();
    for raw in text.lines() {
        let (body, comment) = raw
            .split_once('#')
            .map_or((raw, None), |(a, b)| (a, Some(b)));
        let mut fields: Vec<String> = body.split_whitespace().map(str::to_owned).collect();
        let shared = files && fields.first().is_some_and(|p| shared_path(p));
        if !shared {
            for field in &mut fields {
                if field.starts_with("u:") {
                    let original =
                        context_type(field).ok_or_else(|| invalid("malformed security context"))?;
                    let mapped = names.get(original).ok_or_else(|| {
                        invalid(format!("context references undeclared type: {original}"))
                    })?;
                    let mut parts: Vec<_> = field.split(':').map(str::to_owned).collect();
                    parts[2] = mapped.clone();
                    *field = parts.join(":");
                } else if seapp {
                    if let Some((key, value)) = field.split_once('=') {
                        if matches!(key, "domain" | "type") && value != "*" {
                            *field = format!(
                                "{key}={}",
                                names.get(value).ok_or_else(|| invalid(format!(
                                    "seapp references undeclared type: {value}"
                                )))?
                            );
                        }
                    }
                }
            }
        }
        out.push_str(&fields.join(" "));
        if let Some(comment) = comment {
            out.push_str(" #");
            out.push_str(comment);
        }
        out.push('\n');
    }
    Ok(out)
}

pub fn generate(id: &str, inputs: &BTreeMap<String, String>) -> io::Result<Plan> {
    if !valid_id(id) {
        return Err(invalid("invalid profile ID"));
    }
    let hashes: Vec<_> = inputs
        .iter()
        .map(|(path, text)| Input {
            path: path.clone(),
            sha256: digest(text.as_bytes()),
        })
        .collect();
    let mut plan = Plan {
        version: VERSION,
        id: id.into(),
        input_hash: digest(&serde_json::to_vec(&hashes)?),
        inputs: hashes,
        types: Names::new(),
        attributes: Names::new(),
        shared_types: BTreeSet::new(),
        placeholders: BTreeSet::new(),
        contexts: BTreeMap::new(),
        declarations: Vec::new(),
        rules: BTreeSet::new(),
        native_rules: BTreeMap::new(),
        unsupported: Vec::new(),
        unsupported_source: BTreeMap::new(),
        retained_host: Vec::new(),
    };
    let mut statements = Vec::new();
    for (path, text) in inputs.iter().filter(|(p, _)| p.ends_with(".cil")) {
        for (line, expr) in parse(text).map_err(|e| invalid(format!("{path}: {e}")))? {
            statements.push((format!("{path}:{line}"), expr));
        }
    }
    let mut used = BTreeSet::new();
    for (_, expr) in &statements {
        let list = expr.list()?;
        let Some(op) = list.first().and_then(|e| e.atom().ok()) else {
            return Err(invalid("empty CIL statement"));
        };
        if matches!(op, "type" | "typeattribute") {
            if list.len() != 2 {
                return Err(invalid("invalid type declaration"));
            }
            let original = list[1].atom()?;
            let name = format!("ssal_{id}_{original}");
            if op == "typeattribute" && plan.attributes.contains_key(original) {
                continue;
            }
            if !symbol(original) || !symbol(&name) || !used.insert(name.clone()) {
                return Err(invalid(format!("policy name length/collision: {name}")));
            }
            if op == "type" {
                plan.types.insert(original.into(), name);
            } else {
                plan.attributes.insert(original.into(), name);
            }
        }
    }
    if plan.types.is_empty() {
        return Err(invalid("no GSI type declarations"));
    }
    for (location, expr) in &statements {
        let l = expr.list()?;
        if l[0].atom()? == "typealiasactual" && l.len() == 3 {
            let actual = plan
                .types
                .get(l[2].atom()?)
                .cloned()
                .ok_or_else(|| invalid(format!("{location}: unresolved type alias")))?;
            plan.types.insert(l[1].atom()?.into(), actual);
        }
    }
    let universe: BTreeSet<_> = plan.types.keys().cloned().collect();
    let mut sets = BTreeMap::new();
    let mut expressions: BTreeMap<String, Vec<Expr>> = plan
        .attributes
        .keys()
        .map(|n| (n.clone(), Vec::new()))
        .collect();
    for (location, expr) in &statements {
        let l = expr.list()?;
        if l[0].atom()? == "typeattributeset" {
            if l.len() != 3 {
                plan.unsupported
                    .push(format!("{location}: invalid typeattributeset"));
                continue;
            }
            expressions
                .entry(l[1].atom()?.into())
                .or_default()
                .push(l[2].clone());
        }
        if matches!(l[0].atom()?, "genfscon" | "fsuse") {
            if let Some(Expr::List(context)) = l.last() {
                if context.len() >= 3 {
                    if let Ok(t) = context[2].atom() {
                        plan.shared_types.insert(t.into());
                    }
                }
            }
        }
    }
    for name in expressions.keys() {
        if let Err(e) = resolve_attribute(
            name,
            &expressions,
            &universe,
            &mut sets,
            &mut BTreeSet::new(),
        ) {
            plan.unsupported.push(e.to_string());
        }
    }
    for (path, text) in inputs.iter().filter(|(p, _)| p.ends_with("file_contexts")) {
        for raw in text.lines() {
            let fields: Vec<_> = raw.split('#').next().unwrap().split_whitespace().collect();
            if fields.first().is_some_and(|p| shared_path(p)) {
                for context in &fields[1..] {
                    if let Some(name) = context_type(context) {
                        plan.shared_types.insert(name.into());
                    }
                }
            }
        }
        let _ = path;
    }
    for private in [
        "binder_device",
        "hwbinder_device",
        "vndbinder_device",
        "properties_device",
        "property_info",
        "properties_serial",
        "property_socket",
        "lmkd_socket",
    ] {
        plan.shared_types.remove(private);
    }
    // Attributes stay private. Separate target-only sets can include shared Host labels.
    let mut active_attributes = BTreeSet::new();
    for (_, expr) in &statements {
        let l = expr.list()?;
        if matches!(
            l[0].atom()?,
            "allow"
                | "auditallow"
                | "dontaudit"
                | "allowx"
                | "auditallowx"
                | "dontauditx"
                | "typetransition"
                | "typechange"
                | "typemember"
        ) {
            for e in l.iter().skip(1).take(2) {
                if let Ok(name) = e.atom() {
                    if plan.attributes.contains_key(name) {
                        active_attributes.insert(name.to_owned());
                    }
                }
            }
        }
    }
    let mut target_attrs = Names::new();
    let mut native_rules = BTreeMap::new();
    for (original, name) in &plan.attributes {
        if !active_attributes.contains(original) {
            continue;
        }
        plan.declarations.push(format!("attribute {name}"));
        native::record(
            &mut native_rules,
            format!("attribute {name}"),
            6,
            0,
            &[name],
        );
        let target = format!("ssal_{id}_targets_{original}");
        if !symbol(&target) || !used.insert(target.clone()) {
            return Err(invalid(format!("policy name length/collision: {target}")));
        }
        plan.declarations.push(format!("attribute {target}"));
        native::record(
            &mut native_rules,
            format!("attribute {target}"),
            6,
            0,
            &[&target],
        );
        target_attrs.insert(original.clone(), target);
    }
    // KernelSU requires an initial attribute; use a private one, never Host domain/file_type.
    let initial = format!("ssal_{id}_owned");
    if !used.insert(initial.clone()) {
        return Err(invalid("reserved attribute collision"));
    }
    plan.declarations.push(format!("attribute {initial}"));
    native::record(
        &mut native_rules,
        format!("attribute {initial}"),
        6,
        0,
        &[&initial],
    );
    for name in plan.types.values().collect::<BTreeSet<_>>() {
        plan.declarations.push(format!("type {name} {initial}"));
        native::record(
            &mut native_rules,
            format!("type {name} {initial}"),
            4,
            0,
            &[name, &initial],
        );
    }
    for (attribute, values) in &sets {
        if !active_attributes.contains(attribute) {
            continue;
        }
        let Some(mapped) = plan.attributes.get(attribute) else {
            plan.unsupported
                .push(format!("undeclared attribute {attribute}"));
            continue;
        };
        for original in values {
            let name = &plan.types[original];
            plan.rules.insert(format!("typeattribute {name} {mapped}"));
            native::record(
                &mut native_rules,
                format!("typeattribute {name} {mapped}"),
                5,
                0,
                &[name, mapped],
            );
            plan.rules
                .insert(format!("typeattribute {name} {}", target_attrs[attribute]));
            native::record(
                &mut native_rules,
                format!("typeattribute {name} {}", target_attrs[attribute]),
                5,
                0,
                &[name, &target_attrs[attribute]],
            );
            if plan.shared_types.contains(original) {
                native::record(
                    &mut native_rules,
                    format!("typeattribute {original} {}", target_attrs[attribute]),
                    5,
                    0,
                    &[original, &target_attrs[attribute]],
                );
                plan.rules.insert(format!(
                    "typeattribute {original} {}",
                    target_attrs[attribute]
                ));
            }
        }
    }
    // Host mlsconstrain rules evaluate against Host mlstrustedsubject/mlstrustedobject.
    for host_attr in ["mlstrustedsubject", "mlstrustedobject"] {
        if let Some(values) = sets.get(host_attr) {
            for original in values {
                if let Some(name) = plan.types.get(original) {
                    let rule = format!("typeattribute {name} {host_attr}");
                    native::record(&mut native_rules, rule.clone(), 5, 0, &[name, host_attr]);
                    plan.rules.insert(rule);
                }
            }
        }
    }
    let source = |name: &str| -> io::Result<String> {
        plan.types
            .get(name)
            .or_else(|| plan.attributes.get(name))
            .cloned()
            .ok_or_else(|| invalid(format!("unresolved source {name}")))
    };
    let targets = |name: &str| -> io::Result<Vec<String>> {
        if let Some(a) = target_attrs.get(name) {
            return Ok(vec![a.clone()]);
        }
        let mut result = vec![plan
            .types
            .get(name)
            .ok_or_else(|| invalid(format!("unresolved target {name}")))?
            .clone()];
        if plan.shared_types.contains(name) {
            result.push(name.into());
        }
        Ok(result)
    };
    let av_pairs = |s: &str, t: &str| -> io::Result<Vec<(String, String)>> {
        if t == "self" {
            let members = if plan.attributes.contains_key(s) {
                sets.get(s).cloned().unwrap_or_default()
            } else {
                BTreeSet::from([s.into()])
            };
            members
                .iter()
                .map(|name| {
                    let mapped = source(name)?;
                    Ok((mapped.clone(), mapped))
                })
                .collect()
        } else {
            let mapped = source(s)?;
            Ok(targets(t)?
                .into_iter()
                .map(|target| (mapped.clone(), target))
                .collect())
        }
    };
    for (location, expr) in &statements {
        let l = expr.list()?;
        let op = l[0].atom()?;
        let converted = (|| -> io::Result<Vec<String>> {
            match op {
                "allowx" | "auditallowx" | "dontauditx" if l.len() == 4 => {
                    let xp = l[3].list()?;
                    if xp.len() != 3 || !symbol(xp[1].atom()?) {
                        return Err(invalid("invalid xperm operation"));
                    }
                    if xp[0].atom()? != "ioctl" {
                        return Err(invalid(format!(
                            "unsupported xperm operation: {}",
                            xp[0].atom()?
                        )));
                    }
                    let mut ranges = Vec::new();
                    let number = |e: &Expr| -> io::Result<u16> {
                        let a = e.atom()?;
                        u16::from_str_radix(
                            a.strip_prefix("0x")
                                .ok_or_else(|| invalid("invalid ioctl number"))?,
                            16,
                        )
                        .map_err(|_| invalid("ioctl outside u16"))
                    };
                    for e in xp[2].list()? {
                        match e {
                            Expr::Atom(_) => ranges.push(format!("0x{:04x}", number(e)?)),
                            Expr::List(r) if r.len() == 3 && r[0].atom()? == "range" => {
                                let (start, end) = (number(&r[1])?, number(&r[2])?);
                                if start > end {
                                    return Err(invalid("reversed ioctl range"));
                                }
                                ranges.push(format!("0x{start:04x}-0x{end:04x}"));
                            }
                            _ => return Err(invalid("unsupported ioctl set")),
                        }
                    }
                    if ranges.is_empty() {
                        return Err(invalid("empty ioctl set"));
                    }
                    let operation = match op {
                        "allowx" => "allowxperm",
                        "auditallowx" => "auditallowxperm",
                        _ => "dontauditxperm",
                    };
                    Ok(av_pairs(l[1].atom()?, l[2].atom()?)?
                        .iter()
                        .map(|(s, t)| {
                            for range in &ranges {
                                native::record(
                                    &mut native_rules,
                                    format!(
                                        "{operation} {s} {t} {} ioctl {range}",
                                        xp[1].atom().unwrap()
                                    ),
                                    2,
                                    match op {
                                        "allowx" => 1,
                                        "auditallowx" => 2,
                                        _ => 3,
                                    },
                                    &[s, t, xp[1].atom().unwrap(), "ioctl", range],
                                );
                            }
                            format!(
                                "{operation} {s} {t} {} ioctl {{ {} }}",
                                xp[1].atom().unwrap(),
                                ranges.join(" ")
                            )
                        })
                        .collect())
                }
                "allow" | "auditallow" | "dontaudit" if l.len() == 4 => {
                    let cp = l[3].list()?;
                    if cp.len() != 2 {
                        return Err(invalid("classpermission sets not expanded"));
                    }
                    let class = cp[0].atom()?;
                    let permissions: Vec<_> = cp[1]
                        .list()?
                        .iter()
                        .map(Expr::atom)
                        .collect::<io::Result<_>>()?;
                    if !symbol(class)
                        || permissions.is_empty()
                        || permissions.iter().any(|p| !symbol(p))
                    {
                        return Err(invalid("invalid class/permissions"));
                    }
                    let permission_chunks = [permissions_text(&permissions)];
                    let mut rules = Vec::new();
                    for (s, target) in av_pairs(l[1].atom()?, l[2].atom()?)? {
                        for permissions in &permission_chunks {
                            let text = format!("{op} {s} {target} {class} {{ {permissions} }}");
                            for permission in permissions.split_whitespace() {
                                native::record(
                                    &mut native_rules,
                                    text.clone(),
                                    1,
                                    match op {
                                        "allow" => 1,
                                        "auditallow" => 3,
                                        _ => 4,
                                    },
                                    &[&s, &target, class, permission],
                                );
                            }
                            rules.push(text);
                        }
                    }
                    Ok(rules)
                }
                "typetransition" | "typechange" | "typemember"
                    if l.len() == 5 || (op == "typetransition" && l.len() == 6) =>
                {
                    let s = source(l[1].atom()?)?;
                    let t = source(l[2].atom()?)?;
                    let class = l[3].atom()?;
                    let result = source(l.last().unwrap().atom()?)?;
                    if !symbol(class) {
                        return Err(invalid("invalid transition class"));
                    }
                    let operation = match op {
                        "typetransition" => "type_transition",
                        "typechange" => "type_change",
                        _ => "type_member",
                    };
                    let filename = if l.len() == 6 {
                        let f = l[4].atom()?;
                        if f.is_empty()
                            || f.bytes()
                                .any(|c| !c.is_ascii_graphic() || b"{}*\"\\;#".contains(&c))
                        {
                            return Err(invalid("unsupported transition filename"));
                        }
                        format!(" {f}")
                    } else {
                        String::new()
                    };
                    let text = format!("{operation} {s} {t} {class} {result}{filename}");
                    let object = if l.len() == 6 { l[4].atom()? } else { "" };
                    if op == "typetransition" {
                        native::record(
                            &mut native_rules,
                            text.clone(),
                            7,
                            0,
                            &[&s, &t, class, &result, object],
                        );
                    } else {
                        native::record(
                            &mut native_rules,
                            text.clone(),
                            8,
                            if op == "typechange" { 1 } else { 2 },
                            &[&s, &t, class, &result],
                        );
                    }
                    Ok(vec![text])
                }
                // Compile-time assertions and schema: existing Host constraints stay untouched.
                "type"
                | "typealias"
                | "typealiasactual"
                | "typeattribute"
                | "typeattributeset"
                | "expandtypeattribute"
                | "neverallow"
                | "neverallowx"
                | "class"
                | "classorder"
                | "common"
                | "classcommon"
                | "sid"
                | "sidorder"
                | "sidcontext"
                | "user"
                | "userrole"
                | "userlevel"
                | "userrange"
                | "role"
                | "roletype"
                | "roleattribute"
                | "sensitivity"
                | "sensitivityorder"
                | "category"
                | "categoryorder"
                | "sensitivitycategory"
                | "categoryset"
                | "level"
                | "levelrange"
                | "mls"
                | "handleunknown"
                | "policycap" => Ok(Vec::new()),
                _ => Err(invalid(format!("unsupported {op}"))),
            }
        })();
        if matches!(
            op,
            "mlsconstrain"
                | "constrain"
                | "mlsvalidatetrans"
                | "validatetrans"
                | "fsuse"
                | "genfscon"
        ) {
            plan.retained_host.push(format!("{location}: {op}: active Host constraints/filesystem labels retained; Guest declaration not installed"));
        } else if op == "typepermissive" {
            plan.retained_host.push(format!(
                "{location}: typepermissive ignored; Guest types remain enforcing"
            ));
        } else {
            match converted {
                Ok(rules) => plan.rules.extend(rules),
                Err(e) => {
                    let (path, line) = location.rsplit_once(':').unwrap();
                    let raw = inputs[path]
                        .lines()
                        .nth(line.parse::<usize>().unwrap() - 1)
                        .unwrap_or("");
                    plan.unsupported_source.insert(location.clone(), raw.into());
                    plan.unsupported.push(format!("{location}: {e}"));
                }
            }
        }
    }
    for (path, text) in inputs.iter().filter(|(p, _)| p.ends_with("_contexts")) {
        match rewrite(
            text,
            &plan.types,
            path.ends_with("seapp_contexts"),
            path.ends_with("file_contexts"),
        ) {
            Ok(text) => {
                plan.contexts.insert(path.clone(), text);
            }
            Err(e) => plan.unsupported.push(format!("{path}: {e}")),
        }
    }
    // The launcher directly executes the Guest linker for its private helper binaries.
    if let Some(linker) = plan.types.get("system_linker_exec") {
        for domain in ["init", "shell", "derive_classpath"] {
            if let Some(domain) = plan.types.get(domain) {
                native::record(
                    &mut native_rules,
                    format!("allow {domain} {linker} file {{ entrypoint }}"),
                    1,
                    1,
                    &[domain, linker, "file", "entrypoint"],
                );
                plan.rules
                    .insert(format!("allow {domain} {linker} file entrypoint"));
            }
        }
    }
    // Rust's Guest property worker creates its own exec-error pipe before spawning services.
    if let Some(init) = plan.types.get("init") {
        let rule = format!("allow {init} {init} fifo_file {{ create }}");
        native::record(
            &mut native_rules,
            rule.clone(),
            1,
            1,
            &[init, init, "fifo_file", "create"],
        );
        plan.rules.insert(rule);
        for domain in ["shell", "mediaswcodec", "bootanim"] {
            if let Some(target) = plan.types.get(domain) {
                // Guest system mounts remain nosuid; permit only the explicit Guest domain transition.
                let rule = format!("allow {init} {target} process2 {{ nosuid_transition }}");
                native::record(
                    &mut native_rules,
                    rule.clone(),
                    1,
                    1,
                    &[init, target, "process2", "nosuid_transition"],
                );
                plan.rules.insert(rule);
            }
        }
        if let Some(adbd) = plan.types.get("adbd") {
            for (src, dst) in [(init, adbd)]
                .into_iter()
                .chain(plan.types.get("shell").map(|shell| (adbd, shell)))
            {
                let rule = format!("allow {src} {dst} process2 {{ nosuid_transition }}");
                native::record(
                    &mut native_rules,
                    rule.clone(),
                    1,
                    1,
                    &[src, dst, "process2", "nosuid_transition"],
                );
                plan.rules.insert(rule);
            }
            for (domain, permissions) in [
                (adbd, &["entrypoint", "execute", "getattr", "map", "open", "read"][..]),
                (init, &["execute", "getattr", "open", "read"][..]),
            ] {
                for permission in permissions {
                    let rule = format!("allow {domain} adbd_exec file {{ {permission} }}");
                    native::record(
                        &mut native_rules,
                        rule.clone(),
                        1,
                        1,
                        &[domain, "adbd_exec", "file", permission],
                    );
                    plan.rules.insert(rule);
                }
            }
            for (target, permission) in [("node", "node_bind"), ("port", "name_bind")] {
                let rule = format!("allow {adbd} {target} tcp_socket {{ {permission} }}");
                native::record(
                    &mut native_rules,
                    rule.clone(),
                    1,
                    1,
                    &[adbd, target, "tcp_socket", permission],
                );
                plan.rules.insert(rule);
            }
            for ioctl in ["0x5430", "0x5431"] {
                let rule = format!("allowxperm {adbd} devpts chr_file ioctl {ioctl}");
                native::record(
                    &mut native_rules,
                    rule.clone(),
                    2,
                    1,
                    &[adbd, "devpts", "chr_file", "ioctl", ioctl],
                );
                plan.rules.insert(format!("allowxperm {adbd} devpts chr_file ioctl {{ {ioctl} }}"));
            }
        }
    }
    // Guest devpts uses an isolated newinstance mount; allow adbd and shell to use its PTY nodes.
    for original in ["adbd", "shell"] {
        if let Some(domain) = plan.types.get(original) {
            for (class, permissions) in [
                ("dir", &["getattr", "open", "read", "search"][..]),
                ("chr_file", &["getattr", "ioctl", "open", "read", "setattr", "write"][..]),
            ] {
                for permission in permissions {
                    let rule = format!("allow {domain} devpts {class} {{ {permission} }}");
                    native::record(
                        &mut native_rules,
                        rule.clone(),
                        1,
                        1,
                        &[domain, "devpts", class, permission],
                    );
                    plan.rules.insert(rule);
                }
            }
        }
    }
    // Guest processes are execed by KSU and retain KSU-owned inherited FDs.
    if let Some(shell) = plan.types.get("shell") {
        // mksh queries inherited stdin pipes before reading beyond the first line.
        for permission in ["read", "getattr", "ioctl"] {
            let rule = format!("allow {shell} ksu fifo_file {{ {permission} }}");
            native::record(
                &mut native_rules,
                rule.clone(),
                1,
                1,
                &[shell, "ksu", "fifo_file", permission],
            );
            plan.rules.insert(rule);
        }
    }
    for original in [
        "init",
        "shell",
        "adbd",
        "derive_classpath",
        "linkerconfig",
        "servicemanager",
        "hwservicemanager",
        "hal_allocator_default",
        "aidl_lazy_test_server",
        "apexd",
        "installd",
        "artd",
        "vold",
        "netd",
        "lmkd",
        "audioserver",
        "gatekeeperd",
        "keystore",
        "aconfigd",
        concurrent::SYSTEM_SUSPEND_DOMAIN,
        "zygote",
        "system_server_startup",
        "system_server",
        "surfaceflinger",
        "hal_graphics_composer_default",
        "hal_graphics_allocator_default",
        "mediaswcodec",
        "bootanim",
    ] {
        if let Some(domain) = plan.types.get(original) {
            for (class, permission) in [("fd", "use"), ("fifo_file", "write")] {
                let rule = format!("allow {domain} ksu {class} {{ {permission} }}");
                native::record(
                    &mut native_rules,
                    rule.clone(),
                    1,
                    1,
                    &[domain, "ksu", class, permission],
                );
                plan.rules.insert(rule);
            }
        }
    }
    if let Some(lmkd_domain) = plan.types.get("lmkd") {
        for (class, permissions) in [
            ("dir", &["read", "open", "search", "getattr"][..]),
            ("file", &["read", "open", "getattr"][..]),
        ] {
            for permission in permissions {
                let rule = format!("allow {lmkd_domain} cgroup {class} {{ {permission} }}");
                native::record(
                    &mut native_rules,
                    rule.clone(),
                    1,
                    1,
                    &[lmkd_domain, "cgroup", class, permission],
                );
                plan.rules.insert(rule);
            }
        }
    }
    for domain_name in ["system_server", "servicemanager", "hwservicemanager"] {
        if let Some(domain) = plan.types.get(domain_name) {
            for (target, class, permissions) in [
                ("vendor_file", "dir", &["search", "getattr"][..]),
                (
                    "vendor_configs_file",
                    "dir",
                    &["read", "open", "search", "getattr"][..],
                ),
                ("vendor_configs_file", "file", &["read", "open", "getattr"][..]),
                ("vendor_configs_file", "lnk_file", &["read", "getattr"][..]),
            ] {
                for permission in permissions {
                    let rule = format!("allow {domain} {target} {class} {{ {permission} }}");
                    native::record(
                        &mut native_rules,
                        rule.clone(),
                        1,
                        1,
                        &[domain, target, class, permission],
                    );
                    plan.rules.insert(rule);
                }
            }
        }
    }
    if active_attributes.contains("appdomain") {
        if let Some(appdomain) = plan.attributes.get("appdomain") {
            for (class, permission) in [("fd", "use"), ("fifo_file", "write")] {
                let rule = format!("allow {appdomain} ksu {class} {{ {permission} }}");
                native::record(
                    &mut native_rules,
                    rule.clone(),
                    1,
                    1,
                    &[appdomain, "ksu", class, permission],
                );
                plan.rules.insert(rule);
            }
        }
    }
    if let Some(domain) = plan.types.get("derive_classpath") {
        let rule = format!("allow {domain} tmpfs lnk_file {{ read }}");
        native::record(
            &mut native_rules,
            rule.clone(),
            1,
            1,
            &[domain, "tmpfs", "lnk_file", "read"],
        );
        plan.rules.insert(rule);
        // derive_classpath's glob walks are widened only by permissions observed at runtime.
        for (target, permissions) in [
            (Some("vendor_file".to_owned()), &["search"][..]),
            (
                plan.types.get("shell_data_file").cloned(),
                &["search", "read"][..],
            ),
            (
                plan.types.get("system_data_root_file").cloned(),
                &["read"][..],
            ),
        ] {
            if let Some(target) = target {
                let rule = format!(
                    "allow {domain} {target} dir {{ {} }}",
                    permissions.join(" ")
                );
                for permission in permissions {
                    native::record(
                        &mut native_rules,
                        rule.clone(),
                        1,
                        1,
                        &[domain, &target, "dir", permission],
                    );
                }
                plan.rules.insert(rule);
            }
        }
        for (target, permissions) in [
            (Some("vendor_file".to_owned()), &["read", "getattr"][..]),
            (plan.types.get("shell_data_file").cloned(), &["getattr"][..]),
            (Some("tmpfs".to_owned()), &["read"][..]),
        ] {
            if let Some(target) = target {
                let rule = format!(
                    "allow {domain} {target} dir {{ {} }}",
                    permissions.join(" ")
                );
                for permission in permissions {
                    native::record(
                        &mut native_rules,
                        rule.clone(),
                        1,
                        1,
                        &[domain, &target, "dir", permission],
                    );
                }
                plan.rules.insert(rule);
            }
        }
        for (target, permissions) in [
            (Some("tmpfs".to_owned()), &["open"][..]),
            (plan.types.get("shell_data_file").cloned(), &["write"][..]),
            (
                plan.types.get("shell_data_file").cloned(),
                &["add_name", "remove_name"][..],
            ),
        ] {
            if let Some(target) = target {
                let rule = format!(
                    "allow {domain} {target} dir {{ {} }}",
                    permissions.join(" ")
                );
                for permission in permissions {
                    native::record(
                        &mut native_rules,
                        rule.clone(),
                        1,
                        1,
                        &[domain, &target, "dir", permission],
                    );
                }
                plan.rules.insert(rule);
            }
        }
        if let Some(target) = plan.types.get("shell_data_file") {
            // /data exports are committed by renaming the successfully written .tmp file.
            let rule = format!("allow {domain} {target} file {{ create open write rename }}");
            for permission in ["create", "open", "write", "rename"] {
                native::record(
                    &mut native_rules,
                    rule.clone(),
                    1,
                    1,
                    &[domain, target, "file", permission],
                );
            }
            plan.rules.insert(rule);
        }
    }
    // The launcher's shell client exchanges Binder objects with the test server and its callback.
    if let (Some(shell), Some(server)) = (
        plan.types.get("shell"),
        plan.types.get("aidl_lazy_test_server"),
    ) {
        for (source, target) in [(shell, server), (server, shell)] {
            let rule = format!("allow {source} {target} binder {{ call transfer }}");
            for permission in ["call", "transfer"] {
                native::record(
                    &mut native_rules,
                    rule.clone(),
                    1,
                    1,
                    &[source, target, "binder", permission],
                );
            }
            plan.rules.insert(rule);
        }
    }
    // The APEX readiness client runs in the same Guest domain as the service.
    if let Some(apexd) = plan.types.get("apexd") {
        let rule = format!("allow {apexd} {apexd} binder {{ call }}");
        if plan.rules.insert(rule.clone()) {
            native::record(&mut native_rules, rule, 1, 1, &[apexd, apexd, "binder", "call"]);
        }
    }
    concurrent::add_system_suspend_rules(&mut plan, &mut native_rules);
    // Property files are created under the directory type, then receive their final Guest label.
    if let (Some(init), Some(directory)) =
        (plan.types.get("init"), plan.types.get("properties_device"))
    {
        let rule = format!("allow {init} {directory} file {{ relabelfrom }}");
        native::record(
            &mut native_rules,
            rule.clone(),
            1,
            1,
            &[init, directory, "file", "relabelfrom"],
        );
        plan.rules.insert(rule);
    }
    if let (Some(init), Some(device)) = (plan.types.get("init"), plan.types.get("device")) {
        let rule = format!("allow {init} {device} dir {{ relabelfrom }}");
        native::record(
            &mut native_rules,
            rule.clone(),
            1,
            1,
            &[init, device, "dir", "relabelfrom"],
        );
        plan.rules.insert(rule);
    }
    for exec_name in ["vold_exec", "netd_exec", "lmkd_exec", "lmkd_socket", "audioserver_exec"] {
        if let Some(exec_type) = plan.types.get(exec_name) {
            let rule = format!("allow {exec_type} tmpfs filesystem {{ associate }}");
            if plan.rules.insert(rule.clone()) {
                native::record(
                    &mut native_rules,
                    rule,
                    1,
                    1,
                    &[exec_type, "tmpfs", "filesystem", "associate"],
                );
            }
        }
    }
    if let Some(audioserver) = plan.types.get("audioserver") {
        for hw_name in ["hal_audio_hwservice", "hidl_base_hwservice"] {
            if let Some(hw_type) = plan.types.get(hw_name) {
                let rule = format!("allow {audioserver} {hw_type} hwservice_manager {{ add }}");
                if plan.rules.insert(rule.clone()) {
                    native::record(
                        &mut native_rules,
                        rule,
                        1,
                        1,
                        &[audioserver, hw_type, "hwservice_manager", "add"],
                    );
                }
            }
        }
        for (target, class, perm) in [
            ("ksu", "unix_stream_socket", "connectto"),
            ("tmpfs", "sock_file", "write"),
        ] {
            let rule = format!("allow {audioserver} {target} {class} {{ {perm} }}");
            if plan.rules.insert(rule.clone()) {
                native::record(&mut native_rules, rule, 1, 1, &[audioserver, target, class, perm]);
            }
        }
    }
    // binderfs context= mounts require the Guest binder label to associate with its filesystem.
    for device in ["binder_device", "hwbinder_device"]
        .into_iter()
        .filter_map(|name| plan.types.get(name))
    {
        let rule = format!("allow {device} {device} filesystem {{ associate }}");
        if plan.rules.insert(rule.clone()) {
            native::record(
                &mut native_rules,
                rule,
                1,
                1,
                &[device, device, "filesystem", "associate"],
            );
        }
    }
    if let Some(shell) = plan.types.get("shell") {
        // lshal resolves built-in manager bookkeeping; the HIDL probe also resolves IAllocator.
        for service in [
            "hidl_manager_hwservice",
            "hidl_token_hwservice",
            "hidl_allocator_hwservice",
        ]
        .into_iter()
        .filter_map(|name| plan.types.get(name))
        {
            let rule = format!("allow {shell} {service} hwservice_manager {{ find }}");
            if plan.rules.insert(rule.clone()) {
                native::record(
                    &mut native_rules,
                    rule,
                    1,
                    1,
                    &[shell, service, "hwservice_manager", "find"],
                );
            }
        }
        if let Some(manager) = plan.types.get("hwservicemanager") {
            // IBase::debug receives the Guest lshal pipe's write end.
            for (class, permission) in [("fd", "use"), ("fifo_file", "write")] {
                let rule = format!("allow {manager} {shell} {class} {{ {permission} }}");
                if plan.rules.insert(rule.clone()) {
                    native::record(
                        &mut native_rules,
                        rule,
                        1,
                        1,
                        &[manager, shell, class, permission],
                    );
                }
            }
        }
        if let Some(allocator) = plan.types.get("hal_allocator_default") {
            for (source, target, class, permissions) in [
                (shell, allocator, "binder", &["call", "transfer"][..]),
                (shell, allocator, "fd", &["use"][..]),
                (allocator, shell, "binder", &["transfer"][..]),
                (allocator, shell, "fd", &["use"][..]),
                (allocator, shell, "fifo_file", &["write"][..]),
            ] {
                let rule = format!(
                    "allow {source} {target} {class} {{ {} }}",
                    permissions.join(" ")
                );
                if plan.rules.insert(rule.clone()) {
                    for permission in permissions {
                        native::record(
                            &mut native_rules,
                            rule.clone(),
                            1,
                            1,
                            &[source, target, class, permission],
                        );
                    }
                }
            }
        }
    }
    // memfd uses the shared kernel tmpfs SID, outside the relabeled Guest mounts.
    if let Some(tmpfs) = plan.types.get("tmpfs") {
        let transitions: Vec<_> = native_rules
            .values()
            .flatten()
            .filter(|command| {
                command.cmd == 7 && command.args[1] == *tmpfs && command.args[2] == "file"
            })
            .cloned()
            .collect();
        for command in transitions {
            let args = &command.args;
            let rule = format!(
                "type_transition {} tmpfs file {}{}",
                args[0],
                args[3],
                if args[4].is_empty() {
                    String::new()
                } else {
                    format!(" {}", args[4])
                }
            );
            native::record(
                &mut native_rules,
                rule.clone(),
                7,
                0,
                &[&args[0], "tmpfs", "file", &args[3], &args[4]],
            );
            plan.rules.insert(rule);
        }
    }
    concurrent::add_health_rules(&mut plan, &mut native_rules)?;
    concurrent::add_gatekeeper_rules(&mut plan, &mut native_rules)?;
    concurrent::add_keymint_rules(&mut plan, &mut native_rules)?;
    concurrent::add_thermal_rules(&mut plan, &mut native_rules)?;
    concurrent::add_sensors_rules(&mut plan, &mut native_rules)?;
    plan.native_rules = native_rules;
    // Partial offline fixtures remain supported; mounted preparation requires these types.
    if ["init", "socket_device", "property_socket"]
        .iter()
        .all(|name| plan.types.contains_key(*name))
    {
        plan.ensure_property_socket_transition()?;
    }
    if ["init", "servicemanager"]
        .iter()
        .all(|name| plan.types.contains_key(*name))
    {
        plan.ensure_kernel_av_access()?;
    }
    Ok(plan)
}

/// Hash first: unchanged GSI input never invokes the parser or rewrites generated artifacts.
pub fn prepare(
    profile: &Path,
    id: &str,
    files: &BTreeMap<String, String>,
    force_regen: bool,
) -> io::Result<(Plan, bool)> {
    let directory = profile.join("selinux");
    fs::create_dir_all(&directory)?;
    let path = directory.join("plan.json");
    let hashes: Vec<_> = files
        .iter()
        .map(|(path, text)| Input {
            path: path.clone(),
            sha256: digest(text.as_bytes()),
        })
        .collect();
    let hash = digest(&serde_json::to_vec(&hashes)?);
    if !force_regen && path.is_file() {
        let plan: Plan = serde_json::from_slice(&fs::read(&path)?)?;
        if plan.version == VERSION && plan.id == id && plan.input_hash == hash {
            return Ok((plan, false));
        }
    }
    let plan = match generate(id, files) {
        Ok(plan) => plan,
        Err(error) => {
            atomic(
                &directory.join("generation-error.json"),
                &serde_json::to_vec_pretty(
                    &serde_json::json!({"id":id,"input_hash":hash,"inputs":hashes,"error":error.to_string()}),
                )?,
            )?;
            return Err(error);
        }
    };
    let bytes = serde_json::to_vec_pretty(&plan)?;
    let history = directory.join("plans");
    fs::create_dir_all(&history)?;
    atomic(
        &history.join(format!("v{VERSION}-{}.json", plan.input_hash)),
        &bytes,
    )?;
    atomic(&path, &bytes)?;
    Ok((plan, true))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn classpath_exports_can_commit_temp_file_with_guest_only_permissions() -> io::Result<()> {
        let plan = generate(
            "p0001",
            &BTreeMap::from([(
                "policy.cil".into(),
                "(type derive_classpath) (type shell_data_file)".into(),
            )]),
        )?;
        for (class, permissions) in [
            ("dir", &["add_name", "remove_name"][..]),
            ("file", &["create", "open", "write", "rename"][..]),
        ] {
            let rule = format!(
                "allow ssal_p0001_derive_classpath ssal_p0001_shell_data_file {class} {{ {} }}",
                permissions.join(" ")
            );
            assert!(plan.rules.contains(&rule));
            let commands = &plan.native_rules[&rule];
            assert_eq!(commands.len(), permissions.len());
            for permission in permissions {
                assert!(commands.iter().any(|command| command.args
                    == [
                        "ssal_p0001_derive_classpath",
                        "ssal_p0001_shell_data_file",
                        class,
                        permission
                    ]));
            }
            assert_eq!(
                native::encode(&plan, &[rule])?
                    .iter()
                    .map(|b| b.commands)
                    .sum::<usize>(),
                permissions.len()
            );
        }
        assert!(!plan
            .rules
            .iter()
            .any(|rule| rule.starts_with("allow derive_classpath ")));
        Ok(())
    }
    #[test]
    fn live_kernel_av_access_is_guest_only_and_idempotent() -> io::Result<()> {
        let mut plan = generate(
            "p0001",
            &BTreeMap::from([(
                "policy.cil".into(),
                "(type init) (type servicemanager) (type zygote) (type installd)".into(),
            )]),
        )?;
        let generated = serde_json::to_vec(&plan)?;
        plan.ensure_kernel_av_access()?;
        plan.ensure_kernel_av_access()?;
        assert_eq!(serde_json::to_vec(&plan)?, generated);
        let added: Vec<_> = plan
            .rules
            .iter()
            .filter(|r| r.contains(" kernel security "))
            .cloned()
            .collect();
        assert_eq!(
            added,
            vec![
                "allow ssal_p0001_init kernel security { compute_av }",
                "allow ssal_p0001_installd kernel security { check_context }",
                "allow ssal_p0001_servicemanager kernel security { compute_av }",
                "allow ssal_p0001_zygote kernel security { check_context }",
            ]
        );
        assert_eq!(
            native::encode(&plan, &added)?
                .iter()
                .map(|b| b.commands)
                .sum::<usize>(),
            4
        );
        Ok(())
    }
    #[test]
    fn self_rules_expand_to_each_concrete_member_without_cross_grants() -> io::Result<()> {
        let plan = generate(
            "p0001",
            &BTreeMap::from([(
                "policy.cil".into(),
                r#"
            (type a) (type b) (typeattribute apps) (typeattributeset apps (a b))
            (allow apps self (process (fork)))
            (allowx apps self (ioctl file (0x1234)))
            (auditallow a self (file (read))) (dontaudit b self (file (write)))
        "#
                .into(),
            )]),
        )?;
        let rules: BTreeSet<_> = plan
            .rules
            .iter()
            .filter(|r| !r.starts_with("typeattribute "))
            .cloned()
            .collect();
        assert_eq!(
            rules,
            BTreeSet::from([
                "allow ssal_p0001_a ssal_p0001_a process { fork }".into(),
                "allow ssal_p0001_b ssal_p0001_b process { fork }".into(),
                "allowxperm ssal_p0001_a ssal_p0001_a file ioctl { 0x1234 }".into(),
                "allowxperm ssal_p0001_b ssal_p0001_b file ioctl { 0x1234 }".into(),
                "auditallow ssal_p0001_a ssal_p0001_a file { read }".into(),
                "dontaudit ssal_p0001_b ssal_p0001_b file { write }".into(),
            ])
        );
        for commands in plan.native_rules.values() {
            for c in commands {
                assert!(!c.args.iter().any(|a| a == "self"));
            }
        }
        assert!(native::PolicyCommand {
            cmd: 1,
            subcmd: 1,
            args: vec!["a".into(), "self".into(), "file".into(), "read".into()]
        }
        .encode()
        .is_err());
        Ok(())
    }
    fn fixture() -> BTreeMap<String, String> {
        BTreeMap::from([
            ("system/etc/selinux/plat_sepolicy.cil".into(), "(type zygote) (type system_server) (type vendor_file) (type system_file) (type binder_device) (typeattribute domain) (typeattributeset domain (zygote system_server)) (allow domain vendor_file (file (read open))) (allow zygote self (process (fork))) (typetransition zygote system_file process system_server)".into()),
            ("system/etc/selinux/plat_file_contexts".into(), "/vendor(/.*)? u:object_r:vendor_file:s0\n/system(/.*)? u:object_r:system_file:s0\n/dev/binder u:object_r:binder_device:s0\n".into()),
            ("system/etc/selinux/plat_seapp_contexts".into(), "user=system domain=system_server type=system_file levelFrom=user\n".into()),
        ])
    }
    #[test]
    fn health_domain_is_private_and_does_not_inherit_host_power_access() -> io::Result<()> {
        let mut inputs = fixture();
        inputs
            .get_mut("system/etc/selinux/plat_sepolicy.cil")
            .unwrap()
            .push_str(" (type servicemanager) (type hal_health_service)");
        let plan = generate("p0001", &inputs)?;
        let health = &plan.types["ssal_health"];
        assert!(plan.rules.contains(&format!(
            "allow {health} ssal_p0001_hal_health_service service_manager {{ add find }}"
        )));
        assert!(plan.rules.contains(&format!(
            "allow {health} ssal_p0001_system_server binder {{ call transfer }}"
        )));
        assert!(!plan.rules.iter().any(|rule| {
            rule.starts_with(&format!("typeattribute {health} "))
                || rule.starts_with(&format!("allow {health} "))
                    && rule.split_whitespace().nth(2).is_some_and(|target| {
                        target == "binder_device" || target.contains("sysfs")
                    })
        }));
        Ok(())
    }

    #[test]
    fn gatekeeper_and_keymint_domains_are_private_and_isolated() -> io::Result<()> {
        let mut inputs = fixture();
        inputs.get_mut("system/etc/selinux/plat_sepolicy.cil").unwrap().push_str(
            " (type servicemanager) (type keystore) (type gatekeeperd) (type vold) (type hal_gatekeeper_service) (type hal_keymint_service) (type hal_sharedsecret_service) (type hal_secureclock_service)",
        );
        let plan = generate("p0001", &inputs)?;
        let gk = &plan.types["ssal_gatekeeper"];
        let km = &plan.types["ssal_keymint"];
        assert!(plan.rules.contains(&format!(
            "allow {gk} ssal_p0001_hal_gatekeeper_service service_manager {{ add find }}"
        )));
        assert!(plan.rules.contains(&format!(
            "allow {km} ssal_p0001_hal_keymint_service service_manager {{ add find }}"
        )));
        assert!(plan.rules.contains(&format!(
            "allow ssal_p0001_keystore {km} binder {{ call transfer }}"
        )));
        for domain in [gk, km] {
            assert!(!plan.rules.iter().any(|rule| {
                rule.starts_with(&format!("typeattribute {domain} "))
                    || rule.starts_with(&format!("allow {domain} "))
                        && rule.split_whitespace().nth(2).is_some_and(|target| {
                            target == "binder_device"
                                || target.contains("tee")
                                || target.contains("smcinvoke")
                        })
            }));
        }
        Ok(())
    }

    #[test]
    fn hwbinder_labels_and_rules_target_guest_types() -> io::Result<()> {
        let mut inputs = fixture();
        inputs
            .get_mut("system/etc/selinux/plat_sepolicy.cil")
            .unwrap()
            .push_str(" (type init) (type servicemanager) (type shell) (type hwservicemanager) (type hal_allocator_default) (type hwbinder_device) (type hidl_token_hwservice) (type hidl_allocator_hwservice)");
        let contexts = "system/etc/selinux/plat_hwservice_contexts";
        inputs.insert(contexts.into(), "android.hidl.token::ITokenManager u:object_r:hidl_token_hwservice:s0\nandroid.hidl.allocator::IAllocator u:object_r:hidl_allocator_hwservice:s0\n".into());
        let plan = generate("p0001", &inputs)?;
        assert!(plan.contexts[contexts].contains("u:object_r:ssal_p0001_hidl_token_hwservice:s0"));
        assert!(plan.contexts[contexts].contains("u:object_r:ssal_p0001_hidl_allocator_hwservice:s0"));
        for rule in [
            "allow ssal_p0001_hwservicemanager kernel security { compute_av }",
            "allow ssal_p0001_hwbinder_device ssal_p0001_hwbinder_device filesystem { associate }",
            "allow ssal_p0001_shell ssal_p0001_hidl_token_hwservice hwservice_manager { find }",
            "allow ssal_p0001_shell ssal_p0001_hidl_allocator_hwservice hwservice_manager { find }",
            "allow ssal_p0001_hwservicemanager ssal_p0001_shell fd { use }",
            "allow ssal_p0001_hwservicemanager ssal_p0001_shell fifo_file { write }",
            "allow ssal_p0001_shell ssal_p0001_hal_allocator_default binder { call transfer }",
            "allow ssal_p0001_shell ssal_p0001_hal_allocator_default fd { use }",
            "allow ssal_p0001_hal_allocator_default ssal_p0001_shell binder { transfer }",
            "allow ssal_p0001_hal_allocator_default ssal_p0001_shell fd { use }",
            "allow ssal_p0001_hal_allocator_default ssal_p0001_shell fifo_file { write }",
        ] {
            assert!(plan.rules.contains(rule), "missing rule: {rule}");
            assert!(plan.native_rules.contains_key(rule), "missing native rule: {rule}");
        }
        assert!(!plan.rules.iter().any(|rule| rule.contains(" hwbinder_device ")));
        Ok(())
    }

    #[test]
    fn launcher_aidl_calls_only_extend_guest_peers() -> io::Result<()> {
        let mut inputs = fixture();
        inputs
            .get_mut("system/etc/selinux/plat_sepolicy.cil")
            .unwrap()
            .push_str(" (type shell) (type aidl_lazy_test_server) (type apexd)");
        let plan = generate("p0001", &inputs)?;
        let apex_call = "allow ssal_p0001_apexd ssal_p0001_apexd binder { call }";
        assert!(plan.rules.contains(apex_call));
        assert_eq!(plan.native_rules[apex_call].len(), 1);
        for (source, target) in [
            ("shell", "aidl_lazy_test_server"),
            ("aidl_lazy_test_server", "shell"),
        ] {
            let rule =
                format!("allow ssal_p0001_{source} ssal_p0001_{target} binder {{ call transfer }}");
            assert!(plan.rules.contains(&rule));
            assert_eq!(
                native::encode(&plan, &[rule])?
                    .iter()
                    .map(|b| b.commands)
                    .sum::<usize>(),
                2
            );
        }
        assert!(!plan.rules.iter().any(
            |r| r.starts_with("allow shell ")
                || r.starts_with("allow aidl_lazy_test_server ")
                || r.starts_with("allow apexd ")
        ));
        Ok(())
    }
    #[test]
    fn launcher_fd_permissions_only_extend_guest_helper_clients() -> io::Result<()> {
        let mut inputs = fixture();
        inputs
            .get_mut("system/etc/selinux/plat_sepolicy.cil")
            .unwrap()
            .push_str(" (type init) (type shell) (type derive_classpath) (type linkerconfig) (type servicemanager) (type aidl_lazy_test_server) (type apexd) (type properties_device) (type system_server_startup)");
        inputs
            .get_mut("system/etc/selinux/plat_sepolicy.cil")
            .unwrap()
            .push_str(" (type surfaceflinger) (type installd)");
        let plan = generate("p0001", &inputs)?;
        let rules: Vec<_> = plan
            .rules
            .iter()
            .filter(|r| r.contains(" ksu "))
            .cloned()
            .collect();
        assert_eq!(rules.len(), 27);
        assert!(rules.contains(&"allow ssal_p0001_shell ksu fifo_file { read }".to_owned()));
        for permission in ["getattr", "ioctl"] {
            let rule = format!("allow ssal_p0001_shell ksu fifo_file {{ {permission} }}");
            assert!(rules.contains(&rule));
            assert_eq!(
                native::encode(&plan, &[rule])?
                    .iter()
                    .map(|batch| batch.commands)
                    .sum::<usize>(),
                1
            );
        }
        let relabel = "allow ssal_p0001_init ssal_p0001_properties_device file { relabelfrom }";
        assert!(plan.rules.contains(relabel));
        assert!(plan.native_rules.contains_key(relabel));
        for source in [
            "init",
            "shell",
            "derive_classpath",
            "linkerconfig",
            "servicemanager",
            "aidl_lazy_test_server",
            "apexd",
            "installd",
            "zygote",
            "system_server_startup",
            "system_server",
            "surfaceflinger",
        ] {
            for (class, permission) in [("fd", "use"), ("fifo_file", "write")] {
                let rule = format!("allow ssal_p0001_{source} ksu {class} {{ {permission} }}");
                assert!(rules.contains(&rule));
                assert_eq!(
                    native::encode(&plan, &[rule])?
                        .iter()
                        .map(|b| b.commands)
                        .sum::<usize>(),
                    1
                );
            }
        }
        Ok(())
    }

    #[test]
    fn guest_property_spawn_pipe_permission_is_guest_only() -> io::Result<()> {
        let plan = generate(
            "p0001",
            &BTreeMap::from([(
                "policy.cil".into(),
                "(type init) (type shell) (type bootanim) (type unrelated)".into(),
            )]),
        )?;
        let rule = "allow ssal_p0001_init ssal_p0001_init fifo_file { create }";
        assert!(plan.rules.contains(rule));
        assert_eq!(plan.native_rules[rule].len(), 1);
        assert_eq!(
            plan.native_rules[rule][0].args,
            ["ssal_p0001_init", "ssal_p0001_init", "fifo_file", "create"]
        );
        assert!(!plan
            .rules
            .iter()
            .any(|rule| rule.starts_with("allow init ")));
        for domain in ["shell", "bootanim"] {
            let target = format!("ssal_p0001_{domain}");
            let transition = format!("allow ssal_p0001_init {target} process2 {{ nosuid_transition }}");
            assert!(plan.rules.contains(&transition));
            assert_eq!(
                plan.native_rules[&transition][0].args,
                [
                    "ssal_p0001_init",
                    target.as_str(),
                    "process2",
                    "nosuid_transition"
                ]
            );
        }
        assert_eq!(
            plan.rules
                .iter()
                .filter(|rule| rule.contains("nosuid_transition"))
                .count(),
            2
        );
        Ok(())
    }

    #[test]
    fn kernel_tmpfs_transitions_keep_guest_sources_and_outputs() -> io::Result<()> {
        let mut inputs = fixture();
        inputs.get_mut("system/etc/selinux/plat_sepolicy.cil").unwrap().push_str(
            " (type tmpfs) (type zygote_tmpfs) (type system_server_tmpfs) (typetransition zygote tmpfs file zygote_tmpfs) (typetransition system_server tmpfs file system_server_tmpfs)");
        let plan = generate("p0001", &inputs)?;
        for domain in ["zygote", "system_server"] {
            for target in ["tmpfs", "ssal_p0001_tmpfs"] {
                let rule = format!(
                    "type_transition ssal_p0001_{domain} {target} file ssal_p0001_{domain}_tmpfs"
                );
                assert!(plan.rules.contains(&rule));
                assert_eq!(
                    native::encode(&plan, &[rule])?
                        .iter()
                        .map(|batch| batch.commands)
                        .sum::<usize>(),
                    1
                );
            }
        }
        assert!(!plan
            .rules
            .iter()
            .any(|rule| rule.starts_with("type_transition zygote ")
                || rule.starts_with("type_transition system_server ")));
        Ok(())
    }
    #[test]
    fn converts_private_types_shared_labels_and_transitions() -> io::Result<()> {
        let plan = generate("p0001", &fixture())?;
        plan.usable()?;
        assert!(plan
            .rules
            .contains("allow ssal_p0001_domain vendor_file file { read open }"));
        assert!(plan.rules.contains("type_transition ssal_p0001_zygote ssal_p0001_system_file process ssal_p0001_system_server"));
        assert!(plan.contexts["system/etc/selinux/plat_file_contexts"]
            .contains("/vendor(/.*)? u:object_r:vendor_file:s0"));
        assert!(plan.contexts["system/etc/selinux/plat_file_contexts"]
            .contains("/dev/binder u:object_r:ssal_p0001_binder_device:s0"));
        let binder_device = &plan.types["binder_device"];
        let binderfs_rule =
            format!("allow {binder_device} {binder_device} filesystem {{ associate }}");
        assert!(plan.rules.contains(&binderfs_rule));
        assert!(plan.native_rules.contains_key(&binderfs_rule));
        assert_eq!(
            native::encode(&plan, &[binderfs_rule])?
                .iter()
                .map(|batch| batch.commands)
                .sum::<usize>(),
            1
        );
        assert!(plan.contexts["system/etc/selinux/plat_seapp_contexts"]
            .contains("domain=ssal_p0001_system_server"));
        assert!(plan.declarations.iter().all(|s| !s.ends_with(" domain")));
        assert_eq!(plan.context("zygote", true)?, "u:r:ssal_p0001_zygote:s0");
        Ok(())
    }
    #[test]
    fn preserves_long_permission_sets_without_text_splitting() -> io::Result<()> {
        let permissions = (0..24)
            .map(|n| format!("permission{n:02}"))
            .collect::<Vec<_>>();
        let mut supplied = permissions.clone();
        supplied.insert(3, permissions[0].clone());
        let mut files = fixture();
        files
            .get_mut("system/etc/selinux/plat_sepolicy.cil")
            .unwrap()
            .push_str(&format!(
                " (allow system_server self (file ({})))",
                supplied.join(" ")
            ));

        let plan = generate("p0001", &files)?;
        let rules = plan
            .rules
            .iter()
            .filter(|rule| {
                rule.starts_with("allow ssal_p0001_system_server ssal_p0001_system_server file { ")
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
                    "ssal_p0001_system_server",
                    "ssal_p0001_system_server",
                    "file"
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
        assert_eq!(observed, permissions.iter().map(String::as_str).collect());
        Ok(())
    }
    #[test]
    fn rejects_unsupported_and_name_collisions() -> io::Result<()> {
        let mut inputs = fixture();
        inputs
            .get_mut("system/etc/selinux/plat_sepolicy.cil")
            .unwrap()
            .push_str("\n(booleanif foo (true (allow zygote self (process (fork)))))");
        let p = generate("p0001", &inputs)?;
        assert!(p.usable().is_err());
        assert!(p.unsupported[0].contains("plat_sepolicy.cil:2"));
        inputs.insert("extra.cil".into(), "(type owned)".into());
        assert!(generate("p0001", &inputs).is_err());
        assert!(generate("../p0001", &fixture()).is_err());
        assert!(parse("(type foo").is_err());
        assert!(parse("(type \"foo)").is_err());
        Ok(())
    }
    #[test]
    fn combines_partition_attributes_aliases_and_ioctl_without_host_sources() -> io::Result<()> {
        let mut files = fixture();
        files.insert("system_ext/etc/selinux/system_ext_sepolicy.cil".into(), "(typeattribute domain) (typeattribute selected) (typeattributeset domain (system_server)) (typeattributeset selected (and domain (not (system_server)))) (typealias server_alias) (typealiasactual server_alias system_server) (allowx selected vendor_file (ioctl file ((range 0x1200 0x12ff)))) (typetransition zygote zygote anon_inode \"[userfaultfd]\" system_file) (allowx zygote self (nlmsg netlink_audit_socket (0x3e9)))".into());
        let plan = generate("p0002", &files)?;
        plan.usable()?;
        assert_eq!(plan.types["server_alias"], plan.types["system_server"]);
        assert!(plan
            .rules
            .contains("typeattribute ssal_p0002_zygote ssal_p0002_selected"));
        assert!(!plan
            .rules
            .contains("typeattribute ssal_p0002_system_server ssal_p0002_selected"));
        assert!(plan
            .rules
            .contains("allowxperm ssal_p0002_selected vendor_file file ioctl { 0x1200-0x12ff }"));
        assert!(plan.rules.contains("type_transition ssal_p0002_zygote ssal_p0002_zygote anon_inode ssal_p0002_system_file [userfaultfd]"));
        assert_eq!(plan.unsupported.len(), 1);
        for rule in &plan.rules {
            let fields: Vec<_> = rule.split_whitespace().collect();
            if fields[0] == "typeattribute" {
                assert!(fields[2].starts_with("ssal_p0002_"));
            } else {
                assert!(fields[1].starts_with("ssal_p0002_"));
            }
            assert!(!matches!(fields[0], "permissive" | "deny" | "enforce"));
        }
        Ok(())
    }
    #[test]
    fn discovers_partition_roots_but_not_compat_mapping_cil() -> io::Result<()> {
        let root = std::env::temp_dir().join(format!("ssal-policy-inputs-{}", std::process::id()));
        fs::create_dir_all(root.join("system/etc/selinux/mapping"))?;
        fs::create_dir_all(root.join("product/etc/selinux"))?;
        fs::write(
            root.join("system/etc/selinux/plat_sepolicy.cil"),
            "(type foo)",
        )?;
        fs::write(
            root.join("system/etc/selinux/mapping/old.cil"),
            "(type old)",
        )?;
        fs::write(
            root.join("product/etc/selinux/product_sepolicy.cil"),
            "(type bar)",
        )?;
        let files = inputs(&root)?;
        assert_eq!(files.len(), 2);
        assert!(files.contains_key("product/etc/selinux/product_sepolicy.cil"));
        fs::remove_dir_all(root)?;
        Ok(())
    }
    #[test]
    fn cache_changes_only_for_changed_inputs_and_ids_never_recycle() -> io::Result<()> {
        let root = std::env::temp_dir().join(format!("ssal-policy-cache-{}", std::process::id()));
        fs::create_dir_all(&root)?;
        let id = allocate_id(&root)?;
        assert_eq!(id, "p0001");
        let profile = root.join("profile");
        fs::create_dir(&profile)?;
        let files = fixture();
        assert!(prepare(&profile, &id, &files, false)?.1);
        assert!(!prepare(&profile, &id, &files, false)?.1);
        assert!(prepare(&profile, &id, &files, true)?.1);
        assert!(!prepare(&profile, &id, &files, false)?.1);
        let mut stale = generate(&id, &files)?;
        stale.version = 1;
        atomic(
            &profile.join("selinux/plan.json"),
            &serde_json::to_vec(&stale)?,
        )?;
        assert!(prepare(&profile, &id, &files, false)?.1);
        let mut changed = files;
        changed
            .get_mut("system/etc/selinux/plat_seapp_contexts")
            .unwrap()
            .push_str("# changed\n");
        assert!(prepare(&profile, &id, &changed, false)?.1);
        assert_eq!(fs::read_dir(profile.join("selinux/plans"))?.count(), 2);
        fs::remove_dir_all(&profile)?;
        assert_eq!(allocate_id(&root)?, "p0002");
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn system_image_id_reuses_same_image_and_isolates_different_images() -> io::Result<()> {
        let root = std::env::temp_dir().join(format!("ssal-sysimg-id-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let img1 = root.join("images/img1");
        let img2 = root.join("images/img2");
        fs::create_dir_all(&img1)?;
        fs::create_dir_all(&img2)?;
        assert_eq!(system_image_id(&root, &img1)?, "p0001");
        assert_eq!(system_image_id(&root, &img1)?, "p0001");
        assert_eq!(system_image_id(&root, &img2)?, "p0002");
        fs::remove_dir_all(root)?;
        Ok(())
    }
    #[test]
    fn desired_plan_matches_generation_cache_and_legacy_runtime_corrections() -> io::Result<()> {
        let root = std::env::temp_dir().join(format!("ssal-desired-plan-{}", std::process::id()));
        let mut files = fixture();
        let cil = files
            .get_mut("system/etc/selinux/plat_sepolicy.cil")
            .unwrap();
        cil.push_str(
            " (type init) (type servicemanager) (type socket_device) (type property_socket)",
        );
        let generated = generate("p0001", &files)?;
        let expected = serde_json::to_vec_pretty(&generated)?;
        let (miss, regenerated) = prepare(&root, "p0001", &files, false)?;
        assert!(regenerated);
        let (hit, regenerated) = prepare(&root, "p0001", &files, false)?;
        assert!(!regenerated);
        for plan in [&miss, &hit] {
            assert_eq!(serde_json::to_vec_pretty(plan)?, expected);
        }
        assert_eq!(fs::read(root.join("selinux/plan.json"))?, expected);
        assert_eq!(
            fs::read(root.join(format!(
                "selinux/plans/v{VERSION}-{}.json",
                generated.input_hash
            )))?,
            expected
        );

        let mut legacy = generated.clone();
        legacy.version = 11;
        let corrections = [
            "allow ssal_p0001_init kernel security { compute_av }",
            "allow ssal_p0001_servicemanager kernel security { compute_av }",
            "type_transition ssal_p0001_init ssal_p0001_socket_device sock_file ssal_p0001_property_socket",
        ];
        for rule in corrections {
            assert!(legacy.rules.remove(rule));
            assert!(legacy.native_rules.remove(rule).is_some());
        }
        atomic(
            &root.join("selinux/plan.json"),
            &serde_json::to_vec(&legacy)?,
        )?;
        let (upgraded, regenerated) = prepare(&root, "p0001", &files, false)?;
        assert!(regenerated);
        assert_eq!(serde_json::to_vec_pretty(&upgraded)?, expected);
        // Reproduce the old mounted-only correction without changing its rule/command set.
        legacy.ensure_property_socket_transition()?;
        legacy.ensure_kernel_av_access()?;
        assert_eq!(legacy.rules, generated.rules);
        assert_eq!(legacy.native_rules, generated.native_rules);
        let mut repeated = generated.clone();
        repeated.ensure_property_socket_transition()?;
        repeated.ensure_kernel_av_access()?;
        assert_eq!(serde_json::to_vec_pretty(&repeated)?, expected);

        files.get_mut("system/etc/selinux/plat_sepolicy.cil").unwrap().push_str(
            " (typetransition init socket_device sock_file property_socket) (typetransition init socket_device sock_file property_socket)",
        );
        let duplicate = generate("p0001", &files)?;
        assert_eq!(duplicate.rules, generated.rules);
        assert_eq!(duplicate.native_rules, generated.native_rules);
        #[cfg(unix)]
        {
            let expected_batches = runtime::encode_native(&generated)?;
            for plan in [&miss, &hit, &upgraded, &duplicate] {
                let batches = runtime::encode_native(plan)?;
                assert_eq!(batches.len(), expected_batches.len());
                for (actual, expected) in batches.iter().zip(&expected_batches) {
                    assert_eq!(actual.payload, expected.payload);
                    assert_eq!(actual.statements, expected.statements);
                }
            }
            let mut missing = generated.clone();
            missing.native_rules.remove(corrections[0]);
            assert!(runtime::check_native(&missing).is_err());
        }
        fs::remove_dir_all(root)?;
        Ok(())
    }
    #[test]
    #[ignore = "set SSAL_POLICY_FIXTURE to a saved guest partition export"]
    fn saved_gsi() -> io::Result<()> {
        let root = std::path::PathBuf::from(std::env::var("SSAL_POLICY_FIXTURE").unwrap());
        let mut files = BTreeMap::new();
        for partition in ["system", "system_ext", "product"] {
            let dir = root.join(partition).join("etc/selinux");
            if dir.is_dir() {
                collect(&dir, &format!("{partition}/etc/selinux"), &mut files)?;
            }
        }
        let plan = generate("p0001", &files)?;
        println!(
            "GSI inputs={} types={} attributes={} rules={} unsupported={} retained_host={}",
            plan.inputs.len(),
            plan.types.len(),
            plan.attributes.len(),
            plan.rules.len(),
            plan.unsupported.len(),
            plan.retained_host.len()
        );
        for issue in plan.unsupported.iter().take(3) {
            println!("{issue}");
        }
        #[cfg(unix)]
        {
            let batches = runtime::encode_native(&plan)?;
            assert!(batches
                .iter()
                .all(|b| b.payload.len() <= native::BATCH_BYTES));
            assert_eq!(plan.types.len(), 2040);
            println!(
                "native batches={} commands={} bytes={}",
                batches.len(),
                batches.iter().map(|b| b.commands).sum::<usize>(),
                batches.iter().map(|b| b.payload.len()).sum::<usize>()
            );
            assert_eq!(plan.rules.len(), 49895);
            assert_eq!(
                plan.rules
                    .iter()
                    .filter(|r| r.starts_with("type_transition "))
                    .count(),
                407
            );
            assert_eq!(
                plan.rules
                    .iter()
                    .filter(|r| r.starts_with("type_transition ")
                        && (r.ends_with("[userfaultfd]") || r.ends_with("[io_uring]")))
                    .count(),
                51
            );
            assert_eq!(batches.iter().map(|b| b.commands).sum::<usize>(), 133895);
            assert_eq!(
                batches.iter().map(|b| b.payload.len()).sum::<usize>(),
                11267592
            );
        }
        for original in [
            "zygote",
            "system_server",
            "system_server_startup",
            "init",
            "servicemanager",
            "binder_device",
            "properties_device",
            "property_info",
            "properties_serial",
            "property_socket",
            "default_prop",
        ] {
            plan.context(original, false)?;
        }
        plan.usable()
    }

    #[test]
    fn guest_mls_trusted_types_inherit_host_mls_attributes() -> io::Result<()> {
        let mut files = BTreeMap::new();
        files.insert(
            "system/etc/selinux/plat_sepolicy.cil".into(),
            "(type zygote) (type binder_device) (typeattribute mlstrustedsubject) (typeattribute mlstrustedobject) (typeattributeset mlstrustedsubject (zygote)) (typeattributeset mlstrustedobject (binder_device))".into(),
        );
        let plan = generate("p0003", &files)?;
        assert!(plan
            .rules
            .contains("typeattribute ssal_p0003_zygote mlstrustedsubject"));
        assert!(plan
            .rules
            .contains("typeattribute ssal_p0003_binder_device mlstrustedobject"));
        Ok(())
    }
}
