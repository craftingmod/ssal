//! Filesystem command parsing (`mkdir`) and safe Guest directory creation for `init.rc`.
use super::aid;
use super::file_contexts::FileContexts;
use super::parser::expand;
use super::{Line, Plan, Properties};
use std::ffi::CString;
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};

/// Parsed `mkdir <path> [mode] [owner] [group] [options...]` specification from `init.rc`.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct MkdirSpec {
    pub path: String,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub source: String,
}

pub(crate) fn parse_mkdir(line: &Line, properties: &Properties) -> Option<MkdirSpec> {
    if line.words.first().map(String::as_str) != Some("mkdir") || line.words.len() < 2 {
        return None;
    }
    let Some(mut path) = expand(&line.words[1], properties) else {
        line.skip("missing Guest property in mkdir path");
        return None;
    };
    while path.len() > 1 && path.ends_with('/') {
        path.pop();
    }
    let tail = &line.words[2..];
    let opt_start = tail
        .iter()
        .position(|word| word.contains('='))
        .unwrap_or(tail.len());
    if tail[opt_start..].iter().any(|word| !word.contains('=')) {
        line.skip("invalid mkdir option order");
        return None;
    }
    let positional = &tail[..opt_start];
    if positional.len() > 3 {
        line.skip("too many mkdir arguments");
        return None;
    }
    let mode = match positional.first() {
        Some(raw) => match u32::from_str_radix(raw, 8) {
            Ok(mode) if mode <= 0o7777 => mode,
            _ => {
                line.skip("invalid mkdir mode");
                return None;
            }
        },
        None => 0o755,
    };
    let uid = match positional.get(1) {
        Some(owner) => match aid::lookup(owner) {
            Some(uid) => uid,
            None => {
                line.skip("unknown mkdir owner");
                return None;
            }
        },
        None => 0,
    };
    let gid = match positional.get(2) {
        Some(group) => match aid::lookup(group) {
            Some(gid) => gid,
            None => {
                line.skip("unknown mkdir group");
                return None;
            }
        },
        None => 0,
    };
    Some(MkdirSpec {
        path,
        mode,
        uid,
        gid,
        source: line.source.clone(),
    })
}

fn validate_guest_abs_path(guest_abs_path: &str) -> io::Result<&str> {
    if !guest_abs_path.starts_with('/') || guest_abs_path.contains('\0') {
        return Err(io::Error::other("invalid Guest directory path"));
    }
    let rel = guest_abs_path.trim_start_matches('/');
    if rel.is_empty()
        || rel.split('/').any(|part| part == "." || part == "..")
        || !Path::new(rel)
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
    {
        return Err(io::Error::other("invalid Guest directory path"));
    }
    Ok(rel)
}

/// Safely creates a directory under `root`, rejecting symlinks along every component.
pub fn ensure_directory(
    root: &Path,
    guest_abs_path: &str,
    mode: u32,
    uid: u32,
    gid: u32,
    file_contexts: Option<&FileContexts>,
) -> io::Result<PathBuf> {
    let rel = validate_guest_abs_path(guest_abs_path)?;
    let mut current = root.to_path_buf();
    let mut created = false;
    for part in Path::new(rel).components() {
        current.push(part.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(meta) if meta.is_dir() => created = false,
            Ok(_) => {
                return Err(io::Error::other(format!(
                    "not a real directory: {}",
                    current.display()
                )));
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                fs::create_dir(&current)?;
                created = true;
            }
            Err(err) => return Err(err),
        }
    }
    if created {
        if unsafe { libc::geteuid() } == 0 || uid != 0 || gid != 0 {
            let cpath = CString::new(current.as_os_str().as_bytes())
                .map_err(|_| io::Error::other("invalid directory path"))?;
            if unsafe { libc::chown(cpath.as_ptr(), uid, gid) } != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        // Apply permissions after chown so special mode bits (e.g. setgid 02750) are preserved.
        fs::set_permissions(&current, fs::Permissions::from_mode(mode))?;
    }
    if let Some(fc) = file_contexts {
        if let Some(ctx) = fc.lookup_dir(guest_abs_path) {
            crate::guest_policy::runtime::set_label(&current, ctx)?;
        }
    }
    Ok(current)
}

fn within_writable_root(path: &str) -> bool {
    path == "/data"
        || path.starts_with("/data/")
        || path == "/metadata"
        || path.starts_with("/metadata/")
}

fn matches_prefix(path: &str, prefix: &str) -> bool {
    let trimmed = prefix.trim_end_matches('/');
    path == trimmed || path.starts_with(&format!("{trimmed}/"))
}

/// Applies `mkdir` commands from `plan` matching `triggers` and `allowed_prefixes` (restricted to `/data/` and `/metadata/`).
pub fn apply_mkdirs(
    root: &Path,
    plan: &Plan,
    triggers: &[&str],
    properties: &Properties,
    allowed_prefixes: &[&str],
    label: bool,
) -> io::Result<usize> {
    if allowed_prefixes.is_empty()
        || allowed_prefixes
            .iter()
            .any(|prefix| !within_writable_root(prefix))
    {
        return Err(io::Error::other("disallowed initrc mkdir prefix"));
    }
    let file_contexts = if label {
        Some(FileContexts::load_from_guest_root(root)?)
    } else {
        None
    };
    let mut applied = 0;
    for spec in plan.mkdir_specs(triggers, properties) {
        if !within_writable_root(&spec.path)
            || !allowed_prefixes
                .iter()
                .any(|prefix| matches_prefix(&spec.path, prefix))
        {
            continue;
        }
        match ensure_directory(
            root,
            &spec.path,
            spec.mode,
            spec.uid,
            spec.gid,
            file_contexts.as_ref(),
        ) {
            Ok(_) => applied += 1,
            Err(err) => {
                eprintln!(
                    "Guest initrc mkdir skip {} {}: {err}",
                    spec.source, spec.path
                );
            }
        }
    }
    Ok(applied)
}
