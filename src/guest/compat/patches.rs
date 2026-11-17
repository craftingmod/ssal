use serde::Deserialize;
use ssal::namespace_mounts::Mounts;
use std::fs::{self, File};
use std::io;
use std::path::Path;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::guest) struct Patch {
    pub(in crate::guest) source: String,
    pub(in crate::guest) target: String,
}

pub(in crate::guest) fn prepare_lock_compat(
    mounts: &mut Mounts,
    root: &Path,
    userdata: &Path,
    profile_dir: &Path,
) -> io::Result<()> {
    let profile_path = profile_dir.join("profile.json");
    let profile: serde_json::Value = serde_json::from_slice(&fs::read(profile_path)?)?;
    let config = ssal::guest_lock_compat::Config::from_profile(&profile)?;
    // This stage is offline-only until the recorded runtime blockers are resolved.
    config.runtime_gate()?;
    let plan = config.plan(
        profile["guest_lock_compat_creation"]["version"] == 1,
        if config.enabled {
            crate::guest::userdata::fresh(userdata)?
        } else {
            false
        },
    )?;
    for entry in plan {
        // Only the built-in XML is certified as a mount input at present. RRO
        // remains a separate blocked result, never silently skipped.
        let bytes = match entry.target {
            ssal::guest_lock_compat::XML_TARGET => ssal::guest_lock_compat::XML.as_bytes(),
            _ => {
                return Err(io::Error::other(
                    "Weaver RRO idmap/immutable activation not certified",
                ))
            }
        };
        ssal::namespace_mounts::inject_compat_file(mounts, root, &entry, bytes)?;
    }
    Ok(())
}

pub(in crate::guest) fn apply(
    mounts: &mut Mounts,
    patches: &[Patch],
    source: &Path,
    root: &Path,
    apex_phase: bool,
) -> io::Result<()> {
    for patch in patches {
        if patch.target.starts_with("apex/") != apex_phase {
            continue;
        }
        let source = source.join(&patch.source);
        if source.exists() {
            let target = crate::guest::mount::guest_path(root, &patch.target)?;
            if source.is_file() != target.is_file() || source.is_dir() != target.is_dir() {
                return Err(io::Error::other(format!(
                    "patch type mismatch: {}",
                    target.display()
                )));
            }
            ssal::guest_policy::runtime::bind_file(mounts, root, &source, &target)?;
            // Keep the versioned APEX view consistent with the active alias.
            if apex_phase {
                let parts: Vec<_> = patch.target.splitn(3, '/').collect();
                for entry in fs::read_dir(root.join("apex"))? {
                    let entry = entry?;
                    if entry
                        .file_name()
                        .to_string_lossy()
                        .starts_with(&format!("{}@", parts[1]))
                    {
                        let relative =
                            format!("apex/{}/{}", entry.file_name().to_string_lossy(), parts[2]);
                        ssal::guest_policy::runtime::bind_file(
                            mounts,
                            root,
                            &source,
                            &crate::guest::mount::guest_path(root, &relative)?,
                        )?;
                    }
                }
            }
        }
    }
    Ok(())
}

pub(in crate::guest) fn permission_controller(
    mounts: &mut Mounts,
    patch_dir: &Path,
    root: &Path,
) -> io::Result<()> {
    let source = patch_dir.join("PermissionController_patched.apk");
    if !source.exists() {
        return Ok(());
    }
    let mut targets = Vec::new();
    for entry in fs::read_dir(root.join("apex"))? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name != "com.android.permission" && !name.starts_with("com.android.permission@") {
            continue;
        }
        let mut directories = vec![entry.path()];
        while let Some(path) = directories.pop() {
            for child in fs::read_dir(path)? {
                let child = child?;
                if child.file_type()?.is_dir() {
                    directories.push(child.path());
                } else if child.file_type()?.is_file()
                    && child.file_name() == "PermissionController.apk"
                {
                    targets.push(child.path());
                }
            }
        }
    }
    if targets.is_empty() {
        return Err(io::Error::other(
            "PermissionController patch supplied but no target APK found",
        ));
    }
    for target in targets {
        ssal::guest_policy::runtime::bind_file(mounts, root, &source, &target)?;
    }
    Ok(())
}

pub(in crate::guest) fn code_bridges(
    mounts: &mut Mounts,
    root: &Path,
    patch_dir: &Path,
) -> io::Result<()> {
    let code = crate::guest::mount::directory(root, "run/ssal", 0o755)?;
    let daemon = std::env::current_exe()?;
    if let Some(module_bin) = daemon.parent() {
        for name in [
            "ssal",
            "ssald",
            "ssal-enforcing-binder",
            "ssal-binder-probe",
            "ssal-binder-probe.json",
        ] {
            let source = module_bin.join(name);
            if source.is_file() {
                let target = code.join(name);
                File::create(&target)?;
                ssal::guest_policy::runtime::bind_file(mounts, root, &source, &target)?;
            }
        }
    }
    // Opt-in only: an explicit guest bridge binary, never host /data/adb.
    let su = patch_dir.join("su");
    if su.is_file() {
        let xbin = crate::guest::mount::guest_path(root, "system/xbin")?;
        if xbin != root.join("system/xbin") {
            return Err(io::Error::other(
                "su bridge requires a real /system/xbin directory",
            ));
        }
        mounts.tmpfs(&xbin, 0o755)?;
        let target = xbin.join("su");
        File::create(&target)?;
        mounts.bind(&su, &target, true, false)?;
    }
    Ok(())
}
