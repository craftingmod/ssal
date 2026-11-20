//! Initial mount layout; service execution requires an explicit disposable probe mode.
pub(crate) mod apex;
mod devices;
mod filesystem;
pub(crate) mod loop_device;
pub(crate) mod namespace;
pub(in crate::guest) mod profile;
mod readonly;

pub(crate) fn seal_system(root: &Path) -> io::Result<()> {
    readonly::seal(root)
}

#[cfg(test)]
use devices::{GUEST_DEVICE_NODES, GUEST_DEV_ENTRIES};
use profile::{relative as profile_relative, Profile};
pub(crate) use ssal::namespace_mounts::guest_path;
#[cfg(test)]
use ssal::namespace_mounts::inject_compat_file;
use ssal::namespace_mounts::{mount, Mounts};
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

pub(super) fn cpath(path: &Path) -> io::Result<CString> {
    CString::new(path.as_os_str().as_bytes()).map_err(|_| io::Error::other("invalid mount path"))
}

pub(super) fn relative(path: &str) -> bool {
    profile_relative(path)
}

pub(crate) fn require_guest_exec_admission() -> io::Result<()> {
    Err(io::Error::other(
        "Automatic Guest launch is disabled; use the explicit disposable --guest-service-worker launcher",
    ))
}

// Reject symlinks at every directory component, including persistent userdata.
pub(crate) fn directory(root: &Path, relative_path: &str, mode: u32) -> io::Result<PathBuf> {
    if !relative(relative_path) {
        return Err(io::Error::other("invalid directory path"));
    }
    let mut path = root.to_owned();
    for part in Path::new(relative_path).components() {
        path.push(part.as_os_str());
        match fs::symlink_metadata(&path) {
            Ok(meta) if meta.is_dir() => (),
            Ok(_) => {
                return Err(io::Error::other(format!(
                    "not a real directory: {}",
                    path.display()
                )))
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                fs::create_dir(&path)?;
                fs::set_permissions(&path, fs::Permissions::from_mode(mode))?;
            }
            Err(e) => return Err(e),
        }
    }
    Ok(path)
}

fn owned_directory(root: &Path, path: &str, mode: u32, uid: u32, gid: u32) -> io::Result<()> {
    let path = directory(root, path, mode)?;
    if unsafe { libc::chown(cpath(&path)?.as_ptr(), uid, gid) } != 0 {
        return Err(io::Error::last_os_error());
    }
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}

pub(super) fn same_directory(source: &Path, target: &Path) -> io::Result<()> {
    let a = fs::metadata(source)?;
    let b = fs::metadata(target)?;
    if (a.dev(), a.ino()) != (b.dev(), b.ino()) {
        return Err(io::Error::other(format!(
            "wrong backing directory: {}",
            target.display()
        )));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn verify(
    system: &Path,
    userdata: &Path,
    profile_dir: &Path,
    base: &Path,
    loop_nodes: &crate::guest::mount::loop_device::LoopNodes,
    mode: &str,
    host_mount_namespace: &Path,
    force_regen: bool,
    admission: &mut Option<File>,
    profile: &Profile,
) -> io::Result<()> {
    let root = base.join("rootfs");
    let cache = base.join("apex-cache");
    fs::create_dir(&root)?;
    let mut mounts = Mounts::new();
    let mut cgroups = crate::guest::cgroup::GuestCgroups::default();
    let overlay_backing = userdata.join(format!(".ssal-overlay-{}", std::process::id()));
    let mut overlay_created = false;
    let hwbinder = mode == "--guest-hwbinder-worker";
    let mapped_launch = matches!(
        mode,
        "--guest-child-worker"
            | "--guest-service-worker"
            | "--guest-services-6a-worker"
            | "--guest-services-6b-worker"
            | "--guest-zygote-7a-worker"
    );
    let installd_probe =
        mode == "--guest-zygote-7a-worker" && crate::guest::launcher::installd_probe_requested();
    let surfaceflinger_retest =
        std::env::var("SSAL_Y702_SURFACEFLINGER_RETEST").as_deref() == Ok("1");
    let system_server_graphics = mode == "--guest-zygote-7a-worker"
        && crate::guest::launcher::graphics_system_server_requested();
    if surfaceflinger_retest
        && !matches!(mode, "--guest-service-worker" | "--guest-hwbinder-worker")
        && !system_server_graphics
    {
        return Err(io::Error::other(
            "Y702 SurfaceFlinger retest requires a guest service or HwBinder worker",
        ));
    }
    if surfaceflinger_retest && !crate::guest::concurrent::graphics::requested() {
        return Err(io::Error::other(
            "Y702 SurfaceFlinger retest requires SSAL_Y702_GRAPHICS=1",
        ));
    }
    let y702_graphics =
        (mode == "--shell-worker" && crate::guest::concurrent::graphics::requested())
            || surfaceflinger_retest
            || system_server_graphics;
    if y702_graphics {
        crate::guest::concurrent::graphics::require_y702()?;
    }
    let shell_applied_policy_only = mode == "--shell-worker"
        && std::env::var("SSAL_SHELL_APPLIED_POLICY_ONLY").as_deref() == Ok("1");
    let policy = if installd_probe || shell_applied_policy_only {
        Some(ssal::guest_policy::runtime::load_applied_for_probe(system, profile_dir)?)
    } else if hwbinder || mode == "--prepare-worker"
        || mode == "--shell-worker"
        || (mapped_launch && profile_dir.join("selinux/plan.json").is_file())
    {
        Some(ssal::guest_policy::runtime::prepare_mounted(
            system,
            profile_dir,
            force_regen,
        )?)
    } else {
        None
    };
    if hwbinder || matches!(
        mode,
        "--guest-processgroup-worker"
            | "--guest-memory-worker"
            | "--guest-child-worker"
            | "--guest-service-worker"
            | "--guest-services-6a-worker"
            | "--guest-services-6b-worker"
            | "--guest-zygote-7a-worker"
    ) {
        crate::guest::process::supervision::install_signal_handlers();
        crate::guest::process::supervision::enable_subreaper()?;
    }
    let result = (|| {
        if mode == "--guest-data-worker" {
            crate::diagnostics::data::fresh(userdata)?;
        }
        mounts.tmpfs(&root, 0o755)?;
        filesystem::compose_system(&mut mounts, system, &root)?;
        if installd_probe {
            let lower = fs::symlink_metadata(guest_path(&root, "system/bin/installd")?)?;
            let host = fs::metadata("/system/bin/installd")?;
            if !lower.is_file()
                || lower.dev() != fs::metadata(system)?.dev()
                || (lower.dev(), lower.ino()) == (host.dev(), host.ino())
            {
                return Err(io::Error::other("Guest installd lower backing is not the system image"));
            }
        }
        if let Some(plan) = &policy {
            fs::create_dir(&overlay_backing)?;
            overlay_created = true;
            fs::set_permissions(&overlay_backing, fs::Permissions::from_mode(0o700))?;
            ssal::guest_policy::runtime::isolate_system(
                plan,
                &mut mounts,
                &root,
                &overlay_backing,
            )?;
        }
        crate::guest::compat::patches::prepare_lock_compat(
            &mut mounts,
            &root,
            userdata,
            profile_dir,
        )?;
        for name in ["product", "system_ext"] {
            if root.join(name).symlink_metadata().is_err()
                && guest_path(&root, &format!("system/{name}")).is_ok()
            {
                symlink(format!("/system/{name}"), root.join(name))?;
            }
        }
        for path in ["data", "dev", "proc", "sys", "vendor", "odm", "vendor_dlkm"] {
            directory(&root, path, 0o755)?;
        }
        mounts.bind(userdata, &root.join("data"), false, false)?;
        mount(
            Path::new("none"),
            &root.join("data"),
            None,
            libc::MS_BIND | libc::MS_REMOUNT | libc::MS_NOSUID | libc::MS_NODEV,
            "",
        )?;
        if overlay_created {
            // restorecon /data must not relabel the metadata backing the Guest system/APEX views.
            let hidden = root.join("data").join(overlay_backing.file_name().unwrap());
            mounts.tmpfs(&hidden, 0o000)?;
            if fs::read_dir(&hidden)?.next().is_some() {
                return Err(io::Error::other(
                    "Guest overlay backing is visible through /data",
                ));
            }
        }
        devices::prepare_guest_dev(&mut mounts, &root, y702_graphics)?;
        if let Some(plan) = &policy {
            if mapped_launch || hwbinder {
                devices::prepare_guest_ashmem(&root, plan)?;
            }
            let dev = root.join("dev");
            let dev_expected = plan.context("device", false)?;
            ssal::guest_policy::runtime::set_label(&dev, &dev_expected)
                .map_err(|error| io::Error::other(format!("label Guest /dev: {error}")))?;
            let dev_actual = ssal::unix::image_context(&File::open(&dev)?)?;
            if dev_actual != dev_expected {
                return Err(io::Error::other(format!(
                    "Guest /dev label mismatch: expected {dev_expected}, got {dev_actual}"
                )));
            }
            println!("Guest /dev label verified as {dev_actual}");
            let socket = root.join("dev/socket");
            let expected = plan.context("socket_device", false)?;
            ssal::guest_policy::runtime::set_label(&socket, &expected)
                .map_err(|error| io::Error::other(format!("label Guest /dev/socket: {error}")))?;
            let actual = ssal::unix::image_context(&File::open(&socket)?)?;
            if actual != expected {
                return Err(io::Error::other(format!(
                    "Guest /dev/socket label mismatch: expected {expected}, got {actual}"
                )));
            }
            println!("Guest /dev/socket label verified as {actual}");
        }
        for path in &profile.tmpfs {
            directory(&root, path, 0o755)?;
            mounts.tmpfs(&root.join(path), 0o755)?;
        }
        for entry in &profile.runtime_tmpfs {
            let mode = u32::from_str_radix(&entry.mode, 8).map_err(io::Error::other)?;
            let target = directory(&root, &entry.path, mode)?;
            mounts.tmpfs(&target, mode)?;
            owned_directory(&root, &entry.path, mode, entry.uid, entry.gid)?;
            if entry.path == "metadata" {
                let aconfig = directory(&root, "metadata/aconfig", 0o775)?;
                mounts.tmpfs(&aconfig, 0o775)?;
                owned_directory(&root, "metadata/aconfig", 0o775, 0, 1000)?;
            }
            if entry.readonly {
                mount(
                    Path::new("tmpfs"),
                    &target,
                    None,
                    libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV,
                    "",
                )?;
            }
        }
        mounts.attach(
            Path::new("proc"),
            &root.join("proc"),
            Some("proc"),
            libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
            "",
        )?;
        mounts.attach(
            Path::new("sysfs"),
            &root.join("sys"),
            Some("sysfs"),
            libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
            "",
        )?;
        if hwbinder || matches!(
            mode,
            "--guest-cgroup-worker"
                | "--guest-child-worker"
                | "--guest-processgroup-worker"
                | "--guest-memory-worker"
                | "--guest-service-worker"
                | "--guest-services-6a-worker"
                | "--guest-services-6b-worker"
                | "--guest-zygote-7a-worker"
        ) {
            if hwbinder || matches!(
                mode,
                "--guest-processgroup-worker"
                    | "--guest-cgroup-worker"
                    | "--guest-memory-worker"
                    | "--guest-child-worker"
                    | "--guest-service-worker"
                    | "--guest-services-6a-worker"
                    | "--guest-services-6b-worker"
                    | "--guest-zygote-7a-worker"
            ) {
                for key in ["SSAL_MEMORY_HIGH", "SSAL_MEMORY_MAX"] {
                    crate::guest::cgroup::memory_limit(std::env::var(key).ok().as_deref())?;
                }
                cgroups.memory = Some(crate::guest::cgroup::GuestMemory::prepare()?);
            }
            cgroups.prepare(&mut mounts, &root)?;
        }
        if mode == "--guest-cgroup-worker" {
            return crate::guest::cgroup::guest_cgroup_probe(&root);
        }
        if mode == "--guest-processgroup-worker" {
            return crate::guest::cgroup::processgroup_probe(&mut mounts, &mut cgroups, &root);
        }
        for path in profile.host_readonly.iter().filter(|_| !hwbinder) {
            let source = Path::new("/").join(path);
            if source.is_dir() {
                mounts.bind(&source, &root.join(path), true, false)?;
            } else {
                println!("optional host mount absent: /{path}");
            }
        }
        for entry in &profile.host_runtime {
            let source = Path::new("/").join(&entry.path);
            if source.is_dir() {
                let target = guest_path(&root, &entry.path)?;
                mounts.bind(&source, &target, entry.readonly, false)?;
            }
        }
        if policy.is_some() {
            // Context validation is a kernel query; policy controls remain read-only.
            mounts.bind(
                Path::new("/sys/fs/selinux/context"),
                &guest_path(&root, "sys/fs/selinux/context")?,
                false,
                false,
            )?;
        }
        for (path, mode, uid, gid) in [
            ("mnt/user", 0o755, 0, 0),
            ("mnt/user/0", 0o755, 0, 0),
            ("mnt/user/0/self", 0o755, 0, 0),
            ("mnt/installer", 0o755, 0, 0),
            ("mnt/androidwritable", 0o755, 0, 0),
            ("mnt/pass_through", 0o700, 0, 0),
            ("mnt/pass_through/0", 0o710, 0, 1023),
            ("mnt/pass_through/0/self", 0o710, 0, 1023),
            ("mnt/pass_through/0/emulated", 0o710, 0, 1023),
            ("mnt/pass_through/0/emulated/0", 0o710, 0, 1023),
            ("mnt/appfuse", 0o711, 0, 0),
            ("mnt/media_rw", 0o750, 0, 1023),
            ("mnt/expand", 0o771, 1000, 1000),
            ("mnt/secure", 0o700, 0, 0),
            ("mnt/secure/asec", 0o700, 0, 0),
            ("mnt/asec", 0o755, 0, 1000),
            ("mnt/obb", 0o755, 0, 1000),
            ("mnt/runtime", 0o700, 0, 0),
        ] {
            owned_directory(&root, path, mode, uid, gid)?;
        }
        for view in ["default", "read", "write", "full"] {
            directory(&root, &format!("mnt/runtime/{view}/self"), 0o755)?;
            symlink(
                "/mnt/user/0/primary",
                root.join(format!("mnt/runtime/{view}/self/primary")),
            )?;
        }
        owned_directory(&root.join("data"), "media", 0o770, 1023, 1023)?;
        owned_directory(&root.join("data"), "media/0", 0o770, 1023, 1023)?;
        for (path, mode, uid, gid) in [
            ("misc", 0o1771, 1000, 9998),
            ("misc/apexdata", 0o711, 0, 0),
            ("misc/apexdata/com.android.tethering", 0o771, 1000, 1000),
            ("misc/apexdata/com.android.tethering/netstats", 0o771, 1000, 1000),
            ("misc/critical-events", 0o771, 1000, 1000),
            ("misc_ce", 0o1771, 1000, 9998),
            ("misc_de", 0o1771, 1000, 9998),
            ("system", 0o775, 1000, 1000),
            ("system/dropbox", 0o700, 1000, 1000),
            ("system/users", 0o775, 1000, 1000),
            ("system/users/0", 0o775, 1000, 1000),
            ("system_ce", 0o770, 1000, 1000),
            ("system_ce/0", 0o770, 1000, 1000),
            ("system_de", 0o770, 1000, 1000),
            ("system_de/0", 0o770, 1000, 1000),
        ] {
            owned_directory(&root.join("data"), path, mode, uid, gid)?;
        }
        let media = root.join("data/media");
        for (source, target) in [
            ("user/0", "data/data"),
            ("user_de/0", "data_mirror/data_de/null/0"),
            ("user/0", "data_mirror/data_ce/null/0"),
            ("misc/profiles/cur", "data_mirror/cur_profiles"),
            ("misc/profiles/ref", "data_mirror/ref_profiles"),
        ] {
            let source = directory(&root.join("data"), source, 0o711)?;
            let target = directory(&root, target, 0o711)?;
            mounts.bind(&source, &target, false, false)?;
        }
        for target in &profile.media_views {
            let target = directory(&root, target, 0o755)?;
            mounts.bind(&media, &target, false, false)?;
            same_directory(&media, &target)?;
        }
        symlink("../emulated/0", root.join("mnt/user/0/self/primary"))?;
        symlink("emulated/0", root.join("mnt/user/0/primary"))?;
        symlink("/mnt/user/0/self", root.join("storage/self"))?;
        same_directory(
            &media.join("0"),
            &guest_path(&root, "storage/self/primary")?,
        )?;
        symlink("/storage/self/primary", root.join("mnt/sdcard"))?;
        if root.join("sdcard").symlink_metadata().is_err() {
            symlink("/storage/self/primary", root.join("sdcard"))?;
        }
        let patch_dir = profile_dir.join("patches");
        if let Some(plan) = &policy {
            ssal::guest_policy::runtime::install(plan, &mut mounts, &root)?;
        }
        crate::guest::compat::patches::apply(
            &mut mounts,
            &profile.patches,
            &patch_dir,
            &root,
            false,
        )?;
        crate::guest::compat::patches::code_bridges(&mut mounts, &root, &patch_dir)?;
        println!("guest stage: APEX preparation");
        apex::prepare(&mut mounts, &root, &cache, loop_nodes, policy.as_ref())?;
        println!("guest stage: APEX patches");
        crate::guest::compat::patches::apply(
            &mut mounts,
            &profile.patches,
            &patch_dir,
            &root,
            true,
        )?;
        crate::guest::compat::patches::permission_controller(&mut mounts, &patch_dir, &root)?;
        if let Some(plan) = &policy {
            let shell = guest_path(&root, "system/bin/sh")?;
            let shell_label = ssal::unix::image_context(&File::open(&shell)?)?;
            let expected = plan.context("system_data_file", false)?;
            let probe = root.join(format!(
                "data/.ssal-restorecon-probe-{}",
                std::process::id()
            ));
            let file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&probe)?;
            let result = (|| {
                let before = ssal::unix::image_context(&file)?;
                if before == expected {
                    return Err(io::Error::other(
                        "restorecon probe already has target label",
                    ));
                }
                let status = crate::guest::process::command::root_command(
                    &root,
                    "/system/bin/restorecon",
                    false,
                )?
                .env("LD_PRELOAD", "/run/ssal/ssal-context-map.so")
                .args(["-RF", "/data"])
                .status()
                .map_err(|e| io::Error::other(format!("execute Guest restorecon: {e}")))?;
                if !status.success() {
                    return Err(io::Error::other(
                        "restorecon Guest userdata using mapped file_contexts failed",
                    ));
                }
                let actual = ssal::unix::image_context(&file)?;
                if actual != expected {
                    return Err(io::Error::other(format!(
                        "Guest restorecon did not relabel userdata probe: expected {expected}, got {actual}"
                    )));
                }
                println!("Guest restorecon: actual userdata probe label changed from {before} to {actual}");
                Ok(())
            })();
            let cleanup = fs::remove_file(&probe);
            result?;
            cleanup?;
            if ssal::unix::image_context(&File::open(&shell)?)? != shell_label {
                return Err(io::Error::other(
                    "Guest restorecon changed the system overlay label",
                ));
            }
        }
        seal_system(&root)?;
        if y702_graphics {
            let plan = policy
                .as_ref()
                .ok_or_else(|| io::Error::other("Y702 graphics requires a Guest SELinux plan"))?;
            crate::guest::concurrent::graphics::apply_vendor_access(
                plan,
                shell_applied_policy_only,
            )?;
            if (hwbinder && surfaceflinger_retest) || system_server_graphics {
                crate::guest::concurrent::graphics::apply_hwbinder_vintf_access(plan)?;
                crate::guest::concurrent::graphics::apply_surfaceflinger_graphics_access(plan)?;
                crate::guest::concurrent::graphics::apply_virtual_composer_access(plan)?;
                crate::guest::concurrent::graphics::apply_graphics_allocator_access(plan)?;
            }
        }
        if hwbinder {
            return crate::guest::hwbinder::verify(&mut mounts, &root, host_mount_namespace);
        }
        if mode == "--shell-worker" {
            return crate::guest::shell::standalone(
                &mut mounts,
                &root,
                profile_dir,
                host_mount_namespace,
                admission,
            );
        }
        if mode == "--guest-memory-worker" {
            let helper = std::env::var_os("SSAL_PHASE7D_FIX_HELPER");
            if let Some(path) = &helper {
                cgroups.create(&crate::guest::cgroup::task_cgroup_path()?.join("phase7d_fix"))?;
                let target = directory(&root, "run/ssal", 0o755)?.join("phase7d-fix-probe");
                File::create(&target)?;
                mounts.bind(Path::new(path), &target, true, false)?;
            }
            return crate::guest::launcher::memory_probe(&root, helper.is_some());
        }
        if matches!(
            mode,
            "--guest-child-worker"
                | "--guest-service-worker"
                | "--guest-services-6a-worker"
                | "--guest-services-6b-worker"
                | "--guest-zygote-7a-worker"
        ) {
            return crate::guest::launcher::verify(
                &mut mounts,
                &root,
                userdata,
                mode == "--guest-services-6a-worker" || mode == "--guest-services-6b-worker",
                mode == "--guest-services-6b-worker",
                mode == "--guest-zygote-7a-worker",
                host_mount_namespace,
                profile_dir,
                admission,
            );
        }
        {
            println!("guest stage: linkerconfig generation");
            crate::guest::runtime::linkerconfig::linkerconfig(&root)?;
            let probe = crate::diagnostics::guest::verify(&root, userdata)?;
            crate::service_contract::report(&root, &probe)?;
            if mode == "--binder-probe-worker" {
                crate::binder_probe::verify(&root)?;
            }
            if mode == "--selinux-probe-worker" {
                crate::diagnostics::selinux::verify(&root)?;
            }
            if mode == "--servicemanager-preflight-worker" {
                crate::diagnostics::selinux::preflight::verify(&root)?;
            }
            if mode == "--servicemanager-runtime-preflight-worker" {
                crate::diagnostics::selinux::runtime_preflight::verify(&root)?;
            }
            if mode == "--enforcing-binder-worker" {
                crate::diagnostics::selinux::enforcing::verify(&root)?;
            }
            if mode == "--servicemanager-worker" {
                crate::diagnostics::selinux::servicemanager::verify(&root)?;
            }
            if mode == "--guest-data-worker" {
                crate::diagnostics::selinux::servicemanager::verify_phase2(&root, userdata)?;
            }
        }
        same_directory(userdata, &root.join("data"))?;
        println!("mount profile: {}\nrootfs: {}\nmedia views: verified against guest /data/media\nGuest /dev: isolated tmpfs; only checked pseudo-devices and opt-in Guest cgroup subtrees; Host Binder, property, Binder-control, HAL, cgroup roots and BPF paths absent\nGuest execution: {}\nAPEX activation, full Guest property service, Android services, FUSE permissions, SELinux compatibility: NOT validated", profile.name, root.display(), if mode == "--guest-child-worker" { "limited diagnostic child completed; Android services remain blocked" } else { "blocked pending Host proc/root, exec-FD and signal/ptrace boundary evidence" });
        let info = fs::read_to_string("/proc/self/mountinfo")?;
        for path in &mounts.paths {
            let line = info
                .lines()
                .find(|line| line.split_whitespace().nth(4) == path.to_str())
                .ok_or_else(|| {
                    io::Error::other(format!("mountinfo entry missing: {}", path.display()))
                })?;
            println!("guest mountinfo: {line}");
        }
        Ok(())
    })();
    let result = result.and_then(|()| crate::guest::process::supervision::check_interrupted());
    let descendants = if cgroups.memory.is_some() {
        crate::guest::process::supervision::cleanup_descendants(true)
    } else {
        Ok(())
    };
    let descendants = descendants.and_then(|()| {
        if mode == "--guest-zygote-7a-worker"
            && (std::env::var_os("SSAL_PHASE7FB_FORK").is_some()
                || std::env::var_os("SSAL_START_SYSTEM_SERVER").is_some())
        {
            for path in &cgroups.created {
                crate::guest::cgroup::remove_empty_cgroup_children(path)?;
            }
        }
        Ok(())
    });
    if descendants.is_err() {
        cgroups.preserve = true;
    }
    let cleanup = mounts.cleanup();
    let cgroup_cleanup = cgroups.cleanup();
    println!(
        "Guest cgroup cleanup: {}",
        if cgroup_cleanup.is_ok() {
            "passed"
        } else {
            "failed"
        }
    );
    let residual = fs::read_to_string("/proc/self/mountinfo").and_then(|info| {
        if info
            .lines()
            .filter_map(|line| line.split_whitespace().nth(4))
            .any(|path| Path::new(path).starts_with(&root))
        {
            Err(io::Error::other("guest rootfs mounts remain after cleanup"))
        } else {
            println!("worker rootfs residual mount check: verified absent");
            Ok(())
        }
    });
    let overlay_cleanup = if overlay_created && cleanup.is_ok() && residual.is_ok() {
        fs::remove_dir_all(&overlay_backing)
    } else {
        Ok(())
    };
    let cleanup = [
        descendants,
        cleanup,
        cgroup_cleanup,
        residual,
        overlay_cleanup,
    ]
    .into_iter()
    .filter_map(Result::err)
    .map(|error| error.to_string())
    .collect::<Vec<_>>();
    let cleanup = if cleanup.is_empty() {
        Ok(())
    } else {
        Err(io::Error::other(cleanup.join("; ")))
    };
    if mode == "--servicemanager-worker" || mode == "--guest-data-worker" {
        if let Err(error) = &cleanup {
            crate::diagnostics::selinux::servicemanager::mark_recovery(
                &root.display().to_string(),
                &error.to_string(),
            );
        }
    }
    if mode == "--selinux-probe-worker"
        || mode == "--servicemanager-preflight-worker"
        || mode == "--servicemanager-runtime-preflight-worker"
        || mode == "--enforcing-binder-worker"
        || mode == "--servicemanager-worker"
        || mode == "--guest-data-worker"
    {
        println!(
            "SELinux transition resource summary: {}",
            serde_json::json!({
                "cleanup": if cleanup.is_ok() { "passed" } else { "failed" },
                "scope": "guest_rootfs_mounts", "error": cleanup.as_ref().err().map(ToString::to_string)
            })
        );
    }
    match (result, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(e), Ok(())) | (Ok(()), Err(e)) => Err(e),
        (Err(e), Err(cleanup)) => Err(io::Error::other(format!("{e}; {cleanup}"))),
    }
}

#[cfg(test)]
mod tests {
    use crate::guest::concurrent::mount_profile::profile;
    use super::*;

    #[test]
    fn compat_collisions_abort_before_mount_and_preserve_originals() -> io::Result<()> {
        let root =
            std::env::temp_dir().join(format!("ssal-compat-collision-{}", std::process::id()));
        fs::create_dir(&root)?;
        let result = (|| -> io::Result<()> {
            let parent = directory(&root, "system/etc/sysconfig", 0o755)?;
            let target = parent.join("ssal-lockscreen.xml");
            let config = ssal::guest_lock_compat::Config {
                enabled: true,
                disable_weaver_on_unsecured_users: false,
                ..Default::default()
            };
            let plan = config.plan(true, true)?;
            let before = fs::read_to_string("/proc/self/mountinfo")?;
            let mut mounts = Mounts::new();
            for _ in 0..2 {
                fs::write(&target, b"original")?;
                let error =
                    inject_compat_file(&mut mounts, &root, &plan[0], b"replacement").unwrap_err();
                assert_eq!(error.to_string(), "compatibility target collision");
                assert_eq!(fs::read(&target)?, b"original");
                fs::remove_file(&target)?;
                symlink("missing", &target)?;
                let error =
                    inject_compat_file(&mut mounts, &root, &plan[0], b"replacement").unwrap_err();
                assert_eq!(error.to_string(), "compatibility target collision");
                fs::remove_file(&target)?;
            }
            assert!(mounts.paths.is_empty());
            mounts.cleanup()?;
            assert_eq!(before, fs::read_to_string("/proc/self/mountinfo")?);
            Ok(())
        })();
        fs::remove_dir_all(root)?;
        result
    }

    #[test]
    fn finds_runtime_linkerconfig_and_legacy_system_fallback() -> io::Result<()> {
        let root = std::env::temp_dir().join(format!("ssal-linkerconfig-{}", std::process::id()));
        fs::create_dir_all(root.join("system/bin"))?;
        fs::create_dir_all(root.join("apex/com.android.runtime/bin"))?;
        assert_eq!(
            crate::guest::runtime::linkerconfig::linkerconfig_binary(&root)
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotFound
        );
        let legacy = root.join("system/bin/linkerconfig");
        fs::write(&legacy, b"fixture")?;
        fs::set_permissions(&legacy, fs::Permissions::from_mode(0o755))?;
        assert_eq!(
            crate::guest::runtime::linkerconfig::linkerconfig_binary(&root)?,
            "/system/bin/linkerconfig"
        );
        let runtime = root.join("apex/com.android.runtime/bin/linkerconfig");
        fs::write(&runtime, b"fixture")?;
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o755))?;
        assert_eq!(
            crate::guest::runtime::linkerconfig::linkerconfig_binary(&root)?,
            "/apex/com.android.runtime/bin/linkerconfig"
        );
        fs::remove_file(&legacy)?;
        symlink("/apex/com.android.runtime/bin/linkerconfig", &legacy)?;
        assert_eq!(
            crate::guest::runtime::linkerconfig::linkerconfig_binary(&root)?,
            "/apex/com.android.runtime/bin/linkerconfig"
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn ashmem_path_uses_only_kernel_boot_id() {
        assert_eq!(
            devices::ashmem_device_name("187ab5ca-c953-4032-b5fb-38875175d198\n").unwrap(),
            "ashmem187ab5ca-c953-4032-b5fb-38875175d198"
        );
        for invalid in [
            "",
            "../ashmem",
            "187ab5ca/c953-4032-b5fb-38875175d198",
            "z87ab5ca-c953-4032-b5fb-38875175d198",
        ] {
            assert!(devices::ashmem_device_name(invalid).is_err());
        }
    }

    #[test]
    fn profile_preserves_data_boundary() -> io::Result<()> {
        let p = profile()?;
        assert_eq!(p.media_views.len(), 4);
        assert_eq!(p.core["dev"], "guest-tmpfs-minimal");
        assert_eq!(
            GUEST_DEVICE_NODES,
            [
                ("null", 1, 3),
                ("zero", 1, 5),
                ("random", 1, 8),
                ("urandom", 1, 9)
            ]
        );
        assert!(p.tmpfs.iter().all(|path| !path.starts_with("dev/")));
        assert!(p
            .host_runtime
            .iter()
            .all(|entry| !matches!(entry.path.as_str(), "sys/fs/cgroup" | "sys/fs/bpf")));
        assert!(p.tmpfs.iter().any(|s| s == "mnt"));
        assert!(GUEST_DEV_ENTRIES.contains(&"socket"));
        assert!(GUEST_DEV_ENTRIES.contains(&"binderfs"));
        assert!(p
            .runtime_tmpfs
            .iter()
            .any(|entry| entry.path == "tmp" && entry.mode == "1777" && !entry.readonly));
        assert!(p
            .runtime_tmpfs
            .iter()
            .any(|entry| entry.path == "cache" && !entry.readonly));
        assert!(p
            .runtime_tmpfs
            .iter()
            .filter(|entry| matches!(entry.path.as_str(), "metadata" | "config"))
            .all(|entry| entry.readonly));
        assert!(p
            .host_readonly
            .iter()
            .all(|s| matches!(s.as_str(), "vendor" | "odm" | "vendor_dlkm")));
        assert!(!relative("../data"));
        assert!(!relative("/data"));
        Ok(())
    }

    #[test]
    fn automatic_launch_requires_explicit_disposable_worker() {
        let error = require_guest_exec_admission().unwrap_err();
        assert!(error.to_string().contains("--guest-service-worker"));
    }

    #[test]
    fn refuses_userdata_symlink_escape() -> io::Result<()> {
        let root = std::env::temp_dir().join(format!("ssal-mount-paths-{}", std::process::id()));
        fs::create_dir(&root)?;
        symlink("/tmp", root.join("media"))?;
        assert!(directory(&root, "media/0", 0o770).is_err());
        fs::remove_file(root.join("media"))?;
        fs::remove_dir(root)?;
        Ok(())
    }

    #[test]
    fn android_absolute_symlinks_stay_inside_guest() -> io::Result<()> {
        let root = std::env::temp_dir().join(format!("ssal-guest-links-{}", std::process::id()));
        fs::create_dir_all(root.join("system/product/apex"))?;
        fs::create_dir_all(root.join("mnt/user/0/emulated/0"))?;
        fs::create_dir_all(root.join("mnt/user/0/self"))?;
        fs::create_dir(root.join("storage"))?;
        symlink("/system/product", root.join("product"))?;
        symlink("/mnt/user/0/self", root.join("storage/self"))?;
        symlink("../emulated/0", root.join("mnt/user/0/self/primary"))?;
        assert_eq!(
            guest_path(&root, "product/apex")?,
            root.join("system/product/apex")
        );
        assert_eq!(
            guest_path(&root, "storage/self/primary")?,
            root.join("mnt/user/0/emulated/0")
        );
        symlink("/tmp", root.join("escape"))?;
        assert!(guest_path(&root, "escape").is_err());
        symlink("loop", root.join("loop"))?;
        assert!(guest_path(&root, "loop").is_err());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    #[ignore = "requires Linux CAP_SYS_ADMIN; run in a disposable privileged container"]
    fn real_mounts_preserve_host_and_cleanup_recursively() -> io::Result<()> {
        namespace::enter()?;
        let base = std::env::temp_dir().join(format!("ssal-real-mounts-{}", std::process::id()));
        let root = base.join("rootfs");
        let data = base.join("userdata");
        fs::create_dir_all(&root)?;
        fs::create_dir(&data)?;
        fs::create_dir(data.join("media"))?;
        fs::create_dir(data.join("media/0"))?;
        fs::write(data.join("media/0/guest-marker"), b"guest")?;
        let host_dev = fs::metadata("/dev")?;
        let mut mounts = Mounts::new();
        let result: io::Result<()> = (|| {
            mounts.tmpfs(&root, 0o755)?;
            directory(&root, "dev", 0o755)?;
            mounts.bind(Path::new("/dev"), &root.join("dev"), false, true)?;
            directory(&root, "data", 0o755)?;
            mounts.bind(&data, &root.join("data"), false, false)?;
            directory(&root, "mnt", 0o755)?;
            mounts.tmpfs(&root.join("mnt"), 0o755)?;
            directory(&root, "storage", 0o755)?;
            mounts.tmpfs(&root.join("storage"), 0o755)?;
            for view in &profile()?.media_views {
                let target = directory(&root, view, 0o755)?;
                mounts.bind(&root.join("data/media"), &target, false, false)?;
                same_directory(&data.join("media"), &target)?;
                assert_eq!(fs::read(target.join("0/guest-marker"))?, b"guest");
                assert!(!target.join("0/0").exists());
            }
            fs::write(root.join("mnt/user/0/emulated/0/new"), b"new")?;
            assert_eq!(fs::read(data.join("media/0/new"))?, b"new");
            let readonly = root.join("readonly");
            fs::create_dir(&readonly)?;
            mounts.bind(&data, &readonly, true, false)?;
            assert!(fs::write(readonly.join("blocked"), b"blocked").is_err());
            fs::write(data.join("source-still-writable"), b"ok")?;
            assert!(mounts
                .attach(
                    Path::new("/no-such-ssal-source"),
                    &readonly,
                    None,
                    libc::MS_BIND,
                    ""
                )
                .is_err());
            Ok(())
        })();
        let cleanup = mounts.cleanup();
        result?;
        cleanup?;
        assert_eq!(host_dev.ino(), fs::metadata("/dev")?.ino());
        assert!(!fs::read_to_string("/proc/self/mountinfo")?
            .lines()
            .any(|line| line
                .split_whitespace()
                .nth(4)
                .is_some_and(|p| Path::new(p).starts_with(&base))));
        fs::remove_dir_all(base)?;
        Ok(())
    }
}
