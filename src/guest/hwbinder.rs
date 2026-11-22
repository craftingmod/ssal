//! Standalone Guest HwBinder validation without starting Android init or Host HALs.
use crate::diagnostics::selinux::{access_allowed, require_guest_domain_mode};
use crate::guest::{binder, environment, init::Service, launcher, mount, runtime};
use ssal::namespace_mounts::Mounts;
use std::fs::{self, File};
use std::io::{self, BufRead};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::Stdio;
use std::time::{Duration, Instant};

pub(super) const MANAGER: &str = "/system_ext/bin/hwservicemanager";
pub(super) const ALLOCATOR: &str = "/system_ext/bin/hw/android.hidl.allocator@1.0-service";
pub(super) const GRAPHICS_ALLOCATOR: &str =
    "/vendor/bin/hw/vendor.qti.hardware.display.allocator-service";
pub(super) const COMPOSER: &str = "/run/ssal/ssal-virtual-composer";
const SHELL_PROBE: &str = "ssal-hwbinder-probe.sh";
const NATIVE_PROBE: &str = "ssal-hwbinder-probe";
const LOG_PRELOAD: &str = "ssal-phase2-log.so";
const ALLOCATOR_SERVICE: &str = "android.hidl.allocator@1.0::IAllocator/ashmem";

fn verify_process_identity(
    name: &str,
    service: &Service,
    expected_sid: &str,
    host_namespace: &Path,
    rdev: u64,
) -> io::Result<()> {
    let pid = service.pid();
    let process = Path::new("/proc").join(pid.to_string());
    if service.exited()?
        || fs::read_to_string(process.join("attr/current"))?
            .trim_matches(['\0', '\n'])
            != expected_sid
        || fs::read_link(process.join("ns/mnt"))? == host_namespace
    {
        return Err(io::Error::other(format!(
            "Guest {name} process identity mismatch"
        )));
    }
    let uses_private_device = fs::read_dir(process.join("fd"))?.any(|entry| {
        entry
            .ok()
            .and_then(|entry| fs::metadata(entry.path()).ok())
            .is_some_and(|meta| meta.file_type().is_char_device() && meta.rdev() == rdev)
    });
    if !uses_private_device {
        return Err(io::Error::other(format!(
            "Guest {name} must hold its private HwBinder FD"
        )));
    }
    Ok(())
}

pub(super) fn wait_manager(
    root: &Path,
    manager: &mut Service,
    plan: &ssal::guest_policy::Plan,
    host_namespace: &Path,
    rdev: u64,
) -> io::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        crate::guest::process::supervision::check_interrupted()?;
        manager.drain_output()?;
        if manager.exited()? {
            return Err(io::Error::other(
                "Guest hwservicemanager exited before readiness",
            ));
        }
        let ready = launcher::run(
            root,
            "/system/bin/sh",
            &["-c", "getprop hwservicemanager.ready"],
            2000,
        )?;
        if ready.trim() == "true" {
            let sid = plan.context("hwservicemanager", true)?;
            verify_process_identity("hwservicemanager", manager, &sid, host_namespace, rdev)?;
            println!(
                "GUEST_HWSERVICEMANAGER_READY=PASS pid={} sid={sid} device={}:{}",
                manager.pid(),
                libc::major(rdev),
                libc::minor(rdev)
            );
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(io::Error::other("Guest hwservicemanager readiness timed out"));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn register_presenter_pair() -> Option<OwnedFd> {
    let mut fds = [-1 as libc::c_int; 2];
    if unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    } != 0
    {
        eprintln!(
            "GUEST_VIRTUAL_COMPOSER_PRESENTER=WARN socketpair_err={}",
            io::Error::last_os_error()
        );
        return None;
    }
    let composer_fd = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    let daemon_fd = unsafe { OwnedFd::from_raw_fd(fds[1]) };

    let mut stream = match UnixStream::connect(format!("{}/run/ssald.sock", ssal::unix::ROOT)) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("GUEST_VIRTUAL_COMPOSER_PRESENTER=WARN ssald_connect_err={e}");
            return None;
        }
    };
    let req = ssal::unix::Request {
        version: ssal::unix::VERSION,
        command: "register-presenter".into(),
        image_name: None,
        profile_name: None,
        force_regen: false,
        native_sepolicy: false,
        permissive: false,
        audit: false,
    };
    if let Err(e) = ssal::unix::send(&mut stream, &req, Some(daemon_fd.as_raw_fd())) {
        eprintln!("GUEST_VIRTUAL_COMPOSER_PRESENTER=WARN ssald_send_err={e}");
        return None;
    }
    let mut line = String::new();
    if let Err(e) = io::BufReader::new(stream).read_line(&mut line) {
        eprintln!("GUEST_VIRTUAL_COMPOSER_PRESENTER=WARN ssald_read_err={e}");
        return None;
    }
    match serde_json::from_str::<ssal::unix::Response>(&line) {
        Ok(resp) if resp.ok => {
            println!("GUEST_VIRTUAL_COMPOSER_PRESENTER=PASS {}", resp.message);
            Some(composer_fd)
        }
        Ok(resp) => {
            eprintln!("GUEST_VIRTUAL_COMPOSER_PRESENTER=WARN {}", resp.message);
            None
        }
        Err(e) => {
            eprintln!("GUEST_VIRTUAL_COMPOSER_PRESENTER=WARN invalid_resp={e}");
            None
        }
    }
}

pub(super) fn start_composer(
    root: &Path,
    plan: &ssal::guest_policy::Plan,
    binder: u64,
    hwbinder: u64,
) -> io::Result<Service> {
    let sid = plan.context("hal_graphics_composer_default", true)?;
    let (input, env): (Stdio, &[(&str, &str)]) = match register_presenter_pair() {
        Some(composer_fd) => (Stdio::from(composer_fd), &[("SSAL_PRESENTER_FD", "0")]),
        None => (Stdio::null(), &[]),
    };
    let mut service = Service::start_with_input(
        root,
        COMPOSER,
        &["serve", &binder.to_string(), &hwbinder.to_string(), &sid],
        "virtual-composer",
        1000,
        None,
        env,
        input,
    )?;
    service.wait_text(
        "guest_binder_registered=android.hardware.graphics.composer3.IComposer/default",
    )?;
    println!("GUEST_VIRTUAL_COMPOSER_READY=PASS pid={} sid={sid}", service.pid());
    Ok(service)
}

fn wait_hidl_service_ready(
    service: &mut Service,
    probe: &impl Fn(&str) -> io::Result<String>,
) -> io::Result<String> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        service.drain_output()?;
        if service.exited()? {
            let log = fs::read_to_string(&service.log).unwrap_or_default();
            return Err(io::Error::other(format!(
                "Guest HIDL test server exited before service registration: {log}"
            )));
        }
        match probe("live") {
            Ok(output) => return Ok(output),
            Err(error) if Instant::now() < deadline => {
                let _ = error;
                std::thread::sleep(Duration::from_millis(200));
            }
            Err(error) => return Err(error),
        }
    }
}

fn verify_allocator_cycle(
    root: &Path,
    service_name: &str,
    allocator_sid: &str,
    host_namespace: &Path,
    rdev: u64,
    device: &str,
    native_probe: &impl Fn(&str) -> io::Result<String>,
    shell_probe: Option<&dyn Fn(&str) -> io::Result<String>>,
    label: &str,
) -> io::Result<()> {
    let mut allocator = Service::start(root, ALLOCATOR, &[], service_name, 1000, None, &[])?;
    let allocator_pid = allocator.pid();
    let result: io::Result<()> = (|| {
        wait_hidl_service_ready(&mut allocator, native_probe)?;
        verify_process_identity(
            "hal_allocator_default",
            &allocator,
            allocator_sid,
            host_namespace,
            rdev,
        )?;
        println!(
            "{label}=PASS service={ALLOCATOR_SERVICE} pid={allocator_pid} sid={allocator_sid} device={device}"
        );
        if let Some(shell) = shell_probe {
            shell("allocator")?;
        }
        Ok(())
    })();
    let stopped = allocator.stop();
    result?;
    stopped
}

pub(super) fn verify(mounts: &mut Mounts, root: &Path, host_namespace: &Path) -> io::Result<()> {
    let surfaceflinger_retest =
        std::env::var("SSAL_Y702_SURFACEFLINGER_RETEST").as_deref() == Ok("1");
    if unsafe { libc::unshare(libc::CLONE_NEWNET) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let plan = ssal::guest_policy::runtime::load(root)?
        .ok_or_else(|| io::Error::other("Guest HwBinder SELinux plan missing"))?;
    for domain in ["hwservicemanager", "hal_allocator_default", "shell"] {
        let sid = plan.context(domain, true)?;
        require_guest_domain_mode(&plan, &sid)?;
        if !plan.is_permissive_domain(&sid)
            && Path::new("/dev/hwbinder").exists()
            && access_allowed(&sid, "u:object_r:hwbinder_device:s0", "chr_file", "open")?
        {
            return Err(io::Error::other(format!("{sid} can open Host HwBinder")));
        }
    }
    for path in ["dev/binder", "dev/hwbinder", "dev/vndbinder"] {
        if root.join(path).try_exists()? {
            return Err(io::Error::other(format!(
                "unexpected Guest endpoint /{path}"
            )));
        }
    }
    for (path, exec_type) in [
        (MANAGER, "hwservicemanager_exec"),
        (ALLOCATOR, "hal_allocator_default_exec"),
    ] {
        let executable = mount::guest_path(root, path.trim_start_matches('/'))?;
        let expected_label = plan.context(exec_type, false)?;
        if ssal::unix::image_context(&File::open(&executable)?)? != expected_label {
            return Err(io::Error::other(format!(
                "Guest {path} executable label mismatch"
            )));
        }
    }
    let sid = plan.context("hwservicemanager", true)?;
    let allocator_sid = plan.context("hal_allocator_default", true)?;
    let mut driver = binder::Session::new();
    let (major, minor) = driver.provision_hwbinder(root)?;
    let device = format!("{major}:{minor}");
    let rdev = libc::makedev(major, minor);
    let mut guest_binder = binder::Session::new();
    runtime::linkerconfig::linkerconfig(root)?;
    let executable = std::env::current_exe()?;
    let bin = executable.parent().unwrap();
    for name in [SHELL_PROBE, NATIVE_PROBE, LOG_PRELOAD] {
        let target = root.join("run/ssal").join(name);
        File::create(&target)?;
        if name == SHELL_PROBE {
            let label = plan.context("shell_data_file", false)?;
            ssal::guest_policy::runtime::set_label(&target, &label)?;
        }
        ssal::guest_policy::runtime::bind_file(mounts, root, &bin.join(name), &target)?;
    }
    let mut properties =
        environment::start_property_service(mounts, root, bin, host_namespace, false)?;
    let readiness = launcher::run(
        root,
        "/system/bin/sh",
        &["-c", "getprop hwservicemanager.ready"],
        2000,
    )?;
    if !matches!(readiness.trim(), "" | "false") {
        return Err(io::Error::other(
            "Guest hwservicemanager readiness must start unset or false",
        ));
    }
    let shell_probe = |phase: &str| {
        launcher::run(
            root,
            "/system/bin/sh",
            &["/run/ssal/ssal-hwbinder-probe.sh", &device, phase],
            2000,
        )
    };
    let native_probe = |phase: &str| {
        launcher::run(
            root,
            "/system/bin/bootstrap/linker64",
            &["/run/ssal/ssal-hwbinder-probe", &device, phase],
            2000,
        )
    };
    if surfaceflinger_retest {
        let target = root.join("run/ssal").join(SHELL_PROBE);
        let file = fs::metadata(&target)?;
        let directory = fs::metadata(target.parent().unwrap())?;
        let label = ssal::unix::image_context(&File::open(&target)?)?;
        println!(
            "GUEST_HWBINDER_PROBE_FILE mode={:o} uid={} gid={} label={label} dir_mode={:o}",
            file.mode() & 0o777,
            file.uid(),
            file.gid(),
            directory.mode() & 0o777
        );
        let readable = launcher::run(
            root,
            "/system/bin/sh",
            &[
                "-c",
                "if cat /run/ssal/ssal-hwbinder-probe.sh >/dev/null; then echo probe_read=PASS; else echo probe_read=FAIL; fi",
            ],
            2000,
        )?;
        println!("GUEST_HWBINDER_PROBE_READ={}", readable.trim());
    }
    if surfaceflinger_retest {
        crate::guest::concurrent::graphics::install_vintf(mounts, root, &plan, true, false)?;
    }
    native_probe("empty")?;
    shell_probe("empty")?;
    let mut manager = Service::start(root, MANAGER, &[], "hwservicemanager", 1000, None, &[])?;
    let pid = manager.child.id();
    let check = (|| {
        wait_manager(root, &mut manager, &plan, host_namespace, rdev)?;
        native_probe("absent")?;
        shell_probe("live")?;

        verify_allocator_cycle(
            root,
            "hal_allocator_default",
            &allocator_sid,
            host_namespace,
            rdev,
            &device,
            &native_probe,
            Some(&shell_probe),
            "GUEST_HIDL_SERVER_READY",
        )?;

        native_probe("absent")?;
        println!("GUEST_HIDL_SERVER_STOP=PASS service={ALLOCATOR_SERVICE} state=absent");

        verify_allocator_cycle(
            root,
            "hal_allocator_default_restart",
            &allocator_sid,
            host_namespace,
            rdev,
            &device,
            &native_probe,
            None,
            "GUEST_HIDL_SERVER_RESTART",
        )?;

        if surfaceflinger_retest {
            let binder_ipc = bin.join("ssal-binder-ipc");
            if binder_ipc.is_file() {
                let target = root.join("run/ssal/ssal-binder-ipc");
                File::create(&target)?;
                ssal::guest_policy::runtime::bind_file(mounts, root, &binder_ipc, &target)?;
            }
            let composer_bin = bin.join("ssal-virtual-composer");
            let composer_target = root.join("run/ssal/ssal-virtual-composer");
            if composer_bin.is_file() {
                File::create(&composer_target)?;
                let sys_file = plan.context("system_file", false)?;
                ssal::guest_policy::runtime::set_label(&composer_target, &sys_file)?;
                ssal::guest_policy::runtime::bind_file(mounts, root, &composer_bin, &composer_target)?;
            }
            for path in crate::guest::concurrent::mount_profile::profile()?.host_readonly {
                let source = Path::new("/").join(&path);
                if source.is_dir() {
                    mounts.bind(&source, &root.join(path), true, false)?;
                }
            }
            runtime::linkerconfig::linkerconfig(root)?;
            let qti_alloc_path = GRAPHICS_ALLOCATOR;
            let mut graphics_allocator = if root.join(qti_alloc_path.trim_start_matches('/')).is_file() {
                let svc = Service::start(
                    root,
                    qti_alloc_path,
                    &[],
                    "graphics-allocator",
                    1000,
                    None,
                    &[],
                )?;
                std::thread::sleep(Duration::from_millis(400));
                if svc.exited()? {
                    println!("GUEST_GRAPHICS_ALLOCATOR_EXITED_EARLY=true");
                } else {
                    println!("GUEST_GRAPHICS_ALLOCATOR_READY=PASS pid={}", svc.pid());
                }
                Some(svc)
            } else {
                None
            };
            let (binder_major, binder_minor, _) = guest_binder.provision(root)?;
            guest_binder
                .private_device()?
                .set_permissions(<fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o666))?;
            let guest_binder_rdev = libc::makedev(binder_major, binder_minor);
            let mut guest_servicemanager = Service::start(
                root,
                "/system/bin/servicemanager",
                &[],
                "servicemanager",
                1000,
                None,
                &[],
            )?;
            guest_servicemanager.wait_guest_servicemanager_property(root, "SurfaceFlinger")?;
            guest_servicemanager.wait_guest_context_manager(root, guest_binder_rdev)?;
            println!("GUEST_SERVICEMANAGER_READY=PASS device_rdev={guest_binder_rdev}");
            let mut virtual_composer = if composer_bin.is_file() {
                Some(start_composer(root, &plan, guest_binder_rdev, rdev)?)
            } else {
                None
            };
            let sf_result = launcher::retest_surfaceflinger(
                root,
                guest_binder_rdev,
                Some(rdev),
            );
            if let Some(mut svc) = virtual_composer.take() {
                let _ = svc.stop();
            }
            if let Some(mut svc) = graphics_allocator.take() {
                let _ = svc.stop();
            }
            guest_servicemanager.stop()?;
            sf_result?;
        }
        Ok(())
    })();
    let binder_unmounted = guest_binder.cleanup();
    if surfaceflinger_retest {
        let _ = fs::remove_file(root.join("dev/binder"));
    }
    let stopped = manager.stop();
    let dead = if check.is_ok() && stopped.is_ok() {
        native_probe("dead").and_then(|_| shell_probe("dead")).map(|_| ())
    } else {
        Ok(())
    };
    let properties_stopped = properties.stop();
    let unmounted = driver.cleanup();
    stopped?;
    properties_stopped?;
    binder_unmounted?;
    unmounted?;
    require_guest_domain_mode(&plan, &sid)?;
    require_guest_domain_mode(&plan, &allocator_sid)?;
    println!("GUEST_HWBINDER_CLEANUP=PASS manager_pid={pid} reaped=true mounts=absent");
    check.and(dead)
}
