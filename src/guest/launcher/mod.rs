//! Disposable Guest service launcher; shared PID namespace is intentional.
mod net;
use crate::diagnostics::launcher::{
    fork_probe, system_server_preflight, system_server_runtime_sid,
};
use crate::guest::concurrent::{gatekeeper, graphics, health, keymint, system_suspend};
use crate::guest::hwbinder;
use crate::guest::environment::start_property_service;
use crate::guest::init::{wait_for_system_server, Service};
use ssal::guest_initrc::{self as initrc, BootService};
use crate::guest::runtime::classpath::{
    derive_guest_classpath, guest_env_value, DERIVE_CLASSPATH_CONTEXT,
};
use ssal::namespace_mounts::Mounts;
use std::fs::{self, File};
use std::io::{self, BufRead, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub(crate) use crate::diagnostics::launcher::fork_probe::client as fork_client;

pub(crate) const GUEST_PROBE_CONTEXT: &[u8] = b"u:r:ssal_guest_probe:s0\0";
const PROPERTY_SERVICE_CONTEXT: &[u8] = b"u:r:ssal_property:s0\0";
const AIDL_SERVER_CONTEXT: &[u8] = b"u:r:aidl_lazy_test_server:s0\0";
const INPUT_INJECTOR_CONTEXT: &[u8] = b"u:r:ssal_input_injector:s0\0";
const INSTALLD: &str = "/system/bin/installd";
const ARTD: &str = "/apex/com.android.art/bin/artd";
const INSTALLD_CAPS: u32 = 0xff;

pub(crate) fn installd_probe_requested() -> bool {
    std::env::var_os("SSAL_GUEST_INSTALLD_PROBE").as_deref() == Some(std::ffi::OsStr::new("1"))
}

pub(super) fn graphics_system_server_requested() -> bool {
    crate::guest::system_server_enabled() && graphics::requested()
}

pub(in crate::guest) fn uses_own_diagnostics(executable: &str) -> bool {
    // The Rust Binder services use mapped exec SIDs and write their own diagnostics.
    [
        crate::guest::init::binder_service::APEX.executable,
        crate::guest::init::binder_service::VOLD.executable,
        crate::guest::init::binder_service::NETD.executable,
        "/run/ssal/ssal-virtual-audio",
        "/run/ssal/ssal-lmkd",
        system_suspend::SERVICE.executable,
        health::SERVICE.executable,
        gatekeeper::SERVICE.executable,
        keymint::SERVICE.executable,
        hwbinder::COMPOSER,
        "/vendor/bin/hw/vendor.qti.hardware.display.allocator-service",
    ]
    .contains(&executable)
}

pub(in crate::guest) use crate::guest::runtime::zygote::{
    system_server_requested, zygote_args, zygote_sockets,
};
fn mapped_exec_domain(executable: &str, exec_context: Option<&[u8]>) -> &'static str {
    if exec_context == Some(PROPERTY_SERVICE_CONTEXT) {
        "init"
    } else if exec_context == Some(AIDL_SERVER_CONTEXT) {
        "aidl_lazy_test_server"
    } else if exec_context == Some(DERIVE_CLASSPATH_CONTEXT) {
        "derive_classpath"
    } else if exec_context == Some(INPUT_INJECTOR_CONTEXT) {
        "shell"
    } else {
        match executable {
            "/system/bin/app_process64" => "zygote",
            "/system/bin/servicemanager" => "servicemanager",
            crate::guest::hwbinder::MANAGER => "hwservicemanager",
            crate::guest::hwbinder::ALLOCATOR => "hal_allocator_default",
            "/system/bin/surfaceflinger" => "surfaceflinger",
            hwbinder::COMPOSER => "hal_graphics_composer_default",
            hwbinder::GRAPHICS_ALLOCATOR => "hal_graphics_allocator_default",
            "/run/ssal/ssal-apexservice" => crate::guest::init::binder_service::APEX.domain,
            "/run/ssal/ssal-vold" => crate::guest::init::binder_service::VOLD.domain,
            "/run/ssal/ssal-netd" => crate::guest::init::binder_service::NETD.domain,
            "/run/ssal/ssal-virtual-audio" => "audioserver",
            "/run/ssal/ssal-lmkd" => "lmkd",
            "/system/bin/audioserver" => "audioserver",
            "/run/ssal/ssal-system-suspend" => system_suspend::SERVICE.domain,
            "/run/ssal/ssal-health" => health::SERVICE.domain,
            "/run/ssal/ssal-gatekeeper" => gatekeeper::SERVICE.domain,
            "/run/ssal/ssal-keymint" => keymint::SERVICE.domain,
            "/apex/com.android.adbd/bin/adbd" => "adbd",
            "/system/bin/gatekeeperd" => "gatekeeperd",
            "/system/bin/keystore2" => "keystore",
            "/system/bin/aconfigd-system" => "aconfigd",
            "/apex/com.android.sdkext/bin/derive_classpath" => "derive_classpath",
            "/apex/com.android.runtime/bin/linkerconfig" | "/system/bin/linkerconfig" => {
                "linkerconfig"
            }
            ARTD => "artd",
            _ => "shell",
        }
    }
}

fn start_input_listener(socket_path: &Path) -> Option<OwnedFd> {
    use std::os::unix::ffi::OsStrExt;
    let c_path = std::ffi::CString::new(socket_path.as_os_str().as_bytes()).ok()?;
    let bytes = c_path.as_bytes_with_nul();
    let mut sun: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    sun.sun_family = libc::AF_UNIX as _;
    if bytes.len() > sun.sun_path.len() {
        eprintln!("GUEST_INPUT_INJECTOR=WARN socket path too long");
        return None;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(
            bytes.as_ptr(),
            sun.sun_path.as_mut_ptr().cast::<u8>(),
            bytes.len(),
        );
    }
    let _ = fs::remove_file(socket_path);
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        eprintln!("GUEST_INPUT_INJECTOR=WARN socket_err={}", io::Error::last_os_error());
        return None;
    }
    let listener = unsafe { OwnedFd::from_raw_fd(fd) };
    let addr_len = (std::mem::size_of::<libc::sa_family_t>() + bytes.len()) as libc::socklen_t;
    if unsafe {
        libc::bind(
            listener.as_raw_fd(),
            (&sun as *const libc::sockaddr_un).cast(),
            addr_len,
        )
    } != 0
        || unsafe { libc::listen(listener.as_raw_fd(), 4) } != 0
    {
        eprintln!("GUEST_INPUT_INJECTOR=WARN bind_listen_err={}", io::Error::last_os_error());
        return None;
    }
    let _ = fs::set_permissions(socket_path, fs::Permissions::from_mode(0o666));
    Some(listener)
}

fn spawn_input_accept_relay(listener: OwnedFd) {
    std::thread::Builder::new()
        .name("ssal-input-accept".into())
        .spawn(move || {
            loop {
                let peer = unsafe {
                    libc::accept4(
                        listener.as_raw_fd(),
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                        libc::SOCK_CLOEXEC,
                    )
                };
                if peer < 0 {
                    let err = io::Error::last_os_error();
                    if err.raw_os_error() == Some(libc::EINTR) {
                        continue;
                    }
                    eprintln!("GUEST_INPUT_INJECTOR=WARN accept_err={err}");
                    break;
                }
                let peer_fd = unsafe { OwnedFd::from_raw_fd(peer) };
                let mut stream =
                    match UnixStream::connect(format!("{}/run/ssald.sock", ssal::unix::ROOT)) {
                        Ok(s) => s,
                        Err(e) => {
                            eprintln!("GUEST_INPUT_INJECTOR=WARN ssald_connect_err={e}");
                            continue;
                        }
                    };
                let req = ssal::unix::Request {
                    version: ssal::unix::VERSION,
                    command: "register-input".into(),
                    image_name: None,
                    profile_name: None,
                    force_regen: false,
                    native_sepolicy: false,
                };
                if let Err(e) = ssal::unix::send(&mut stream, &req, Some(peer_fd.as_raw_fd())) {
                    eprintln!("GUEST_INPUT_INJECTOR=WARN ssald_send_err={e}");
                    continue;
                }
                let mut line = String::new();
                if io::BufReader::new(stream).read_line(&mut line).is_ok() {
                    if let Ok(resp) = serde_json::from_str::<ssal::unix::Response>(&line) {
                        if resp.ok {
                            println!("GUEST_INPUT_INJECTOR=PASS {}", resp.message);
                            break;
                        }
                    }
                }
            }
        })
        .ok();
}

pub(crate) fn retest_surfaceflinger(
    root: &Path,
    guest_binder: u64,
    guest_hwbinder: Option<u64>,
) -> io::Result<()> {
    let plan = ssal::guest_policy::runtime::load(root)?
        .ok_or_else(|| io::Error::other("Guest SELinux plan missing for SurfaceFlinger"))?;
    let sid = plan.context("surfaceflinger", true)?;
    let gpu = fs::metadata(root.join("dev").join(crate::guest::concurrent::graphics::KGSL))?;
    let binder = fs::metadata(root.join("dev/binder"))?;
    let actual_hwbinder = fs::metadata(root.join("dev/hwbinder"))
        .ok()
        .map(|device| device.rdev());
    if binder.rdev() != guest_binder || actual_hwbinder != guest_hwbinder {
        return Err(io::Error::other("Y702 Guest graphics/Binder device isolation mismatch"));
    }
    println!(
        "SF_RETEST_BEGIN uid=1000 sid={sid} gpu_rdev={} binder_rdev={} hwbinder_rdev={actual_hwbinder:?}",
        gpu.rdev(),
        binder.rdev()
    );
    let mut service = match Service::start(
        root,
        "/system/bin/surfaceflinger",
        &[],
        "sf-retest",
        1000,
        None,
        &[],
    ) {
        Ok(service) => Some(service),
        Err(error) => {
            println!("SF_RETEST_START_FAILED={error}");
            None
        }
    };
    if let Some(running) = &service {
        let pid = running.pid();
        let actual_sid = fs::read_to_string(format!("/proc/{pid}/attr/current"))
            .map(|sid| sid.trim_matches(['\0', '\n']).to_owned())
            .unwrap_or_else(|error| format!("unavailable:{error}"));
        let actual_uid = fs::read_to_string(format!("/proc/{pid}/status"))
            .ok()
            .and_then(|status| {
                status
                    .lines()
                    .find(|line| line.starts_with("Uid:"))
                    .and_then(|line| line.split_whitespace().nth(1).map(str::to_owned))
            })
            .unwrap_or_else(|| "unavailable".into());
        println!("SF_RETEST_PROCESS pid={pid} {actual_uid} sid={actual_sid}");
        if actual_uid != "1000" || actual_sid != sid {
            service.take().unwrap().stop()?;
            return Err(io::Error::other(format!(
                "Guest SurfaceFlinger identity mismatch: uid={actual_uid} sid={actual_sid}"
            )));
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if running.exited()? {
                break;
            }
            if let Ok(out) = run(
                root,
                "/system/bin/sh",
                &["-c", "service check SurfaceFlingerAIDL"],
                2000,
            ) {
                if out.contains(": found") {
                    break;
                }
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    }
    for name in ["SurfaceFlinger", "SurfaceFlingerAIDL"] {
        let result = run(
            root,
            "/system/bin/sh",
            &["-c", &format!("service check {name}")],
            2000,
        );
        match result {
            Ok(output) => println!("SF_RETEST_BINDER {name}: {}", output.trim()),
            Err(error) => println!("SF_RETEST_BINDER {name}: failed: {error}"),
        }
    }
    if let Ok(displays) = run(
        root,
        "/system/bin/sh",
        &["-c", "dumpsys SurfaceFlinger --display-id"],
        2000,
    ) {
        println!("SF_RETEST_DISPLAY_ID: {}", displays.trim());
    }
    let alive = service
        .as_ref()
        .map(Service::exited)
        .transpose()?
        .is_some_and(|exited| !exited);
    println!("SF_RETEST_ALIVE_AFTER_LOOKUPS={alive}");
    if let Some(mut service) = service.take() {
        service.stop()?;
    }
    if alive {
        Ok(())
    } else {
        Err(io::Error::other("Guest SurfaceFlinger exited before observation completed"))
    }
}

use ssal::platform::process::join_cgroups;

pub(crate) fn command(
    root: &Path,
    executable: &str,
    uid: u32,
    exec_context: Option<&[u8]>,
) -> io::Result<Command> {
    crate::guest::process::supervision::check_interrupted()?;
    // A real Guest mount root also gives Zygote's FD allowlist Guest-relative proc paths.
    let suspend = executable == system_suspend::SERVICE.executable;
    let pivot = suspend
        || (executable == "/system/bin/app_process64"
            && exec_context != Some(INPUT_INJECTOR_CONTEXT)
            && (std::env::var_os("SSAL_PHASE7FB_FORK").is_some()
                || crate::guest::system_server_enabled()));
    let derive_classpath_linker = executable == "/system/bin/bootstrap/linker64"
        && exec_context == Some(DERIVE_CLASSPATH_CONTEXT);
    let mapped_installd =
        executable == INSTALLD && (installd_probe_requested() || graphics_system_server_requested());
    let memlock_unlimited = executable == "/system/bin/keystore2";
    let mut command = crate::guest::process::command::root_command(root, executable, pivot)?;
    let exec_context = if let Some(plan) = ssal::guest_policy::runtime::load(root)? {
        let original = if mapped_installd {
            "installd"
        } else {
            mapped_exec_domain(executable, exec_context)
        };
        let mut context = plan.context(original, true)?.into_bytes();
        context.push(0);
        Some(context)
    } else {
        exec_context.map(<[u8]>::to_vec)
    };
    let property_service = exec_context
        .as_deref()
        .is_some_and(|context| context.ends_with(b"_init:s0\0"))
        || exec_context.as_deref() == Some(PROPERTY_SERVICE_CONTEXT);
    let pre_exec_cgroups: Vec<_> = if property_service {
        Vec::new()
    } else {
        crate::guest::cgroup::guest_cgroup_mounts(crate::guest::cgroup::backend()?)
            .into_iter()
            .map(|(_, target)| Path::new("/").join(target))
            .collect()
    };
    command.env("LD_LIBRARY_PATH", "/run/ssal");
    if executable == "/system/bin/bootstrap/linker64" {
        command.env(
            "LD_LIBRARY_PATH",
            if derive_classpath_linker {
                "/run/ssal:/apex/com.android.sdkext/lib64:/system/lib64"
            } else {
                "/system/lib64/bootstrap:/system/lib64"
            },
        );
    }
    command
        .env("ANDROID_ROOT", "/system")
        .env("ANDROID_DATA", "/data")
        .env("ANDROID_RUNTIME_ROOT", "/apex/com.android.runtime")
        .env("ANDROID_ART_ROOT", "/apex/com.android.art")
        .env("ASEC_MOUNTPOINT", "/mnt/asec")
        .env("ANDROID_STORAGE", "/storage")
        .env("ANDROID_I18N_ROOT", "/apex/com.android.i18n")
        .env("ANDROID_TZDATA_ROOT", "/apex/com.android.tzdata")
        .stdin(Stdio::null());
    if executable == "/apex/com.android.art/bin/artd" {
        command.env("LD_LIBRARY_PATH", "/run/ssal:/apex/com.android.art/lib64:/system/lib64:/apex/com.android.os.statsd/lib64:/apex/com.android.i18n/lib64");
    }
    if executable == "/apex/com.android.sdkext/bin/derive_classpath" {
        command.env(
            "LD_LIBRARY_PATH",
            "/run/ssal:/apex/com.android.sdkext/lib64:/system/lib64",
        );
    }
    let parent = std::process::id() as libc::pid_t;
    let installd_namespace = mapped_installd
        .then(|| fs::read_link("/proc/self/ns/mnt"))
        .transpose()?;
    let cgroup_ns = crate::guest::cgroup::namespace_fd();
    unsafe {
        command.pre_exec(move || {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 || libc::getppid() != parent
            {
                return Err(io::Error::other("Guest launcher parent disappeared"));
            }
            // The root transition already ran; only this child joins Guest cgroups.
            join_cgroups(&pre_exec_cgroups)?;
            if !property_service {
                crate::guest::cgroup::verify_guest_mount_membership(std::process::id())?;
            }
            if let Some(fd) = cgroup_ns {
                if libc::setns(fd, libc::CLONE_NEWCGROUP) != 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            if suspend {
                system_suspend::mask_host_power()?;
            }
            if let Some(context) = &exec_context {
                fs::write("/proc/thread-self/attr/exec", context)?;
            }
            if memlock_unlimited {
                let rlim = libc::rlimit {
                    rlim_cur: libc::RLIM_INFINITY,
                    rlim_max: libc::RLIM_INFINITY,
                };
                if libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) != 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            if libc::setgroups(0, std::ptr::null()) != 0
                || libc::setresgid(uid, uid, uid) != 0
                || libc::setresuid(uid, uid, uid) != 0
            {
                return Err(io::Error::last_os_error());
            }
            if let Some(expected) = &installd_namespace {
                let namespace = fs::read_link("/proc/self/ns/mnt")?;
                if &namespace != expected {
                    return Err(io::Error::other("Guest installd pre-exec namespace mismatch"));
                }
                let evidence = format!(
                    "Guest installd pre-exec pid={} mount_namespace={}\n",
                    libc::getpid(),
                    namespace.display()
                );
                libc::write(libc::STDERR_FILENO, evidence.as_ptr().cast(), evidence.len());
                limit_installd_capabilities()?;
                // The parent opened stdin before chroot, under its management SID.
                if libc::close(libc::STDIN_FILENO) != 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    Ok(command)
}

fn limit_installd_capabilities() -> io::Result<()> {
    // Retain at most the DAC and identity capabilities used by the Phase 2 daemon.
    let header = [0x20080522u32, 0];
    let mut caps = [[0u32; 3]; 2]; // effective, permitted, inheritable
    unsafe {
        if libc::syscall(libc::SYS_capget, header.as_ptr(), caps.as_mut_ptr()) != 0
            || libc::prctl(libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) != 0
        {
            return Err(io::Error::last_os_error());
        }
        let permitted = caps[0][1] & INSTALLD_CAPS;
        for bit in 0..64 {
            let present = libc::prctl(libc::PR_CAPBSET_READ, bit, 0, 0, 0);
            if present < 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::EINVAL) && bit >= 32 {
                    break;
                }
                return Err(error);
            }
            if present != 0
                && (bit >= 32 || permitted & (1 << bit) == 0)
                && libc::prctl(libc::PR_CAPBSET_DROP, bit, 0, 0, 0) != 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        caps = [[caps[0][0] & permitted, permitted, 0], [0; 3]];
        if libc::syscall(libc::SYS_capset, header.as_ptr(), caps.as_ptr()) != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

pub(crate) fn run(root: &Path, exe: &str, args: &[&str], uid: u32) -> io::Result<String> {
    run_as(root, exe, args, uid, GUEST_PROBE_CONTEXT)
}

pub(in crate::guest) fn run_as(
    root: &Path,
    exe: &str,
    args: &[&str],
    uid: u32,
    context: &[u8],
) -> io::Result<String> {
    let mut child_command = command(root, exe, uid, Some(context))?;
    child_command.args(args);
    if matches!(
        exe,
        "/apex/com.android.sdkext/bin/derive_classpath"
            | "/apex/com.android.runtime/bin/linkerconfig"
            | "/system/bin/linkerconfig"
            | "/system/bin/aconfigd-system"
    ) {
        child_command.env("LD_PRELOAD", "/run/ssal/ssal-phase2-log.so");
    }
    if exe == "/system/bin/aconfigd-system" {
        child_command.env("ANDROID_FILE__dev_kmsg", "2");
    }
    if std::env::var_os("SSAL_TRACE_GUEST_SIGABRT").is_some()
        && (exe == "/apex/com.android.runtime/bin/linkerconfig"
            || exe == "/system/bin/linkerconfig")
    {
        let executable_copy = root
            .parent()
            .ok_or_else(|| io::Error::other("Guest worker directory missing"))?
            .join("linkerconfig.debug.elf");
        fs::copy(
            crate::guest::mount::guest_path(root, exe.trim_start_matches('/'))?,
            &executable_copy,
        )?;
        println!(
            "linkerconfig trace binary copy: {}",
            executable_copy.display()
        );
        child_command.env("LD_PRELOAD", "/run/ssal/ssal-abort-trace.so");
    }
    let output = crate::guest::process::command::run_with_timeout(
        &mut child_command,
        exe,
        Duration::from_secs(20),
    )?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    println!(
        "Guest call executable={exe} args={args:?} return={}\n{stdout}{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "Guest call {exe} {args:?}: {}",
            output.status
        )));
    }
    Ok(stdout.into_owned())
}

pub(crate) fn readiness_client() -> io::Result<()> {
    let (uid, euid, gid, egid) = unsafe {
        (
            libc::getuid(),
            libc::geteuid(),
            libc::getgid(),
            libc::getegid(),
        )
    };
    if (uid, euid, gid, egid) != (1000, 1000, 1000, 1000) {
        return Err(io::Error::other(format!(
            "unexpected client credentials uid={uid} euid={euid} gid={gid} egid={egid}"
        )));
    }
    let status = fs::read_to_string("/proc/self/status")?;
    for name in ["CapInh:", "CapPrm:", "CapEff:", "CapAmb:"] {
        let value = status
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .ok_or_else(|| io::Error::other("capability status missing"))?;
        if u64::from_str_radix(value.trim(), 16).unwrap_or(u64::MAX) != 0 {
            return Err(io::Error::other(format!(
                "client capability {name}={value}"
            )));
        }
    }
    let mut socket = match UnixStream::connect("zygote") {
        Ok(socket) => socket,
        Err(e)
            if e.kind() == io::ErrorKind::ConnectionRefused
                || e.kind() == io::ErrorKind::NotFound =>
        {
            eprintln!("connect pending: {e}");
            std::process::exit(2);
        }
        Err(e) => return Err(io::Error::other(format!("connect: {e}"))),
    };
    socket.set_read_timeout(Some(Duration::from_secs(30)))?;
    socket.set_write_timeout(Some(Duration::from_secs(30)))?;
    query_abi(&mut socket)?;
    println!("Guest Zygote ABI socket query=arm64-v8a client_pid={} uid={uid} euid={euid} gid={gid} egid={egid} capabilities=0", std::process::id());
    Ok(())
}

pub(in crate::guest) fn guest_servicemanager_property(root: &Path) -> io::Result<String> {
    Ok(run(
        root,
        "/system/bin/sh",
        &["-c", "getprop servicemanager.ready"],
        1000,
    )?
    .trim()
    .to_owned())
}

fn read_initrc_properties(root: &Path) -> io::Result<initrc::Properties> {
    let output = run(root, "/system/bin/sh", &["-c", "getprop"], 1000)?;
    Ok(output
        .lines()
        .filter_map(|line| {
            let (key, value) = line.strip_prefix('[')?.strip_suffix(']')?.split_once("]: [")?;
            Some((key.to_owned(), value.to_owned()))
        })
        .collect())
}

pub(in crate::guest) fn probe_guest_context_manager(root: &Path) -> io::Result<String> {
    let mut command = command(
        root,
        "/system/bin/bootstrap/linker64",
        1000,
        Some(GUEST_PROBE_CONTEXT),
    )?;
    command.args(["/run/ssal/ssal-binder-ipc", "context-manager"]);
    let output = crate::guest::process::command::run_with_timeout(
        &mut command,
        "Guest Binder Context Manager probe",
        Duration::from_secs(2),
    )?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "Guest Binder Context Manager probe: {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    if !stdout.contains("\"event\":\"context_manager_lookup_passed\"") {
        return Err(io::Error::other(
            "Guest Binder Context Manager probe returned no success evidence",
        ));
    }
    Ok(stdout)
}

fn query_abi(socket: &mut UnixStream) -> io::Result<()> {
    socket
        .write_all(b"1\n--query-abi-list\n")
        .map_err(|e| io::Error::other(format!("ABI request: {e}")))?;
    let mut length = [0; 4];
    socket
        .read_exact(&mut length)
        .map_err(|e| io::Error::other(format!("ABI length: {e}")))?;
    if u32::from_be_bytes(length) != 9 {
        return Err(io::Error::other(format!(
            "invalid ABI response length {}",
            u32::from_be_bytes(length)
        )));
    }
    let mut abi = [0; 9];
    socket
        .read_exact(&mut abi)
        .map_err(|e| io::Error::other(format!("ABI response: {e}")))?;
    if &abi != b"arm64-v8a" {
        return Err(io::Error::other(format!(
            "unexpected ABI response: {:?}",
            String::from_utf8_lossy(&abi)
        )));
    }
    Ok(())
}

fn capture_stalled_system_server_dump(
    root: &Path,
    zygote: &mut Service,
    pid: u32,
) -> io::Result<()> {
    let phase = root.parent().unwrap().join("phase7b");
    let stderr_path = phase.join("stderr.log");
    let stderr = fs::read_to_string(&stderr_path)?;
    if let Some(marker) = ["startCoreServices", "startOtherServices", "SystemReady"]
        .iter()
        .find(|marker| stderr.contains(**marker))
    {
        println!("SYSTEMSERVER_PROGRESS marker={marker}");
        return Ok(());
    }

    let process = Path::new("/proc").join(pid.to_string());
    let status = fs::read_to_string(process.join("status"))?;
    let parent = status
        .lines()
        .find_map(|line| line.strip_prefix("PPid:"))
        .and_then(|parent| parent.trim().parse::<u32>().ok());
    let cmdline_bytes = fs::read(process.join("cmdline"))?;
    let cmdline = String::from_utf8_lossy(&cmdline_bytes);
    let guest_root = fs::metadata(root)?;
    let process_root = fs::metadata(process.join("root"))?;
    if parent != Some(zygote.child.id())
        || !cmdline.contains("system_server")
        || (guest_root.dev(), guest_root.ino()) != (process_root.dev(), process_root.ino())
    {
        println!("SYSTEMSERVER_THREAD_DUMP=SKIPPED pid={pid} reason=identity_changed");
        return Ok(());
    }

    if unsafe { libc::kill(pid as i32, libc::SIGQUIT) } != 0 {
        println!(
            "SYSTEMSERVER_THREAD_DUMP=SIGQUIT_FAILED pid={pid} error={}",
            io::Error::last_os_error()
        );
        return Ok(());
    }
    println!("SYSTEMSERVER_THREAD_DUMP_REQUESTED pid={pid} signal=SIGQUIT");
    let start_marker = format!("----- pid {pid} at ");
    let end_marker = format!("----- end {pid} -----");
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if let Some(diagnostics) = &mut zygote.diagnostics {
            diagnostics.tick()?;
        }
        let stderr = fs::read_to_string(&stderr_path)?;
        if let Some(start) = stderr.find(&start_marker) {
            if let Some(end) = stderr[start..].find(&end_marker) {
                let end = start + end + end_marker.len();
                let dump = &stderr[start..end];
                fs::write(phase.join("system-server-thread-dump.txt"), dump)?;
                println!(
                    "SYSTEMSERVER_THREAD_DUMP=PASS pid={pid} bytes={}",
                    dump.len()
                );
                return Ok(());
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    println!("SYSTEMSERVER_THREAD_DUMP=MISSING pid={pid}");
    Ok(())
}

pub(crate) fn memory_probe(root: &Path, hierarchy_test: bool) -> io::Result<()> {
    let oom_test = hierarchy_test && std::env::var_os("SSAL_PHASE7D_FIX_OOM").is_some();
    let backend = crate::guest::cgroup::backend()?;
    if hierarchy_test && backend == crate::guest::cgroup::Backend::V1 {
        // shortcut: the Phase 7D OOM proof is v2-only, add a v1 probe before using that phase there.
        return Err(io::Error::other(
            "phase 7D OOM hierarchy probe currently requires cgroup v2",
        ));
    }
    let group = crate::guest::cgroup::memory_group(backend);
    let mut service = Service::start(
        root,
        if hierarchy_test {
            "/system/bin/bootstrap/linker64"
        } else {
            "/system/bin/sh"
        },
        if oom_test {
            &["/run/ssal/phase7d-fix-probe", "--oom"]
        } else if hierarchy_test {
            &["/run/ssal/phase7d-fix-probe"]
        } else {
            &["-c", "sleep 10"]
        },
        "memory-probe",
        1000,
        Some(GUEST_PROBE_CONTEXT),
        &[],
    )?;
    let pid = service.child.id();
    if hierarchy_test {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let status = fs::read_to_string(format!("/proc/{pid}/status"))?;
            if status
                .lines()
                .any(|line| line.starts_with("State:") && line.contains("stopped"))
            {
                break;
            }
            if service.exited()? || Instant::now() >= deadline {
                return Err(io::Error::other("allocator did not stop"));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let subgroup = crate::guest::cgroup::task_cgroup_path()?.join("phase7d_fix");
        fs::write(subgroup.join("cgroup.procs"), pid.to_string())?;
        let before = crate::guest::cgroup::usage(&group, backend)?;
        if unsafe { libc::kill(pid as i32, libc::SIGCONT) } != 0 {
            return Err(io::Error::last_os_error());
        }
        if oom_test {
            let events = group.join("memory.events");
            loop {
                if let Some(diagnostics) = &mut service.diagnostics {
                    diagnostics.tick()?;
                }
                let text = fs::read_to_string(&events)?;
                let count = text
                    .lines()
                    .find_map(|line| line.strip_prefix("max "))
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(0);
                if count > 0 {
                    let limit: u64 = crate::guest::cgroup::read(group.join("memory.max"))?
                        .parse()
                        .map_err(io::Error::other)?;
                    let current: u64 = crate::guest::cgroup::read(group.join("memory.current"))?
                        .parse()
                        .map_err(io::Error::other)?;
                    if current > limit {
                        return Err(io::Error::other("memory.current exceeded max"));
                    }
                    println!("HIERARCHICAL_LIMIT current={current} max={limit} events={text:?}");
                    service.stop()?;
                    return Ok(());
                }
                if service.exited()? || Instant::now() >= deadline {
                    return Err(io::Error::other(format!(
                        "subgroup memory.max not observed: {text}"
                    )));
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        let stdout = root.parent().unwrap().join("phase7b/stdout.log");
        let children = loop {
            if let Some(diagnostics) = &mut service.diagnostics {
                diagnostics.tick()?;
            }
            let content = fs::read_to_string(&stdout)?;
            if let Some(line) = content.lines().find(|line| line.starts_with("normal=")) {
                break line.to_owned();
            }
            if service.exited()? || Instant::now() >= deadline {
                return Err(io::Error::other("allocator children not ready"));
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        for field in children.split_whitespace() {
            let (kind, value) = field
                .split_once('=')
                .ok_or_else(|| io::Error::other("invalid child report"))?;
            let child: u32 = value.parse().map_err(io::Error::other)?;
            if kind == "detached" {
                loop {
                    let stat = fs::read_to_string(format!("/proc/{child}/stat"))?;
                    let session = stat
                        .rsplit_once(')')
                        .and_then(|(_, rest)| rest.split_whitespace().nth(3))
                        .and_then(|value| value.parse::<u32>().ok());
                    if session == Some(child) {
                        break;
                    }
                    if Instant::now() >= deadline {
                        return Err(io::Error::other("setsid child not ready"));
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
            let member = crate::guest::cgroup::verify_membership(
                child,
                &crate::guest::cgroup::memory_mount(backend),
                &subgroup,
            )?;
            println!("GUEST_CHILD pid={child} membership={member}");
        }
        let after = crate::guest::cgroup::usage(&group, backend)?;
        if after < before + 8 * 1024 * 1024 {
            return Err(io::Error::other(format!(
                "hierarchical memory charge too small: {before} -> {after}"
            )));
        }
        println!(
            "HIERARCHICAL_MEMORY before={before} after={after} delta={}",
            after - before
        );
    }
    let membership = crate::guest::cgroup::verify_guest_membership(pid)?;
    let current = crate::guest::cgroup::usage(&group, backend)?;
    if current == 0 {
        return Err(io::Error::other("Guest memory accounting is empty"));
    }
    println!("GUEST_MEMORY_PROBE pid={pid} membership={membership} memory_usage={current}");
    if let Some(diagnostics) = &mut service.diagnostics {
        diagnostics.tick()?;
    }
    if hierarchy_test
        && (std::env::var_os("SSAL_PHASE7D_FIX_HOLD").is_some()
            || std::env::var_os("SSAL_PHASE7D_FIX_TIMEOUT").is_some())
    {
        let timeout = std::env::var_os("SSAL_PHASE7D_FIX_TIMEOUT").is_some();
        let deadline = Instant::now() + Duration::from_secs(if timeout { 2 } else { 30 });
        println!("GUEST_LIFECYCLE_WAIT timeout_test={timeout}");
        loop {
            crate::guest::process::supervision::check_interrupted()?;
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "Guest lifecycle test timeout",
                ));
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    service.stop()?;
    Ok(())
}

fn isolated(root: &Path, userdata: &Path) -> io::Result<()> {
    let identity = |path: &Path| -> io::Result<_> {
        let m = fs::metadata(path)?;
        Ok((m.dev(), m.ino()))
    };
    if identity(&root.join("data"))? != identity(userdata)?
        || identity(userdata)?.0 == identity(Path::new("/data"))?.0
    {
        return Err(io::Error::other("Guest userdata identity mismatch"));
    }
    for path in [
        "dev/socket/property_service",
        "dev/socket/property_service_for_system",
        "dev/socket/init",
        "dev/socket/ctl.start",
        "dev/hwbinder",
        "dev/vndbinder",
    ] {
        if fs::symlink_metadata(root.join(path)).is_ok() {
            return Err(io::Error::other(format!(
                "unexpected Guest endpoint {path}"
            )));
        }
    }
    if fs::read_dir(root.join("dev/socket"))?.next().is_some() {
        return Err(io::Error::other(
            "Guest control socket directory is not empty",
        ));
    }
    Ok(())
}

fn prepare_aconfig_storage(root: &Path) -> io::Result<()> {
    let plan = ssal::guest_policy::runtime::load(root)?;
    for (rel, mode, label_type) in [
        ("metadata/aconfig", 0o775, "aconfig_storage_metadata_file"),
        (
            "metadata/aconfig/flags",
            0o770,
            "aconfig_storage_flags_metadata_file",
        ),
        (
            "metadata/aconfig/maps",
            0o775,
            "aconfig_storage_metadata_file",
        ),
        (
            "metadata/aconfig/boot",
            0o775,
            "aconfig_storage_metadata_file",
        ),
    ] {
        let dir = crate::guest::mount::directory(root, rel, mode)?;
        std::os::unix::fs::chown(&dir, Some(0), Some(1000))?;
        fs::set_permissions(&dir, std::os::unix::fs::PermissionsExt::from_mode(mode))?;
        if let Some(plan) = &plan {
            if plan.types.contains_key(label_type) {
                ssal::guest_policy::runtime::set_label(&dir, &plan.context(label_type, false)?)?;
            }
        }
    }
    if root.join("system/bin/aconfigd-system").is_file() {
        for subcmd in ["early-platform-init", "platform-init"] {
            match run(root, "/system/bin/aconfigd-system", &[subcmd], 1000) {
                Ok(out) => {
                    println!("GUEST_ACONFIGD_INIT subcmd={subcmd} output_len={}", out.len());
                }
                Err(err)
                    if subcmd == "platform-init"
                        && root.join("metadata/aconfig/maps/system.package.map").is_file() =>
                {
                    eprintln!("GUEST_ACONFIGD_INIT subcmd={subcmd} partial (vendor absent): {err}");
                }
                Err(err) => return Err(err),
            }
        }
    }
    Ok(())
}

fn prepare_security_daemon_dir(
    root: &Path,
    rel: &str,
    uid: u32,
    gid: u32,
    mode: u32,
    label_type: &str,
) -> io::Result<()> {
    let dir = crate::guest::mount::directory(root, rel, mode)?;
    std::os::unix::fs::chown(&dir, Some(uid), Some(gid))?;
    fs::set_permissions(&dir, fs::Permissions::from_mode(mode))?;
    if let Some(plan) = ssal::guest_policy::runtime::load(root)? {
        ssal::guest_policy::runtime::set_label(&dir, &plan.context(label_type, false)?)?;
    }
    Ok(())
}

fn start_data_service(root: &Path, exe: &str, name: &str) -> io::Result<Service> {
    if exe == INSTALLD {
        let plan = if installd_probe_requested() || graphics_system_server_requested() {
            ssal::guest_policy::runtime::load(root)?
        } else {
            None
        };
        for (path, label) in [
            ("data/misc/user", "misc_user_data_file"),
            ("data/misc/installd", "install_data_file"),
        ] {
            let path = crate::guest::mount::directory(root, path, 0o755)?;
            if let Some(plan) = &plan {
                ssal::guest_policy::runtime::set_label(&path, &plan.context(label, false)?)?;
            }
        }
    }
    Service::start(root, exe, &[], name, 0, Some(GUEST_PROBE_CONTEXT), &[])
}

fn probe_installd(root: &Path, userdata: &Path, host_ns: &Path, binder: u64) -> io::Result<()> {
    let plan = ssal::guest_policy::runtime::load(root)?
        .ok_or_else(|| io::Error::other("Guest installd requires the mapped policy"))?;
    let exe = File::open(root.join("system/bin/installd"))?;
    let upper = File::open(userdata.join(format!(
        ".ssal-overlay-{}/system/upper/bin/installd",
        std::process::id()
    )))?;
    let expected_label = plan.context("installd_exec", false)?;
    let host = fs::metadata(INSTALLD)?;
    let private = upper.metadata()?;
    let guest = exe.metadata()?;
    let block = root.join("dev/block");
    if !block.symlink_metadata()?.is_dir()
        || fs::read_dir(&block)?.next().is_some()
        || binder == fs::metadata("/dev/binder")?.rdev()
    {
        return Err(io::Error::other("Guest installd device isolation failed"));
    }
    if !private.is_file()
        || private.dev() != fs::metadata(userdata)?.dev()
        || private.dev() == host.dev()
        || private.len() != guest.len()
        || (guest.dev(), guest.ino()) == (host.dev(), host.ino())
        || ssal::unix::image_context(&upper)? != expected_label
        || ssal::unix::image_context(&exe)? != expected_label
    {
        return Err(io::Error::other("Guest installd executable backing verification failed"));
    }
    println!(
        "Guest installd backing: overlay={}:{} upper={}:{} host={}:{} label={expected_label}",
        guest.dev(), guest.ino(), private.dev(), private.ino(), host.dev(), host.ino()
    );
    let mut service = start_data_service(root, INSTALLD, "installd")?;
    let pid = service.pid();
    let result = (|| {
        let proc = Path::new("/proc").join(pid.to_string());
        let sid = fs::read_to_string(proc.join("attr/current"))?;
        let sid = sid.trim_matches(['\0', '\n']);
        let ns = fs::read_link(proc.join("ns/mnt"))?;
        let actual = fs::metadata(proc.join("exe"))?;
        let status = fs::read_to_string(proc.join("status"))?;
        let mask = |field: &str| {
            status.lines().find_map(|line| line.strip_prefix(field))
                .and_then(|bits| u64::from_str_radix(bits.trim(), 16).ok())
                .ok_or_else(|| io::Error::other(format!("Guest installd {field} missing")))
        };
        let effective = mask("CapEff:")?;
        let bounding = mask("CapBnd:")?;
        println!(
            "Guest installd identity pid={pid} sid={sid} CapEff={effective:016x} CapBnd={bounding:016x} mount_namespace={}",
            ns.display()
        );
        if sid != plan.context("installd", true)?
            || ns == host_ns
            || ns != fs::read_link("/proc/self/ns/mnt")?
            || (actual.dev(), actual.ino()) != (guest.dev(), guest.ino())
            || (effective | bounding) & !u64::from(INSTALLD_CAPS) != 0
        {
            return Err(io::Error::other("Guest installd runtime identity mismatch"));
        }
        std::thread::sleep(Duration::from_millis(500));
        if service.exited()? {
            return Err(io::Error::other("Guest installd exited before Binder lookup"));
        }
        let reply = run(
            root,
            "/system/bin/bootstrap/linker64",
            &["/run/ssal/ssal-binder-ipc", "inspect-data-service", "installd"],
            1000,
        )?;
        if !reply.contains("\"descriptor\":\"android.os.IInstalld\"") {
            return Err(io::Error::other("Guest installd Binder descriptor missing"));
        }
        println!("GUEST_INSTALLD_PROBE=PASS private_binder={binder} descriptor=android.os.IInstalld");
        Ok(())
    })();
    service.drain_output()?;
    println!("Guest installd log:\n{}", fs::read_to_string(&service.log)?);
    service.stop()?;
    result
}

fn check_boot_services(services: &mut [Service]) -> io::Result<()> {
    crate::guest::process::supervision::check_interrupted()?;
    for service in services {
        service.drain_output()?;
        if service.exited()? {
            if service.log.file_name().is_some_and(|name| name == "artd.log")
                && service.exit_status()? == Some((libc::CLD_EXITED, 0))
            {
                // artd is a lazy AIDL service and exits cleanly when idle.
                continue;
            }
            let log = fs::read_to_string(&service.log).unwrap_or_default();
            if !log.is_empty() {
                eprintln!("Guest boot service {} log:\n{log}", service.pid());
            }
            return Err(io::Error::other(format!(
                "Guest boot service {} exited (see {})",
                service.pid(),
                service.log.display(),
            )));
        }
    }
    Ok(())
}

fn system_server_display_progress(stderr: &str, pid: u32) -> (bool, bool) {
    let pid = pid.to_string();
    let mut waited_for_display = false;
    let mut ready = [false; 3];
    let mut readiness_failed = false;
    for line in stderr.lines() {
        if line.split_whitespace().nth(2) != Some(pid.as_str()) {
            continue;
        }
        if let Some((_, timing)) = line.split_once(" SystemServerTiming: ") {
            waited_for_display |= timing.starts_with("WaitForDisplay took to complete:");
            for (seen, phase) in ready.iter_mut().zip([
                "MakeWindowManagerServiceReady took to complete:",
                "MakeDisplayManagerServiceReady took to complete:",
                "StartActivityManagerReadyPhase took to complete:",
            ]) {
                *seen |= timing.starts_with(phase);
            }
        }
        if let Some((_, message)) = line.split_once(" SystemServer: ") {
            readiness_failed |= message.contains("making Window Manager Service ready")
                || message.contains("making Display Manager Service ready");
        }
    }
    (
        waited_for_display,
        waited_for_display && ready.into_iter().all(|seen| seen) && !readiness_failed,
    )
}

fn preopt_system_apps(
    root: &Path,
    profile_dir: &Path,
    classpaths: &crate::guest::runtime::classpath::GuestClasspaths,
) -> io::Result<()> {
    let dalvik_arm64 = crate::guest::mount::directory(root, "data/dalvik-cache/arm64", 0o771)?;
    let label = ssal::guest_policy::runtime::load(root)?
        .map(|plan| plan.context("dalvikcache_data_file", false))
        .transpose()?;
    if let Some(ref ctx) = label {
        ssal::guest_policy::runtime::set_label(&dalvik_arm64, ctx)?;
    }

    let apk_rel = "system/system_ext/priv-app/SystemUI/SystemUI.apk";
    let apk_host = root.join(apk_rel);
    if !apk_host.is_file() {
        return Ok(());
    }
    let apk_len = fs::metadata(&apk_host)?.len();
    let stamp = format!("boot={}\napk_len={apk_len}\n", classpaths.boot);
    let cache_dir = profile_dir.join("dalvik-cache/arm64");
    let stamp_path = cache_dir.join("systemui.stamp");
    let base = "system@system_ext@priv-app@SystemUI@SystemUI.apk@classes";
    let required_exts = ["dex", "vdex"];
    let all_exts = ["dex", "vdex", "art"];

    if fs::read_to_string(&stamp_path).ok().as_deref() == Some(stamp.as_str())
        && required_exts
            .iter()
            .all(|ext| cache_dir.join(format!("{base}.{ext}")).is_file())
    {
        for ext in all_exts {
            let name = format!("{base}.{ext}");
            let src = cache_dir.join(&name);
            if !src.is_file() {
                continue;
            }
            let dst = dalvik_arm64.join(&name);
            fs::copy(&src, &dst)?;
            fs::set_permissions(&dst, fs::Permissions::from_mode(0o644))?;
            if let Some(ref ctx) = label {
                ssal::guest_policy::runtime::set_label(&dst, ctx)?;
            }
        }
        println!("GUEST_PREOPT_SYSTEMUI=CACHE_HIT dir={}", dalvik_arm64.display());
        return Ok(());
    }

    let guest_apk = "/system/system_ext/priv-app/SystemUI/SystemUI.apk";
    let oat_file = format!("/data/dalvik-cache/arm64/{base}.dex");
    let vdex_file = format!("/data/dalvik-cache/arm64/{base}.vdex");
    let art_file = format!("/data/dalvik-cache/arm64/{base}.art");
    if let Some(shell_data) = ssal::guest_policy::runtime::load(root)?
        .map(|plan| plan.context("shell_data_file", false))
        .transpose()?
    {
        ssal::guest_policy::runtime::set_label(&dalvik_arm64, &shell_data)?;
    }
    let mut cmd = command(root, "/system/bin/bootstrap/linker64", 0, None)?;
    cmd.args([
        "/apex/com.android.art/bin/dex2oat64",
        &format!("--dex-file={guest_apk}"),
        &format!("--oat-file={oat_file}"),
        &format!("--output-vdex={vdex_file}"),
        &format!("--app-image-file={art_file}"),
        "--instruction-set=arm64",
        "--instruction-set-features=default",
        "--compiler-filter=speed",
        "--boot-image=/apex/com.android.art/javalib/boot.art:/system/framework/boot-framework.art",
        "--class-loader-context=PCL[]{PCL[/system_ext/framework/androidx.window.extensions.jar]#PCL[/system_ext/framework/androidx.window.sidecar.jar]}",
        "-j4",
    ])
    .env("BOOTCLASSPATH", &classpaths.boot)
    .env(
        "LD_LIBRARY_PATH",
        "/run/ssal:/apex/com.android.art/lib64:/system/lib64:/apex/com.android.os.statsd/lib64:/apex/com.android.i18n/lib64",
    );
    if let Some(ref d2o) = classpaths.dex2oat {
        cmd.env("DEX2OATBOOTCLASSPATH", d2o);
    }
    match crate::guest::process::command::run_with_timeout(
        &mut cmd,
        "/system/bin/bootstrap/linker64",
        Duration::from_secs(60),
    ) {
        Ok(out) if out.status.success() => {
            if let Some(ref ctx) = label {
                ssal::guest_policy::runtime::set_label(&dalvik_arm64, ctx)?;
            }
            fs::create_dir_all(&cache_dir)?;
            for ext in all_exts {
                let name = format!("{base}.{ext}");
                let dst = dalvik_arm64.join(&name);
                if dst.is_file() {
                    fs::set_permissions(&dst, fs::Permissions::from_mode(0o644))?;
                    if let Some(ref ctx) = label {
                        ssal::guest_policy::runtime::set_label(&dst, ctx)?;
                    }
                    let _ = fs::copy(&dst, cache_dir.join(&name));
                }
            }
            let _ = fs::write(&stamp_path, &stamp);
            println!("GUEST_PREOPT_SYSTEMUI=PASS compiled=true");
        }
        Ok(out) => {
            println!(
                "GUEST_PREOPT_SYSTEMUI=SKIP status={} stderr={}",
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Err(e) => {
            println!("GUEST_PREOPT_SYSTEMUI=SKIP error={e}");
        }
    }
    Ok(())
}

fn notify_host_boot_completed(_host_mount_namespace: &Path, pid: Option<u32>) {
    let message = match pid {
        Some(pid) => format!("ApexService::markBootCompleted (system_server pid={pid})"),
        None => "ApexService::markBootCompleted".to_string(),
    };
    let host_ns_path = "/proc/1/ns/mnt";
    let Ok(host_mnt) = File::open(host_ns_path) else {
        eprintln!("Guest host notify failed: open {host_ns_path}");
        return;
    };
    let host_fd = host_mnt.as_raw_fd();
    let mut command = std::process::Command::new("/system/bin/cmd");
    command.args([
        "activity",
        "broadcast",
        "-a",
        "alyac.android.ssalsurface.ACTION_GUEST_BOOT_COMPLETED",
        "-n",
        "alyac.android.ssalsurface/.BootDebugNotificationReceiver",
        "--es",
        "message",
        &message,
    ]);
    unsafe {
        command.pre_exec(move || {
            if libc::setns(host_fd, libc::CLONE_NEWNS) != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    match command.output() {
        Ok(output) => {
            println!(
                "GUEST_HOST_NOTIFY status={} stdout={} stderr={}",
                output.status,
                String::from_utf8_lossy(&output.stdout).trim(),
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        Err(error) => {
            eprintln!("Guest host notify spawn failed: {error}");
        }
    }
}

fn system_server_boot_completed(stderr: &str, pid: u32) -> bool {
    let pid = pid.to_string();
    stderr.lines().any(|line| {
        line.split_whitespace().nth(2) == Some(pid.as_str())
            && line
                .split_once(" SystemServerTiming: ")
                .or_else(|| line.split_once(" ActivityManagerTiming: "))
                .is_some_and(|(_, timing)| timing.starts_with("OnBootPhase_1000 took to complete:"))
    })
}

fn report_system_server_display_progress(root: &Path, pid: u32) -> io::Result<(bool, bool)> {
    let stderr = fs::read(root.parent().unwrap().join("phase7b/stderr.log"))?;
    let text = String::from_utf8_lossy(&stderr);
    let (display, ready) = system_server_display_progress(&text, pid);
    let boot_completed = system_server_boot_completed(&text, pid);
    println!("GUEST_DMS_DEFAULT_DISPLAY pid={pid} phase_returned={display}");
    println!("GUEST_SYSTEM_READY pid={pid} phase_returned={ready}");
    println!("GUEST_BOOT_COMPLETED pid={pid} phase_returned={boot_completed}");
    Ok((ready, boot_completed))
}

fn adbd_requested(start_system_server: bool) -> bool {
    start_system_server && !crate::guest::disabled("ADBD")
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify(
    mounts: &mut Mounts,
    root: &Path,
    userdata: &Path,
    phase6a: bool,
    phase6b: bool,
    phase7a: bool,
    host_mount_namespace: &Path,
    profile_dir: &Path,
    admission: &mut Option<File>,
) -> io::Result<()> {
    let start_system_server = system_server_requested(
        phase7a,
        ssal::guest_policy::runtime::load(root)?.is_some(),
    )?;
    let apex_check_only = std::env::var_os("SSAL_GUEST_APEX_CHECK_ONLY").is_some();
    let system_server_graphics = graphics_system_server_requested();
    let suspend_enabled = system_suspend::enabled();
    let installd_probe = phase7a && installd_probe_requested();
    if installd_probe && (start_system_server || apex_check_only || suspend_enabled) {
        return Err(io::Error::other("Guest installd probe requires an isolated service run"));
    }
    if start_system_server && std::env::var_os("SSAL_PHASE7FB_FORK").is_some() {
        return Err(io::Error::other(
            "SystemServer bring-up cannot use the app fork diagnostic",
        ));
    }
    let phase7i_property_tests = std::env::var_os("SSAL_PHASE7I_PROPERTIES").is_some();
    if ssal::guest_policy::runtime::load(root)?.is_some()
        && [
            "SSAL_PHASE7FC_BYPASS_SETCONTEXT",
            "SSAL_PHASE8B3B_NOOP",
            "SSAL_PHASE8B3D_SAME_CONTEXT",
            "SSAL_PHASE8B5_ONCE",
        ]
        .iter()
        .any(|key| std::env::var_os(key).is_some())
    {
        return Err(io::Error::other(
            "profile SELinux mapping cannot use fixed-SID or SELinux-bypass diagnostic runtimes",
        ));
    }
    let system_server_preflight = system_server_preflight::enabled()?;
    let runtime_sid = system_server_runtime_sid::enabled(phase7a)?;
    let use_initrc = match std::env::var_os("SSAL_GUEST_INITRC").as_deref() {
        None => false,
        Some(value) if value == "1" && phase7a && !runtime_sid => true,
        _ => return Err(io::Error::other(
            "SSAL_GUEST_INITRC=1 requires the Guest Zygote worker with its normal launch path",
        )),
    };
    if system_server_preflight
        && (!phase7a
            || [
                "SSAL_PHASE8B3B_NOOP",
                "SSAL_PHASE8B3D_TRACE",
                "SSAL_PHASE8B3D_SAME_CONTEXT",
            ]
            .iter()
            .any(|key| std::env::var_os(key).is_some()))
    {
        return Err(io::Error::other(
            "8B-4B-1 requires Phase 7I and unmodified Guest SELinux libraries",
        ));
    }
    if fs::read_to_string("/sys/fs/selinux/enforce")?.trim() != "1" {
        return Err(io::Error::other("Host global Enforcing required"));
    }
    isolated(root, userdata)?;
    let adbd_enabled = phase7a
        && adbd_requested(start_system_server)
        && root.join("apex/com.android.adbd/bin/adbd").is_file();
    let mut adb_host_listener = if adbd_enabled {
        Some(net::bind_adb_host_listener(profile_dir)?)
    } else {
        None
    };
    if phase7a {
        let host_net_namespace = fs::read_link("/proc/1/ns/net")?;
        if unsafe { libc::unshare(libc::CLONE_NEWNET) } != 0 {
            return Err(io::Error::other(format!(
                "Guest Zygote network namespace: {}",
                io::Error::last_os_error()
            )));
        }
        let guest_net_namespace = fs::read_link("/proc/self/ns/net")?;
        if host_net_namespace == guest_net_namespace {
            return Err(io::Error::other(
                "Guest Zygote still shares Host abstract socket namespace",
            ));
        }
        println!(
            "Guest Zygote network namespace isolated: Host={} Guest={}",
            host_net_namespace.display(),
            guest_net_namespace.display()
        );
    }
    let _guest_veth_peer_ns = if phase7a {
        let peer_ns = net::setup_guest_veth()?;
        println!("Guest virtual ethernet ready: eth0 (veth, UP|RUNNING)");
        Some(peer_ns)
    } else {
        None
    };
    let runtime = crate::guest::mount::directory(root, "run/ssal", 0o755)?;
    let bin = std::env::current_exe()?.parent().unwrap().to_owned();
    if start_system_server || apex_check_only {
        crate::guest::init::binder_service::APEX.install(mounts, root, &bin)?;
    }
    if start_system_server {
        health::SERVICE.install(mounts, root, &bin)
            .map_err(|error| io::Error::other(format!("install Guest Health HAL: {error}")))?;
        gatekeeper::SERVICE.install(mounts, root, &bin)
            .map_err(|error| io::Error::other(format!("install Guest GateKeeper HAL: {error}")))?;
        keymint::SERVICE.install(mounts, root, &bin)
            .map_err(|error| io::Error::other(format!("install Guest KeyMint HAL: {error}")))?;
        if bin.join("ssal-vold").is_file() {
            crate::guest::init::binder_service::VOLD.install(mounts, root, &bin)?;
        }
        if bin.join("ssal-netd").is_file() {
            crate::guest::init::binder_service::NETD.install(mounts, root, &bin)?;
        }
        if bin.join("ssal-lmkd").is_file() {
            let plan = ssal::guest_policy::runtime::load(root)?
                .ok_or_else(|| io::Error::other("Guest LMKD requires Guest SELinux policy"))?;
            let target = root.join("run/ssal/ssal-lmkd");
            File::create(&target)?;
            ssal::guest_policy::runtime::set_label(&target, &plan.context("lmkd_exec", false)?)?;
            ssal::guest_policy::runtime::bind_file(mounts, root, &bin.join("ssal-lmkd"), &target)?;
        }
        if bin.join("ssal-virtual-audio").is_file() {
            let plan = ssal::guest_policy::runtime::load(root)?
                .ok_or_else(|| io::Error::other("Virtual Audio HAL requires Guest SELinux policy"))?;
            let target = root.join("run/ssal/ssal-virtual-audio");
            File::create(&target)?;
            ssal::guest_policy::runtime::set_label(&target, &plan.context("audioserver_exec", false)?)?;
            ssal::guest_policy::runtime::bind_file(mounts, root, &bin.join("ssal-virtual-audio"), &target)?;
        }
    }
    if suspend_enabled {
        system_suspend::SERVICE.install(mounts, root, &bin)?;
    }
    let mut runtime_bins = vec![
        "ssal-binder-ipc",
        "ssal-phase2-log.so",
        "ssal-zygote-diag.so",
        "ssal-property-service",
    ];
    let ashmem_probe = std::env::var_os("SSAL_ASHMEM_PROBE").is_some();
    if ashmem_probe {
        runtime_bins.push("ssal-ashmem-probe");
    }
    if start_system_server {
        runtime_bins.push("ssal-zygote-fd-reopen.so");
    }
    if std::env::var_os("SSAL_TRACE_GUEST_SIGABRT").is_some() {
        runtime_bins.push("ssal-abort-trace.so");
    }
    if phase7a && std::env::var_os("SSAL_PHASE8B3B_NOOP").is_some() {
        runtime_bins.extend(["ssal-zygote-selinux-noop.so", "ssal-selinux-startup-probe"]);
    }
    for name in runtime_bins {
        if name == "ssal-zygote-diag.so" && !phase7a {
            continue;
        }
        let target = runtime.join(name);
        File::create(&target)?;
        ssal::guest_policy::runtime::bind_file(mounts, root, &bin.join(name), &target)?;
        if name == "ssal-binder-ipc" {
            let helper = File::open(&target)?;
            println!(
                "Guest ssal-binder-ipc helper mode={:o} label={}",
                helper.metadata()?.mode() & 0o7777,
                ssal::unix::image_context(&helper)?
            );
        }
    }
    let aidl_server = runtime.join("ssal-binder-ipc-server");
    File::create(&aidl_server)?;
    let plan = ssal::guest_policy::runtime::load(root)?
        .ok_or_else(|| io::Error::other("Guest SELinux plan missing for AIDL server"))?;
    if start_system_server || system_server_graphics {
        graphics::install_vintf(mounts, root, &plan, system_server_graphics, start_system_server)?;
        crate::guest::concurrent::device_vintf::install_overlay(mounts, root, &plan)?;
        crate::guest::concurrent::device_vintf::install_unavailable_features(mounts, root, &plan)?;
    }
    if system_server_graphics {
        let target = root.join(hwbinder::COMPOSER.trim_start_matches('/'));
        File::create(&target)?;
        ssal::guest_policy::runtime::set_label(&target, &plan.context("system_file", false)?)?;
        ssal::guest_policy::runtime::bind_file(
            mounts,
            root,
            &bin.join("ssal-virtual-composer"),
            &target,
        )?;
        if bin.join("input-injector.jar").is_file() {
            let jar_target = root.join("run/ssal/input-injector.jar");
            File::create(&jar_target)?;
            ssal::guest_policy::runtime::set_label(
                &jar_target,
                &plan.context("system_file", false)?,
            )?;
            ssal::guest_policy::runtime::bind_file(
                mounts,
                root,
                &bin.join("input-injector.jar"),
                &jar_target,
            )?;
        }
    }
    ssal::guest_policy::runtime::set_label(
        &aidl_server,
        &plan.context("aidl_lazy_test_server_exec", false)?,
    )?;
    ssal::guest_policy::runtime::bind_file(mounts, root, &bin.join("ssal-binder-ipc"), &aidl_server)?;
    let aidl_server_file = File::open(&aidl_server)?;
    println!(
        "Guest ssal-binder-ipc server mode={:o} label={}",
        aidl_server_file.metadata()?.mode() & 0o7777,
        ssal::unix::image_context(&aidl_server_file)?
    );
    if phase7a && std::env::var_os("SSAL_PHASE8B3D_SAME_CONTEXT").is_some() {
        mounts.bind(
            &bin.join("ssal-libselinux-same-context.so"),
            &root.join("system/lib64/libselinux.so"),
            true,
            false,
        )?;
    }
    let mut binder = crate::binder_probe::Session::new();
    let mut hw_driver = crate::guest::binder::Session::new();
    if system_server_preflight {
        system_server_preflight::prepare(mounts, root, &bin)?;
    }
    let mut property_service = None;
    let mut shell_environment = None;
    let result = (|| {
        {
            property_service = Some(start_property_service(
                mounts,
                root,
                &bin,
                host_mount_namespace,
                use_initrc,
            )?);
            crate::guest::mount::seal_system(root)?;
            shell_environment = Some(crate::guest::environment::Published::new(
                profile_dir,
                root,
                admission.take(),
            )?);
            let property_script = if !phase7i_property_tests {
                r#"set -eu
sdk=$(getprop ro.build.version.sdk)
abi=$(getprop ro.product.cpu.abilist64)
ready=$(getprop servicemanager.ready)
echo "Guest private properties sdk=$sdk abi64=$abi servicemanager.ready=$ready"
test "$sdk" = 36
test "$abi" = arm64-v8a
test "$ready" = false
echo SSAL_GUEST_PRIVATE_PROPERTIES=PASS
"#
            } else if std::env::var_os("SSAL_PHASE7I_VERIFY_PERSIST").is_some() {
                r#"set -eu
test "$(getprop ro.build.version.sdk)" = 36
test "$(getprop servicemanager.ready)" = false
test "$(getprop persist.ssal_probe)" = 7
test -z "$(getprop sys.ssal_probe)"
echo SSAL_PROPERTY_RESTORE=PASS
"#
            } else {
                r#"set -eu
test "$(getprop ro.build.version.sdk)" = 36
test "$(getprop ro.product.cpu.abilist64)" = arm64-v8a
test "$(getprop servicemanager.ready)" = false
setprop sys.ssal_probe phase7i
test "$(getprop sys.ssal_probe)" = phase7i
setprop persist.ssal_probe 7
test "$(getprop persist.ssal_probe)" = 7
echo SSAL_PROPERTY_BIONIC=PASS
"#
            };
            let property_output = run(root, "/system/bin/sh", &["-c", property_script], 1000)?;
            let expected_marker = if phase7i_property_tests {
                "SSAL_PROPERTY_"
            } else {
                "SSAL_GUEST_PRIVATE_PROPERTIES=PASS"
            };
            if !property_output.contains(expected_marker) {
                return Err(io::Error::other("Guest Bionic property evidence missing"));
            }
        }
        if ashmem_probe {
            let output = run(
                root,
                "/system/bin/bootstrap/linker64",
                &["/run/ssal/ssal-ashmem-probe"],
                1000,
            )?;
            println!("Guest ashmem diagnostic (no Zygote/SystemServer launched):\n{output}");
            return Ok(());
        }
        let (major, minor, _) = binder.provision(root)?;
        let device = binder.private_device()?;
        if unsafe { libc::fchmod(device.as_raw_fd(), 0o666) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let binder = fs::metadata(root.join("dev/binder"))?;
        println!(
            "Guest private Binder DAC uid={} gid={} mode={:04o}",
            binder.uid(),
            binder.gid(),
            binder.mode() & 0o7777
        );
        let area = fs::metadata(root.join("dev/__properties__"))?;
        let host = fs::metadata("/dev/__properties__")?;
        if (area.dev(), area.ino()) == (host.dev(), host.ino()) {
            return Err(io::Error::other("Host property area selected"));
        }
        // Linkerconfig must see Guest properties and only the private Binder alias.
        run(
            root,
            crate::guest::runtime::linkerconfig::linkerconfig_binary(root)?,
            &["--target", "/linkerconfig"],
            0,
        )?;
        let sentinel = File::open("/data")?;
        if unsafe { libc::fcntl(sentinel.as_raw_fd(), libc::F_SETFD, 0) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let guest_local = crate::guest::mount::directory(root, "data/local", 0o751)?;
        fs::set_permissions(&guest_local, fs::Permissions::from_mode(0o751))?;
        let guest_tmp = crate::guest::mount::directory(root, "data/local/tmp", 0o1771)?;
        let guest_tmp_c = std::ffi::CString::new(guest_tmp.as_os_str().as_encoded_bytes())?;
        if unsafe { libc::chown(guest_tmp_c.as_ptr(), 0, 1000) } != 0 {
            return Err(io::Error::last_os_error());
        }
        fs::set_permissions(&guest_tmp, fs::Permissions::from_mode(0o1771))?;
        if let Some(plan) = ssal::guest_policy::runtime::load(root)? {
            ssal::guest_policy::runtime::set_label(
                &guest_tmp,
                &plan.context("shell_data_file", false)?,
            )?;
        }
        let local_metadata = fs::metadata(&guest_local)?;
        let tmp_metadata = fs::metadata(&guest_tmp)?;
        println!(
            "Guest tmp DAC local={}:{}:{:04o} tmp={}:{}:{:04o}",
            local_metadata.uid(),
            local_metadata.gid(),
            local_metadata.mode() & 0o7777,
            tmp_metadata.uid(),
            tmp_metadata.gid(),
            tmp_metadata.mode() & 0o7777
        );
        println!("Guest FD pre-exec: injected Host /data fd={}; root command closes inherited identities and marks later FDs CLOEXEC", sentinel.as_raw_fd());
        let shell_context = ssal::guest_policy::runtime::load(root)?
            .map(|plan| plan.context("shell", true))
            .transpose()?
            .unwrap_or_else(|| "u:r:ssal_guest_probe:s0".into());
        let shell_script = format!(
            r#"set -eu
echo "Guest property snapshot sdk=$(getprop ro.build.version.sdk) abilist=$(getprop ro.product.cpu.abilist) abi64=$(getprop ro.product.cpu.abilist64) zygote=$(getprop ro.zygote) gl_preload=$(getprop ro.zygote.disable_gl_preload) servicemanager.ready=$(getprop servicemanager.ready)"
test "$(getprop ro.build.version.sdk)" = 36
test "$(getprop ro.product.cpu.abilist64)" = arm64-v8a
test "$(getprop ro.zygote.disable_gl_preload)" = 1
test "$(getprop ro.product.cpu.abilist)" = "$(getprop ro.product.cpu.abilist64)"
test -z "$(getprop ro.product.cpu.abilist32)"
test "$(getprop servicemanager.ready)" = false
if test -z "$(getprop ro.boot.serialno)"; then echo "Guest boot serial property=withheld"; else echo "Guest boot serial property=unexpectedly-present"; exit 1; fi
test -e /run/ssal/property-service.json
echo "Guest property-service marker=present"
test -r /run/ssal/ssal-binder-ipc
test -x /run/ssal/ssal-binder-ipc
echo "Guest ssal-binder-ipc access=PASS"
for fd in /proc/$$/fd/*; do
    target=$(readlink "$fd") || continue
    echo "Guest post-exec fd=$fd target=$target"
    case "$target" in /dev/null|pipe:*|/system/bin/sh|/system/bin/mksh) ;; *) exit 31;; esac
done
test "$(cat /proc/$$/attr/current)" = "{shell_context}"
umask 077
marker=/data/local/tmp/ssal-launcher-$$
set -C
printf guest > "$marker"
test "$(cat "$marker")" = guest
rm "$marker"
set +e
setprop ctl.start ssal_must_not_reach_host_init
rc=$?
set -e
echo "Guest ctl.start return=$rc"
test "$rc" != 0
echo SSAL_GUEST_SHELL_PROPERTY_FD=PASS
"#
        );
        let shell = run(root, "/system/bin/sh", &["-c", &shell_script], 1000)?;
        if !shell.contains("SSAL_GUEST_SHELL_PROPERTY_FD=PASS") {
            return Err(io::Error::other("shell evidence missing"));
        }
        drop(sentinel);
        let apex_enabled = start_system_server || apex_check_only;
        let init_plan = use_initrc
            .then(|| initrc::Plan::load(root, &read_initrc_properties(root)?))
            .transpose()?;
        let mut boot = init_plan.as_ref().map(|plan| plan.boot(apex_enabled));
        if let Some(queue) = &mut boot {
            let next = queue.next_start(&read_initrc_properties(root)?)?;
            if next != Some(BootService::Servicemanager) {
                return Err(io::Error::other(format!(
                    "Guest initrc requires servicemanager before other boot services, got {next:?}"
                )));
            }
        }
        let mut manager = Service::start(
            root,
            BootService::Servicemanager.executable(),
            &[],
            "servicemanager",
            1000,
            Some(GUEST_PROBE_CONTEXT),
            &[],
        )?;
        manager.wait_guest_servicemanager_property(root, "not run")?;
        println!("GUEST_SERVICEMANAGER_PROPERTY=PASS value=true");
        let guest_binder = fs::metadata(root.join("dev/binder"))?.rdev();
        manager.wait_guest_context_manager(root, guest_binder)?;
        let mut server = Service::start(
            root,
            "/run/ssal/ssal-binder-ipc-server",
            &["server"],
            "aidl-server",
            1000,
            Some(AIDL_SERVER_CONTEXT),
            &[("LD_LIBRARY_PATH", "/system/lib64/bootstrap:/system/lib64")],
        )?;
        if let Err(error) = server.wait_text("\"event\":\"registered\"") {
            manager.readiness_diagnostics(
                root,
                "Guest AIDL service registration failed",
                "not run",
            );
            return Err(error);
        }
        let ipc = match run(
            root,
            "/system/bin/bootstrap/linker64",
            &["/run/ssal/ssal-binder-ipc", "client"],
            1000,
        ) {
            Ok(ipc) => ipc,
            Err(error) => {
                manager.readiness_diagnostics(root, "Guest AIDL service lookup failed", "failed");
                return Err(error);
            }
        };
        if !ipc.contains("\"event\":\"ipc_passed\"") {
            manager.readiness_diagnostics(
                root,
                "Guest AIDL service lookup returned no success event",
                "failed",
            );
            return Err(io::Error::other("AIDL IPC success evidence missing"));
        }
        println!("GUEST_SERVICEMANAGER_READINESS=PASS property=servicemanager.ready:true context_manager=Guest_handle_0 service_lookup=aidl_lazy_test_1 private_binder={major}:{minor}");
        println!("PHASE5B=PASS shell=PASS private_aidl=PASS properties=PASS host_control_socket=ABSENT private_binder={major}:{minor}");
        if !system_server_graphics
            && std::env::var("SSAL_Y702_SURFACEFLINGER_RETEST").as_deref() == Ok("1")
        {
            retest_surfaceflinger(root, guest_binder, None)?;
        }
        let mut apexservice = if apex_enabled {
            let apex = &crate::guest::init::binder_service::APEX;
            if let Some(queue) = &mut boot {
                let next = queue.next_start(&read_initrc_properties(root)?)?;
                if next != Some(BootService::Apexd) {
                    return Err(io::Error::other(format!(
                        "Guest initrc requires apexd before Zygote, got {next:?}"
                    )));
                }
                println!("Guest initrc map apexd -> {}", apex.executable);
            }
            let service = apex.start(root, guest_binder)?;
            apex.check(root, guest_binder, use_initrc)?;
            Some(service)
        } else { None };
        if suspend_enabled {
            let pid = manager.pid();
            let proc = PathBuf::from(format!("/proc/{pid}"));
            let sid = fs::read_to_string(proc.join("attr/current"))?;
            let namespace = fs::read_link(proc.join("ns/mnt"))?;
            let path = "apex/apex-info-list.xml";
            let list = fs::metadata(proc.join("root").join(path))?;
            let guest = fs::metadata(root.join(path))?;
            if namespace == host_mount_namespace || (list.dev(), list.ino()) != (guest.dev(), guest.ino()) {
                return Err(io::Error::other("Guest servicemanager APEX mount identity mismatch"));
            }
            println!(
                "Guest VINTF reader pid={pid} sid={} mount_namespace={} apex_info_dev={} apex_info_ino={}",
                sid.trim_end_matches(['\0', '\n']), namespace.display(), list.dev(), list.ino()
            );
        }
        let mut suspend = suspend_enabled
            .then(|| system_suspend::start(root, &bin, guest_binder))
            .transpose()?;
        let mut boot_services = Vec::new();
        if start_system_server {
            prepare_aconfig_storage(root)?;
            health::start(root, &bin, guest_binder, &mut boot_services)?;
            let auth_token_key = keymint::random_bytes::<32>()?;
            keymint::start(root, guest_binder, &auth_token_key, &mut boot_services)?;
            gatekeeper::start(root, guest_binder, &auth_token_key, &mut boot_services)?;
            prepare_security_daemon_dir(
                root,
                "data/misc/gatekeeper",
                1000,
                1000,
                0o700,
                "gatekeeper_data_file",
            )?;
            prepare_security_daemon_dir(
                root,
                "data/misc/adb",
                1000,
                2000,
                0o2750,
                "adb_data_file",
            )?;
            boot_services.push(Service::start(
                root,
                "/system/bin/gatekeeperd",
                &["/data/misc/gatekeeper"],
                "gatekeeperd",
                1000,
                None,
                &[],
            )?);
        } else if adbd_enabled {
            prepare_security_daemon_dir(
                root,
                "data/misc/adb",
                1000,
                2000,
                0o2750,
                "adb_data_file",
            )?;
        }
        if adbd_enabled {
            if let Some((listener, port)) = adb_host_listener.take() {
                net::spawn_adb_relay(listener, port);
            }
        }
        if system_server_graphics {
            let (major, minor) = hw_driver.provision_hwbinder(root)?;
            let hwbinder_rdev = libc::makedev(major, minor);
            let mut hwmanager = Service::start(
                root,
                hwbinder::MANAGER,
                &[],
                "hwservicemanager",
                1000,
                None,
                &[],
            )?;
            hwbinder::wait_manager(root, &mut hwmanager, &plan, host_mount_namespace, hwbinder_rdev)?;
            boot_services.push(hwmanager);
            if start_system_server {
                prepare_security_daemon_dir(
                    root,
                    "data/misc/keystore",
                    1017,
                    1017,
                    0o700,
                    "keystore_data_file",
                )?;
                boot_services.push(Service::start(
                    root,
                    "/system/bin/keystore2",
                    &["/data/misc/keystore"],
                    "keystore2",
                    1017,
                    None,
                    &[],
                )?);
            }
            boot_services.push(Service::start(
                root,
                hwbinder::GRAPHICS_ALLOCATOR,
                &[],
                "graphics-allocator",
                1000,
                None,
                &[],
            )?);
            boot_services.push(hwbinder::start_composer(
                root,
                &plan,
                guest_binder,
                hwbinder_rdev,
            )?);
            boot_services.push(Service::start(
                root,
                "/system/bin/surfaceflinger",
                &[],
                "surfaceflinger",
                1000,
                None,
                &[],
            )?);
            let deadline = Instant::now() + Duration::from_secs(15);
            loop {
                check_boot_services(&mut boot_services)?;
                let registry = run(
                    root,
                    "/system/bin/sh",
                    &["-c", "service check SurfaceFlinger; service check SurfaceFlingerAIDL"],
                    2000,
                )?;
                if registry.contains("Service SurfaceFlinger: found")
                    && registry.contains("Service SurfaceFlingerAIDL: found")
                {
                    println!("GUEST_SURFACEFLINGER_READY=PASS {registry:?}");
                    break;
                }
                if Instant::now() >= deadline {
                    return Err(io::Error::other(format!(
                        "Guest SurfaceFlinger registration timed out: {registry}"
                    )));
                }
                std::thread::sleep(Duration::from_millis(200));
            }
            boot_services.push(start_data_service(root, INSTALLD, "installd")?);
            if bin.join("ssal-vold").is_file() {
                boot_services.push(
                    crate::guest::init::binder_service::VOLD.start_with_hwbinder(
                        root,
                        guest_binder,
                        Some(hwbinder_rdev),
                    )?,
                );
            }
            if bin.join("ssal-netd").is_file() {
                boot_services.push(
                    crate::guest::init::binder_service::NETD.start_with_hwbinder(
                        root,
                        guest_binder,
                        Some(hwbinder_rdev),
                    )?,
                );
            }
            if bin.join("ssal-lmkd").is_file() {
                boot_services.push(start_lmkd(root)?);
            }
            struct ChildGuard(Option<std::process::Child>);
            impl Drop for ChildGuard {
                fn drop(&mut self) {
                    if let Some(mut child) = self.0.take() {
                        let _ = child.kill();
                        let _ = child.wait();
                    }
                }
            }
            let mut _host_audio_bridge = ChildGuard(None);
            if bin.join("ssal-virtual-audio").is_file() {
                let audio_host_bin = bin.join("ssal-audio-host");
                if audio_host_bin.is_file() {
                    let sock_path = root.join("run/ssal/audio.sock");
                    let mut child = Command::new(&audio_host_bin)
                        .arg("serve")
                        .arg(&sock_path)
                        .stdout(Stdio::piped())
                        .stderr(Stdio::inherit())
                        .spawn()?;
                    if let Some(stdout) = child.stdout.take() {
                        use std::io::{BufRead, BufReader};
                        let mut line = String::new();
                        let _ = BufReader::new(stdout).read_line(&mut line);
                        if line.starts_with("host_audio_bridge_ready=") {
                            println!("Host audio bridge ready: {}", sock_path.display());
                        }
                    }
                    _host_audio_bridge.0 = Some(child);
                }
                let hw_rdev_str = hwbinder_rdev.to_string();
                let mut vaudio = Service::start(
                    root,
                    "/run/ssal/ssal-virtual-audio",
                    &["serve", &hw_rdev_str],
                    "virtual-audio",
                    1041,
                    None,
                    &[],
                )?;
                vaudio.wait_text(
                    "guest_hwbinder_registered=android.hardware.audio@7.0::IDevicesFactory/default",
                )?;
                boot_services.push(vaudio);
                boot_services.push(Service::start(
                    root,
                    "/system/bin/audioserver",
                    &[],
                    "audioserver",
                    1041,
                    Some(GUEST_PROBE_CONTEXT),
                    &[],
                )?);
            }
        }
        if installd_probe {
            probe_installd(root, userdata, host_mount_namespace, guest_binder)?;
        } else if phase7a {
            if let Some(queue) = &mut boot {
                let mut properties = read_initrc_properties(root)?;
                if apexservice.is_some() {
                    // The APEX check confirmed the write, which the shell may not be allowed to read.
                    properties
                        .entry("apexd.status".into())
                        .or_insert_with(|| "activated".into());
                }
                let next = queue.next_start(&properties)?;
                if next != Some(BootService::Zygote) {
                    return Err(io::Error::other(format!(
                        "Guest initrc did not request Zygote, got {next:?}"
                    )));
                }
            }
            let controlled_fork = std::env::var_os("SSAL_PHASE7FB_FORK").is_some();
            let app_trace = std::env::var_os("SSAL_PHASE8B3D_TRACE").is_some();
            if controlled_fork && app_trace {
                fork_probe::prepare(mounts, root, &bin, true)?;
            }
            if std::env::var_os("SSAL_PHASE8B3B_NOOP").is_some() {
                // App trace uses the same overlay as Zygote; startup diagnostic uses stock rules.
                for probe_uid in if app_trace {
                    &[0, 1000, 10000][..]
                } else {
                    &[1000][..]
                } {
                    let output = crate::guest::process::command::run_with_timeout(
                        command(
                            root,
                            "/run/ssal/ssal-selinux-startup-probe",
                            *probe_uid,
                            Some(GUEST_PROBE_CONTEXT),
                        )?
                        .env("LD_LIBRARY_PATH", "/run/ssal:/system/lib64")
                        .env("LD_PRELOAD", "/run/ssal/ssal-zygote-selinux-noop.so"),
                        "SELinux startup diagnostic",
                        Duration::from_secs(10),
                    )?;
                    println!(
                        "Guest isolated SELinux startup diagnostic exit={}\n{}{}",
                        output.status,
                        String::from_utf8_lossy(&output.stdout),
                        String::from_utf8_lossy(&output.stderr)
                    );
                    if !output.status.success() {
                        return Err(io::Error::other(
                            "SELinux startup diagnostic failed to execute",
                        ));
                    }
                }
            }
            if controlled_fork && !app_trace {
                fork_probe::prepare(mounts, root, &bin, true)?;
            }
            if system_server_preflight {
                system_server_preflight::run(root, &bin)?;
            }
            if runtime_sid {
                system_server_runtime_sid::prepare(mounts, root, &bin)?;
            }
            crate::guest::mount::directory(root, "data/dalvik-cache", 0o771)?;
            if let Some(plan) = ssal::guest_policy::runtime::load(root)? {
                ssal::guest_policy::runtime::set_label(
                    &root.join("data/dalvik-cache"),
                    &plan.context("dalvikcache_data_file", false)?,
                )?;
            }
            // The Guest shell cannot getattr the protected Zygote socket type.
            let zygote_socket = root.join("dev/socket/zygote");
            match fs::symlink_metadata(&zygote_socket) {
                Ok(_) => return Err(io::Error::other("Guest Zygote socket already exists")),
                Err(error) if error.kind() == io::ErrorKind::NotFound => (),
                Err(error) => return Err(error),
            }
            if fs::metadata(root.join("system/bin/app_process64"))?
                .permissions()
                .mode()
                & 0o111
                == 0
            {
                return Err(io::Error::other("Guest Zygote binary is not executable"));
            }
            let binary = run(
                root,
                "/system/bin/sh",
                &[
                    "-c",
                    "set -eu; stat -c '%n %s %a %u %g' /system/bin/app_process64; sha256sum /system/bin/app_process64; getprop ro.product.cpu.abilist64; getprop ro.zygote.disable_gl_preload",
                ],
                0,
            )?;
            println!("Guest Zygote binary preflight:\n{binary}");
            let classpaths = derive_guest_classpath(root)?;
            if system_server_graphics && !runtime_sid {
                preopt_system_apps(root, profile_dir, &classpaths)?;
            }
            let boot_classpath = if controlled_fork {
                format!("{}:/system/framework/am.jar", classpaths.boot)
            } else {
                classpaths.boot.clone()
            };
            let mut zygote_env = vec![
                ("ANDROID_BOOTLOGO", "1"),
                ("ANDROID_ASSETS", "/system/app"),
                ("EXTERNAL_STORAGE", "/sdcard"),
                (
                    "LD_LIBRARY_PATH",
                    // Let the generated ART namespace own libart and its runtime singleton.
                    "/run/ssal:/apex/com.android.adbd/lib64:/system/lib64:/apex/com.android.os.statsd/lib64:/apex/com.android.i18n/lib64",
                ),
                ("BOOTCLASSPATH", boot_classpath.as_str()),
                ("SYSTEMSERVERCLASSPATH", classpaths.system_server.as_str()),
            ];
            if let Some(classpath) = classpaths.dex2oat.as_deref() {
                zygote_env.push(("DEX2OATBOOTCLASSPATH", classpath));
            }
            if let Some(jars) = classpaths.standalone_system_server.as_deref() {
                zygote_env.push(("STANDALONE_SYSTEMSERVER_JARS", jars));
            }
            if system_server_graphics && !runtime_sid {
                let mut artd_env = vec![
                    ("BOOTCLASSPATH", classpaths.boot.as_str()),
                    ("SYSTEMSERVERCLASSPATH", classpaths.system_server.as_str()),
                ];
                if let Some(classpath) = classpaths.dex2oat.as_deref() {
                    artd_env.push(("DEX2OATBOOTCLASSPATH", classpath));
                }
                boot_services.push(Service::start(
                    root,
                    ARTD,
                    &[],
                    "artd",
                    0,
                    Some(GUEST_PROBE_CONTEXT),
                    &artd_env,
                )?);
            }
            let mut input_injector: Option<Service> = None;
            if system_server_graphics && bin.join("input-injector.jar").is_file() {
                let shell_domain = &plan.types["shell"];
                let sock_dir_ctx = plan.context("socket_device", false)?;
                let sock_dir_type = sock_dir_ctx.split(':').nth(2).unwrap_or("socket_device");
                for rule in [
                    format!("allow {shell_domain} ksu unix_stream_socket {{ read write getattr connectto }}"),
                    format!("allow {shell_domain} {sock_dir_type} dir {{ search getattr }}"),
                    format!("allow {shell_domain} {sock_dir_type} sock_file {{ read write getattr }}"),
                ] {
                    let _ = Command::new("/data/adb/ksu/bin/ksud")
                        .args(["sepolicy", "patch", &rule])
                        .status();
                }
                if let Some(listener) = start_input_listener(&root.join("dev/socket/ssal-input.sock")) {
                    spawn_input_accept_relay(listener);
                    let mut injector_env = vec![
                        ("BOOTCLASSPATH", classpaths.boot.as_str()),
                        ("SYSTEMSERVERCLASSPATH", classpaths.system_server.as_str()),
                        ("CLASSPATH", "/run/ssal/input-injector.jar"),
                        (
                            "LD_LIBRARY_PATH",
                            "/run/ssal:/apex/com.android.adbd/lib64:/system/lib64:/apex/com.android.os.statsd/lib64:/apex/com.android.i18n/lib64",
                        ),
                    ];
                    if let Some(classpath) = classpaths.dex2oat.as_deref() {
                        injector_env.push(("DEX2OATBOOTCLASSPATH", classpath));
                    }
                    input_injector = Some(Service::start(
                        root,
                        "/system/bin/sh",
                        &[
                            "-c",
                            "exec /system/bin/app_process64 /system/bin --nice-name=ssal-input-injector dev.ssal.input.InputInjector",
                        ],
                        "input-injector",
                        2000,
                        None,
                        &injector_env,
                    )?);
                }
            }
            zygote_env.push(("SSAL_PHASE7I_PROPERTIES", "1"));
            if controlled_fork && std::env::var_os("SSAL_PHASE7FC_BYPASS_SETCONTEXT").is_some() {
                zygote_env.push(("SSAL_PHASE7FC_BYPASS_SETCONTEXT", "1"));
            }
            if runtime_sid {
                return system_server_runtime_sid::run(root, &bin, &zygote_env);
            }
            println!(
                "Guest Zygote launch socket=/dev/socket/zygote start_system_server={start_system_server} private_binder={major}:{minor}"
            );
            let args = zygote_args(controlled_fork, start_system_server);
            let mut zygote = Service::start(
                root,
                BootService::Zygote.executable(),
                &args,
                "guest-zygote",
                0,
                Some(GUEST_PROBE_CONTEXT),
                &zygote_env,
            )?;
            zygote.wait_for_socket(&root.join("dev/socket/zygote"))?;
            let system_server_pid = if start_system_server {
                Some(wait_for_system_server(root, &mut zygote)?)
            } else {
                None
            };
            let pid = zygote.child.id();
            let guest_root = fs::metadata(root)?;
            let process_root = fs::metadata(format!("/proc/{pid}/root"))?;
            if (guest_root.dev(), guest_root.ino()) != (process_root.dev(), process_root.ino()) {
                return Err(io::Error::other("Guest Zygote root identity mismatch"));
            }
            let domain = fs::read_to_string(format!("/proc/{pid}/attr/current"))?;
            let expected = ssal::guest_policy::runtime::load(root)?
                .map(|p| p.context("zygote", true))
                .transpose()?
                .unwrap_or_else(|| "u:r:ssal_guest_probe:s0".into());
            if domain.trim_matches('\0').trim() != expected {
                return Err(io::Error::other(format!(
                    "Guest Zygote domain mismatch: {domain:?}"
                )));
            }
            let status = fs::read_to_string(format!("/proc/{pid}/status"))?;
            let uid = status
                .lines()
                .find(|line| line.starts_with("Uid:"))
                .ok_or_else(|| io::Error::other("Guest Zygote UID missing"))?;
            if uid.split_whitespace().skip(1).any(|value| value != "0") {
                return Err(io::Error::other(format!("Guest Zygote is not root: {uid}")));
            }
            if fs::read_link(format!("/proc/{pid}/ns/net"))? != fs::read_link("/proc/self/ns/net")?
            {
                return Err(io::Error::other(
                    "Guest Zygote left its isolated network namespace",
                ));
            }
            let guest_binder = fs::metadata(root.join("dev/binder"))?.rdev();
            let host_binder = fs::metadata("/dev/binder")?.rdev();
            if guest_binder == host_binder {
                return Err(io::Error::other("Guest Binder resolves to Host Binder"));
            }
            let mut private_binder_fds = 0;
            for fd in fs::read_dir(format!("/proc/{pid}/fd"))? {
                let fd = fd?;
                let target = fs::read_link(fd.path())?;
                if target == Path::new("/dev/binder") {
                    if fs::metadata(fd.path())?.rdev() != guest_binder {
                        return Err(io::Error::other("Guest Zygote opened a non-Guest Binder"));
                    }
                    private_binder_fds += 1;
                }
            }
            println!(
                "Guest Zygote ready pid={pid} root=Guest uid=0 domain={} isolated_netns=true private_binder_fds={private_binder_fds}",
                domain.trim_matches('\0').trim()
            );
            let process_stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
            let starttime = process_stat
                .rsplit_once(") ")
                .and_then(|(_, fields)| fields.split_whitespace().nth(19))
                .ok_or_else(|| io::Error::other("Zygote starttime missing"))?;
            let socket = fs::metadata(root.join("dev/socket/zygote"))?;
            println!(
                "Guest Zygote socket file inode={} uid={} gid={} mode={:o}",
                socket.ino(),
                socket.uid(),
                socket.gid(),
                socket.mode() & 0o777
            );
            let environ = fs::read(format!("/proc/{pid}/environ"))?;
            let standalone_env_matches = match classpaths.standalone_system_server.as_deref() {
                Some(expected) => {
                    guest_env_value(&environ, "STANDALONE_SYSTEMSERVER_JARS")
                        == Some(expected.as_bytes())
                }
                None => guest_env_value(&environ, "STANDALONE_SYSTEMSERVER_JARS").is_none(),
            };
            if guest_env_value(&environ, "SYSTEMSERVERCLASSPATH")
                != Some(classpaths.system_server.as_bytes())
                || !standalone_env_matches
            {
                return Err(io::Error::other(
                    "Guest system-server classpath environment mismatch",
                ));
            }
            println!(
                "Guest Zygote classpath environment verified system_server_entries={} standalone_entries={}",
                classpaths.system_server.split(':').count(),
                classpaths
                    .standalone_system_server
                    .as_deref()
                    .map_or(0, |v| v.split(':').count())
            );
            let inherited_sockets: Vec<_> = environ
                .split(|b| *b == 0)
                .filter_map(|entry| {
                    [
                        b"ANDROID_SOCKET_zygote=".as_slice(),
                        b"ANDROID_SOCKET_usap_pool_primary=".as_slice(),
                    ]
                    .iter()
                    .find_map(|prefix| {
                        entry
                            .strip_prefix(*prefix)
                            .map(|fd| String::from_utf8_lossy(fd).into_owned())
                    })
                })
                .collect();
            if inherited_sockets.len() != 2 {
                return Err(io::Error::other(
                    "Guest inherited socket environment missing",
                ));
            }
            let mut socket_fds = Vec::new();
            for fd in fs::read_dir(format!("/proc/{pid}/fd"))? {
                let fd = fd?;
                if let Ok(target) = fs::read_link(fd.path()) {
                    if target.to_string_lossy().starts_with("socket:[") {
                        println!(
                            "Guest Zygote fd={} target={}",
                            fd.file_name().to_string_lossy(),
                            target.display()
                        );
                        if inherited_sockets
                            .contains(&fd.file_name().to_string_lossy().into_owned())
                        {
                            socket_fds.push((fd.file_name(), target));
                        }
                    }
                }
            }
            if socket_fds.len() != 2 {
                return Err(io::Error::other("Guest inherited socket FDs missing"));
            }
            for entry in environ
                .split(|b| *b == 0)
                .filter(|entry| entry.starts_with(b"ANDROID_SOCKET_"))
            {
                println!("Guest Zygote env={}", String::from_utf8_lossy(entry));
            }
            let observation_seconds = 360;
            let mut deadline = Instant::now() + Duration::from_secs(observation_seconds);
            let hold_after_boot = std::env::var("SSAL_HOLD_AFTER_BOOT_SECS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .filter(|&s| s > 0);
            let mut boot_hold_deadline: Option<Instant> = None;
            let mut observed_system_ready = false;
            let mut observed_apex_boot_completed = false;
            let mut watch_ticks: u32 = 0;
            while Instant::now() < deadline {
                crate::guest::process::supervision::check_interrupted()?;
                manager.drain_output()?;
                if manager.exited()? {
                    return Err(io::Error::other(
                        "Guest servicemanager exited during SystemServer residence",
                    ));
                }
                check_boot_services(&mut boot_services)?;
                if let Some(service) = input_injector.as_mut() {
                    let _ = service.drain_output();
                    if service.exited().unwrap_or(false) {
                        let status = service.exit_status().ok().flatten();
                        let log = fs::read_to_string(&service.log).unwrap_or_default();
                        eprintln!(
                            "GUEST_INPUT_INJECTOR=EXITED status={status:?} log={log:?}"
                        );
                        input_injector = None;
                    }
                }
                if use_initrc {
                    if let Some(service) = &mut property_service {
                        service.drain_output()?;
                        if service.exited()? {
                            return Err(io::Error::other("Guest property service exited during Zygote residence"));
                        }
                    }
                }
                if let Some(service) = &mut apexservice {
                    service.drain_output()?;
                    if !observed_apex_boot_completed
                        && service
                            .log_contains("guest_apex_call=markBootCompleted")
                            .unwrap_or(false)
                    {
                        observed_apex_boot_completed = true;
                        notify_host_boot_completed(host_mount_namespace, system_server_pid);
                    }
                    if service.exited()? {
                        return Err(io::Error::other("Guest apexservice exited during SystemServer residence"));
                    }
                }
                if let Some((service, broker)) = &mut suspend {
                    service.drain_output()?;
                    if service.exited()? || broker.exited()? {
                        return Err(io::Error::other("Guest SystemSuspend or Host Power Broker exited"));
                    }
                }
                if let Some(diagnostics) = &mut zygote.diagnostics {
                    diagnostics.tick()?;
                }
                if zygote.exited()? {
                    if let (true, Some(pid)) = (system_server_graphics, system_server_pid) {
                        zygote.tick_diagnostics()?;
                        let _ = report_system_server_display_progress(root, pid)?;
                    }
                    return Err(io::Error::other("Guest Zygote exited during residence"));
                }
                watch_ticks = watch_ticks.wrapping_add(1);
                if watch_ticks % 10 == 0 {
                    if let (true, Some(pid)) = (system_server_graphics, system_server_pid) {
                        zygote.tick_diagnostics()?;
                        if let Ok(stderr) = fs::read(root.parent().unwrap().join("phase7b/stderr.log")) {
                            let text = String::from_utf8_lossy(&stderr);
                            if !observed_system_ready && system_server_display_progress(&text, pid).1 {
                                observed_system_ready = true;
                                println!("GUEST_SYSTEM_READY pid={pid} phase_returned=true");
                            }
                            if boot_hold_deadline.is_none() && system_server_boot_completed(&text, pid) {
                                println!("GUEST_BOOT_COMPLETED pid={pid} phase_returned=true");
                                if let Some(secs) = hold_after_boot {
                                    println!("GUEST_HOLD_AFTER_BOOT secs={secs}");
                                    let until = Instant::now() + Duration::from_secs(secs);
                                    boot_hold_deadline = Some(until);
                                    if until > deadline {
                                        deadline = until;
                                    }
                                } else {
                                    break;
                                }
                            }
                        }
                    }
                }
                if boot_hold_deadline.is_some_and(|until| Instant::now() >= until) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            let end_stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
            let end_starttime = end_stat
                .rsplit_once(") ")
                .and_then(|(_, fields)| fields.split_whitespace().nth(19));
            if end_starttime != Some(starttime) {
                return Err(io::Error::other(
                    "Guest Zygote identity changed during residence",
                ));
            }
            if fs::metadata(root.join("dev/socket/zygote"))?.ino() != socket.ino() {
                return Err(io::Error::other(
                    "Guest Zygote socket changed during residence",
                ));
            }
            for (fd, target) in &socket_fds {
                if fs::read_link(format!("/proc/{pid}/fd/{}", fd.to_string_lossy()))
                    .ok()
                    .as_ref()
                    != Some(target)
                {
                    return Err(io::Error::other(
                        "Guest Zygote socket FD changed during residence",
                    ));
                }
            }
            crate::guest::cgroup::verify_guest_membership(pid)?;
            println!("Guest Zygote residence pid={pid} starttime={starttime} seconds={observation_seconds} membership=verified");
            if let Some(expected) = system_server_pid {
                capture_stalled_system_server_dump(root, &mut zygote, expected)?;
                if wait_for_system_server(root, &mut zygote)? != expected {
                    return Err(io::Error::other("Guest SystemServer identity changed"));
                }
                println!("PHASE7A_SYSTEM_SERVER=PASS framework_entry=true residence_seconds={observation_seconds}");
                if system_server_graphics {
                    zygote.tick_diagnostics()?;
                    let (ready, boot_completed) =
                        report_system_server_display_progress(root, expected)?;
                    if !ready || !boot_completed {
                        return Err(io::Error::other(
                            "Guest SystemServer did not verify display, SystemReady, and BootCompleted phases",
                        ));
                    }
                }
            }
            if controlled_fork {
                fork_probe::run(root, &mut zygote, true)?;
            }
            loop {
                crate::guest::process::supervision::check_interrupted()?;
                zygote.tick_diagnostics()?;
                zygote.drain_output()?;
                for service in &mut boot_services {
                    service.tick_diagnostics()?;
                    service.drain_output()?;
                }
                if let Some(service) = &mut apexservice {
                    service.tick_diagnostics()?;
                    service.drain_output()?;
                }
                if zygote.exited()? {
                    return Err(io::Error::other("Guest Zygote exited unexpectedly"));
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        }
        if phase6a {
            println!("PHASE6A=START installd/artd through common launcher");
            if phase6b {
                crate::guest::mount::directory(root, "data/misc/profiles/cur/0", 0o771)?;
            }
            for (exe, name) in [
                (INSTALLD, "installd"),
                ("/apex/com.android.art/bin/artd", "artd"),
            ] {
                let mut service = start_data_service(root, exe, name)?;
                std::thread::sleep(Duration::from_millis(500));
                if service.exited()? {
                    return Err(io::Error::other(format!(
                        "Phase6A {exe} exited: {}",
                        fs::read_to_string(&service.log)?
                    )));
                }
                println!(
                    "PHASE6A service={name} pid={} alive_after_500ms=true",
                    service.child.id()
                );
                run(
                    root,
                    "/system/bin/bootstrap/linker64",
                    &["/run/ssal/ssal-binder-ipc", "inspect-data-service", name],
                    1000,
                )?;
                if phase6b && name == "installd" {
                    let paths = [
                        "user/0/com.android.ssal.phase2",
                        "user_de/0/com.android.ssal.phase2",
                    ];
                    let profiles = [
                        "misc/profiles/cur/0/com.android.ssal.phase2",
                        "misc/profiles/ref/com.android.ssal.phase2",
                    ];
                    for path in paths.into_iter().chain(profiles) {
                        match fs::symlink_metadata(userdata.join(path)) {
                            Err(e) if e.kind() == io::ErrorKind::NotFound => (),
                            _ => {
                                return Err(io::Error::other("Phase 2 test package already exists"))
                            }
                        }
                    }
                    let major = major.to_string();
                    let minor = minor.to_string();
                    let host_rdev = fs::metadata("/dev/binder")?.rdev().to_string();
                    let call = |role: &str| {
                        run(
                            root,
                            "/system/bin/bootstrap/linker64",
                            &[
                                "/run/ssal/ssal-binder-probe",
                                role,
                                "/dev/binder",
                                &major,
                                &minor,
                                "phase2",
                                &host_rdev,
                            ],
                            1000,
                        )
                    };
                    let create = (|| -> io::Result<()> {
                        let created = call("data-installd-create")?;
                        if !created.contains("\"result\":\"installd_created\"") {
                            return Err(io::Error::other("installd create evidence missing"));
                        }
                        for path in paths {
                            let actual = fs::symlink_metadata(root.join("data").join(path))?;
                            let expected = fs::symlink_metadata(userdata.join(path))?;
                            if !actual.is_dir()
                                || actual.uid() != 10000
                                || (actual.dev(), actual.ino()) != (expected.dev(), expected.ino())
                            {
                                return Err(io::Error::other(
                                    "installd output ownership/backing mismatch",
                                ));
                            }
                        }
                        Ok(())
                    })();
                    let deleted = call("data-installd-delete");
                    for path in profiles {
                        match fs::remove_dir_all(userdata.join(path)) {
                            Ok(()) => (),
                            Err(e) if e.kind() == io::ErrorKind::NotFound => (),
                            Err(e) => return Err(e),
                        }
                    }
                    let deleted = deleted?;
                    if !deleted.contains("\"result\":\"installd_deleted\"") {
                        return Err(io::Error::other("installd delete evidence missing"));
                    }
                    for path in paths {
                        match fs::symlink_metadata(userdata.join(path)) {
                            Err(e) if e.kind() == io::ErrorKind::NotFound => (),
                            _ => return Err(io::Error::other("installd did not remove test data")),
                        }
                    }
                    create?;
                    println!("PHASE6B_INSTALD=PASS create=PASS delete=PASS guest_backing=PASS");
                }
                service.stop()?;
            }
            if phase6b {
                return Err(io::Error::other(
                    "Phase 6B artd dexopt integration not implemented",
                ));
            }
        }
        if let Some(service) = &mut apexservice { service.stop()?; }
        while let Some(mut service) = boot_services.pop() {
            service.stop()?;
        }
        if system_server_graphics {
            hw_driver.cleanup()?;
            fs::remove_file(root.join("dev/hwbinder"))?;
        }
        if let Some((service, broker)) = &mut suspend {
            service.stop()?;
            broker.stop()?;
        }
        server.stop()?;
        manager.stop()?;
        if let Some(environment) = shell_environment.take() {
            *admission = Some(environment.finish()?);
        }
        if let Some(service) = &mut property_service {
            service.stop()?;
            fs::remove_file(root.join("dev/socket/property_service"))?;
            fs::remove_file(root.join("dev/socket/property_service_for_system"))?;
        }
        isolated(root, userdata)?;
        Ok(())
    })();
    let mut cleanup_errors = Vec::new();
    if let Some(environment) = shell_environment.take() {
        match environment.finish() {
            Ok(lock) => *admission = Some(lock),
            Err(error) => cleanup_errors.push(error.to_string()),
        }
    }
    if let Some(service) = &mut property_service {
        if let Err(error) = service.stop() {
            cleanup_errors.push(error.to_string());
        }
        match fs::remove_file(root.join("dev/socket/property_service")) {
            Ok(()) => (),
            Err(error) if error.kind() == io::ErrorKind::NotFound => (),
            Err(error) => cleanup_errors.push(error.to_string()),
        }
        match fs::remove_file(root.join("dev/socket/property_service_for_system")) {
            Ok(()) => (),
            Err(error) if error.kind() == io::ErrorKind::NotFound => (),
            Err(error) => cleanup_errors.push(error.to_string()),
        }
    }
    if phase7a && std::env::var_os("SSAL_PHASE7FB_FORK").is_some() {
        if let Err(error) = fork_probe::cleanup(root) {
            cleanup_errors.push(error.to_string());
        }
    }
    if let Err(error) = binder.cleanup() {
        cleanup_errors.push(format!("Private Binder cleanup: {error}"));
    }
    if let Err(error) = hw_driver.cleanup() {
        cleanup_errors.push(format!("Private HwBinder cleanup: {error}"));
    }
    if fs::read_to_string("/sys/fs/selinux/enforce")?.trim() != "1" {
        cleanup_errors.push("Host global Enforcing changed".into());
    }
    let cleanup = if cleanup_errors.is_empty() {
        Ok(())
    } else {
        Err(io::Error::other(cleanup_errors.join("; ")))
    };
    match (result, cleanup) {
        (Err(error), Err(cleanup)) => Err(io::Error::other(format!("{error}; {cleanup}"))),
        (Err(error), _) | (_, Err(error)) => Err(error),
        _ => Ok(()),
    }
}

fn start_lmkd(root: &Path) -> io::Result<Service> {
    use std::os::fd::{FromRawFd, OwnedFd};

    let contexts = ssal::guest_policy::runtime::load(root)?
        .map(|plan| -> io::Result<_> {
            Ok((
                plan.context("lmkd", true)?,
                plan.context("lmkd_socket", false)?,
            ))
        })
        .transpose()?;

    let raw = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    let socket = unsafe { OwnedFd::from_raw_fd(raw) };
    let fd = socket.as_raw_fd();

    let log = root.join("run/ssal/lmkd.log");
    File::create(&log)?;
    let mut cmd = command(root, "/run/ssal/ssal-lmkd", 0, None)?;
    cmd.env("ANDROID_SOCKET_lmkd", fd.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    unsafe {
        cmd.pre_exec(move || {
            if let Some((sock_ctx, file_ctx)) = &contexts {
                fs::write("/proc/thread-self/attr/sockcreate", format!("{sock_ctx}\0"))?;
                fs::write("/proc/thread-self/attr/fscreate", format!("{file_ctx}\0"))?;
            }
            let bound = libc::socket(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0);
            if bound < 0 {
                return Err(io::Error::last_os_error());
            }
            let bound_guard = OwnedFd::from_raw_fd(bound);
            let sock_path = c"/dev/socket/lmkd";
            let _ = libc::unlink(sock_path.as_ptr());
            let mut addr: libc::sockaddr_un = std::mem::zeroed();
            addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
            let bytes = sock_path.to_bytes_with_nul();
            for (dst, &src) in addr.sun_path.iter_mut().zip(bytes.iter()) {
                *dst = src as libc::c_char;
            }
            let addr_len = (std::mem::size_of::<libc::sa_family_t>() + bytes.len()) as libc::socklen_t;
            let bind_rc = libc::bind(bound_guard.as_raw_fd(), (&raw const addr).cast(), addr_len);
            if contexts.is_some() {
                fs::write("/proc/thread-self/attr/sockcreate", b"\0")?;
                fs::write("/proc/thread-self/attr/fscreate", b"\0")?;
            }
            if bind_rc != 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::chown(sock_path.as_ptr(), 0, 1000) != 0 {
                return Err(io::Error::last_os_error());
            }
            fs::set_permissions(Path::new("/dev/socket/lmkd"), fs::Permissions::from_mode(0o660))?;
            if bound_guard.as_raw_fd() == fd {
                std::mem::forget(bound_guard);
            } else if libc::dup2(bound_guard.as_raw_fd(), fd) < 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::fcntl(fd, libc::F_SETFD, 0) != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let mut service = Service::from_child(cmd.spawn()?, log);
    drop(socket);
    service.output.push(crate::diagnostics::zygote::Stream::new(
        service.child.stdout.take().unwrap(),
        File::options().append(true).open(&service.log)?,
    )?);
    service.output.push(
        crate::diagnostics::zygote::Stream::new(
            service.child.stderr.take().unwrap(),
            File::options().append(true).open(&service.log)?,
        )?
        .with_session_log(),
    );
    service.wait_text("guest_lmkd_ready=1")?;
    Ok(service)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn common_workers_share_live_property_readiness() {
        // Wiring regression: every caller enters this setup before any phase-specific work.
        let source = include_str!("mod.rs");
        let verify = source.split("pub(crate) fn verify(").nth(1).unwrap();
        let setup = verify
            .split("let mut manager = Service::start(")
            .next()
            .unwrap();
        assert!(setup.contains("\"ssal-property-service\","));
        assert!(setup.contains("property_service = Some(start_property_service("));
        assert!(!setup.contains("if phase7i_properties"));
        assert!(!setup.contains("--initialize-private-properties"));
        assert!(include_str!("../environment.rs").contains("\"servicemanager.ready=false\""));
        assert!(!source.contains(concat!("\"servicemanager.ready", "=true\"")));
        let property = verify
            .find("manager.wait_guest_servicemanager_property(")
            .unwrap();
        let context = verify.find("manager.wait_guest_context_manager(").unwrap();
        let aidl = verify.find("\"aidl-server\"").unwrap();
        assert!(property < context && context < aidl);
    }

    #[test]
    fn daemon_failure_stderr_survives_child_exit() -> io::Result<()> {
        let log = std::env::temp_dir().join(format!("ssal-property-stderr-{}", std::process::id()));
        let output = File::create(&log)?;
        let mut command = Command::new("/bin/sh");
        command
            .args(["-c", "echo 'property startup failure fixture' >&2; exit 1"])
            .stderr(Stdio::piped());
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = command.spawn()?;
        let stream = crate::diagnostics::zygote::Stream::new(child.stderr.take().unwrap(), output)?;
        let mut service = Service {
            child,
            log: log.clone(),
            stopped: false,
            diagnostics: None,
            output: vec![stream],
        };
        let error = service
            .wait_text("guest_property_service_ready")
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("property startup failure fixture"));
        service.stop()?;
        assert_eq!(service.child.wait()?.code(), Some(1));
        fs::remove_file(log)?;
        Ok(())
    }

    #[test]
    fn child_joins_every_hierarchy_before_exec() -> io::Result<()> {
        let directory = std::env::temp_dir().join(format!("ssal-pre-exec-{}", std::process::id()));
        fs::create_dir_all(&directory)?;
        let groups: Vec<_> = ["unified", "memory"]
            .into_iter()
            .map(|name| directory.join(name))
            .collect();
        for group in &groups {
            fs::create_dir(group)?;
            fs::write(group.join("cgroup.procs"), "parent")?;
        }
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "printf %s $$"]);
        let child_groups = groups.clone();
        unsafe {
            command.pre_exec(move || join_cgroups(&child_groups));
        }
        let output = command.output()?;
        assert!(output.status.success());
        for group in &groups {
            assert_eq!(fs::read(group.join("cgroup.procs"))?, output.stdout);
        }
        fs::remove_file(groups[1].join("cgroup.procs"))?;
        std::os::unix::fs::symlink("/dev/null", groups[1].join("cgroup.procs"))?;
        assert!(command.spawn().is_err());
        // A failed join must prevent exec, including when an earlier hierarchy succeeded.
        fs::remove_file(groups[1].join("cgroup.procs"))?;
        fs::remove_dir(&groups[1])?;
        assert!(command.spawn().is_err());
        fs::remove_dir_all(directory)?;
        Ok(())
    }

    #[test]
    fn mapped_helpers_use_their_guest_domains() {
        for executable in [
            "/apex/com.android.runtime/bin/linkerconfig",
            "/system/bin/linkerconfig",
        ] {
            assert_eq!(
                mapped_exec_domain(executable, Some(GUEST_PROBE_CONTEXT)),
                "linkerconfig"
            );
        }
        assert_eq!(
            mapped_exec_domain(
                "/system/bin/bootstrap/linker64",
                Some(PROPERTY_SERVICE_CONTEXT)
            ),
            "init"
        );
        for (executable, domain) in [
            ("/system/bin/app_process64", "zygote"),
            ("/system/bin/servicemanager", "servicemanager"),
            ("/system/bin/surfaceflinger", "surfaceflinger"),
            ("/run/ssal/ssal-apexservice", "apexd"),
            ("/run/ssal/ssal-system-suspend", "system_suspend"),
            ("/run/ssal/ssal-health", "ssal_health"),
            ("/run/ssal/ssal-gatekeeper", "ssal_gatekeeper"),
            ("/run/ssal/ssal-keymint", "ssal_keymint"),
            ("/system/bin/gatekeeperd", "gatekeeperd"),
            ("/system/bin/keystore2", "keystore"),
            ("/system/bin/aconfigd-system", "aconfigd"),
            ("/system/bin/sh", "shell"),
        ] {
            assert_eq!(
                mapped_exec_domain(executable, Some(GUEST_PROBE_CONTEXT)),
                domain
            );
        }
        assert_eq!(
            mapped_exec_domain("/run/ssal/ssal-binder-ipc-server", Some(AIDL_SERVER_CONTEXT)),
            "aidl_lazy_test_server"
        );
    }

    #[test]
    fn system_server_requires_explicit_mapped_zygote_worker() {
        assert!(system_server_requested(true, true).unwrap());
        assert!(!system_server_requested(false, true).unwrap());
        assert!(!system_server_requested(true, false).unwrap());
    }

    #[test]
    fn display_progress_requires_completed_phases_from_the_guest_pid() {
        let stderr = [
            "11-20 01:00:00.000 42 42 V SystemServerTiming: WaitForDisplay took to complete: 1ms",
            "11-20 01:00:00.000 42 42 V SystemServerTiming: MakeWindowManagerServiceReady took to complete: 1ms",
            "11-20 01:00:00.000 42 42 V SystemServerTiming: MakeDisplayManagerServiceReady took to complete: 1ms",
            "11-20 01:00:00.000 42 42 V SystemServerTiming: StartActivityManagerReadyPhase took to complete: 1ms",
        ];
        assert_eq!(system_server_display_progress(&stderr[..3].join("\n"), 42), (true, false));
        assert_eq!(system_server_display_progress(&stderr.join("\n"), 43), (false, false));
        assert_eq!(system_server_display_progress(&stderr.join("\n"), 42), (true, true));
        let failed = format!("{}\n11-20 01:00:00.000 42 42 E SystemServer: BOOT FAILURE making Display Manager Service ready", stderr.join("\n"));
        assert_eq!(system_server_display_progress(&failed, 42), (true, false));
        assert!(!system_server_boot_completed(&stderr.join("\n"), 42));
        let boot_done = format!("{}\n11-20 01:00:01.000 42 42 V SystemServerTiming: OnBootPhase_1000 took to complete: 12ms", stderr.join("\n"));
        assert!(!system_server_boot_completed(&boot_done, 43));
        assert!(system_server_boot_completed(&boot_done, 42));
    }

    #[test]
    fn native_zygote_options_precede_java_socket_argument() {
        let args = zygote_args(false, true);
        assert_eq!(
            args,
            [
                "-Xzygote",
                "/system/bin",
                "--zygote",
                "--start-system-server",
                "--socket-name=zygote"
            ]
        );
        assert!(!zygote_args(false, false).contains(&"--start-system-server"));
        assert!(zygote_args(true, false).contains(&"-XX:ForceJavaZygoteForkLoop=true"));
    }

    #[test]
    fn abi_query_requires_valid_response() -> io::Result<()> {
        for reply in [
            b"\0\0\0\x09arm64-v8a".as_slice(),
            b"\0\0\0\x09wrong-abi",
            b"\0\0\0\x09arm",
        ] {
            let (mut client, mut server) = UnixStream::pair()?;
            server.write_all(reply)?;
            server.shutdown(std::net::Shutdown::Write)?;
            assert_eq!(
                query_abi(&mut client).is_ok(),
                reply.ends_with(b"arm64-v8a")
            );
            let mut request = [0; 19];
            server.read_exact(&mut request)?;
            assert_eq!(&request, b"1\n--query-abi-list\n");
        }
        Ok(())
    }

    #[test]
    fn zygote_socket_fds_survive_exec() -> io::Result<()> {
        let root = std::env::temp_dir().join(format!("ssal-zygote-sockets-{}", std::process::id()));
        fs::create_dir_all(root.join("dev/socket"))?;
        let mut command = Command::new("/bin/sh");
        unsafe {
            command.pre_exec(ssal::unix::cloexec_unexpected_fds);
        }
        let sockets = zygote_sockets(&mut command, &root.join("dev/socket"), None)?;
        let status = command.args(["-c", "test -S /proc/self/fd/$ANDROID_SOCKET_zygote && test -S /proc/self/fd/$ANDROID_SOCKET_usap_pool_primary && test \"$ANDROID_SOCKET_zygote\" != \"$ANDROID_SOCKET_usap_pool_primary\""]).status()?;
        assert!(status.success());
        assert!(root.join("dev/socket/zygote").exists());
        drop(sockets);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn zygote_early_exit_retains_diagnostics_through_service_drop() -> io::Result<()> {
        let directory =
            std::env::temp_dir().join(format!("ssal-7b-service-{}", std::process::id()));
        crate::diagnostics::zygote::Diagnostics::prepare(&directory)?;
        let log = directory.join("legacy.log");
        File::create(&log)?;
        let mut command = Command::new("/bin/sh");
        command
            .args([
                "-c",
                "ulimit -c 0; printf 'zygote fatal fixture' >&2; kill -ABRT $$",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut service = Service {
            child: command.spawn()?,
            log,
            stopped: false,
            diagnostics: None,
            output: Vec::new(),
        };
        let deadline = Instant::now() + Duration::from_secs(5);
        while service.exit_status()?.is_none() {
            assert!(Instant::now() < deadline, "fixture did not exit");
            std::thread::sleep(Duration::from_millis(10));
        }
        service.diagnostics = Some(crate::diagnostics::zygote::Diagnostics::attach(
            &mut service.child,
            &directory,
            &directory.join("missing-cgroup"),
            crate::diagnostics::zygote::launch_time(),
            Instant::now(),
            None,
        )?);
        assert!(service
            .wait_for_socket(Path::new("ssal_7b_fixture_absent"))
            .is_err());
        let status = service.exit_status()?.expect("fixture exited");
        assert!(matches!(status.0, libc::CLD_KILLED | libc::CLD_DUMPED));
        assert_eq!(status.1, libc::SIGABRT);
        assert_eq!(service.exit_status()?, Some(status));
        drop(service);
        let metadata = fs::read_to_string(directory.join("metadata.jsonl"))?;
        let exit: serde_json::Value = serde_json::from_str(metadata.lines().last().unwrap())?;
        assert_eq!(exit["signal"], libc::SIGABRT);
        assert!(fs::read_to_string(directory.join("stderr.log"))?.contains("zygote fatal fixture"));
        fs::remove_dir_all(directory)?;
        Ok(())
    }

    #[test]
    fn readiness_wait_drains_zygote_stderr_before_abi_reply() -> io::Result<()> {
        let directory =
            std::env::temp_dir().join(format!("ssal-readiness-drain-{}", std::process::id()));
        crate::diagnostics::zygote::Diagnostics::prepare(&directory)?;
        let log = directory.join("legacy.log");
        File::create(&log)?;
        let mut command = Command::new("/bin/sh");
        command
            .current_dir(&directory)
            .args(["-c", "head -c 131072 /dev/zero >&2; touch ready; sleep 30"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(())
                }
            });
        }
        let mut service = Service {
            child: command.spawn()?,
            log,
            stopped: false,
            diagnostics: None,
            output: Vec::new(),
        };
        service.diagnostics = Some(crate::diagnostics::zygote::Diagnostics::attach(
            &mut service.child,
            &directory,
            &directory.join("missing-cgroup"),
            crate::diagnostics::zygote::launch_time(),
            Instant::now(),
            None,
        )?);
        let mut query = Command::new("/bin/sh");
        query.current_dir(&directory).args(["-c", "i=0; while [ $i -lt 200 ]; do if [ -f ready ]; then echo abi-ready; exit 0; fi; i=$((i+1)); sleep 0.01; done; exit 1"]);
        let output = service.readiness_output(query)?;
        assert!(output.status.success());
        assert_eq!(output.stdout, b"abi-ready\n");
        drop(service);
        assert_eq!(fs::metadata(directory.join("stderr.log"))?.len(), 131072);
        fs::remove_dir_all(directory)?;
        Ok(())
    }

    #[test]
    fn owned_service_is_reaped_and_stop_is_idempotent() -> io::Result<()> {
        let log = std::env::temp_dir().join(format!("ssal-launcher-test-{}", std::process::id()));
        let output = File::create(&log)?;
        let mut cmd = Command::new("/bin/sh");
        cmd.args(["-c", "sleep 30 & wait"])
            .stdout(output.try_clone()?)
            .stderr(output);
        unsafe {
            cmd.pre_exec(|| {
                if libc::setsid() < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = cmd.spawn()?;
        let pid = child.id();
        let mut service = Service {
            child,
            log: log.clone(),
            stopped: false,
            diagnostics: None,
            output: Vec::new(),
        };
        service.stop()?;
        service.stop()?;
        assert!(service.stopped);
        assert_eq!(unsafe { libc::kill(pid as i32, 0) }, -1);
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::ESRCH));
        fs::remove_file(log)?;
        Ok(())
    }

    #[test]
    fn exited_leader_does_not_leave_its_process_group_running() -> io::Result<()> {
        let log = std::env::temp_dir().join(format!("ssal-exited-leader-{}", std::process::id()));
        let output = File::create(&log)?;
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "sleep 30 & echo $!"]).stdout(output);
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(())
                }
            });
        }
        let mut service = Service {
            child: command.spawn()?,
            log: log.clone(),
            stopped: false,
            diagnostics: None,
            output: Vec::new(),
        };
        let deadline = Instant::now() + Duration::from_secs(3);
        while !service.exited()? {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(10));
        }
        let pid: u32 = fs::read_to_string(&log)?
            .trim()
            .parse()
            .map_err(io::Error::other)?;
        service.stop()?;
        while let Ok(stat) = fs::read_to_string(format!("/proc/{pid}/stat")) {
            if stat.split_whitespace().nth(2) == Some("Z") {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "background process remained alive"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        fs::remove_file(log)?;
        Ok(())
    }
}
