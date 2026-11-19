//! Concurrent Mode SystemSuspend adapter and Host wakelock broker.
use crate::guest::init::{binder_service::BinderService, Service};
use std::{
    fs::{self, File},
    io,
    os::unix::{
        fs::{FileTypeExt, MetadataExt},
        net::UnixStream,
        process::CommandExt,
    },
    path::Path,
    process::{Command, Stdio},
    time::Duration,
};

pub(crate) const SERVICE: BinderService = BinderService {
    name: "system_suspend",
    executable: "/run/ssal/ssal-system-suspend",
    domain: "system_suspend",
    exec_type: "system_suspend_exec",
};

pub(in crate::guest) fn enabled() -> bool {
    std::env::var("SSAL_GUEST_SYSTEM_SUSPEND").as_deref() != Ok("0")
}

pub(in crate::guest) fn start(
    root: &Path,
    bin: &Path,
    guest_binder: u64,
) -> io::Result<(Service, Service)> {
    let host = fs::metadata("/dev/binder")?;
    let init = fs::metadata("/proc/1/root/dev/binder")?;
    if !host.file_type().is_char_device()
        || (host.dev(), host.ino(), host.rdev()) != (init.dev(), init.ino(), init.rdev())
        || host.rdev() == guest_binder
    {
        return Err(io::Error::other(
            "Host Power Broker Binder identity mismatch",
        ));
    }
    let plan = ssal::guest_policy::runtime::load(root)?
        .ok_or_else(|| io::Error::other("Guest Binder policy missing"))?;
    let context = plan.context(SERVICE.domain, true)?;
    let (guest, host_socket) = UnixStream::pair()?;
    guest.set_read_timeout(Some(Duration::from_secs(2)))?;
    guest.set_write_timeout(Some(Duration::from_secs(2)))?;
    host_socket.set_read_timeout(Some(Duration::from_secs(10)))?;
    host_socket.set_write_timeout(Some(Duration::from_secs(2)))?;
    let parent = std::process::id() as libc::pid_t;
    let log = root.join("run/ssal/power-broker.log");
    let mut command = Command::new(bin.join("ssal-system-suspend"));
    command
        .env_clear()
        .args(["broker", &host.rdev().to_string()])
        .stdin(Stdio::from(std::os::fd::OwnedFd::from(host_socket)))
        .stdout(Stdio::null())
        .stderr(File::create(&log)?);
    unsafe {
        command.pre_exec(move || {
            ssal::unix::cloexec_unexpected_fds()?;
            crate::guest::process::command::isolate_process_group(false)?;
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 || libc::getppid() != parent
            {
                return Err(io::Error::other("Host Power Broker parent disappeared"));
            }
            Ok(())
        });
    }
    let broker = Service::from_child(command.spawn()?, log);
    let mut service = Service::start_with_input(
        root,
        SERVICE.executable,
        &["serve", &guest_binder.to_string(), &context],
        SERVICE.name,
        1000,
        Some(crate::guest::launcher::GUEST_PROBE_CONTEXT),
        &[],
        Stdio::from(std::os::fd::OwnedFd::from(guest)),
    )?;
    service.wait_text("guest_binder_registered=android.system.suspend.ISystemSuspend/default")?;
    Ok((service, broker))
}


pub(in crate::guest) fn mask_host_power() -> io::Result<()> {
    if Path::new("/sys/power").try_exists()?
        && unsafe {
            libc::mount(
                c"tmpfs".as_ptr(),
                c"/sys/power".as_ptr(),
                c"tmpfs".as_ptr(),
                libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
                std::ptr::null(),
            )
        } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
