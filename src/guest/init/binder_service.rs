//! Shared installation and supervised lifetime for Guest Binder system services.
use super::Service;
use ssal::namespace_mounts::Mounts;
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

pub(crate) struct BinderService {
    pub name: &'static str,
    pub executable: &'static str,
    pub domain: &'static str,
    pub exec_type: &'static str,
}

pub(crate) const APEX: BinderService = BinderService {
    name: "apexservice",
    executable: "/run/ssal/ssal-apexservice",
    domain: "apexd",
    exec_type: "apexd_exec",
};

pub(crate) const SUSPEND: BinderService = BinderService {
    name: "system_suspend",
    executable: "/run/ssal/ssal-system-suspend",
    domain: "system_suspend",
    exec_type: "system_suspend_exec",
};

pub(crate) fn start_suspend(
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
    let context = plan.context(SUSPEND.domain, true)?;
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
        SUSPEND.executable,
        &["serve", &guest_binder.to_string(), &context],
        SUSPEND.name,
        1000,
        Some(crate::guest::launcher::GUEST_PROBE_CONTEXT),
        &[],
        Stdio::from(std::os::fd::OwnedFd::from(guest)),
    )?;
    service.wait_text("guest_binder_registered=android.system.suspend.ISystemSuspend/default")?;
    Ok((service, broker))
}

impl BinderService {
    pub fn install(&self, mounts: &mut Mounts, root: &Path, bin: &Path) -> io::Result<()> {
        let plan = ssal::guest_policy::runtime::load(root)?.ok_or_else(|| {
            io::Error::other("Binder system services require Guest SELinux policy")
        })?;
        let target = root.join(self.executable.trim_start_matches('/'));
        File::create(&target)?;
        ssal::guest_policy::runtime::set_label(&target, &plan.context(self.exec_type, false)?)?;
        ssal::guest_policy::runtime::bind_file(
            mounts,
            root,
            &bin.join(target.file_name().unwrap()),
            &target,
        )
    }

    pub fn start(&self, root: &Path, guest_binder: u64) -> io::Result<Service> {
        let plan = ssal::guest_policy::runtime::load(root)?
            .ok_or_else(|| io::Error::other("Guest Binder policy missing"))?;
        let context = plan.context(self.domain, true)?;
        let device = guest_binder.to_string();
        let mut service = Service::start(
            root,
            self.executable,
            &["serve", &device, &context],
            self.name,
            0,
            Some(crate::guest::launcher::GUEST_PROBE_CONTEXT),
            &[],
        )?;
        service.wait_text(&format!("guest_binder_registered={}", self.name))?;
        Ok(service)
    }

    pub fn check(&self, root: &Path, guest_binder: u64, activate: bool) -> io::Result<()> {
        let plan = ssal::guest_policy::runtime::load(root)?
            .ok_or_else(|| io::Error::other("Guest Binder policy missing"))?;
        let context = plan.context(self.domain, true)?;
        let mode = if activate {
            "check-and-activate"
        } else {
            "check"
        };
        let check = crate::guest::launcher::run(
            root,
            self.executable,
            &[mode, &guest_binder.to_string(), &context],
            0,
        )?;
        if !check.contains("guest_apex_aidl=PASS") {
            return Err(io::Error::other(format!(
                "{} Binder check evidence missing",
                self.name
            )));
        }
        Ok(())
    }
}
