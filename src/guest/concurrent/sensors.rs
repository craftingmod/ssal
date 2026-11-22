use crate::guest::init::{binder_service::BinderService, Service};
use std::{
    fs::File,
    io,
    os::unix::{net::UnixStream, process::CommandExt},
    path::Path,
    process::{Command, Stdio},
};

const HAL: &str = "android.hardware.sensors.ISensors/default";
pub(super) const VINTF: &str = r#"<manifest version="1.0" type="framework">
    <hal format="aidl">
        <name>android.hardware.sensors</name>
        <version>3</version>
        <fqname>ISensors/default</fqname>
    </hal>
</manifest>
"#;

pub(crate) const SERVICE: BinderService = BinderService {
    name: "sensors",
    executable: "/run/ssal/ssal-sensors",
    domain: "ssal_sensors",
    exec_type: "ssal_sensors_exec",
};

pub(in crate::guest) fn start(
    root: &Path,
    bin: &Path,
    guest_binder: u64,
    services: &mut Vec<Service>,
) -> io::Result<()> {
    let plan = ssal::guest_policy::runtime::load(root)?
        .ok_or_else(|| io::Error::other("Guest Sensors SELinux policy missing"))?;
    let context = plan.context(SERVICE.domain, true)?;
    crate::diagnostics::selinux::require_guest_domain_mode(&plan, &context)?;

    let (guest_sock, host_sock) = UnixStream::pair()?;
    let parent = std::process::id() as libc::pid_t;
    let log = root.join("run/ssal/sensor-host.log");
    let mut command = Command::new(bin.join("ssal-sensor-host"));
    command
        .env_clear()
        .arg("serve")
        .stdin(Stdio::from(std::os::fd::OwnedFd::from(host_sock)))
        .stdout(Stdio::null())
        .stderr(File::create(&log)?);
    unsafe {
        command.pre_exec(move || {
            ssal::unix::cloexec_unexpected_fds()?;
            crate::guest::process::command::isolate_process_group(false)?;
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0
                || libc::getppid() != parent
            {
                return Err(io::Error::other("Host sensor bridge parent disappeared"));
            }
            Ok(())
        });
    }
    let host_bridge = Service::from_child(command.spawn()?, log);
    services.push(host_bridge);

    let mut service = Service::start_with_input(
        root,
        SERVICE.executable,
        &["serve", &guest_binder.to_string(), &context],
        SERVICE.name,
        1000,
        None,
        &[],
        Stdio::from(std::os::fd::OwnedFd::from(guest_sock)),
    )?;
    service.wait_text(&format!("guest_binder_registered={HAL}"))?;
    println!(
        "GUEST_SENSORS_READY=PASS pid={} sid={context}",
        service.pid()
    );
    services.push(service);
    Ok(())
}
