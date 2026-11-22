use crate::guest::init::{binder_service::BinderService, Service};
use std::{
    io::{self, Write},
    os::fd::{FromRawFd, OwnedFd},
    path::Path,
    process::Stdio,
};

const HAL: &str = "android.hardware.gatekeeper.IGatekeeper/default";
pub(super) const VINTF: &str = r#"<manifest version="1.0" type="framework">
    <hal format="aidl">
        <name>android.hardware.gatekeeper</name>
        <version>1</version>
        <fqname>IGatekeeper/default</fqname>
    </hal>
</manifest>
"#;

pub(crate) const SERVICE: BinderService = BinderService {
    name: "gatekeeper",
    executable: "/run/ssal/ssal-gatekeeper",
    domain: "ssal_gatekeeper",
    exec_type: "ssal_gatekeeper_exec",
};

pub(super) fn pipe_bytes(bytes: &[u8]) -> io::Result<Stdio> {
    let mut fds = [0 as libc::c_int; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let read_fd = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    let mut write_file = std::fs::File::from(unsafe { OwnedFd::from_raw_fd(fds[1]) });
    write_file.write_all(bytes)?;
    drop(write_file);
    Ok(Stdio::from(read_fd))
}

pub(in crate::guest) fn start(
    root: &Path,
    guest_binder: u64,
    auth_token_key: &[u8; 32],
    services: &mut Vec<Service>,
) -> io::Result<()> {
    let plan = ssal::guest_policy::runtime::load(root)?
        .ok_or_else(|| io::Error::other("Guest GateKeeper SELinux policy missing"))?;
    let context = plan.context(SERVICE.domain, true)?;
    crate::diagnostics::selinux::require_guest_domain_mode(&plan, &context)?;
    let input = pipe_bytes(auth_token_key)?;
    let mut service = Service::start_with_input(
        root,
        SERVICE.executable,
        &["serve", &guest_binder.to_string(), &context],
        SERVICE.name,
        1000,
        None,
        &[],
        input,
    )?;
    service.wait_text(&format!("guest_binder_registered={HAL}"))?;
    println!(
        "GUEST_GATEKEEPER_READY=PASS pid={} sid={context}",
        service.pid()
    );
    services.push(service);
    Ok(())
}
