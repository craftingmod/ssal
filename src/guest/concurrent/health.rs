use crate::guest::init::{binder_service::BinderService, Service};
use std::{
    fs::{self, File},
    io,
    os::unix::{
        fs::{FileTypeExt, MetadataExt},
        process::CommandExt,
    },
    path::Path,
    process::{Command, Stdio},
};

const HAL: &str = "android.hardware.health.IHealth/default";
pub(super) const VINTF: &str = r#"<manifest version="1.0" type="framework">
    <hal format="aidl">
        <name>android.hardware.health</name>
        <version>4</version>
        <fqname>IHealth/default</fqname>
    </hal>
</manifest>
"#;

pub(crate) const SERVICE: BinderService = BinderService {
    name: "health",
    executable: "/run/ssal/ssal-health",
    domain: "ssal_health",
    exec_type: "ssal_health_exec",
};

pub(in crate::guest) fn start(
    root: &Path,
    bin: &Path,
    guest_binder: u64,
    services: &mut Vec<Service>,
) -> io::Result<()> {
    let plan = ssal::guest_policy::runtime::load(root)?
        .ok_or_else(|| io::Error::other("Guest Health SELinux policy missing"))?;
    let context = plan.context(SERVICE.domain, true)?;
    crate::diagnostics::selinux::require_guest_domain_mode(&plan, &context)?;
    let source = std::env::var("SSAL_GUEST_HEALTH_SOURCE").unwrap_or_else(|_| "host".into());
    let input = match source.as_str() {
        "diagnostic" => Stdio::null(),
        "host" => {
            let host = fs::metadata("/dev/binder")?;
            if !host.file_type().is_char_device() || host.rdev() == guest_binder {
                return Err(io::Error::other(
                    "Host battery provider Binder identity mismatch",
                ));
            }
            let parent = std::process::id() as libc::pid_t;
            let log = root.join("run/ssal/health-provider.log");
            let mut command = Command::new(bin.join("ssal-health"));
            command
                .env_clear()
                .args(["host-provider", &host.rdev().to_string()])
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(File::create(&log)?);
            unsafe {
                command.pre_exec(move || {
                    ssal::unix::cloexec_unexpected_fds()?;
                    crate::guest::process::command::isolate_process_group(false)?;
                    if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0
                        || libc::getppid() != parent
                    {
                        return Err(io::Error::other("Host battery provider parent disappeared"));
                    }
                    Ok(())
                });
            }
            let mut child = command.spawn()?;
            let input = Stdio::from(child.stdout.take().unwrap());
            services.push(Service::from_child(child, log));
            input
        }
        _ => {
            return Err(io::Error::other(
                "SSAL_GUEST_HEALTH_SOURCE must be host or diagnostic",
            ))
        }
    };
    let mut service = Service::start_with_input(
        root,
        SERVICE.executable,
        &["serve", &guest_binder.to_string(), &context, &source],
        SERVICE.name,
        1000,
        None,
        &[],
        input,
    )?;
    service.wait_text(&format!("guest_binder_registered={HAL}"))?;
    println!(
        "GUEST_HEALTH_READY=PASS pid={} sid={context} source={source}",
        service.pid()
    );
    services.push(service);
    Ok(())
}
