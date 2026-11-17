//! Shared installation and supervised lifetime for Guest Binder system services.
use super::Service;
use ssal::namespace_mounts::Mounts;
use std::{fs::File, io, path::Path};

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

    pub fn check(&self, root: &Path, guest_binder: u64, expected: &str) -> io::Result<()> {
        let plan = ssal::guest_policy::runtime::load(root)?
            .ok_or_else(|| io::Error::other("Guest Binder policy missing"))?;
        let context = plan.context(self.domain, true)?;
        let check = crate::guest::launcher::run(
            root,
            self.executable,
            &["check", &guest_binder.to_string(), &context],
            0,
        )?;
        if !check.contains(expected) {
            return Err(io::Error::other(format!(
                "{} Binder check evidence missing",
                self.name
            )));
        }
        Ok(())
    }
}
