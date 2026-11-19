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

pub(crate) const VOLD: BinderService = BinderService {
    name: "vold",
    executable: "/run/ssal/ssal-vold",
    domain: "vold",
    exec_type: "vold_exec",
};

pub(crate) const NETD: BinderService = BinderService {
    name: "netd",
    executable: "/run/ssal/ssal-netd",
    domain: "netd",
    exec_type: "netd_exec",
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
        self.start_with_hwbinder(root, guest_binder, None)
    }

    pub fn start_with_hwbinder(
        &self,
        root: &Path,
        guest_binder: u64,
        guest_hwbinder: Option<u64>,
    ) -> io::Result<Service> {
        let plan = ssal::guest_policy::runtime::load(root)?
            .ok_or_else(|| io::Error::other("Guest Binder policy missing"))?;
        let context = plan.context(self.domain, true)?;
        let device = guest_binder.to_string();
        let hw = guest_hwbinder.map(|v| v.to_string());
        let mut args = vec!["serve", device.as_str(), context.as_str()];
        if let Some(hw) = hw.as_deref() {
            args.push(hw);
        }
        let mut service = Service::start(
            root,
            self.executable,
            &args,
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
