use std::fs::{self, File};
use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
pub(crate) struct Service {
    pub(in crate::guest) child: Child,
    pub(in crate::guest) log: std::path::PathBuf,
    pub(in crate::guest) stopped: bool,
    pub(in crate::guest) diagnostics: Option<crate::diagnostics::zygote::Diagnostics>,
    pub(in crate::guest) output: Vec<crate::diagnostics::zygote::Stream>,
}
impl Service {
    pub(crate) fn from_child(child: Child, log: std::path::PathBuf) -> Self {
        Self {
            child,
            log,
            stopped: false,
            diagnostics: None,
            output: Vec::new(),
        }
    }
    pub(crate) fn pid(&self) -> u32 {
        self.child.id()
    }
    pub(crate) fn tick_diagnostics(&mut self) -> io::Result<()> {
        if let Some(diagnostics) = &mut self.diagnostics {
            diagnostics.tick()?;
        }
        Ok(())
    }
    pub(in crate::guest) fn exit_status(&self) -> io::Result<Option<(i32, i32)>> {
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        if unsafe {
            libc::waitid(
                libc::P_PID,
                self.child.id(),
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok((unsafe { info.si_pid() } != 0).then(|| (info.si_code, unsafe { info.si_status() })))
    }
    pub(crate) fn exited(&self) -> io::Result<bool> {
        Ok(self.exit_status()?.is_some())
    }
    pub(crate) fn start(
        root: &Path,
        exe: &str,
        args: &[&str],
        name: &str,
        uid: u32,
        exec_context: Option<&[u8]>,
        env: &[(&str, &str)],
    ) -> io::Result<Self> {
        Self::start_with_input(root, exe, args, name, uid, exec_context, env, Stdio::null())
    }

    pub(crate) fn start_with_input(
        root: &Path,
        exe: &str,
        args: &[&str],
        name: &str,
        uid: u32,
        exec_context: Option<&[u8]>,
        env: &[(&str, &str)],
        input: Stdio,
    ) -> io::Result<Self> {
        let log = root.join(format!("run/ssal/{name}.log"));
        File::create(&log)?;
        let mut command = crate::guest::launcher::command(root, exe, uid, exec_context)?;
        let rust_service = crate::guest::launcher::uses_own_diagnostics(exe);
        let installd_probe = name == "installd" && crate::guest::launcher::installd_probe_requested();
        command.stdin(input);
        if !rust_service && name != "memory-probe" {
            command.env("LD_PRELOAD", "/run/ssal/ssal-phase2-log.so");
        }
        for (key, value) in env {
            command.env(key, value);
        }
        let diagnostic_dir = root
            .parent()
            .ok_or_else(|| io::Error::other("session parent missing"))?
            .join("phase7b");
        let is_zygote = name == "guest-zygote";
        let diagnostic = is_zygote || name == "memory-probe";
        if diagnostic {
            crate::diagnostics::zygote::Diagnostics::prepare(&diagnostic_dir)?;
        }
        if is_zygote {
            if std::env::var_os("SSAL_CONTEXT_MAP_AVC_RESET").is_some() {
                command.env("SSAL_CONTEXT_MAP_AVC_RESET", "1");
            }
            if std::env::var_os("SSAL_CONTEXT_MAP_RAW_SETCON").is_some() {
                command.env("SSAL_CONTEXT_MAP_RAW_SETCON", "1");
            }
            fs::copy(
                root.join("linkerconfig/ld.config.txt"),
                diagnostic_dir.join("ld.config.txt"),
            )?;
            if !root.join("run/ssal/ssal-zygote-diag.so").is_file() {
                return Err(io::Error::other("Guest Zygote diagnostic preload missing"));
            }
            command
                .env(
                    "LD_PRELOAD",
                    "/run/ssal/ssal-phase2-log.so:/run/ssal/ssal-zygote-diag.so",
                )
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            if std::env::var_os("SSAL_PHASE7FB_FORK").is_some()
                || crate::guest::system_server_enabled()
            {
                command.env("LD_PRELOAD", "/run/ssal/ssal-phase2-log.so:/run/ssal/ssal-zygote-diag.so:/run/ssal/ssal-zygote-fd-reopen.so")
                    .env("SSAL_PHASE7FB_FD_REOPEN", "1");
            }
            if std::env::var_os("SSAL_PHASE8B3B_NOOP").is_some() {
                let preload = command
                    .get_envs()
                    .find_map(|(key, value)| {
                        (key == "LD_PRELOAD")
                            .then_some(value.unwrap().to_string_lossy().into_owned())
                    })
                    .unwrap();
                command
                    .env(
                        "LD_PRELOAD",
                        format!("/run/ssal/ssal-zygote-selinux-noop.so:{preload}"),
                    )
                    .env("SSAL_PHASE8B3B_NOOP", "1")
                    .env_remove("SSAL_PHASE7FC_BYPASS_SETCONTEXT");
            }
            if std::env::var_os("SSAL_PHASE8B5_ONCE").is_some() {
                command.env("LD_PRELOAD", "/run/ssal/ssal-system-server-runtime-sid.so:/run/ssal/ssal-phase2-log.so:/run/ssal/ssal-zygote-diag.so:/run/ssal/ssal-zygote-fd-reopen.so");
            }
        } else {
            command.stdout(Stdio::piped()).stderr(Stdio::piped());
        }
        let sockets = if is_zygote {
            let contexts = ssal::guest_policy::runtime::load(root)?
                .map(|plan| -> io::Result<_> {
                    Ok((
                        plan.context("zygote", true)?,
                        plan.context("zygote_socket", false)?,
                    ))
                })
                .transpose()?;
            crate::guest::launcher::zygote_sockets(
                &mut command,
                Path::new("/dev/socket"),
                contexts,
            )?
        } else {
            Vec::new()
        };
        if !rust_service && ssal::guest_policy::runtime::load(root)?.is_some() {
            let preload = command
                .get_envs()
                .find_map(|(key, value)| {
                    (key == "LD_PRELOAD").then(|| value.map(|s| s.to_string_lossy().into_owned()))
                })
                .flatten();
            command.env(
                "LD_PRELOAD",
                preload.map_or_else(
                    || "/run/ssal/ssal-context-map.so".into(),
                    |s| format!("/run/ssal/ssal-context-map.so:{s}"),
                ),
            );
        }
        let launch_ms = crate::diagnostics::zygote::launch_time();
        let started = Instant::now();
        let child = command.args(args).spawn()?;
        drop(sockets);
        if installd_probe {
            let proc = Path::new("/proc").join(child.id().to_string());
            let namespace = fs::read_link(proc.join("ns/mnt"))
                .map(|path| path.display().to_string())
                .unwrap_or_else(|error| format!("unavailable: {error}"));
            let caps = fs::read_to_string(proc.join("status"))
                .map(|status| {
                    status
                        .lines()
                        .filter(|line| line.starts_with("CapEff:") || line.starts_with("CapBnd:"))
                        .collect::<Vec<_>>()
                        .join(" ")
                })
                .unwrap_or_else(|error| format!("unavailable: {error}"));
            println!("Guest installd post-exec pid={} mount_namespace={namespace} {caps}", child.id());
        }
        let context = fs::read_to_string(format!("/proc/{}/attr/current", child.id()))
            .map(|context| context.trim_matches('\0').trim().to_owned())
            .unwrap_or_else(|error| format!("unavailable: {error}"));
        println!(
            "Guest service={name} pid={} sid={context:?} executable={exe}",
            child.id()
        );
        let mut service = Self {
            child,
            log,
            stopped: false,
            diagnostics: None,
            output: Vec::new(),
        };
        if diagnostic {
            // Package scanning can emit several MiB before SystemReady.
            let stderr_limit = (is_zygote && crate::guest::launcher::graphics_system_server_requested())
                .then_some(16 * 1024 * 1024);
            service.diagnostics = Some(crate::diagnostics::zygote::Diagnostics::attach(
                &mut service.child,
                &diagnostic_dir,
                &crate::guest::cgroup::memory_group(crate::guest::cgroup::backend()?),
                launch_ms,
                started,
                stderr_limit,
            )?);
            println!("Guest diagnostics={}", diagnostic_dir.display());
        }
        if !diagnostic {
            // The parent writes logs; Guest daemons need not write a system_file.
            service.output.push(crate::diagnostics::zygote::Stream::new(
                service.child.stdout.take().unwrap(),
                File::options().append(true).open(&service.log)?,
            )?);
            service.output.push(crate::diagnostics::zygote::Stream::new(
                service.child.stderr.take().unwrap(),
                File::options().append(true).open(&service.log)?,
            )?);
            service.drain_output()?;
        }
        if let Some((code, status)) = service.exit_status()? {
            service.drain_output()?;
            let log = fs::read_to_string(&service.log).unwrap_or_default();
            if !log.is_empty() {
                println!("Guest service log before cleanup:\n{log}");
            }
            return Err(io::Error::other(format!(
                "Guest service={name} exited after exec: waitid_code={code} status={status}; pre-exec cgroups verified"
            )));
        }
        let membership = match crate::guest::cgroup::verify_guest_membership(service.child.id()) {
            Ok(membership) => membership,
            Err(error) => {
                let cgroup = fs::read_to_string(format!("/proc/{}/cgroup", service.child.id()))
                    .unwrap_or_else(|e| format!("unavailable: {e}"));
                let log = fs::read_to_string(&service.log).unwrap_or_default();
                println!(
                    "{} Guest service membership failed pid={} cgroup={cgroup} exit_status={:?} error={error}; pre-exec cgroups verified; membership mismatch does not establish exit cause",
                    crate::diagnostics::zygote::launch_time(),
                    service.child.id(),
                    service.exit_status()?
                );
                if !log.is_empty() {
                    println!("Guest service log before cleanup:\n{log}");
                }
                return Err(error);
            }
        };
        println!(
            "Guest service memory cgroup membership pid={} path={membership}",
            service.child.id()
        );
        Ok(service)
    }
    pub(in crate::guest) fn drain_output(&mut self) -> io::Result<()> {
        for stream in &mut self.output {
            stream.drain()?;
        }
        Ok(())
    }
    pub(in crate::guest) fn log_contains(&self, text: &str) -> io::Result<bool> {
        let log = fs::read_to_string(&self.log)?;
        Ok(log.contains(text))
    }
    pub(in crate::guest) fn wait_text(&mut self, text: &str) -> io::Result<()> {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            crate::guest::process::supervision::check_interrupted()?;
            let exited = self.exited()?;
            self.drain_output()?;
            let log = fs::read_to_string(&self.log)?;
            if exited {
                return Err(io::Error::other(format!(
                    "Guest service exited before readiness: {log}"
                )));
            }
            if log.contains(text) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(io::Error::other(format!(
                    "Guest service readiness timeout ({text}): {log}"
                )));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    pub(in crate::guest) fn readiness_diagnostics(
        &mut self,
        root: &Path,
        reason: &str,
        service_lookup: &str,
    ) {
        if let Err(error) = self.drain_output() {
            eprintln!("Guest servicemanager log drain failed: {error}");
        }
        let pid = self.child.id();
        let wchan = fs::read_to_string(format!("/proc/{pid}/wchan"))
            .unwrap_or_else(|error| format!("unavailable: {error}"));
        let mut fds = fs::read_dir(format!("/proc/{pid}/fd"))
            .map(|entries| {
                let mut fds: Vec<_> = entries
                    .flatten()
                    .map(|entry| {
                        let number = entry.file_name().to_string_lossy().into_owned();
                        let target = fs::read_link(entry.path())
                            .map(|path| path.display().to_string())
                            .unwrap_or_else(|error| format!("unavailable: {error}"));
                        let rdev = fs::metadata(entry.path())
                            .ok()
                            .filter(|metadata| metadata.file_type().is_char_device())
                            .map(|metadata| format!(" rdev={}", metadata.rdev()))
                            .unwrap_or_default();
                        format!("{number}->{target}{rdev}")
                    })
                    .collect();
                fds.sort();
                fds.join(",")
            })
            .unwrap_or_else(|error| format!("unavailable: {error}"));
        if fds.len() > 4096 {
            fds.truncate(4096);
        }
        let binder = fs::metadata(root.join("dev/binder"))
            .map(|metadata| format!("rdev={}", metadata.rdev()))
            .unwrap_or_else(|error| format!("unavailable: {error}"));
        let property_area = fs::metadata(root.join("dev/__properties__"))
            .map(|metadata| format!("dev={} ino={}", metadata.dev(), metadata.ino()))
            .unwrap_or_else(|error| format!("unavailable: {error}"));
        let property = crate::guest::launcher::guest_servicemanager_property(root)
            .map(|value| format!("{value:?}"))
            .unwrap_or_else(|error| format!("unavailable: {error}"));
        let context_manager = crate::guest::launcher::probe_guest_context_manager(root)
            .map(|value| value.trim().to_owned())
            .unwrap_or_else(|error| format!("failed: {error}"));
        let log = fs::read_to_string(&self.log)
            .map(|value| value.chars().take(4096).collect::<String>())
            .unwrap_or_else(|error| format!("unavailable: {error}"));
        println!(
            "Guest servicemanager readiness diagnostics: reason={reason:?} pid={pid} exit_status={:?} wchan={wchan:?} property={property} guest_property_area={property_area} guest_binder={binder} service_lookup={service_lookup:?}",
            self.exit_status()
        );
        println!("Guest servicemanager FDs: {fds}");
        println!("Guest Binder Context Manager probe: {context_manager}");
        println!("Guest servicemanager log: {log}");
    }
    pub(in crate::guest) fn wait_guest_context_manager(
        &mut self,
        root: &Path,
        expected_binder: u64,
    ) -> io::Result<()> {
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut context_manager = Err("not checked".to_owned());
        let mut next_context_manager_probe = Instant::now();
        loop {
            crate::guest::process::supervision::check_interrupted()?;
            if self.exited()? {
                self.readiness_diagnostics(root, "Guest servicemanager exited", "not run");
                return Err(io::Error::other(
                    "Guest servicemanager exited before semantic readiness",
                ));
            }
            if Instant::now() >= next_context_manager_probe {
                context_manager = crate::guest::launcher::probe_guest_context_manager(root)
                    .map_err(|error| error.to_string());
                next_context_manager_probe = Instant::now() + Duration::from_secs(1);
            }
            if let Ok(evidence) = &context_manager {
                let actual_binder = fs::metadata(root.join("dev/binder"))?.rdev();
                if actual_binder != expected_binder {
                    self.readiness_diagnostics(root, "Guest Binder identity changed", "not run");
                    return Err(io::Error::other(
                        "Guest Binder device changed during Context Manager readiness",
                    ));
                }
                println!(
                    "Guest Binder Context Manager=reachable pid={} private_binder_rdev={actual_binder}\n{evidence}",
                    self.child.id()
                );
                return Ok(());
            }
            if Instant::now() >= deadline {
                self.readiness_diagnostics(root, "semantic readiness timeout", "not run");
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("Guest Binder Context Manager timeout: {context_manager:?}"),
                ));
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    }
    pub(in crate::guest) fn wait_guest_servicemanager_property(
        &mut self,
        root: &Path,
        service_lookup: &str,
    ) -> io::Result<()> {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            crate::guest::process::supervision::check_interrupted()?;
            self.drain_output()?;
            if self.exited()? {
                self.readiness_diagnostics(root, "Guest servicemanager exited", service_lookup);
                return Err(io::Error::other(
                    "Guest servicemanager exited before servicemanager.ready=true",
                ));
            }
            let property = crate::guest::launcher::guest_servicemanager_property(root)
                .unwrap_or_else(|error| format!("unavailable: {error}"));
            if property == "true" {
                return Ok(());
            }
            if Instant::now() >= deadline {
                self.readiness_diagnostics(root, "servicemanager.ready timeout", service_lookup);
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("Guest servicemanager.ready remained {property:?}"),
                ));
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    }
    pub(in crate::guest) fn wait_for_socket(&mut self, socket_path: &Path) -> io::Result<()> {
        let deadline = Instant::now() + Duration::from_secs(90);
        loop {
            crate::guest::process::supervision::check_interrupted()?;
            if let Some(diagnostics) = &mut self.diagnostics {
                diagnostics.tick()?;
            }
            let log = fs::read_to_string(&self.log)?;
            if self.exited()? {
                return Err(io::Error::other(format!(
                    "Guest Zygote exited before socket readiness: {log}"
                )));
            }
            if socket_path.exists() {
                let mut command = Command::new("/proc/self/exe");
                command
                    .arg("--zygote-readiness-client")
                    .current_dir(
                        socket_path
                            .parent()
                            .ok_or_else(|| io::Error::other("socket parent missing"))?,
                    )
                    .stdin(Stdio::null());
                unsafe {
                    command.pre_exec(|| {
                        ssal::unix::cloexec_unexpected_fds()?;
                        if libc::setgroups(0, std::ptr::null()) != 0
                            || libc::setresgid(1000, 1000, 1000) != 0
                            || libc::setresuid(1000, 1000, 1000) != 0
                            || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
                        {
                            return Err(io::Error::last_os_error());
                        }
                        Ok(())
                    });
                }
                let output = self.readiness_output(command)?;
                if output.status.success() {
                    if self.exited()? {
                        return Err(io::Error::other("Guest Zygote exited after ABI response"));
                    }
                    print!("{}", String::from_utf8_lossy(&output.stdout));
                    return Ok(());
                }
                if output.status.code() != Some(2) {
                    return Err(io::Error::other(format!(
                        "Guest Zygote readiness client failed: {}",
                        String::from_utf8_lossy(&output.stderr)
                    )));
                }
            }
            if Instant::now() >= deadline {
                return Err(io::Error::other(format!(
                    "Guest Zygote socket readiness timeout ({}): {log}",
                    socket_path.display()
                )));
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
    pub(in crate::guest) fn readiness_output(
        &mut self,
        mut command: Command,
    ) -> io::Result<std::process::Output> {
        std::thread::scope(|scope| {
            let query = scope.spawn(move || command.output());
            while !query.is_finished() {
                crate::guest::process::supervision::check_interrupted()?;
                if let Some(diagnostics) = &mut self.diagnostics {
                    diagnostics.tick()?;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            query
                .join()
                .map_err(|_| io::Error::other("Zygote readiness query panicked"))?
        })
    }
    pub(crate) fn stop(&mut self) -> io::Result<()> {
        if self.stopped {
            return Ok(());
        }
        // Keep the leader unreaped until the owned process group has been stopped.
        if unsafe { libc::kill(-(self.child.id() as i32), libc::SIGKILL) } != 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) {
                return Err(error);
            }
        }
        let status = self.child.wait()?;
        self.drain_output()?;
        self.stopped = true;
        if let Some(diagnostics) = &mut self.diagnostics {
            diagnostics.finish(status)?;
        }
        println!(
            "Guest owned service pid={} stopped={status}\n{}",
            self.child.id(),
            fs::read_to_string(&self.log)?
        );
        Ok(())
    }
}

impl Drop for Service {
    fn drop(&mut self) {
        if let Err(e) = self.stop() {
            eprintln!("Guest service cleanup: {e}");
        }
    }
}
