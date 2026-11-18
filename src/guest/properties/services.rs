//! Experimental foreground Guest services; this registry never adopts existing PIDs.
use super::{server::PeerCredentials, Properties};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

const DEFAULT_RESTART_PERIOD: Duration = Duration::from_secs(5);

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
/// A trusted foreground service. Descendants must remain in its process group.
pub struct ServiceDefinition {
    pub name: String,
    pub executable: String,
    #[serde(default)]
    pub args: Vec<String>,
    /// Exact init-style keys: aidl/<registered-name> or <HIDL-interface>/<instance>.
    #[serde(default)]
    pub interfaces: Vec<String>,
    pub uid: u32,
    pub gid: u32,
    /// Original Guest policy domain, translated using this session's SELinux type map.
    pub domain: String,
    #[serde(default)]
    pub oneshot: Option<bool>,
    /// Seconds from the previous start. Crashes use a minimum of five seconds.
    #[serde(default)]
    pub restart_period: Option<u32>,
}

impl ServiceDefinition {
    fn restart_delay(&self, rc: Option<(bool, Option<u32>)>) -> Option<Duration> {
        let (oneshot, period) = rc.unwrap_or((self.restart_period.is_none(), None));
        (!self.oneshot.unwrap_or(oneshot)).then(|| {
            self.restart_period
                .or(period)
                .map(|seconds| Duration::from_secs(seconds.into()))
                .unwrap_or(DEFAULT_RESTART_PERIOD)
        })
    }
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}

pub(super) fn validate_control(action: &str, name: &str) -> io::Result<()> {
    let (action, valid_target) = match action.strip_prefix("interface_") {
        Some(action) => (action, valid_interface(name)),
        None => (action, valid_name(name)),
    };
    if !matches!(action, "start" | "stop" | "restart") || !valid_target {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unsupported Guest control or invalid service name",
        ));
    }
    Ok(())
}

fn valid_interface(name: &str) -> bool {
    name.contains('/')
        && rsproperties::wire::validate_value_len("ctl.interface_start", name).is_ok()
        && name.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'/' | b'@' | b':')
        })
        && name.split('/').all(|part| !matches!(part, "" | "." | ".."))
}

fn open_executable(
    path: &std::path::Path,
    validate: impl FnOnce(&std::path::Path) -> io::Result<()>,
) -> io::Result<fs::File> {
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Guest executable must be a regular file",
        ));
    }
    validate(std::path::Path::new(&format!(
        "/proc/self/fd/{}",
        file.as_raw_fd()
    )))?;
    // shortcut: pin ELF executables with CLOEXEC; invoke scripts through an explicit Guest interpreter.
    let mut magic = [0; 4];
    file.read_exact_at(&mut magic, 0)?;
    if magic != *b"\x7fELF" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Guest executable must be ELF; use an explicit interpreter for scripts",
        ));
    }
    Ok(file)
}

fn has_memory_cgroup(task_magic: u64, procs: &std::path::Path) -> io::Result<bool> {
    match fs::metadata(procs) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound && task_magic == 0x6367_7270 => {
            Ok(false)
        }
        Err(error) => Err(error),
    }
}

struct Service {
    definition: ServiceDefinition,
    context: String,
    child: Option<Child>,
    state: &'static str,
    started_at: Instant,
    restart_delay: Option<Duration>,
    restart: Option<Restart>,
    spawn: fn(&ServiceDefinition, &str) -> io::Result<Child>,
}

#[derive(Clone, Copy)]
enum Restart {
    Manual,
    Automatic { since: Instant, delay: Duration },
}

impl Service {
    fn start(&mut self) -> io::Result<()> {
        let started_at = Instant::now();
        self.child = Some((self.spawn)(&self.definition, &self.context)?);
        self.started_at = started_at;
        self.state = "running";
        Ok(())
    }

    fn spawn(definition: &ServiceDefinition, context: &str) -> io::Result<Child> {
        let executable = open_executable(
            std::path::Path::new(&definition.executable),
            super::guest_input,
        )
        .map_err(|error| io::Error::new(error.kind(), format!("Guest executable pin: {error}")))?;
        let mut command = Command::new(format!("/proc/self/fd/{}", executable.as_raw_fd()));
        command
            .arg0(&definition.executable)
            .args(&definition.args)
            .env_clear()
            .env("PATH", "/system/bin:/system/xbin")
            .env("ANDROID_ROOT", "/system")
            .env("ANDROID_DATA", "/data")
            .current_dir("/")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0);
        let context = context.to_owned();
        let uid = definition.uid;
        let gid = definition.gid;
        let parent = std::process::id() as i32;
        let mut groups: Vec<_> = ["/sys/fs/cgroup", "/dev/cpuctl", "/dev/cpuset", "/dev/blkio"]
            .into_iter()
            .map(std::path::PathBuf::from)
            .collect();
        let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::statfs(c"/sys/fs/cgroup".as_ptr(), &mut stat) } != 0 {
            return Err(io::Error::last_os_error());
        }
        match stat.f_type as u64 {
            0x6367_7270 | 0x0027_e0eb => {}
            _ => return Err(io::Error::other("Guest cgroup filesystem required")),
        }
        // Android can use a v2 task hierarchy together with a v1 memory controller.
        if has_memory_cgroup(
            stat.f_type as u64,
            std::path::Path::new("/dev/memcg/cgroup.procs"),
        )? {
            groups.push("/dev/memcg".into());
        }
        unsafe {
            command.pre_exec(move || {
                crate::unix::cloexec_unexpected_fds()?;
                crate::platform::process::join_cgroups(&groups)?;
                fs::write("/proc/thread-self/attr/exec", context.as_bytes())?;
                if libc::setgroups(0, std::ptr::null()) != 0
                    || libc::setresgid(gid, gid, gid) != 0
                    || libc::setresuid(uid, uid, uid) != 0
                    // shortcut: secureexec can clear PDEATHSIG; add owner-side monitoring before promising immediate worker-failure cleanup.
                    || libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0
                    || libc::getppid() != parent
                {
                    return Err(io::Error::other(
                        "Guest service credentials/parent gate failed",
                    ));
                }
                Ok(())
            });
        }
        let result = command.spawn();
        drop(executable);
        result
    }

    fn exited(&self) -> io::Result<bool> {
        let Some(child) = &self.child else {
            return Ok(false);
        };
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        if unsafe {
            libc::waitid(
                libc::P_PID,
                child.id(),
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { info.si_pid() } != 0)
    }

    fn kill_group(&self) -> io::Result<()> {
        if let Some(child) = &self.child {
            // shortcut: foreground services must keep descendants in this group; add per-service cgroups before supporting daemonization.
            // WNOWAIT proves ownership without releasing the leader PID/PGID for reuse.
            self.exited()?;
            if unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) } != 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() != Some(libc::ESRCH) {
                    return Err(error);
                }
            }
        }
        Ok(())
    }

    fn reap(&mut self) -> io::Result<Option<ExitStatus>> {
        self.kill_group()?;
        let status = self.child.as_mut().map(Child::wait).transpose()?;
        self.child = None;
        self.state = "stopped";
        Ok(status)
    }
}

pub(super) struct Registry(
    BTreeMap<String, Service>,
    BTreeSet<String>,
    BTreeMap<String, String>,
);

impl Registry {
    pub fn new(
        definitions: Vec<ServiceDefinition>,
        types: &BTreeMap<String, String>,
    ) -> io::Result<Self> {
        let mut services = BTreeMap::new();
        let mut interfaces = BTreeMap::new();
        for definition in definitions {
            let path = std::path::Path::new(&definition.executable);
            if !valid_name(&definition.name)
                || !path.is_absolute()
                || path
                    .components()
                    .any(|c| matches!(c, std::path::Component::ParentDir))
                || definition.executable.contains('\0')
                || definition.args.iter().any(|s| s.contains('\0'))
                || definition.uid == u32::MAX
                || definition.gid == u32::MAX
                || definition.domain == "init"
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid Guest service definition",
                ));
            }
            let target = types
                .get(&definition.domain)
                .filter(|target| {
                    target.starts_with("ssal_p")
                        && target.len() <= 255
                        && target
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
                })
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "service needs a mapped Guest SELinux domain",
                    )
                })?;
            let name = definition.name.clone();
            for interface in &definition.interfaces {
                if !valid_interface(interface)
                    || interfaces.insert(interface.clone(), name.clone()).is_some()
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "invalid or duplicate Guest interface",
                    ));
                }
            }
            let restart_delay = definition.restart_delay(None);
            let service = Service {
                definition,
                context: format!("u:r:{target}:s0"),
                child: None,
                state: "stopped",
                started_at: Instant::now(),
                restart_delay,
                restart: None,
                spawn: Service::spawn,
            };
            if services.insert(name, service).is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "duplicate Guest service",
                ));
            }
        }
        let sources = types
            .values()
            .filter(|target| {
                target.starts_with("ssal_p")
                    && target
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'_')
            })
            .map(|target| format!("u:r:{target}:s0"))
            .collect();
        Ok(Self(services, sources, interfaces))
    }

    pub fn guest_sources(&self) -> BTreeSet<String> {
        self.1.clone()
    }

    pub fn apply_restart_options(&mut self, plan: &crate::guest_initrc::Plan) {
        for (name, service) in &mut self.0 {
            let definition = &service.definition;
            let options = plan.restart_options(name, &definition.executable, &definition.args);
            service.restart_delay = definition.restart_delay(options);
        }
    }

    pub fn publish(&self, properties: &mut Properties) -> io::Result<()> {
        for (name, service) in &self.0 {
            properties.set(&format!("init.svc.{name}"), service.state)?;
        }
        Ok(())
    }

    pub fn dispatch(
        &mut self,
        action: &str,
        name: &str,
        peer: Option<PeerCredentials>,
        properties: &mut Properties,
    ) -> io::Result<bool> {
        if validate_control(action, name).is_err() {
            return Ok(false);
        }
        let (action, name) = if let Some(action) = action.strip_prefix("interface_") {
            let Some(service_name) = self.2.get(name) else {
                return Ok(false);
            };
            (action, service_name.as_str())
        } else {
            (action, name)
        };
        let Some(service) = self.0.get_mut(name) else {
            return Ok(false);
        };
        if peer.is_none()
            && (matches!(name, "servicemanager" | "zygote" | "zygote_secondary")
                || service.definition.executable.starts_with("/vendor/")
                || service.definition.executable.starts_with("/odm/"))
        {
            return Ok(false);
        }
        let result = match action {
            "start" if service.child.is_none() && service.restart.is_none() => service.start(),
            "start" => Ok(()),
            "stop" | "restart" => {
                if service.child.is_some() {
                    service.kill_group().map(|()| {
                        service.restart = (action == "restart").then_some(Restart::Manual);
                        service.state = if service.restart.is_some() {
                            "restarting"
                        } else {
                            "stopping"
                        }
                    })
                } else {
                    service.restart = None;
                    service.state = "stopped";
                    if action == "restart" {
                        service.start()
                    } else {
                        Ok(())
                    }
                }
            }
            _ => unreachable!(),
        };
        if let Err(error) = result {
            if let Some(peer) = peer {
                eprintln!(
                    "Guest ctl.{action} service={name} caller_pid={} uid={} gid={} failed: {error}",
                    peer.pid, peer.uid, peer.gid
                );
            } else {
                eprintln!("Guest initrc {action} service={name} failed: {error}");
            }
            properties.set(&format!("init.svc.{name}"), service.state)?;
            return Ok(false);
        }
        properties.set(&format!("init.svc.{name}"), service.state)?;
        Ok(true)
    }

    pub fn tick(&mut self, properties: &mut Properties) -> io::Result<()> {
        for (name, service) in &mut self.0 {
            if service.exited()? {
                let delay = service.restart_delay.filter(|_| service.state == "running");
                if let (Some(delay), Some(status)) = (delay, service.reap()?) {
                    service.restart = Some(Restart::Automatic {
                        since: service.started_at,
                        delay: if status.success() {
                            delay
                        } else {
                            delay.max(DEFAULT_RESTART_PERIOD)
                        },
                    });
                }
                service.state = if service.restart.is_some() {
                    "restarting"
                } else {
                    "stopped"
                };
                properties.set(&format!("init.svc.{name}"), service.state)?;
            }
            if let Some(restart) = service.restart.filter(|_| service.child.is_none()) {
                if let Restart::Automatic { since, delay } = restart {
                    if since.elapsed() < delay {
                        continue;
                    }
                }
                service.restart = None;
                if let Err(error) = service.start() {
                    eprintln!("Guest service={name} restart failed: {error}");
                    if let Restart::Automatic { delay, .. } = restart {
                        service.restart = Some(Restart::Automatic {
                            since: Instant::now(),
                            delay: delay.max(DEFAULT_RESTART_PERIOD),
                        });
                        continue;
                    }
                    service.state = "stopped";
                }
                properties.set(&format!("init.svc.{name}"), service.state)?;
            }
        }
        Ok(())
    }
}

impl Drop for Registry {
    fn drop(&mut self) {
        for (name, service) in &mut self.0 {
            if let Err(error) = service.reap() {
                eprintln!("Guest service={name} cleanup failed: {error}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::time::{Duration, Instant};

    fn definition(name: &str) -> ServiceDefinition {
        ServiceDefinition {
            name: name.into(),
            executable: "/bin/sleep".into(),
            args: vec!["60".into()],
            interfaces: vec![],
            uid: 1000,
            gid: 1000,
            domain: "shell".into(),
            oneshot: None,
            restart_period: None,
        }
    }

    fn registry() -> Registry {
        let mut registry = Registry::new(
            vec![definition("mock")],
            &BTreeMap::from([("shell".into(), "ssal_p0001_shell".into())]),
        )
        .unwrap();
        // Only replace the Android launch boundary; lifecycle, wire, registry and mmap are real.
        registry.0.get_mut("mock").unwrap().spawn = mock_spawn;
        registry
    }

    fn mock_spawn(definition: &ServiceDefinition, _: &str) -> io::Result<Child> {
        Command::new(&definition.executable)
            .args(&definition.args)
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn executable_is_pinned_across_symlink_replacement() {
        let root = super::super::tests::temp_dir("ctl-executable-race");
        fs::create_dir_all(&root).unwrap();
        let link = root.join("service");
        std::os::unix::fs::symlink("/bin/true", &link).unwrap();
        let executable = open_executable(&link, |fd_path| {
            assert_eq!(fs::canonicalize(fd_path)?, fs::canonicalize("/bin/true")?);
            fs::remove_file(&link)?;
            std::os::unix::fs::symlink("/bin/false", &link)
        })
        .unwrap();
        let status = Command::new(format!("/proc/self/fd/{}", executable.as_raw_fd()))
            .arg0("true")
            .status()
            .unwrap();
        assert!(status.success(), "must execute the inspected inode");
        assert!(!Command::new(&link).status().unwrap().success());
        assert!(open_executable(&link, |_| Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "outside Guest roots"
        )))
        .is_err());
        let script = root.join("script");
        fs::write(&script, "#!/bin/sh\nexit 0\n").unwrap();
        assert!(open_executable(&script, |_| Ok(())).is_err());
        drop(executable);
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn pinned_executable_runs_after_uid_drop() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let executable = open_executable(std::path::Path::new("/bin/true"), |_| Ok(())).unwrap();
        let mut command = Command::new(format!("/proc/self/fd/{}", executable.as_raw_fd()));
        unsafe {
            command.pre_exec(move || {
                if libc::setgroups(0, std::ptr::null()) != 0
                    || libc::setresgid(2000, 2000, 2000) != 0
                    || libc::setresuid(2000, 2000, 2000) != 0
                {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        assert!(command.status().unwrap().success());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cgroup_failure_prevents_exec_and_spawn_reaps_partial_child() {
        let root = super::super::tests::temp_dir("ctl-cgroup-failure");
        let group = root.join("group");
        fs::create_dir_all(&group).unwrap();
        fs::write(group.join("cgroup.procs"), "").unwrap();
        let marker = root.join("executed");
        let groups = vec![group.clone(), root.join("missing")];
        let mut command = Command::new("/bin/sh");
        command
            .args(["-c", "touch \"$1\"", "sh"])
            .arg(&marker)
            .process_group(0);
        unsafe {
            command.pre_exec(move || crate::platform::process::join_cgroups(&groups));
        }
        assert!(command.spawn().is_err());
        assert!(!marker.exists());
        let attempted: u32 = fs::read_to_string(group.join("cgroup.procs"))
            .unwrap()
            .parse()
            .unwrap();
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe {
                libc::waitid(
                    libc::P_PID,
                    attempted,
                    &mut info,
                    libc::WEXITED | libc::WNOHANG,
                )
            },
            -1
        );
        assert_eq!(
            io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn hybrid_task_v2_still_requires_present_v1_memory_controller() {
        let root = super::super::tests::temp_dir("ctl-hybrid-memory");
        fs::create_dir_all(&root).unwrap();
        let procs = root.join("cgroup.procs");
        assert!(!has_memory_cgroup(0x6367_7270, &procs).unwrap());
        assert!(has_memory_cgroup(0x0027_e0eb, &procs).is_err());
        fs::write(&procs, "").unwrap();
        assert!(has_memory_cgroup(0x6367_7270, &procs).unwrap());
        assert!(has_memory_cgroup(0x0027_e0eb, &procs).unwrap());
        fs::remove_dir_all(root).unwrap();
    }

    fn request(
        registry: &mut Registry,
        properties: &mut Properties,
        action: &str,
        name: &str,
        allowed: bool,
    ) -> u32 {
        let (mut client, mut server) = UnixStream::pair().unwrap();
        client
            .write_all(&rsproperties::wire::PROP_MSG_SETPROP2.to_le_bytes())
            .unwrap();
        for value in [format!("ctl.{action}"), name.into()] {
            client
                .write_all(&(value.len() as u32).to_le_bytes())
                .unwrap();
            client.write_all(value.as_bytes()).unwrap();
        }
        super::super::server::handle(
            &mut server,
            properties,
            |_, _, control| {
                assert!(control);
                if allowed {
                    Ok(PeerCredentials {
                        pid: 42,
                        uid: 1000,
                        gid: 1000,
                    })
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "unauthorized SID",
                    ))
                }
            },
            |action, target, peer, properties| {
                registry.dispatch(action, target, Some(peer), properties)
            },
            |_, _| panic!("Host/power routing"),
        )
        .unwrap();
        let mut bytes = [0; 4];
        client.read_exact(&mut bytes).unwrap();
        assert!(properties
            .area
            .find(&format!("ctl.{action}"))
            .unwrap()
            .is_none());
        u32::from_le_bytes(bytes)
    }

    fn until(registry: &mut Registry, properties: &mut Properties, state: &str) {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            registry.tick(properties).unwrap();
            if properties.area.get("init.svc.mock").unwrap() == state {
                break;
            }
            assert!(Instant::now() < deadline, "state timeout: {state}");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn automatic_restart_reaps_before_retry_and_explicit_controls_win() {
        let root = super::super::tests::temp_dir("automatic-restart");
        let mut properties = super::super::tests::fixture(&root);
        let mut registry = registry();
        registry.0.get_mut("mock").unwrap().restart_delay = Some(Duration::ZERO);
        let success = rsproperties::wire::PROP_SUCCESS as u32;
        assert_eq!(
            request(&mut registry, &mut properties, "start", "mock", true),
            success
        );
        let crash = |registry: &mut Registry| {
            let child = registry.0.get_mut("mock").unwrap().child.as_mut().unwrap();
            child.kill().unwrap();
            child.id()
        };
        let first = crash(&mut registry);
        until(&mut registry, &mut properties, "restarting");
        let service = registry.0.get_mut("mock").unwrap();
        assert!(service.child.is_none());
        assert!(
            matches!(service.restart, Some(Restart::Automatic { since, delay })
            if since == service.started_at && delay == DEFAULT_RESTART_PERIOD)
        );
        assert_eq!(
            request(&mut registry, &mut properties, "start", "mock", true),
            success
        );
        registry.tick(&mut properties).unwrap();
        assert!(
            registry.0["mock"].child.is_none(),
            "start must respect pending crash delay"
        );

        let service = registry.0.get_mut("mock").unwrap();
        service.restart = Some(Restart::Automatic {
            since: service.started_at,
            delay: Duration::ZERO,
        });
        registry.tick(&mut properties).unwrap();
        assert_eq!(properties.area.get("init.svc.mock").unwrap(), "running");
        assert_ne!(registry.0["mock"].child.as_ref().unwrap().id(), first);

        let second = crash(&mut registry);
        until(&mut registry, &mut properties, "restarting");
        let service = registry.0.get_mut("mock").unwrap();
        service.restart = Some(Restart::Automatic {
            since: service.started_at,
            delay: Duration::ZERO,
        });
        service.spawn = |_, _| Err(io::Error::other("simulated exec failure"));
        registry.tick(&mut properties).unwrap();
        let service = &registry.0["mock"];
        assert!(
            matches!(service.restart, Some(Restart::Automatic { delay, .. })
            if delay == DEFAULT_RESTART_PERIOD)
        );
        assert_eq!(properties.area.get("init.svc.mock").unwrap(), "restarting");
        registry.0.get_mut("mock").unwrap().spawn = mock_spawn;
        assert_eq!(
            request(&mut registry, &mut properties, "restart", "mock", true),
            success
        );
        assert_eq!(properties.area.get("init.svc.mock").unwrap(), "running");
        assert_ne!(registry.0["mock"].child.as_ref().unwrap().id(), second);

        crash(&mut registry);
        until(&mut registry, &mut properties, "restarting");
        assert_eq!(
            request(&mut registry, &mut properties, "stop", "mock", true),
            success
        );
        registry.tick(&mut properties).unwrap();
        assert_eq!(properties.area.get("init.svc.mock").unwrap(), "stopped");
        assert!(registry.0["mock"].restart.is_none());
        assert!(registry.0["mock"].child.is_none());
        assert_eq!(
            request(&mut registry, &mut properties, "start", "mock", true),
            success
        );
        assert_eq!(
            request(&mut registry, &mut properties, "stop", "mock", true),
            success
        );
        until(&mut registry, &mut properties, "stopped");
        assert!(registry.0["mock"].restart.is_none());
        drop(registry);
        drop(properties);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rc_restart_options_bind_to_declared_command_and_clean_exit_uses_period() {
        let root = super::super::tests::temp_dir("rc-restart-options");
        let rc = root.join("system/etc/init/hw");
        fs::create_dir_all(&rc).unwrap();
        fs::write(
            rc.join("init.rc"),
            "
service mock /bin/sleep 60
    restart_period 2
service single /bin/sleep 60
    oneshot
    restart_period 0
",
        )
        .unwrap();
        let plan = crate::guest_initrc::Plan::load(&root, &Default::default()).unwrap();
        let mut registry = registry();
        let mut properties = super::super::tests::fixture(&root);
        assert_eq!(registry.0["mock"].restart_delay, None);
        registry.apply_restart_options(&plan);
        assert_eq!(
            registry.0["mock"].restart_delay,
            Some(Duration::from_secs(2))
        );
        let mut single = definition("single");
        let rc = plan.restart_options("single", &single.executable, &single.args);
        assert_eq!(single.restart_delay(rc), None);
        single.oneshot = Some(false);
        assert_eq!(single.restart_delay(rc), Some(Duration::ZERO));
        single.restart_period = Some(3);
        assert_eq!(single.restart_delay(rc), Some(Duration::from_secs(3)));
        assert!(plan
            .restart_options("single", &single.executable, &[])
            .is_none());

        registry.0.get_mut("mock").unwrap().spawn =
            |_, _| Command::new("/bin/true").process_group(0).spawn();
        let success = rsproperties::wire::PROP_SUCCESS as u32;
        assert_eq!(
            request(&mut registry, &mut properties, "start", "mock", true),
            success
        );
        until(&mut registry, &mut properties, "restarting");
        assert!(
            matches!(registry.0["mock"].restart, Some(Restart::Automatic { delay, .. })
            if delay == Duration::from_secs(2))
        );
        drop(registry);
        drop(properties);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn wire_mock_lifecycle_denials_crash_and_host_boundary() {
        let root = super::super::tests::temp_dir("ctl-lifecycle");
        let mut properties = super::super::tests::fixture(&root);
        let host_root = super::super::tests::temp_dir("ctl-host-area");
        let mut host_properties = super::super::tests::fixture(&host_root);
        host_properties
            .set("init.svc.mock", "host-sentinel")
            .unwrap();
        let mut registry = registry();
        registry.publish(&mut properties).unwrap();
        let mut host = Command::new("/bin/sleep").arg("60").spawn().unwrap();
        let success = rsproperties::wire::PROP_SUCCESS as u32;
        let failure = rsproperties::wire::PROP_ERROR_HANDLE_CONTROL_MESSAGE as u32;
        for name in [
            "",
            "../mock",
            "mock$other",
            "mock other",
            "unregistered",
            "zygote",
        ] {
            assert_eq!(
                request(&mut registry, &mut properties, "start", name, true),
                failure
            );
        }
        assert_eq!(
            request(
                &mut registry,
                &mut properties,
                "interface_start",
                "mock",
                true
            ),
            failure
        );
        assert_eq!(
            request(&mut registry, &mut properties, "start", "mock", false),
            failure
        );
        assert!(registry.0["mock"].child.is_none());
        assert_eq!(
            request(&mut registry, &mut properties, "start", "mock", true),
            success
        );
        let first = registry.0["mock"].child.as_ref().unwrap().id();
        assert_eq!(properties.area.get("init.svc.mock").unwrap(), "running");
        assert_eq!(
            request(&mut registry, &mut properties, "start", "mock", true),
            success
        );
        assert_eq!(registry.0["mock"].child.as_ref().unwrap().id(), first);
        for _ in 0..2 {
            assert_eq!(
                request(&mut registry, &mut properties, "stop", "mock", true),
                success
            );
        }
        until(&mut registry, &mut properties, "stopped");
        assert_eq!(
            request(&mut registry, &mut properties, "restart", "mock", true),
            success
        );
        let second = registry.0["mock"].child.as_ref().unwrap().id();
        for _ in 0..2 {
            assert_eq!(
                request(&mut registry, &mut properties, "restart", "mock", true),
                success
            );
        }
        assert_eq!(properties.area.get("init.svc.mock").unwrap(), "restarting");
        until(&mut registry, &mut properties, "running");
        assert_ne!(registry.0["mock"].child.as_ref().unwrap().id(), second);
        // A rejected request cannot change the PID or the last published state.
        let running = registry.0["mock"].child.as_ref().unwrap().id();
        assert_eq!(
            request(&mut registry, &mut properties, "stop", "mock", false),
            failure
        );
        assert_eq!(registry.0["mock"].child.as_ref().unwrap().id(), running);
        registry
            .0
            .get_mut("mock")
            .unwrap()
            .child
            .as_mut()
            .unwrap()
            .kill()
            .unwrap();
        until(&mut registry, &mut properties, "stopped");
        assert_eq!(
            properties.area.get("ro.property_service.version").unwrap(),
            "2"
        );
        assert_eq!(properties.area.get("persist.number").unwrap(), "1");
        assert_eq!(
            host_properties.area.get("init.svc.mock").unwrap(),
            "host-sentinel"
        );
        assert_eq!(host_properties.area.get("persist.number").unwrap(), "1");
        for name in ["ctl.start", "ctl.stop", "ctl.restart"] {
            assert!(host_properties.area.find(name).unwrap().is_none());
        }
        assert!(
            host.try_wait().unwrap().is_none(),
            "unowned process must survive"
        );
        host.kill().unwrap();
        host.wait().unwrap();
        drop(registry);
        drop(properties);
        drop(host_properties);
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(host_root).unwrap();
    }

    #[test]
    fn registry_validation_and_failed_exec() {
        let types = BTreeMap::from([("shell".into(), "ssal_p0001_shell".into())]);
        assert!(Registry::new(vec![definition("mock"), definition("mock")], &types).is_err());
        assert!(Registry::new(vec![definition("mock")], &BTreeMap::new()).is_err());
        for (executable, domain) in [
            ("relative", "shell"),
            ("/bin/../sleep", "shell"),
            ("/bin/sleep", "init"),
            ("/bin/sleep", "host"),
        ] {
            let mut service = definition("mock");
            service.executable = executable.into();
            service.domain = domain.into();
            assert!(Registry::new(vec![service], &types).is_err());
        }
        let root = super::super::tests::temp_dir("ctl-exec-failure");
        let mut properties = super::super::tests::fixture(&root);
        let mut registry = registry();
        assert!(registry.guest_sources().contains("u:r:ssal_p0001_shell:s0"));
        assert!(!registry.guest_sources().contains("u:r:init:s0"));
        registry.0.get_mut("mock").unwrap().definition.executable =
            "/nonexistent-ssal-guest-mock".into();
        assert_eq!(
            request(&mut registry, &mut properties, "start", "mock", true),
            rsproperties::wire::PROP_ERROR_HANDLE_CONTROL_MESSAGE as u32
        );
        assert_eq!(properties.area.get("init.svc.mock").unwrap(), "stopped");
        drop(registry);
        drop(properties);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn interface_wire_aliases_share_lifecycle_without_service_name_fallback() {
        let root = super::super::tests::temp_dir("ctl-interface");
        let mut properties = super::super::tests::fixture(&root);
        let mut definition = definition("mock");
        let aidl = "aidl/dev.ssal.IMock/default";
        let hidl = "dev.ssal.mock@1.0::IMock/default";
        definition.interfaces = vec![aidl.into(), hidl.into()];
        let mut registry = Registry::new(
            vec![definition],
            &BTreeMap::from([("shell".into(), "ssal_p0001_shell".into())]),
        )
        .unwrap();
        registry.0.get_mut("mock").unwrap().spawn = mock_spawn;
        let success = rsproperties::wire::PROP_SUCCESS as u32;
        let failure = rsproperties::wire::PROP_ERROR_HANDLE_CONTROL_MESSAGE as u32;
        for target in [
            "mock",
            "aidl/unregistered",
            "aidl/",
            "aidl/../mock",
            "aidl/x$y",
            "aidl/x y",
            "aidl/x\0",
        ] {
            assert_eq!(
                request(
                    &mut registry,
                    &mut properties,
                    "interface_start",
                    target,
                    true
                ),
                failure
            );
        }
        for action in ["interface_start", "interface_stop", "interface_restart"] {
            assert_eq!(
                request(&mut registry, &mut properties, action, aidl, false),
                failure
            );
        }
        assert!(registry.0["mock"].child.is_none());
        assert_eq!(
            request(
                &mut registry,
                &mut properties,
                "interface_start",
                aidl,
                true
            ),
            success
        );
        let first = registry.0["mock"].child.as_ref().unwrap().id();
        assert_eq!(
            request(
                &mut registry,
                &mut properties,
                "interface_start",
                hidl,
                true
            ),
            success
        );
        assert_eq!(registry.0["mock"].child.as_ref().unwrap().id(), first);
        assert_eq!(
            request(&mut registry, &mut properties, "interface_stop", hidl, true),
            success
        );
        until(&mut registry, &mut properties, "stopped");
        assert_eq!(
            request(
                &mut registry,
                &mut properties,
                "interface_restart",
                aidl,
                true
            ),
            success
        );
        let second = registry.0["mock"].child.as_ref().unwrap().id();
        for _ in 0..2 {
            assert_eq!(
                request(
                    &mut registry,
                    &mut properties,
                    "interface_restart",
                    hidl,
                    true
                ),
                success
            );
        }
        until(&mut registry, &mut properties, "running");
        assert_ne!(registry.0["mock"].child.as_ref().unwrap().id(), second);
        assert_eq!(
            request(
                &mut registry,
                &mut properties,
                "interface_stop",
                aidl,
                false
            ),
            failure
        );
        assert_eq!(properties.area.get("init.svc.mock").unwrap(), "running");
        assert_eq!(
            request(&mut registry, &mut properties, "start", aidl, true),
            failure
        );
        assert!(properties.area.find("init.svc.aidl").unwrap().is_none());
        assert_eq!(properties.area.get("persist.number").unwrap(), "1");
        drop(registry);
        drop(properties);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn interface_registration_is_optional_validated_and_unambiguous() {
        let mut value = serde_json::json!({"name":"mock", "executable":"/system/bin/sleep", "args":["60"], "uid":1000, "gid":1000, "domain":"shell"});
        let parsed: ServiceDefinition = serde_json::from_value(value.clone()).unwrap();
        assert!(
            parsed.interfaces.is_empty(),
            "old configurations remain valid"
        );
        value["interfaces"] = serde_json::json!(["aidl/apexservice"]);
        let parsed: ServiceDefinition = serde_json::from_value(value).unwrap();
        let types = BTreeMap::from([("shell".into(), "ssal_p0001_shell".into())]);
        assert!(Registry::new(vec![parsed], &types).is_ok());
        for interface in [
            "",
            "mock",
            "aidl/",
            "aidl/a b",
            "aidl/a$b",
            "aidl/../x",
            "aidl/./x",
            "aidl//x",
            "aidl/a\0b",
            &format!("aidl/{}", "x".repeat(100)),
        ] {
            let mut service = definition("mock");
            service.interfaces = vec![interface.into()];
            assert!(
                Registry::new(vec![service], &types).is_err(),
                "{interface:?}"
            );
        }
        let mut first = definition("mock");
        first.interfaces = vec!["aidl/dev.ssal.IMock/default".into()];
        let mut second = definition("other");
        second.interfaces = first.interfaces.clone();
        assert!(Registry::new(vec![first, second], &types).is_err());
        let mut service = definition("mock");
        service.interfaces = vec!["aidl/mock".into(), "aidl/mock".into()];
        assert!(Registry::new(vec![service], &types).is_err());
    }

    #[test]
    fn drop_kills_owned_group_and_reaped_pid_is_never_signaled() {
        let mut registry = registry();
        let service = registry.0.get_mut("mock").unwrap();
        service.start().unwrap();
        let pid = service.child.as_ref().unwrap().id() as i32;
        drop(registry);
        assert_eq!(unsafe { libc::kill(pid, 0) }, -1);
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::ESRCH));
        let mut registry = self::registry();
        let service = registry.0.get_mut("mock").unwrap();
        service.start().unwrap();
        let child = service.child.as_mut().unwrap();
        child.kill().unwrap();
        child.wait().unwrap();
        assert_eq!(
            service.kill_group().unwrap_err().raw_os_error(),
            Some(libc::ECHILD)
        );
        service.child = None;
    }

    #[test]
    fn exited_leader_group_is_killed_before_reap() {
        let mut registry = registry();
        let service = registry.0.get_mut("mock").unwrap();
        let mut child = Command::new("/bin/sh")
            .args(["-c", "sleep 60 & echo $!; exit 0"])
            .process_group(0)
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut output = child.stdout.take().unwrap();
        let mut line = Vec::new();
        loop {
            let mut byte = [0];
            output.read_exact(&mut byte).unwrap();
            if byte[0] == b'\n' {
                break;
            }
            line.push(byte[0]);
        }
        let descendant: i32 = std::str::from_utf8(&line).unwrap().parse().unwrap();
        service.child = Some(child);
        let deadline = Instant::now() + Duration::from_secs(3);
        while !service.exited().unwrap() {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(5));
        }
        service.reap().unwrap();
        while fs::read_to_string(format!("/proc/{descendant}/stat"))
            .is_ok_and(|stat| !stat.split_once(") ").unwrap().1.starts_with('Z'))
        {
            assert!(Instant::now() < deadline, "owned descendant survived");
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}
