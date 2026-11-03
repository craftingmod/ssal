//! Disposable Test B. Never authorizes operational services or switch.
use super::runtime_preflight::environment::{self, Masks};
use super::*;
use serde_json::{json, Value};
#[cfg(target_os = "android")]
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::BufRead;
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver};

const FIELDS: [&str; 5] = [
    "servicemanager",
    "android_service_selinux",
    "host_registry_isolation",
    "property_host_unchanged",
    "cleanup",
];

pub fn check_recovery() -> io::Result<()> {
    let path = Path::new(ssal::unix::ROOT).join("state/binder-recovery-required.json");
    match fs::read(&path) {
        Ok(bytes) => {
            let report: Value = serde_json::from_slice(&bytes)?;
            let boot = report["boot_id"]
                .as_str()
                .filter(|s| {
                    s.len() == 36
                        && s.bytes().enumerate().all(|(i, b)| {
                            if [8, 13, 18, 23].contains(&i) {
                                b == b'-'
                            } else {
                                b.is_ascii_hexdigit()
                            }
                        })
                })
                .ok_or_else(|| {
                    io::Error::other("RECOVERY_REQUIRED: invalid boot ID in recovery marker")
                })?;
            if boot == context("/proc/sys/kernel/random/boot_id")? {
                return Err(io::Error::other(format!(
                    "RECOVERY_REQUIRED: inspect {} before a new probe",
                    path.display()
                )));
            }
            fs::remove_file(path)?;
            Ok(())
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

pub fn mark_recovery(scope: &str, error: &str) {
    let record = json!({"boot_id":context("/proc/sys/kernel/random/boot_id").ok(),"scope":scope,"error":error});
    if let Err(e) = fs::write(
        Path::new(ssal::unix::ROOT).join("state/binder-recovery-required.json"),
        record.to_string(),
    ) {
        eprintln!("RECOVERY_REQUIRED: cannot persist recovery marker: {e}");
    }
}

fn passed(report: &Value) -> bool {
    FIELDS.iter().all(|key| report["checks"][key] == "passed")
}

fn registry_evidence(events: &[Value], expected: &str) -> bool {
    events
        .iter()
        .any(|v| v["event"] == "registry" && v["result"] == expected)
        && events.iter().any(|v| {
            v["event"] == "registry_permission"
                && v["effective_allowed"] == true
                && v["permission"] == "find"
                && v["sid"].is_string()
                && v["target"].is_string()
        })
        && events.iter().any(|v| {
            v["event"] == "registry_policy_status"
                && v["enabled"] == true
                && [json!(0), json!(1)].contains(&v["enforcing"])
        })
}

#[cfg(target_os = "android")]
fn properties() -> io::Result<BTreeMap<String, String>> {
    use std::ffi::{c_char, c_void, CStr};
    unsafe extern "C" {
        fn __system_property_foreach(
            callback: unsafe extern "C" fn(*const c_void, *mut c_void),
            cookie: *mut c_void,
        ) -> i32;
        fn __system_property_read_callback(
            info: *const c_void,
            callback: unsafe extern "C" fn(*mut c_void, *const c_char, *const c_char, u32),
            cookie: *mut c_void,
        );
    }
    unsafe extern "C" fn read(
        cookie: *mut c_void,
        name: *const c_char,
        value: *const c_char,
        _: u32,
    ) {
        let values = &mut *(cookie as *mut BTreeMap<String, String>);
        let digest = Sha256::digest(CStr::from_ptr(value).to_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        values.insert(CStr::from_ptr(name).to_string_lossy().into_owned(), digest);
    }
    unsafe extern "C" fn visit(info: *const c_void, cookie: *mut c_void) {
        __system_property_read_callback(info, read, cookie);
    }
    let mut values = BTreeMap::new();
    if unsafe {
        __system_property_foreach(visit, (&mut values as *mut BTreeMap<String, String>).cast())
    } != 0
        || values.is_empty()
    {
        return Err(io::Error::other("Host property area collection failed"));
    }
    Ok(values)
}

#[cfg(not(target_os = "android"))]
fn properties() -> io::Result<BTreeMap<String, String>> {
    Err(io::Error::other("Android property area required"))
}
struct Process {
    child: Child,
    lines: Receiver<Value>,
    events: Vec<Value>,
    role: String,
    start: String,
    exit: Option<std::process::ExitStatus>,
}

fn starttime(pid: u32) -> io::Result<String> {
    let text = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    text.rsplit_once(')')
        .and_then(|(_, s)| s.split_whitespace().nth(19))
        .map(str::to_owned)
        .ok_or_else(|| io::Error::other("invalid process stat"))
}

impl Process {
    fn spawn(mut command: Command, role: &str) -> io::Result<Self> {
        let mut child = command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        // Child remains unreaped: its PID cannot be reused before cleanup.
        let start = match starttime(child.id()) {
            Ok(s) => s,
            Err(e) => {
                child.kill()?;
                child.wait()?;
                return Err(e);
            }
        };
        let (sender, lines) = mpsc::channel();
        for pipe in [
            Box::new(child.stdout.take().unwrap()) as Box<dyn Read + Send>,
            Box::new(child.stderr.take().unwrap()),
        ] {
            let sender = sender.clone();
            std::thread::spawn(move || {
                for line in io::BufReader::new(pipe.take(256 * 1024))
                    .lines()
                    .map_while(Result::ok)
                {
                    // Raw stderr can contain property values. Retain structured probe events only.
                    if let Ok(value) = serde_json::from_str::<Value>(&line) {
                        let _ = sender.send(value);
                    }
                }
            });
        }
        Ok(Self {
            child,
            lines,
            events: Vec::new(),
            role: role.into(),
            start,
            exit: None,
        })
    }
    fn poll(&mut self) -> io::Result<Option<std::process::ExitStatus>> {
        self.exit = self.child.try_wait()?;
        Ok(self.exit)
    }
    fn collect(&mut self) {
        self.events.extend(self.lines.try_iter());
    }
    fn wait_event(&mut self, result: &str) -> io::Result<()> {
        let deadline = Instant::now() + Duration::from_secs(8);
        loop {
            self.collect();
            if self
                .events
                .iter()
                .any(|v| v["event"] == "registry" && v["result"] == result)
            {
                return Ok(());
            }
            if self.poll()?.is_some() {
                while let Ok(event) = self.lines.recv_timeout(Duration::from_millis(50)) {
                    self.events.push(event);
                }
                if self
                    .events
                    .iter()
                    .any(|v| v["event"] == "registry" && v["result"] == result)
                {
                    return Ok(());
                }
                return Err(io::Error::other(format!(
                    "{} exited before {result}",
                    self.role
                )));
            }
            if Instant::now() >= deadline {
                return Err(io::Error::other(format!(
                    "{}: missing {result} event",
                    self.role
                )));
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }
    fn finish(&mut self) -> io::Result<()> {
        if self.poll()?.is_none() {
            if starttime(self.child.id())? != self.start {
                return Err(io::Error::other("PID ownership changed"));
            }
            if unsafe { libc::kill(self.child.id() as i32, libc::SIGTERM) } != 0
                && io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
            {
                return Err(io::Error::last_os_error());
            }
            for signal in [false, true] {
                if signal {
                    self.child.kill()?;
                }
                let deadline = Instant::now() + Duration::from_secs(2);
                while Instant::now() < deadline {
                    if self.poll()?.is_some() {
                        self.collect();
                        return Ok(());
                    }
                    std::thread::sleep(Duration::from_millis(25));
                }
            }
            return Err(io::Error::other("owned process did not exit after KILL"));
        }
        self.collect();
        Ok(())
    }
    fn evidence(&self) -> Value {
        json!({"role":self.role,"pid":self.child.id(),"starttime":self.start,"events":self.events,"exit_status":self.exit.map(|s|s.to_string())})
    }
}

fn command(root: &Path, identity: [u64; 4], role: &str, name: &str) -> io::Result<Command> {
    let mut command =
        Command::new(std::env::current_exe()?.with_file_name("ssal-enforcing-binder"));
    command
        .arg("test-b")
        .arg(root)
        .args(identity.map(|v| v.to_string()))
        .args(["before", role, name])
        .env_clear()
        .env("PATH", "/system/bin")
        .env("ANDROID_ROOT", "/system")
        .env("ANDROID_DATA", "/data");
    Ok(command)
}

fn client(command: Command, expected: &str, processes: &mut Vec<Process>) -> io::Result<Value> {
    processes.push(Process::spawn(command, expected)?);
    let process = processes.last_mut().unwrap();
    process.wait_event(expected)?;
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if let Some(status) = process.poll()? {
            if !status.success() {
                return Err(io::Error::other("registry client failed after event"));
            }
            process.collect();
            if !registry_evidence(&process.events, expected) {
                return Err(io::Error::other(
                    "registry permission/policy evidence incomplete",
                ));
            }
            return Ok(process.evidence());
        }
        if Instant::now() >= deadline {
            return Err(io::Error::other("registry client exit timeout"));
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn process_identity(
    process: &mut Process,
    root: &Path,
    identity: [u64; 4],
    domain: &str,
    exe: &Path,
) -> io::Result<Value> {
    let base = format!("/proc/{}", process.child.id());
    if process.poll()?.is_some() || starttime(process.child.id())? != process.start {
        return Err(io::Error::other("tracked process exited"));
    }
    let status = fs::read_to_string(format!("{base}/status"))?;
    let current = context(&format!("{base}/attr/current"))?;
    let actual = fs::metadata(format!("{base}/root"))?;
    let expected = fs::metadata(root)?;
    let executable = fs::metadata(format!("{base}/exe"))?;
    let expected_exe = fs::metadata(exe)?;
    let mut binder_fds = Vec::new();
    for entry in fs::read_dir(format!("{base}/fd"))? {
        let entry = entry?;
        let meta = fs::metadata(entry.path())?;
        if std::os::unix::fs::FileTypeExt::is_char_device(&meta.file_type())
            && libc::major(meta.rdev()) == libc::major(identity[2])
        {
            if [meta.dev(), meta.ino(), meta.rdev()] != identity[..3] {
                return Err(io::Error::other("foreign Binder FD"));
            }
            binder_fds.push(entry.file_name().to_string_lossy().into_owned());
        }
    }
    let exact = |key: &str, value: &str| {
        status
            .lines()
            .find_map(|l| l.strip_prefix(key))
            .is_some_and(|s| s.split_whitespace().collect::<Vec<_>>().join(" ") == value)
    };
    if current != domain
        || (actual.dev(), actual.ino()) != (expected.dev(), expected.ino())
        || (executable.dev(), executable.ino()) != (expected_exe.dev(), expected_exe.ino())
        || fs::read_link(format!("{base}/ns/mnt"))? == fs::read_link("/proc/1/ns/mnt")?
        || !exact("Uid:", "1000 1000 1000 1000")
        || !exact("Gid:", "1000 1000 1000 1000")
        || !exact("Groups:", "3009")
        || !["CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:"]
            .iter()
            .all(|key| exact(key, "0000000000000000"))
        || !exact("NoNewPrivs:", "1")
        || !exact("Seccomp:", "2")
        || binder_fds.is_empty()
    {
        return Err(io::Error::other(
            "actual service domain/credentials/root/executable/Binder gate",
        ));
    }
    process.collect();
    if !process
        .events
        .iter()
        .any(|v| v["event"] == "property_connect_blocked" && v["errno"] == libc::EPERM)
    {
        return Err(io::Error::other("property connect filter evidence absent"));
    }
    Ok(
        json!({"pid":process.child.id(),"starttime":process.start,"context":current,"status":status,"binder_fds":binder_fds,"root":[actual.dev(),actual.ino()],"executable":[executable.dev(),executable.ino()],"mount_namespace":fs::read_link(format!("{base}/ns/mnt"))?}),
    )
}

pub fn verify(root: &Path) -> io::Result<()> {
    check_recovery()?;
    let mut report = json!({"schema":1,"validation_scope":"private_binder_test_b","launch_enabled":false,"checks":{},"phase1_complete":false,"cleanup_scope":"Test B processes, FDs and masks/Binder only; outer worker must confirm rootfs/loop release"});
    for field in FIELDS {
        report["checks"][field] = json!("not_run");
    }
    let before = properties();
    let host_before = host_services();
    let host_mounts_before = fs::read_to_string("/proc/1/mountinfo");
    let policy_before = query(TARGET, TARGET, "process", "getattr");
    let enforcing = context("/sys/fs/selinux/enforce")?;
    report["global_enforcing"] = json!(enforcing == "1");
    report["boot_id"] = json!(context("/proc/sys/kernel/random/boot_id")?);
    let name = format!(
        "ssal.probe.{}.{}",
        report["boot_id"].as_str().unwrap(),
        std::process::id()
    );
    report["session"] = json!(name);
    report["servicemanager_sha256"] = json!(super::preflight::digest(
        &crate::guest_mounts::guest_path(root, "system/bin/servicemanager")?
    )?);
    report["execution_spec"] =
        json!(super::runtime_preflight::ServiceExecutionSpec::servicemanager());
    report["policy_sha256"] = json!(policy_hash().ok());
    let mut binder = crate::binder_probe::Session::new();
    let mut masks = Masks { paths: Vec::new() };
    let mut processes = Vec::new();
    let result = (|| -> io::Result<()> {
        if before.is_err()
            || host_before.is_err()
            || fs::read_link("/proc/self/ns/mnt")? == fs::read_link("/proc/1/ns/mnt")?
        {
            return Err(io::Error::other(
                "Host snapshot/private namespace admission failed",
            ));
        }
        let rc = super::preflight::rc_spec(&fs::read_to_string(crate::guest_mounts::guest_path(
            root,
            "system/etc/init/servicemanager.rc",
        )?)?)?;
        if rc["matches_android16_credentials"] != true {
            return Err(io::Error::other(
                "unsupported servicemanager rc credentials",
            ));
        }
        report["rc"] = rc;
        report["helper_manifest"] = crate::guest_probe::verify_binder_helper(
            root,
            &std::env::current_exe()?.with_file_name("ssal-binder-probe"),
        )?;
        report["test_b_overrides"] = json!({"proc":"per-child current SID only; no Host root/FD magic links","data":"disposable empty tmpfs; profile data isolation is Phase 2","task_profiles":"not applied; no Host cgroup destinations exposed","logging":"session regular file at /dev/kmsg; Host device absent","property_area":"empty; not Guest property initialization","connect":"seccomp EPERM; no property payload; no process forks, threads only"});
        binder.provision(root)?;
        report["labels"] = environment::prepare_labels(root, &mut binder)?;
        let device = binder.private_device()?;
        if unsafe { libc::fchown(device.as_raw_fd(), 1000, 1000) } != 0
            || unsafe { libc::fchmod(device.as_raw_fd(), 0o600) } != 0
        {
            return Err(io::Error::last_os_error());
        }
        let meta = device.metadata()?;
        let identity = [
            meta.dev(),
            meta.ino(),
            meta.rdev(),
            fs::metadata("/dev/binder")?.rdev(),
        ];
        report["binder_identity"] = json!(identity);
        masks.mount(
            "tmpfs",
            &root.join("data"),
            Some("tmpfs"),
            libc::MS_NODEV,
            "mode=0755",
        )?;
        fs::create_dir_all(root.join("data/local/tmp"))?;
        super::enforcing::labeled_copy(
            &std::env::current_exe()?.with_file_name("ssal-binder-probe"),
            &root.join("data/local/tmp/ssal-binder-client"),
            "u:object_r:shell_exec:s0",
        )?;
        environment::minimal_devices(root, &binder, &mut masks)?;
        // KernelLogger writes to a session regular file, never the Host kmsg device.
        let log = OpenOptions::new().write(true).open(root.join("dev/kmsg"))?;
        if unsafe { libc::fchown(log.as_raw_fd(), 1000, 1000) } != 0
            || unsafe { libc::fchmod(log.as_raw_fd(), 0o200) } != 0
        {
            return Err(io::Error::last_os_error());
        }
        // Replace the empty proc mask with a template for per-child current-context binds.
        masks.mount(
            "tmpfs",
            &root.join("proc"),
            Some("tmpfs"),
            libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
            "mode=0555",
        )?;
        fs::create_dir_all(root.join("proc/self/attr"))?;
        fs::write(root.join("proc/self/attr/current"), b"")?;
        std::os::unix::fs::symlink("self", root.join("proc/thread-self"))?;
        // Hide Host cgroup/BPF/task-profile destinations, expose only read-only selinuxfs.
        masks.mount(
            "tmpfs",
            &root.join("sys"),
            Some("tmpfs"),
            libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
            "mode=0555",
        )?;
        fs::create_dir_all(root.join("sys/fs/selinux"))?;
        masks.mount(
            "/sys/fs/selinux",
            &root.join("sys/fs/selinux"),
            None,
            libc::MS_BIND,
            "",
        )?;
        // libselinux requires statvfs(selinuxfs) to report RW at its root.
        // Keep only AV/context query endpoints writable; mask every control separately.
        for entry in fs::read_dir("/sys/fs/selinux")? {
            let entry = entry?;
            let name = entry.file_name();
            if ["access", "context", "create", "relabel", "member", "user"]
                .contains(&name.to_str().unwrap_or(""))
            {
                continue;
            }
            let target = root.join("sys/fs/selinux").join(&name);
            masks.mount(
                entry
                    .path()
                    .to_str()
                    .ok_or_else(|| io::Error::other("selinuxfs path"))?,
                &target,
                None,
                libc::MS_BIND,
                "",
            )?;
            masks.mount(
                "none",
                &target,
                None,
                libc::MS_BIND
                    | libc::MS_REMOUNT
                    | libc::MS_RDONLY
                    | libc::MS_NOSUID
                    | libc::MS_NODEV
                    | libc::MS_NOEXEC,
                "",
            )?;
        }
        report["checks"]["servicemanager"] = json!("failed");
        report["checks"]["android_service_selinux"] = json!("failed");
        processes.push(Process::spawn(
            command(root, identity, "manager", &name)?,
            "servicemanager",
        )?);
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            match process_identity(
                &mut processes[0],
                root,
                identity,
                TARGET,
                &crate::guest_mounts::guest_path(root, "system/bin/servicemanager")?,
            ) {
                Ok(value) => {
                    report["manager_identity"] = value;
                    break;
                }
                Err(error) => {
                    if processes[0].poll()?.is_some() || Instant::now() >= deadline {
                        return Err(error);
                    }
                    std::thread::sleep(Duration::from_millis(25));
                }
            }
        }
        // Read-only manager self lookup proves readiness without lazy-start.
        let mut ready = false;
        for _ in 0..5 {
            if processes[0].poll()?.is_some() {
                return Err(io::Error::other("servicemanager exited during readiness"));
            }
            if client(
                command(root, identity, "registry-check", "manager")?,
                "present",
                &mut processes,
            )
            .is_ok()
            {
                ready = true;
                break;
            }
        }
        if !ready {
            return Err(io::Error::other("actual servicemanager not ready"));
        }
        let target = query(TARGET, TARGET, "process", "getattr")?;
        report["target_domain_av"] = json!(target);
        if enforcing == "1" && !target.permissive_domain {
            report["checks"]["android_service_selinux"] = json!("passed");
        }
        processes.push(Process::spawn(
            command(root, identity, "registry-server", &name)?,
            "test_server",
        )?);
        let server_index = processes.len() - 1;
        processes[server_index].wait_event("registered")?;
        report["server_identity"] = process_identity(
            &mut processes[server_index],
            root,
            identity,
            "u:r:shell:s0",
            &root.join("data/local/tmp/ssal-binder-client"),
        )?;
        let echo = client(
            command(root, identity, "registry-echo", &name)?,
            "echo",
            &mut processes,
        )?;
        if !echo["events"].as_array().unwrap().iter().any(|v| {
            v["event"] == "registry" && v["server_pid"] == processes[server_index].child.id()
        }) {
            return Err(io::Error::other("nonce server PID mismatch"));
        }
        report["guest_positive"] = echo;
        report["checks"]["servicemanager"] = json!("passed");
        report["checks"]["host_registry_isolation"] = json!("failed");
        let host = fs::metadata("/dev/binder")?;
        let host_command = |name: &str| -> io::Result<Command> {
            let mut cmd =
                Command::new(std::env::current_exe()?.with_file_name("ssal-binder-probe"));
            cmd.args([
                "registry-check",
                "/dev/binder",
                &libc::major(host.rdev()).to_string(),
                &libc::minor(host.rdev()).to_string(),
                name,
                &host.rdev().to_string(),
            ])
            .env_clear();
            let namespace = fs::File::open("/proc/1/ns/mnt")?;
            unsafe {
                cmd.pre_exec(move || {
                    if libc::setns(namespace.as_raw_fd(), libc::CLONE_NEWNS) != 0 {
                        return Err(io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            Ok(cmd)
        };
        let host_root = fs::metadata("/proc/1/root")?;
        let host_namespace = fs::read_link("/proc/1/ns/mnt")?
            .to_string_lossy()
            .into_owned();
        for (key, service, expected) in [
            ("host_positive", "activity", "present"),
            ("host_negative", name.as_str(), "not_registered"),
        ] {
            let evidence = client(host_command(service)?, expected, &mut processes)?;
            if !evidence["events"].as_array().unwrap().iter().any(|v| {
                v["event"] == "registry_environment"
                    && v["root_dev"] == host_root.dev()
                    && v["root_inode"] == host_root.ino()
                    && v["mount_namespace"] == host_namespace
            }) {
                return Err(io::Error::other(
                    "Host lookup root/namespace identity mismatch",
                ));
            }
            report[key] = evidence;
        }
        report["guest_negative"] = client(
            command(root, identity, "registry-check", "activity")?,
            "not_registered",
            &mut processes,
        )?;
        report["checks"]["host_registry_isolation"] = json!("passed");
        Ok(())
    })();
    report["failure"] = json!(result.as_ref().err().map(ToString::to_string));
    report["manager_diagnostics"] =
        json!(fs::read_to_string(root.join("dev/kmsg")).ok().map(|s| s
            .lines()
            .filter(|l| !l.to_ascii_lowercase().contains("property"))
            .map(str::to_owned)
            .collect::<Vec<_>>()));
    let mut cleanup_errors = Vec::new();
    for process in processes.iter_mut().rev() {
        if let Err(e) = process.finish() {
            cleanup_errors.push(format!("{} PID {}: {e}", process.role, process.child.id()));
        }
    }
    report["processes"] = json!(processes.iter().map(Process::evidence).collect::<Vec<_>>());
    let after = properties();
    let host_after = host_services();
    let host_mounts_after = fs::read_to_string("/proc/1/mountinfo");
    let enforcement_after = context("/sys/fs/selinux/enforce");
    let policy_after = query(TARGET, TARGET, "process", "getattr");
    let selinux_unchanged = enforcement_after.as_ref().is_ok_and(|s| s == &enforcing)
        && policy_before
            .as_ref()
            .ok()
            .zip(policy_after.as_ref().ok())
            .is_some_and(|(a, b)| {
                a.sequence == b.sequence && a.permissive_domain == b.permissive_domain
            });
    report["selinux_boundary"] = json!({"unchanged":selinux_unchanged,"global_after":enforcement_after.as_ref().ok(),"target_before":policy_before.as_ref().ok(),"target_after":policy_after.as_ref().ok()});
    if !selinux_unchanged && report["checks"]["android_service_selinux"] == "passed" {
        report["checks"]["android_service_selinux"] = json!("failed");
    }
    let changed: Vec<_> = match (&before, &after) {
        (Ok(a), Ok(b)) => a
            .keys()
            .chain(b.keys())
            .filter(|k| a.get(*k) != b.get(*k))
            .cloned()
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect(),
        _ => Vec::new(),
    };
    report["host_properties"] = json!({"before_collected":before.is_ok(),"after_collected":after.is_ok(),"changed_names":changed});
    let host_mounts_ok = host_mounts_before
        .as_ref()
        .ok()
        .zip(host_mounts_after.as_ref().ok())
        .is_some_and(|(a, b)| a == b);
    report["host_mounts_unchanged"] = json!(host_mounts_ok);
    let host_ok = host_mounts_ok
        && selinux_unchanged
        && host_before
            .as_ref()
            .ok()
            .zip(host_after.as_ref().ok())
            .is_some_and(|(a, b)| a == b);
    report["host_framework_unchanged"] = json!(host_ok);
    let filter = processes.first().is_some_and(|p| {
        p.events
            .iter()
            .any(|v| v["event"] == "property_connect_blocked")
    });
    report["checks"]["property_host_unchanged"] =
        json!(
            if before.is_ok() && after.is_ok() && changed.is_empty() && filter {
                "passed"
            } else {
                "failed"
            }
        );
    if cleanup_errors.is_empty() {
        if let Err(e) = masks.cleanup() {
            cleanup_errors.push(e.to_string());
        }
        if cleanup_errors.is_empty() {
            if let Err(e) = binder.cleanup() {
                cleanup_errors.push(e.to_string());
            }
        }
    }
    report["checks"]["cleanup"] = json!(if cleanup_errors.is_empty() {
        "passed"
    } else {
        "failed"
    });
    report["cleanup_errors"] = json!(cleanup_errors);
    report["test_b_passed"] = json!(passed(&report) && host_ok);
    report["permissive_diagnostic_passed"] = json!(
        enforcing == "0"
            && host_ok
            && FIELDS
                .iter()
                .filter(|k| **k != "android_service_selinux")
                .all(|k| report["checks"][k] == "passed")
    );
    println!(
        "Servicemanager probe summary: {}",
        serde_json::to_string(&report)?
    );
    if !cleanup_errors.is_empty() {
        // Preserve resource ownership evidence and forbid outer teardown under live tasks.
        let recovery = Path::new(ssal::unix::ROOT).join("state/binder-recovery-required.json");
        if let Err(error) = fs::write(recovery, serde_json::to_vec(&report).unwrap_or_default()) {
            eprintln!("RECOVERY_REQUIRED: could not persist recovery evidence: {error}");
        }
        eprintln!("RECOVERY_REQUIRED: Test B resources retained");
        unsafe { libc::_exit(1) };
    }
    if passed(&report) && host_ok {
        Ok(())
    } else {
        Err(io::Error::other(
            "Test B incomplete; switch remains blocked",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn every_field_is_required_and_permissive_is_not_enforcing() {
        let mut report = json!({"checks":{}});
        for field in FIELDS {
            report["checks"][field] = json!("passed");
        }
        assert!(passed(&report));
        for field in FIELDS {
            for status in ["failed", "not_run", "unavailable"] {
                report["checks"][field] = json!(status);
                assert!(!passed(&report));
            }
            report["checks"][field] = json!("passed");
        }
    }

    #[test]
    fn null_denial_and_disabled_selinux_are_not_isolation_evidence() {
        let mut events = vec![json!({"event":"registry","result":"not_registered"})];
        assert!(!registry_evidence(&events, "not_registered"));
        events.push(json!({"event":"registry_permission","effective_allowed":false,"permission":"find","sid":"u:r:shell:s0","target":"u:object_r:default_android_service:s0"}));
        events.push(json!({"event":"registry_policy_status","enabled":true,"enforcing":1}));
        assert!(!registry_evidence(&events, "not_registered"));
        events[1]["effective_allowed"] = json!(true);
        assert!(registry_evidence(&events, "not_registered"));
        events[2]["enabled"] = json!(false);
        assert!(!registry_evidence(&events, "not_registered"));
    }

    #[test]
    fn supervisor_reaps_owned_process_and_detects_early_exit() -> io::Result<()> {
        let mut command = Command::new("/bin/sleep");
        command.arg("30");
        let mut process = Process::spawn(command, "cleanup-test")?;
        assert!(process.wait_event("never_emitted").is_err());
        process.finish()?;
        assert!(process.poll()?.is_some());
        let mut exited = Process::spawn(Command::new("/bin/false"), "partial-failure")?;
        assert!(exited.wait_event("registered").is_err());
        exited.finish()?;
        Ok(())
    }
}
