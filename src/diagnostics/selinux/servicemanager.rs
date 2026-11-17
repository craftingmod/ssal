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
#[cfg(feature = "phase2c-diagnostic")]
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver};

#[cfg(feature = "phase3-diagnostic")]
#[path = "servicemanager/phase3.rs"]
mod phase3;

const FIELDS: [&str; 5] = [
    "servicemanager",
    "android_service_selinux",
    "host_registry_isolation",
    "property_host_unchanged",
    "cleanup",
];
const TEST_SERVER: &str = "u:r:aidl_lazy_test_server:s0";
const TEST_SERVICE: &str = "u:object_r:aidl_lazy_test_service:s0";
const TEST_SERVER_EXEC: &str = "u:object_r:aidl_lazy_test_server_exec:s0";
const TEST_SERVICE_NAME: &str = "aidl_lazy_test_1";
const BINDER_DEVICE: &str = "u:object_r:binder_device:s0";

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

fn phase1_complete(report: &Value, host_ok: bool, enforcing: bool) -> bool {
    passed(report) && host_ok && enforcing
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

fn group_alive(group: u32) -> io::Result<bool> {
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        if entry.file_name().to_string_lossy().parse::<u32>().is_err() {
            continue;
        }
        let stat = match fs::read_to_string(entry.path().join("stat")) {
            Ok(stat) => stat,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        };
        let tail = stat
            .rsplit_once(")")
            .ok_or_else(|| io::Error::other("invalid process stat during group cleanup"))?
            .1;
        let fields = tail.split_whitespace().collect::<Vec<_>>();
        if fields.get(2).is_some_and(|v| *v == group.to_string())
            && !matches!(fields.first(), Some(&"Z" | &"X" | &"x"))
        {
            return Ok(true);
        }
    }
    Ok(false)
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
        let data_daemon = role.starts_with("phase2-");
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
                    } else if data_daemon && !line.to_ascii_lowercase().contains("property") {
                        let _ = sender.send(json!({"event":"daemon_diagnostic","line":line}));
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
        if self.role.starts_with("phase2-") {
            use std::os::unix::process::ExitStatusExt;
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
            if unsafe { info.si_pid() } != 0 {
                let code = unsafe { info.si_status() };
                self.exit = Some(std::process::ExitStatus::from_raw(
                    if info.si_code == libc::CLD_EXITED {
                        code << 8
                    } else {
                        code
                    },
                ));
            }
            return Ok(self.exit);
        }
        self.exit = self.child.try_wait()?;
        Ok(self.exit)
    }
    fn collect(&mut self) {
        self.events.extend(self.lines.try_iter());
    }
    fn wait_event(&mut self, result: &str) -> io::Result<()> {
        let deadline = Instant::now()
            + Duration::from_secs(if self.role.starts_with("data-") {
                60
            } else {
                8
            });
        loop {
            self.collect();
            if self.events.iter().any(|v| {
                ["registry", "data_operation"]
                    .iter()
                    .any(|kind| v["event"] == *kind)
                    && v["result"] == result
            }) {
                return Ok(());
            }
            if self.poll()?.is_some() {
                while let Ok(event) = self.lines.recv_timeout(Duration::from_millis(50)) {
                    self.events.push(event);
                }
                if self.events.iter().any(|v| {
                    ["registry", "data_operation"]
                        .iter()
                        .any(|kind| v["event"] == *kind)
                        && v["result"] == result
                }) {
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
        self.collect();
        if self.role.starts_with("phase2-") {
            if starttime(self.child.id())? != self.start {
                return Err(io::Error::other("daemon group ownership changed"));
            }
            for signal in [libc::SIGTERM, libc::SIGKILL] {
                let rc = unsafe { libc::kill(-(self.child.id() as i32), signal) };
                if rc != 0 && io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH) {
                    return Err(io::Error::last_os_error());
                }
                let deadline = Instant::now()
                    + Duration::from_secs(if signal == libc::SIGTERM { 1 } else { 3 });
                while group_alive(self.child.id())? && Instant::now() < deadline {
                    std::thread::sleep(Duration::from_millis(25));
                }
                if !group_alive(self.child.id())? {
                    break;
                }
                if signal == libc::SIGKILL {
                    return Err(io::Error::other(
                        "daemon group still live after KILL; retain mounts",
                    ));
                }
            }
        }
        self.stop()
    }
    fn stop(&mut self) -> io::Result<()> {
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
                        if self.role.starts_with("phase2-") {
                            self.exit = Some(self.child.wait()?);
                        }
                        self.collect();
                        return Ok(());
                    }
                    std::thread::sleep(Duration::from_millis(25));
                }
            }
            return Err(io::Error::other("owned process did not exit after KILL"));
        }
        if self.role.starts_with("phase2-") {
            self.exit = Some(self.child.wait()?);
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

#[cfg(feature = "phase2c-diagnostic")]
fn run_phase2c_rsbinder_probe(root: &Path) -> io::Result<Value> {
    let probe = std::env::var_os("SSAL_PHASE2C_RSBINDER_PROBE")
        .map(PathBuf::from)
        .ok_or_else(|| io::Error::other("Phase 2C probe path missing"))?;
    let property_area = root.join("dev/phase2-property-area");
    let guest_probe = root.join("data/local/tmp/ssal-rsbinder-phase2-guest-probe");
    super::enforcing::labeled_copy(&probe, &guest_probe, "u:object_r:shell_exec:s0")?;
    let mut initializer = crate::guest::process::command::command(
        root,
        "/data/local/tmp/ssal-rsbinder-phase2-guest-probe",
        false,
    )?;
    initializer.args([
        "--initialize-private-properties",
        "/dev/phase2-property-area",
    ]);
    let setup = crate::guest::process::command::run_with_timeout(
        &mut initializer,
        "Guest private property initialization",
        Duration::from_secs(10),
    )?;
    if !setup.status.success() {
        return Err(io::Error::other(format!(
            "Guest property initializer exited {}: stdout={}, stderr={}",
            setup.status,
            String::from_utf8_lossy(&setup.stdout),
            String::from_utf8_lossy(&setup.stderr),
        )));
    }
    let properties = root.join("dev/__properties__");
    if !properties.is_dir() || fs::read_dir(&properties)?.next().is_some() {
        return Err(io::Error::other(
            "Guest /dev/__properties__ is not the expected empty directory",
        ));
    }
    if !property_area.is_dir() || !property_area.join("property_info").is_file() {
        return Err(io::Error::other(
            "Guest modern property area is missing property_info",
        ));
    }
    fs::remove_dir(&properties)?;
    fs::rename(&property_area, &properties)?;
    let mut getprop = crate::guest::process::command::command(root, "/system/bin/getprop", false)?;
    getprop.arg("ro.build.version.sdk");
    let getprop = crate::guest::process::command::run_with_timeout(
        &mut getprop,
        "Guest getprop control",
        Duration::from_secs(5),
    )?;
    let guest_getprop = json!({
        "exit_code":getprop.status.code(),
        "stdout":String::from_utf8_lossy(&getprop.stdout).trim(),
        "stderr":String::from_utf8_lossy(&getprop.stderr),
    });
    let property_metadata = fs::metadata(&properties)?;
    let property_label = Command::new("/system/bin/ls")
        .args(["-lZ"])
        .arg(&properties)
        .output()?;
    let private_property_area = json!({
        "kind": if property_metadata.is_file() { "file" } else if property_metadata.is_dir() { "directory" } else { "other" },
        "size_bytes": property_metadata.len(),
        "mode_octal": format!("{:o}", property_metadata.mode() & 0o7777),
        "ls_label": String::from_utf8_lossy(&property_label.stdout).trim(),
    });
    let shell_property_access = json!({
        "directory_search": query("u:r:shell:s0", "u:object_r:properties_device:s0", "dir", "search")?,
        "property_info_open": query("u:r:shell:s0", "u:object_r:property_info:s0", "file", "open")?,
        "property_info_read": query("u:r:shell:s0", "u:object_r:property_info:s0", "file", "read")?,
        "property_info_map": query("u:r:shell:s0", "u:object_r:property_info:s0", "file", "map")?,
        "build_prop_open": query("u:r:shell:s0", "u:object_r:build_prop:s0", "file", "open")?,
        "build_prop_read": query("u:r:shell:s0", "u:object_r:build_prop:s0", "file", "read")?,
        "build_prop_map": query("u:r:shell:s0", "u:object_r:build_prop:s0", "file", "map")?,
        "properties_serial_open": query("u:r:shell:s0", "u:object_r:properties_serial:s0", "file", "open")?,
        "properties_serial_read": query("u:r:shell:s0", "u:object_r:properties_serial:s0", "file", "read")?,
        "properties_serial_map": query("u:r:shell:s0", "u:object_r:properties_serial:s0", "file", "map")?,
    });

    let mut command = crate::guest::process::command::command_for_phase2c(
        root,
        "/data/local/tmp/ssal-rsbinder-phase2-guest-probe",
    )?;
    command.args([
        "--device",
        "/dev/binder",
        "--service",
        "aidl_lazy_test_1",
        "--expected-descriptor",
        "BBinder",
    ]);
    let output = crate::guest::process::command::run_with_timeout(
        &mut command,
        "rsbinder Guest probe",
        Duration::from_secs(20),
    )?;
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let record = stdout
        .lines()
        .find_map(|line| serde_json::from_str::<Value>(line).ok())
        .ok_or_else(|| {
            io::Error::other(format!(
                "Guest probe emitted no JSON (status={}, stdout={stdout:?}, stderr={})",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            ))
        })?;
    Ok(json!({
        "exit_code": output.status.code(),
        "child_reaped": true,
        "property_initializer": String::from_utf8_lossy(&setup.stdout),
        "guest_getprop_control": guest_getprop,
        "private_property_area": private_property_area,
        "shell_property_access": shell_property_access,
        "result": record,
        "stderr": String::from_utf8_lossy(&output.stderr),
    }))
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

fn host_data_paths() -> io::Result<Value> {
    use sha2::{Digest, Sha256};
    let mut paths = serde_json::Map::new();
    for relative in [
        "app/com.android.ssal.phase2",
        "user/0/com.android.ssal.phase2",
        "user_de/0/com.android.ssal.phase2",
        "misc/profiles/cur/0/com.android.ssal.phase2",
        "misc/profiles/ref/com.android.ssal.phase2",
        "dalvik-cache/arm64/data@app@com.android.ssal.phase2@base.apk@classes.dex",
        "dalvik-cache/arm64/data@app@com.android.ssal.phase2@base.apk@classes.vdex",
    ] {
        let path = Path::new("/data").join(relative);
        match fs::symlink_metadata(&path) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                paths.insert(path.display().to_string(), json!("absent"));
            }
            Err(e) => return Err(e),
            Ok(_) => {
                return Err(io::Error::other(format!(
                    "Host test path already exists: {}",
                    path.display()
                )))
            }
        }
    }
    let mut command = Command::new("/system/bin/service");
    command.arg("list").env_clear();
    let output = crate::guest::process::command::run_with_timeout(
        &mut command,
        "Host registry snapshot",
        Duration::from_secs(5),
    )?;
    if !output.status.success()
        || !String::from_utf8_lossy(&output.stdout).contains("android.os.IServiceManager")
    {
        return Err(io::Error::other("Host registry snapshot failed"));
    }
    let digest = Sha256::digest(&output.stdout)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    paths.insert("registry_sha256".into(), json!(digest));
    Ok(json!(paths))
}

fn data_client(
    root: &Path,
    identity: [u64; 4],
    role: &str,
    expected: &str,
    processes: &mut Vec<Process>,
) -> io::Result<Value> {
    processes.push(Process::spawn(
        command(root, identity, role, "phase2")?,
        role,
    )?);
    let process = processes.last_mut().unwrap();
    process.wait_event(expected)?;
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if let Some(status) = process.poll()? {
            process.collect();
            if !status.success() {
                return Err(io::Error::other("data client failed after operation"));
            }
            return Ok(process.evidence());
        }
        if Instant::now() >= deadline {
            return Err(io::Error::other("data client exit timeout"));
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn daemon_identity(
    process: &mut Process,
    root: &Path,
    userdata: &Path,
    identity: [u64; 4],
    name: &str,
) -> io::Result<Value> {
    process.collect();
    if process.poll()?.is_some() {
        return Err(io::Error::other(format!("{name} launcher exited")));
    }
    let pid = process
        .events
        .iter()
        .find(|v| v["event"] == "phase2_child")
        .and_then(|v| v["pid"].as_u64())
        .ok_or_else(|| io::Error::other("daemon child PID not reported"))?;
    let base = format!("/proc/{pid}");
    let start = starttime(pid as u32)?;
    let status = fs::read_to_string(format!("{base}/status"))?;
    let uid = if name == "artd" { 1082 } else { 0 };
    let context = context(&format!("{base}/attr/current"))?;
    let exe = if name == "artd" {
        "apex/com.android.art/bin/artd"
    } else {
        "system/bin/installd"
    };
    let same = |a: &Path, b: &Path| -> io::Result<bool> {
        let a = fs::metadata(a)?;
        let b = fs::metadata(b)?;
        Ok((a.dev(), a.ino()) == (b.dev(), b.ino()))
    };
    let exact = |key: &str, value: &str| {
        status
            .lines()
            .find_map(|l| l.strip_prefix(key))
            .is_some_and(|s| s.split_whitespace().collect::<Vec<_>>().join(" ") == value)
    };
    let bits = if name == "artd" {
        "000000000020000f"
    } else {
        "00000000000000ff"
    };
    if context != format!("u:r:{name}:s0")
        || !same(Path::new(&format!("{base}/root")), root)?
        || !same(Path::new(&format!("{base}/root/data")), userdata)?
        || !same(
            Path::new(&format!("{base}/exe")),
            &crate::guest::mount::guest_path(root, exe)?,
        )?
        || !exact("Uid:", &format!("{uid} {uid} {uid} {uid}"))
        || !exact("Gid:", &format!("{uid} {uid} {uid} {uid}"))
        || !exact("PPid:", &process.child.id().to_string())
        || unsafe { libc::getpgid(pid as i32) } != process.child.id() as i32
        || !exact("NoNewPrivs:", "1")
        || !exact("Seccomp:", "2")
        || !["CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:"]
            .iter()
            .all(|key| exact(key, bits))
        || fs::read_link(format!("{base}/ns/mnt"))? == fs::read_link("/proc/1/ns/mnt")?
    {
        return Err(io::Error::other(format!(
            "{name} domain/credentials/root/exe/namespace gate"
        )));
    }
    let mut fds = Vec::new();
    let mut binder = false;
    for entry in fs::read_dir(format!("{base}/fd"))? {
        let entry = entry?;
        let meta = match fs::metadata(entry.path()) {
            Ok(meta) => meta,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        };
        let path = fs::read_link(entry.path())?;
        if std::os::unix::fs::FileTypeExt::is_char_device(&meta.file_type()) {
            if libc::major(meta.rdev()) == libc::major(identity[2]) {
                if [meta.dev(), meta.ino(), meta.rdev()] != identity[..3] {
                    return Err(io::Error::other("foreign daemon Binder FD"));
                }
                binder = true;
            } else if meta.rdev() != libc::makedev(1, 3) {
                return Err(io::Error::other("unexpected daemon device FD"));
            }
        }
        if (meta.is_file() || meta.is_dir())
            && !path.starts_with(root)
            && !path.starts_with(userdata)
        {
            return Err(io::Error::other(format!(
                "foreign daemon file FD: {}",
                path.display()
            )));
        }
        fds.push(json!({"fd":entry.file_name(),"path":path,"identity":[meta.dev(),meta.ino(),meta.rdev()]}));
    }
    if !binder || starttime(pid as u32)? != start {
        return Err(io::Error::other(format!(
            "daemon Binder FD/starttime gate; wchan={:?}; syscall={:?}",
            fs::read_to_string(format!("{base}/wchan")),
            fs::read_to_string(format!("{base}/syscall"))
        )));
    }
    Ok(
        json!({"pid":pid,"starttime":start,"context":context,"status":status,"fds":fds,"pid_namespace":fs::read_link(format!("{base}/ns/pid")).ok(),"mount_namespace":fs::read_link(format!("{base}/ns/mnt"))?,"executable_sha256":super::preflight::digest(&crate::guest::mount::guest_path(root,exe)?)?}),
    )
}

fn compiler_proc(
    socket: std::os::unix::net::UnixDatagram,
    root: std::path::PathBuf,
    group: u32,
    daemon_namespace: std::path::PathBuf,
    shim: std::path::PathBuf,
) -> io::Result<Value> {
    socket.set_read_timeout(Some(Duration::from_secs(10)))?;
    let result = (|| -> io::Result<Value> {
        let mut bytes = [0u8; 4];
        if socket.recv(&mut bytes)? != bytes.len() {
            return Err(io::Error::other("invalid compiler proc request"));
        }
        let pid = i32::from_ne_bytes(bytes);
        if pid <= 1 || unsafe { libc::getpgid(pid) } != group as i32 {
            return Err(io::Error::other("foreign compiler process group"));
        }
        let proc = std::path::PathBuf::from(format!("/proc/{pid}"));
        let start = starttime(pid as u32)?;
        let actual_root = fs::metadata(proc.join("root"))?;
        let expected_root = fs::metadata(&root)?;
        let executable = fs::metadata(proc.join("exe"))?;
        let expected_exe = fs::metadata(&shim)?;
        let namespace = fs::read_link(proc.join("ns/mnt"))?;
        if (actual_root.dev(), actual_root.ino()) != (expected_root.dev(), expected_root.ino())
            || (executable.dev(), executable.ino()) != (expected_exe.dev(), expected_exe.ino())
            || context(
                proc.join("attr/current")
                    .to_str()
                    .ok_or_else(|| io::Error::other("proc path"))?,
            )? != "u:r:artd:s0"
            || namespace == daemon_namespace
            || namespace == fs::read_link("/proc/1/ns/mnt")?
        {
            return Err(io::Error::other(
                "compiler root/exe/domain/private namespace admission",
            ));
        }
        let own_namespace = fs::File::open("/proc/thread-self/ns/mnt")?;
        let child_namespace = fs::File::open(proc.join("ns/mnt"))?;
        if unsafe { libc::unshare(libc::CLONE_FS) } != 0
            || unsafe { libc::setns(child_namespace.as_raw_fd(), libc::CLONE_NEWNS) } != 0
        {
            return Err(io::Error::last_os_error());
        }
        let binding = (|| -> io::Result<()> {
            ssal::namespace_mounts::mount(&proc, &root.join("proc/self"), None, libc::MS_BIND, "")?;
            std::os::unix::fs::symlink("self", root.join(format!("proc/{pid}")))?;
            if starttime(pid as u32)? != start {
                return Err(io::Error::other("compiler PID changed during proc bind"));
            }
            Ok(())
        })();
        if unsafe { libc::setns(own_namespace.as_raw_fd(), libc::CLONE_NEWNS) } != 0 {
            return Err(io::Error::last_os_error());
        }
        binding?;
        if socket.send(&[1])? != 1 {
            return Err(io::Error::other("compiler proc acknowledgement failed"));
        }
        let mut dropped = [0u8; 4];
        if socket.recv(&mut dropped)? != dropped.len()
            || dropped != bytes
            || starttime(pid as u32)? != start
        {
            return Err(io::Error::other("compiler drop confirmation identity"));
        }
        let status = fs::read_to_string(proc.join("status"))?;
        for key in ["CapInh:", "CapPrm:", "CapEff:", "CapAmb:"] {
            if status
                .lines()
                .find_map(|line| line.strip_prefix(key))
                .is_none_or(|v| v.trim() != "000000000000000f")
            {
                return Err(io::Error::other("compiler retained mount capability"));
            }
        }
        if !status.lines().any(|line| {
            line.strip_prefix("NoNewPrivs:")
                .is_some_and(|v| v.trim() == "1")
        }) {
            return Err(io::Error::other("compiler NNP missing"));
        }
        if socket.send(&[2])? != 1 {
            return Err(io::Error::other(
                "compiler capability acknowledgement failed",
            ));
        }
        Ok(
            json!({"pid":pid,"starttime":start,"mount_namespace":namespace,"root":[actual_root.dev(),actual_root.ino()],"executable":[executable.dev(),executable.ino()],"own_proc_bound":true,"host_pid_tree_exposed":false,"control_fd_closed_before_stock_exec":true,"mount_capability_dropped_before_stock_exec":true}),
        )
    })();
    if result.is_err() {
        let _ = socket.send(&[0]);
    }
    result
}

fn run_data_daemons(
    root: &Path,
    userdata: &Path,
    identity: [u64; 4],
    processes: &mut Vec<Process>,
    report: &mut Value,
    masks: &mut Masks,
) -> io::Result<()> {
    let build = fs::read_to_string(crate::guest::mount::guest_path(root, "system/build.prop")?)?;
    if !build.lines().any(|line| {
        matches!(
            line,
            "ro.build.version.sdk=36" | "ro.system.build.version.sdk=36"
        )
    }) {
        return Err(io::Error::other(
            "Phase 2 bootstrap requires Guest Android SDK 36",
        ));
    }
    let helper = std::env::current_exe()?.with_file_name("ssal-binder-probe");
    let private_area = root.join("dev/phase2-property-area");
    let mut seed = Command::new(helper);
    seed.arg("phase2-properties").arg(&private_area).env_clear();
    let output = crate::guest::process::command::run_with_timeout(
        &mut seed,
        "Phase 2 private readiness property",
        Duration::from_secs(5),
    )?;
    if !output.status.success() {
        return Err(io::Error::other(
            "private readiness property initialization failed",
        ));
    }
    fs::remove_dir(root.join("dev/__properties__"))?;
    fs::rename(private_area, root.join("dev/__properties__"))?;
    let area = fs::metadata(root.join("dev/__properties__"))?;
    let host = fs::metadata("/dev/__properties__")?;
    if !area.is_file()
        || area.len() != 128 * 1024
        || (area.dev(), area.ino()) == (host.dev(), host.ino())
    {
        return Err(io::Error::other("private property area backing mismatch"));
    }
    report["private_properties"] = json!({"format":"Bionic pre-split read-only area","values":{"servicemanager.ready":"false"},"initialized_after_private_manager_ready":true,"identity":[area.dev(),area.ino()],"host_identity":[host.dev(),host.ino()],"property_service":"absent; connect blocked"});
    report["private_properties"]["values"] = json!({"servicemanager.ready":"false","ro.product.cpu.abilist64":"arm64-v8a","dalvik.vm.dex2oat64.enabled":"true","ro.build.version.sdk":"36","ro.build.version.codename":"REL","ro.zygote.disable_gl_preload":"1"});
    report["execution_overrides"] = json!({"artd":"UID/GID 1082; RC data capabilities plus explicitly approved SYS_ADMIN for compiler shim","compiler":"own private mount namespace and PID proc bind; SYS_ADMIN removed and NNP verified before stock art_exec","proc":"own PID only; no Host PID tree; no PID namespace support on this kernel","properties":"fixed Android 16 ARM64 probe bootstrap; Guest SDK checked; no Host values copied","linker":"Guest ART/system/statsd/i18n library paths","logging":"Guest-only LD_PRELOAD routes log messages to session stderr","artd_aidl_revision":"1690c6912a7972c9e62c39b48c706de9b8b18b4a","boot_classpath":"Guest derive_classpath output only"});
    let logger = std::env::current_exe()?.with_file_name("ssal-phase2-log.so");
    let manifest: Value =
        serde_json::from_slice(&fs::read(root.join("run/ssal/ssal-binder-probe.json"))?)?;
    if manifest["phase2_log_sha256"].as_str() != Some(super::preflight::digest(&logger)?.as_str()) {
        return Err(io::Error::other("session logger manifest mismatch"));
    }
    let logger_target = root.join("data/local/tmp/ssal-phase2-log.so");
    fs::File::create(&logger_target)?;
    masks.mount(
        logger
            .to_str()
            .ok_or_else(|| io::Error::other("logger path"))?,
        &logger_target,
        None,
        libc::MS_BIND,
        "",
    )?;
    let classpath_file = root.join("data/local/tmp/phase2-classpath.env");
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&classpath_file)?;
    if unsafe { libc::fchown(file.as_raw_fd(), 1000, 1000) } != 0
        || unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } != 0
    {
        return Err(io::Error::last_os_error());
    }
    drop(file);
    let mut derive = Command::new(std::env::current_exe()?.with_file_name("ssal-enforcing-binder"));
    derive
        .arg("phase2")
        .arg(root)
        .args(identity.map(|v| v.to_string()))
        .args(["before", "derive-classpath", "phase2"])
        .env_clear();
    processes.push(Process::spawn(derive, "phase2-derive-classpath")?);
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = processes.last_mut().unwrap().poll()? {
            if !status.success() {
                return Err(io::Error::other("Guest derive_classpath failed"));
            }
            break;
        }
        if Instant::now() >= deadline {
            return Err(io::Error::other("Guest derive_classpath timeout"));
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    let classpath = fs::read_to_string(classpath_file)?;
    if !["BOOTCLASSPATH", "DEX2OATBOOTCLASSPATH"]
        .iter()
        .all(|name| {
            classpath.lines().any(|line| {
                line.starts_with(&format!("export {name} "))
                    && line
                        .split_whitespace()
                        .nth(2)
                        .is_some_and(|v| !v.is_empty())
            })
        })
    {
        return Err(io::Error::other("Guest derived boot classpaths missing"));
    }
    report["guest_classpath"] = json!(classpath);
    for name in ["installd", "artd"] {
        report["checks"][name] = json!("failed");
        let mut launch =
            Command::new(std::env::current_exe()?.with_file_name("ssal-enforcing-binder"));
        launch
            .arg("phase2")
            .arg(root)
            .args(identity.map(|v| v.to_string()))
            .args(["before", name, "phase2"])
            .env_clear();
        let mut broker_socket = None;
        let shim = std::env::current_exe()?.with_file_name("ssal-art-exec-proc");
        if name == "artd" {
            let manifest: Value =
                serde_json::from_slice(&fs::read(root.join("run/ssal/ssal-binder-probe.json"))?)?;
            if manifest["art_exec_proc_sha256"].as_str()
                != Some(super::preflight::digest(&shim)?.as_str())
            {
                return Err(io::Error::other("compiler proc shim manifest mismatch"));
            }
            let original =
                crate::guest::mount::guest_path(root, "apex/com.android.art/bin/art_exec")?;
            let alias = root.join("run/ssal/phase2-real-art-exec");
            fs::File::create(&alias)?;
            masks.mount(
                original
                    .to_str()
                    .ok_or_else(|| io::Error::other("art_exec path"))?,
                &alias,
                None,
                libc::MS_BIND,
                "",
            )?;
            masks.mount(
                shim.to_str().ok_or_else(|| io::Error::other("shim path"))?,
                &original,
                None,
                libc::MS_BIND,
                "",
            )?;
            let (parent, child) = std::os::unix::net::UnixDatagram::pair()?;
            unsafe {
                launch.pre_exec(move || {
                    if libc::dup2(child.as_raw_fd(), 198) < 0
                        || libc::fcntl(198, libc::F_SETFD, 0) != 0
                    {
                        return Err(io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            broker_socket = Some(parent);
        }
        processes.push(Process::spawn(launch, &format!("phase2-{name}"))?);
        let index = processes.len() - 1;
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            match daemon_identity(&mut processes[index], root, userdata, identity, name) {
                Ok(evidence) => {
                    report[format!("{name}_identity")] = evidence;
                    break;
                }
                Err(e) => {
                    if processes[index].poll()?.is_some() || Instant::now() >= deadline {
                        return Err(e);
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
        }
        if name == "installd" {
            report["installd_create"] = data_client(
                root,
                identity,
                "data-installd-create",
                "installd_created",
                processes,
            )?;
            for relative in [
                "user/0/com.android.ssal.phase2",
                "user_de/0/com.android.ssal.phase2",
            ] {
                let a = fs::symlink_metadata(root.join("data").join(relative))?;
                let b = fs::metadata(userdata.join(relative))?;
                if !a.is_dir() || a.uid() != 10000 || (a.dev(), a.ino()) != (b.dev(), b.ino()) {
                    return Err(io::Error::other(
                        "installd output ownership/backing mismatch",
                    ));
                }
            }
            report["installd_delete"] = data_client(
                root,
                identity,
                "data-installd-delete",
                "installd_deleted",
                processes,
            )?;
            for relative in [
                "user/0/com.android.ssal.phase2",
                "user_de/0/com.android.ssal.phase2",
            ] {
                match fs::symlink_metadata(userdata.join(relative)) {
                    Err(e) if e.kind() == io::ErrorKind::NotFound => (),
                    _ => return Err(io::Error::other("installd did not remove test data")),
                }
            }
            report["checks"][name] = json!("passed");
        } else {
            let app = crate::guest::mount::directory(
                &root.join("data"),
                "app/com.android.ssal.phase2",
                0o755,
            )?;
            let fixture = std::env::current_exe()?.with_file_name("ssal-phase2.apk");
            report["apk_sha256"] = json!(super::preflight::digest(&fixture)?);
            if manifest["phase2_apk_sha256"] != report["apk_sha256"] {
                return Err(io::Error::other("APK fixture manifest mismatch"));
            }
            fs::copy(&fixture, app.join("base.apk"))?;
            fs::set_permissions(
                app.join("base.apk"),
                std::os::unix::fs::PermissionsExt::from_mode(0o644),
            )?;
            let log = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(root.join("data/local/tmp/phase2-dex2oat.log"))?;
            if unsafe { libc::fchown(log.as_raw_fd(), 1000, 1000) } != 0
                || unsafe { libc::fchmod(log.as_raw_fd(), 0o600) } != 0
            {
                return Err(io::Error::last_os_error());
            }
            drop(log);
            let socket = broker_socket
                .take()
                .ok_or_else(|| io::Error::other("compiler proc channel missing"))?;
            let broker_root = root.to_owned();
            let group = processes[index].child.id();
            let namespace = std::path::PathBuf::from(
                report["artd_identity"]["mount_namespace"]
                    .as_str()
                    .ok_or_else(|| io::Error::other("artd namespace evidence"))?,
            );
            let broker = std::thread::spawn(move || {
                compiler_proc(socket, broker_root, group, namespace, shim)
            });
            let compile = data_client(root, identity, "data-artd", "artd_compiled", processes);
            report["compiler_proc"] = broker
                .join()
                .map_err(|_| io::Error::other("compiler proc broker panicked"))??;
            report["artd_compile"] = compile?;
            let mut outputs = Vec::new();
            for file in [
                "dalvik-cache/arm64/data@app@com.android.ssal.phase2@base.apk@classes.dex",
                "dalvik-cache/arm64/data@app@com.android.ssal.phase2@base.apk@classes.vdex",
            ] {
                let path = root.join("data").join(file);
                let a = fs::symlink_metadata(&path)?;
                let b = fs::metadata(userdata.join(file))?;
                if !a.is_file() || a.len() == 0 || (a.dev(), a.ino()) != (b.dev(), b.ino()) {
                    return Err(io::Error::other("artd output missing/foreign backing"));
                }
                outputs.push(
                    json!({"path":path,"size":a.len(),"sha256":super::preflight::digest(&path)?}),
                );
            }
            report["artd_outputs"] = json!(outputs);
            report["checks"][name] = json!("passed");
        }
    }
    report["bind_after_operations"] = crate::diagnostics::data::verify_bind(root, userdata)?;
    Ok(())
}

pub fn verify(root: &Path) -> io::Result<()> {
    verify_mode(root, None)
}

pub fn verify_phase2(root: &Path, userdata: &Path) -> io::Result<()> {
    verify_mode(root, Some(userdata))
}

fn verify_mode(root: &Path, userdata: Option<&Path>) -> io::Result<()> {
    check_recovery()?;
    #[cfg(feature = "phase3-diagnostic")]
    let phase3_requested = std::env::var_os("SSAL_PHASE3_RSBINDER_PROBE").is_some();
    #[cfg(not(feature = "phase3-diagnostic"))]
    let phase3_requested = false;
    let mut report = json!({"schema":1,"validation_scope":"private_binder_test_b","launch_enabled":false,"checks":{},"phase1_complete":false,"cleanup_scope":"Test B processes, FDs and masks/Binder only; outer worker must confirm rootfs/loop release"});
    for field in FIELDS {
        report["checks"][field] = json!("not_run");
    }
    let mut data_report = json!({"schema":1,"validation_scope":"phase2_permissive_directory_bind","launch_enabled":false,"switch_enabled":false,"checks":{}});
    for field in crate::diagnostics::data::FIELDS {
        data_report["checks"][field] = json!("not_run");
    }
    let host_data_before = userdata.map(|_| host_data_paths()).transpose();
    let before = properties();
    let host_before = host_services();
    let host_mounts_before = fs::read_to_string("/proc/1/mountinfo");
    let policy_before = query(TARGET, TARGET, "process", "getattr");
    let enforcing = context("/sys/fs/selinux/enforce")?;
    report["global_enforcing"] = json!(enforcing == "1");
    report["boot_id"] = json!(context("/proc/sys/kernel/random/boot_id")?);
    let name = TEST_SERVICE_NAME.to_owned();
    report["session"] = json!(format!(
        "{}-{}",
        report["boot_id"].as_str().unwrap(),
        std::process::id()
    ));
    report["service_name"] = json!(name);
    report["test_service"] = json!({"name":name,"context":TEST_SERVICE,"server_domain":TEST_SERVER,"entrypoint":TEST_SERVER_EXEC,"policy_rules":["allow aidl_lazy_test_server aidl_lazy_test_server_exec file { entrypoint execute open read getattr map }","allow aidl_lazy_test_server aidl_lazy_test_service service_manager add"]});
    report["servicemanager_sha256"] = json!(super::preflight::digest(
        &crate::guest::mount::guest_path(root, "system/bin/servicemanager")?
    )?);
    report["execution_spec"] =
        json!(super::runtime_preflight::ServiceExecutionSpec::servicemanager());
    report["policy_sha256"] = json!(policy_hash().ok());
    let mut binder = crate::binder_probe::Session::new();
    let mut masks = Masks { paths: Vec::new() };
    let mut processes = Vec::new();
    let result = (|| -> io::Result<()> {
        if let Some(userdata) = userdata {
            if enforcing != "0" {
                return Err(io::Error::other(
                    "Phase 2 diagnostic requires Permissive; no policy/mode changes made by probe",
                ));
            }
            host_data_before
                .as_ref()
                .map_err(|e| io::Error::other(e.to_string()))?;
            data_report["checks"]["guest_data_isolation"] = json!("failed");
            data_report["bind"] = crate::diagnostics::data::verify_bind(root, userdata)?;
            data_report["layout"] = crate::diagnostics::data::prepare(root)?;
            data_report["checks"]["guest_data_isolation"] = json!("passed");
        }
        if before.is_err()
            || host_before.is_err()
            || fs::read_link("/proc/self/ns/mnt")? == fs::read_link("/proc/1/ns/mnt")?
        {
            return Err(io::Error::other(
                "Host snapshot/private namespace admission failed",
            ));
        }
        let rc = super::preflight::rc_spec(&fs::read_to_string(crate::guest::mount::guest_path(
            root,
            "system/etc/init/servicemanager.rc",
        )?)?)?;
        if rc["matches_android16_credentials"] != true {
            return Err(io::Error::other(
                "unsupported servicemanager rc credentials",
            ));
        }
        report["rc"] = rc;
        report["helper_manifest"] = crate::diagnostics::guest::verify_binder_helper(
            root,
            &std::env::current_exe()?.with_file_name("ssal-binder-probe"),
        )?;
        report["test_b_overrides"] = json!({"proc":"per-child current SID only; no Host root/FD magic links","data":"disposable empty tmpfs; profile data isolation is Phase 2","task_profiles":"not applied; no Host cgroup destinations exposed","logging":"session regular file at /dev/kmsg; Host device absent","property_area":"empty; not Guest property initialization","connect":"seccomp EPERM; no property payload; no process forks, threads only"});
        binder.provision(root)?;
        report["labels"] = environment::prepare_labels(root, &mut binder)?;
        let device = binder.private_device()?;
        if unsafe { libc::fchown(device.as_raw_fd(), 1000, 1000) } != 0
            || unsafe {
                libc::fchmod(
                    device.as_raw_fd(),
                    if userdata.is_some() { 0o666 } else { 0o600 },
                )
            } != 0
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
        if userdata.is_none() {
            masks.mount(
                "tmpfs",
                &root.join("data"),
                Some("tmpfs"),
                libc::MS_NODEV,
                "mode=0755",
            )?;
        } else {
            report["test_b_overrides"]["data"] =
                json!("fresh profile directory bind; no tmpfs over /data");
        }
        fs::create_dir_all(root.join("data/local/tmp"))?;
        super::enforcing::labeled_copy(
            &std::env::current_exe()?.with_file_name("ssal-binder-probe"),
            &root.join("data/local/tmp/ssal-binder-client"),
            "u:object_r:shell_exec:s0",
        )?;
        super::enforcing::labeled_copy(
            &std::env::current_exe()?.with_file_name("ssal-binder-probe"),
            &root.join("data/local/tmp/ssal-binder-test-server"),
            "u:object_r:aidl_lazy_test_server_exec:s0",
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
                &crate::guest::mount::guest_path(root, "system/bin/servicemanager")?,
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
        report["guest_test_service_baseline"] = client(
            command(root, identity, "registry-check", &name)?,
            "not_registered",
            &mut processes,
        )?;
        let target = query(TARGET, TARGET, "process", "getattr")?;
        report["target_domain_av"] = json!(target);
        let server_domain = query(TEST_SERVER, TEST_SERVER, "process", "getattr")?;
        let server_add = query(TEST_SERVER, TEST_SERVICE, "service_manager", "add")?;
        report["test_server_domain_av"] = json!(server_domain);
        report["test_server_add_av"] = json!(server_add);
        report["test_server_av"] = json!({
            "entrypoint":query(TEST_SERVER,TEST_SERVER_EXEC,"file","entrypoint")?,
            "execute":query(TEST_SERVER,TEST_SERVER_EXEC,"file","execute")?,
            "binder_open":query(TEST_SERVER,BINDER_DEVICE,"chr_file","open")?,
            "binder_read":query(TEST_SERVER,BINDER_DEVICE,"chr_file","read")?,
            "binder_write":query(TEST_SERVER,BINDER_DEVICE,"chr_file","write")?,
            "binder_ioctl":query(TEST_SERVER,BINDER_DEVICE,"chr_file","ioctl")?,
            "binder_call_manager":query(TEST_SERVER,TARGET,"binder","call")?,
            "binder_transfer_manager":query(TEST_SERVER,TARGET,"binder","transfer")?,
            "ksu_transition":query("u:r:ksu:s0",TEST_SERVER,"process","transition")?,
            "manager_call_test_server":query(TARGET,TEST_SERVER,"binder","call")?,
            "manager_transfer_test_server":query(TARGET,TEST_SERVER,"binder","transfer")?,
            "shell_call_test_server":query("u:r:shell:s0",TEST_SERVER,"binder","call")?,
            "shell_transfer_test_server":query("u:r:shell:s0",TEST_SERVER,"binder","transfer")?,
            "test_server_transfer_shell":query(TEST_SERVER,"u:r:shell:s0","binder","transfer")?
        });
        if enforcing == "1" && !server_add.allowed {
            return Err(io::Error::other(
                "test server service_manager add denied by loaded policy; registration was not attempted",
            ));
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
            TEST_SERVER,
            &root.join("data/local/tmp/ssal-binder-test-server"),
        )?;
        #[cfg(feature = "phase2c-diagnostic")]
        if std::env::var_os("SSAL_PHASE2C_RSBINDER_PROBE").is_some() {
            match run_phase2c_rsbinder_probe(root) {
                Ok(value) => {
                    report["checks"]["rsbinder_guest_probe"] =
                        json!(if value["result"]["ok"] == true {
                            "passed"
                        } else {
                            "failed"
                        });
                    report["rsbinder_guest_probe"] = value;
                }
                Err(error) => {
                    report["checks"]["rsbinder_guest_probe"] = json!("failed");
                    report["rsbinder_guest_probe"] =
                        json!({"setup_error":error.to_string(),"child_reaped":true});
                }
            }
        }
        if enforcing == "1" && !target.permissive_domain && !server_domain.permissive_domain {
            report["checks"]["android_service_selinux"] = json!("passed");
        }
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
        #[cfg(feature = "phase3-diagnostic")]
        if phase3_requested {
            let phase3_result = (|| -> io::Result<Value> {
                let phase2c = if report["rsbinder_guest_probe"].is_object() {
                    report["rsbinder_guest_probe"].clone()
                } else {
                    run_phase2c_rsbinder_probe(root)?
                };
                if phase2c["exit_code"] != 0 || phase2c["result"]["ok"] != true {
                    return Err(io::Error::other(
                        "Phase 2C private Binder probe failed; Phase 3 was not started",
                    ));
                }
                report["rsbinder_guest_probe"] = phase2c;
                phase3::run(root, identity, server_index, &mut processes)
            })();
            match phase3_result {
                Ok(value) => {
                    let passed = value["passed"] == true;
                    report["phase3"] = value;
                    if !passed {
                        return Err(io::Error::other("Phase 3 diagnostic did not pass"));
                    }
                }
                Err(error) => {
                    report["phase3"] = json!({"passed":false,"error":error.to_string()});
                    return Err(error);
                }
            }
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
        if let Some(userdata) = userdata {
            run_data_daemons(
                root,
                userdata,
                identity,
                &mut processes,
                &mut data_report,
                &mut masks,
            )?;
        }
        Ok(())
    })();
    report["failure"] = json!(result.as_ref().err().map(ToString::to_string));
    if userdata.is_some() {
        data_report["compiler_diagnostics"] =
            json!(fs::read_to_string(root.join("data/local/tmp/phase2-dex2oat.log")).ok());
    }
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
    report["phase3_requested"] = json!(phase3_requested);
    report["phase3_complete"] = json!(!phase3_requested || report["phase3"]["passed"] == true);
    let data_complete = if userdata.is_some() {
        let host_data_after = host_data_paths();
        let host_data_ok = host_data_before
            .as_ref()
            .ok()
            .and_then(|v| v.as_ref())
            .zip(host_data_after.as_ref().ok())
            .is_some_and(|(a, b)| a == b);
        data_report["host_data"] = json!({"before":host_data_before.as_ref().ok(),"after":host_data_after.as_ref().ok(),"unchanged":host_data_ok});
        let host_unchanged = host_ok
            && host_data_ok
            && report["checks"]["property_host_unchanged"] == "passed"
            && report["checks"]["host_registry_isolation"] == "passed";
        data_report["checks"]["host_unchanged"] =
            json!(if host_unchanged { "passed" } else { "failed" });
        data_report["checks"]["cleanup"] = report["checks"]["cleanup"].clone();
        data_report["failure"] = report["failure"].clone();
        data_report["runtime"] = report.clone();
        let complete = result.is_ok() && crate::diagnostics::data::complete(&data_report);
        // Outer worker emits the final completion gate after rootfs/loop cleanup.
        data_report["daemon_probe_passed"] = json!(complete);
        data_report["cleanup_scope"] = json!("owned processes, Binder FDs and temporary masks; outer mount/loop release still required");
        println!(
            "Phase 2 data probe summary: {}",
            serde_json::to_string(&data_report)?
        );
        complete
    } else {
        false
    };
    let phase1_complete = phase1_complete(&report, host_ok, enforcing == "1");
    report["test_b_passed"] = json!(phase1_complete);
    report["phase1_complete"] = json!(phase1_complete);
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
    if (phase1_complete || data_complete)
        && (!phase3_requested || report["phase3"]["passed"] == true)
    {
        Ok(())
    } else {
        Err(io::Error::other(if userdata.is_some() {
            "Phase 2 incomplete; switch remains blocked"
        } else {
            "Test B incomplete; switch remains blocked"
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn compiler_broker_rejects_foreign_group_before_any_mount() -> io::Result<()> {
        let (parent, child) = std::os::unix::net::UnixDatagram::pair()?;
        child.send(&(std::process::id() as i32).to_ne_bytes())?;
        assert!(compiler_proc(
            parent,
            Path::new("/").to_owned(),
            u32::MAX,
            Path::new("/").to_owned(),
            Path::new("/missing").to_owned()
        )
        .is_err());
        let mut ack = [1];
        child.recv(&mut ack)?;
        assert_eq!(ack, [0]);
        Ok(())
    }
    #[test]
    fn daemon_cleanup_terminates_group_before_reaping_leader() -> io::Result<()> {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "sleep 30 & wait"]);
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut process = Process::spawn(command, "phase2-cleanup-test")?;
        std::thread::sleep(Duration::from_millis(50));
        assert!(group_alive(process.child.id())?);
        process.finish()?;
        assert!(!group_alive(process.child.id())?);
        assert!(process.exit.is_some());
        Ok(())
    }
    #[test]
    fn every_field_is_required_and_permissive_is_not_enforcing() {
        let mut report = json!({"checks":{}});
        for field in FIELDS {
            report["checks"][field] = json!("passed");
        }
        assert!(passed(&report));
        assert!(phase1_complete(&report, true, true));
        assert!(!phase1_complete(&report, true, false));
        assert!(!phase1_complete(&report, false, true));
        for field in FIELDS {
            for status in ["failed", "not_run", "unavailable"] {
                report["checks"][field] = json!(status);
                assert!(!passed(&report));
                assert!(!phase1_complete(&report, true, true));
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
