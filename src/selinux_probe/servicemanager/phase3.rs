use super::*;
use sha2::{Digest, Sha256};

const SERVICE: &str = "aidl_lazy_test_1";
const SERVER_PATH: &str = "/data/local/tmp/ssal-rsbinder-phase3-server";
const CLIENT_PATH: &str = "/data/local/tmp/ssal-rsbinder-phase3-client";

fn host_command(name: &str) -> io::Result<String> {
    let output = crate::guest_probe::run_with_timeout(
        Command::new("/system/bin/service")
            .args(["check", name])
            .env_clear(),
        "Phase 3 Host ServiceManager check",
        Duration::from_secs(5),
    )?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "Host service check {name} exited {}",
            output.status
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn host_state(private_binder_rdev: u64) -> io::Result<Value> {
    let binder = fs::metadata("/dev/binder")?;
    if binder.rdev() == private_binder_rdev {
        return Err(io::Error::other(
            "Host and Guest Binder identities are equal",
        ));
    }
    let package = host_command("package")?;
    let diagnostic = host_command(SERVICE)?;
    if !package.contains("found") || !diagnostic.contains("not found") {
        return Err(io::Error::other(format!(
            "Host registry gate failed: package={package:?}, {SERVICE}={diagnostic:?}"
        )));
    }
    let properties = super::properties()?;
    let processes = super::host_services()?;
    let mounts = fs::read("/proc/1/mountinfo")?;
    let enforce = super::context("/sys/fs/selinux/enforce")?;
    if enforce != "1" {
        return Err(io::Error::other("Host SELinux is not Enforcing"));
    }
    Ok(json!({
        "package":package,
        "diagnostic_service":diagnostic,
        "host_binder":[binder.dev(),binder.ino(),binder.rdev()],
        "guest_binder_rdev":private_binder_rdev,
        "properties_sha256":digest(&serde_json::to_vec(&properties)?),
        "host_processes_sha256":digest(&serde_json::to_vec(&processes)?),
        "host_mounts_sha256":digest(&mounts),
        "selinux_enforcing":enforce,
    }))
}

fn host_unchanged(before: &Value, private_binder_rdev: u64, stage: &str) -> io::Result<Value> {
    let after = host_state(private_binder_rdev)?;
    if &after != before {
        return Err(io::Error::other(format!(
            "Host state changed during Phase 3 stage {stage}: before={before}, after={after}"
        )));
    }
    Ok(json!({"stage":stage,"unchanged":true,"snapshot":after}))
}

fn wait_event(process: &mut Process, event: &str) -> io::Result<Value> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        process.collect();
        if let Some(value) = process.events.iter().find(|v| v["event"] == event) {
            return Ok(value.clone());
        }
        if process.poll()?.is_some() {
            let events = serde_json::to_string(&process.events).unwrap_or_else(|_| "[]".into());
            return Err(io::Error::other(format!(
                "{} exited before event {event}; events={events}",
                process.role,
            )));
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("{} did not emit {event}", process.role),
            ));
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn wait_exit(process: &mut Process) -> io::Result<Value> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = process.poll()? {
            process.collect();
            if !status.success() {
                return Err(io::Error::other(format!(
                    "{} exited {status}",
                    process.role
                )));
            }
            return Ok(process.evidence());
        }
        if Instant::now() >= deadline {
            process.stop()?;
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("{} did not exit", process.role),
            ));
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn start_server(
    root: &Path,
    identity: [u64; 4],
    binary_path: &Path,
    processes: &mut Vec<Process>,
    instance: usize,
) -> io::Result<Value> {
    processes.push(Process::spawn(
        super::command(root, identity, "phase3-server", SERVICE)?,
        &format!("phase3-server-{instance}"),
    )?);
    let server = processes.last_mut().unwrap();
    let registered = wait_event(server, "registered")?;
    if registered["service"] != SERVICE
        || registered["descriptor"] != "org.ssal.phase3.IPhase3Service"
        || registered["identity"]["pid"] != server.child.id()
        || registered["identity"]["sdk"] != 36
    {
        return Err(io::Error::other(format!(
            "Phase 3 server registration evidence mismatch: {registered}"
        )));
    }
    let observed =
        super::process_identity(server, root, identity, super::TEST_SERVER, binary_path)?;
    Ok(json!({"registered":registered,"process":observed}))
}

fn run_client(
    root: &Path,
    identity: [u64; 4],
    role: &str,
    event: &str,
    processes: &mut Vec<Process>,
) -> io::Result<Value> {
    processes.push(Process::spawn(
        super::command(root, identity, role, SERVICE)?,
        role,
    )?);
    let process = processes.last_mut().unwrap();
    let client_exe = root.join(CLIENT_PATH.trim_start_matches('/'));
    let client_identity = observe_client_identity(process, root, identity, &client_exe)?;
    let evidence = wait_event(process, event)
        .map_err(|error| io::Error::other(format!("{error}; client_identity={client_identity}")))?;
    let exit = wait_exit(process)?;
    Ok(json!({"event":evidence,"identity":client_identity,"process":exit}))
}

fn observe_client_identity(
    process: &mut Process,
    root: &Path,
    identity: [u64; 4],
    exe: &Path,
) -> io::Result<Value> {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match super::process_identity(process, root, identity, "u:r:shell:s0", exe) {
            Ok(value) => return Ok(value),
            Err(error) => {
                let last_error = error.to_string();
                process.collect();
                if process.poll()?.is_some() {
                    let base = format!("/proc/{}", process.child.id());
                    if starttime(process.child.id())? == process.start {
                        if let Ok(current) = fs::read_to_string(format!("{base}/attr/current")) {
                            return Ok(json!({
                                "pid":process.child.id(),
                                "starttime":process.start,
                                "context":current.trim_matches('\0').trim(),
                                "observed_after_exit":true,
                                "live_observer_error":last_error,
                            }));
                        }
                    }
                    return Err(io::Error::other(format!(
                        "client exited before external identity capture: {last_error}"
                    )));
                }
                if Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!("client identity was not observable: {last_error}"),
                    ));
                }
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    }
}

pub(super) fn run(
    root: &Path,
    identity: [u64; 4],
    cxx_server_index: usize,
    processes: &mut Vec<Process>,
) -> io::Result<Value> {
    let source = std::env::var_os("SSAL_PHASE3_RSBINDER_PROBE")
        .map(PathBuf::from)
        .ok_or_else(|| io::Error::other("Phase 3 Rust binary path missing"))?;
    if !source.is_file() {
        return Err(io::Error::other("Phase 3 Rust binary does not exist"));
    }
    let server_path = root.join(SERVER_PATH.trim_start_matches('/'));
    let client_path = root.join(CLIENT_PATH.trim_start_matches('/'));
    for path in [&server_path, &client_path] {
        if fs::symlink_metadata(path).is_ok() {
            return Err(io::Error::other(format!(
                "Phase 3 staging path already exists: {}",
                path.display()
            )));
        }
    }
    super::super::enforcing::labeled_copy(&source, &server_path, super::TEST_SERVER_EXEC)?;
    super::super::enforcing::labeled_copy(&source, &client_path, "u:object_r:shell_exec:s0")?;

    let result = (|| -> io::Result<Value> {
        let host_before = host_state(identity[2])?;
        let host_checks = std::cell::RefCell::new(Vec::new());
        let record_host = |stage: &str| -> io::Result<()> {
            host_checks
                .borrow_mut()
                .push(host_unchanged(&host_before, identity[2], stage)?);
            Ok(())
        };

        let cxx = processes
            .get_mut(cxx_server_index)
            .ok_or_else(|| io::Error::other("C++ Test B server index missing"))?;
        if cxx.role != "test_server"
            || cxx.poll()?.is_some()
            || starttime(cxx.child.id())? != cxx.start
        {
            return Err(io::Error::other("C++ Test B server ownership check failed"));
        }
        let cxx_pid = cxx.child.id();
        let cxx_start = cxx.start.clone();
        cxx.finish()?;
        let absent = run_client(root, identity, "phase3-absent", "service_absent", processes)?;
        record_host("C++ baseline stopped; Guest service absent")?;

        let first_server = start_server(root, identity, &server_path, processes, 1)?;
        let first_ipc = run_client(root, identity, "phase3-client", "ipc_passed", processes)?;
        record_host("AIDL transaction and callback")?;

        processes.push(Process::spawn(
            super::command(root, identity, "phase3-death-client", SERVICE)?,
            "phase3-death-client",
        )?);
        let death_index = processes.len() - 1;
        let client_exe = root.join(CLIENT_PATH.trim_start_matches('/'));
        let death_identity =
            observe_client_identity(&mut processes[death_index], root, identity, &client_exe)?;
        wait_event(&mut processes[death_index], "death_linked")?;
        let server_index = processes
            .iter()
            .rposition(|p| p.role == "phase3-server-1")
            .ok_or_else(|| io::Error::other("Phase 3 server process missing"))?;
        let killed_pid = processes[server_index].child.id();
        let killed_start = processes[server_index].start.clone();
        if processes[server_index].role != "phase3-server-1"
            || starttime(killed_pid)? != killed_start
        {
            return Err(io::Error::other("diagnostic server PID ownership changed"));
        }
        processes[server_index].finish()?;
        let death = wait_event(&mut processes[death_index], "death_observed").map_err(|error| {
            io::Error::other(format!("{error}; client_identity={death_identity}"))
        })?;
        if death["service_absent"] != true {
            return Err(io::Error::other(
                "death client did not observe service removal",
            ));
        }
        let death_process = wait_exit(&mut processes[death_index])?;
        record_host("Binder death notification and Guest lookup")?;

        let second_server = start_server(root, identity, &server_path, processes, 2)?;
        let reconnect = run_client(root, identity, "phase3-client", "ipc_passed", processes)?;
        record_host("controlled restart and reconnection")?;
        let restarted_index = processes
            .iter()
            .rposition(|p| p.role == "phase3-server-2")
            .ok_or_else(|| io::Error::other("restarted Phase 3 server process missing"))?;
        let restart_pid = processes[restarted_index].child.id();
        let restart_start = processes[restarted_index].start.clone();
        if processes[restarted_index].role != "phase3-server-2"
            || starttime(restart_pid)? != restart_start
        {
            return Err(io::Error::other("restarted server PID ownership changed"));
        }
        processes[restarted_index].finish()?;
        let final_absent =
            run_client(root, identity, "phase3-absent", "service_absent", processes)?;
        record_host("final Guest service removal")?;

        Ok(json!({
            "schema":1,
            "passed":true,
            "service":SERVICE,
            "service_descriptor":"org.ssal.phase3.IPhase3Service",
            "host_before":host_before,
            "host_checks":host_checks.into_inner(),
            "cpp_test_b_server_retired":{"pid":cxx_pid,"starttime":cxx_start,"reason":"same Guest service_context name is reused by the opt-in Rust service"},
            "cpp_test_b_baseline":"registration, descriptor lookup, and C++ echo passed before Rust server startup",
            "guest_absent_after_cpp":absent,
            "rust_registration":first_server,
            "transactions_and_callback":first_ipc,
            "death":{"server_pid":killed_pid,"server_starttime":killed_start,"client_identity":death_identity,"client":death,"client_process":death_process},
            "controlled_restart":second_server,
            "reconnection":reconnect,
            "guest_absent_after_final_stop":final_absent,
            "cleanup":{"test_processes_owned_by_test_b_supervisor":true,"staging_paths":[SERVER_PATH,CLIENT_PATH]},
        }))
    })();

    let start = processes.iter().position(|p| p.role.starts_with("phase3-"));
    let mut cleanup_error = None;
    if let Some(start) = start {
        for process in processes[start..].iter_mut().rev() {
            if let Err(error) = process.finish() {
                cleanup_error.get_or_insert_with(|| error.to_string());
            }
        }
    }
    for path in [&server_path, &client_path] {
        match fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                cleanup_error.get_or_insert_with(|| error.to_string());
            }
        }
        if fs::symlink_metadata(path).is_ok() {
            cleanup_error
                .get_or_insert_with(|| format!("staging path remains: {}", path.display()));
        }
    }
    if let Some(error) = cleanup_error {
        return Err(io::Error::other(format!("Phase 3 cleanup failed: {error}")));
    }
    result
}
