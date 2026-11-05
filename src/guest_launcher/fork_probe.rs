//! One ordinary, non-USAP fork through the Guest's Java forkAndSpecialize path.
use super::*;
use std::os::fd::OwnedFd;
use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;

const REQUEST: &[&str] = &[
    "--runtime-args",
    "--setuid=10000",
    "--setgid=10000",
    "--target-sdk-version=36",
    "--nice-name=ssal-fork-probe",
    "--seinfo=ssal_probe",
    "dev.ssal.probe.ForkProbe",
];

fn request(socket: &mut UnixStream) -> io::Result<i32> {
    write!(socket, "{}\n{}\n", REQUEST.len(), REQUEST.join("\n"))?;
    let mut response = [0; 5];
    socket.read_exact(&mut response)?;
    let pid = i32::from_be_bytes(response[..4].try_into().unwrap());
    if pid <= 1 || response[4] != 0 {
        return Err(io::Error::other(format!(
            "fork response pid={pid} wrapper={}",
            response[4]
        )));
    }
    Ok(pid)
}

pub(crate) fn client() -> io::Result<()> {
    // Same credential and capability checks as readiness, on a separate connection.
    super::readiness_client()?;
    let mut socket = UnixStream::connect("zygote")?;
    socket.set_read_timeout(Some(Duration::from_secs(10)))?;
    socket.set_write_timeout(Some(Duration::from_secs(10)))?;
    let pid = request(&mut socket)?;
    println!("FORK_CHILD_PID={pid}");
    Ok(())
}

pub(super) fn prepare(
    mounts: &mut Mounts,
    root: &Path,
    bin: &Path,
    phase7i: bool,
) -> io::Result<()> {
    fs::create_dir(Path::new(crate::guest_mounts::GUEST_CGROUPS[0].0).join("apps"))?;
    let library = root.join("run/ssal/ssal-zygote-fd-reopen.so");
    File::create(&library)?;
    mounts.bind(&bin.join("ssal-zygote-fd-reopen.so"), &library, true, false)?;
    let session = crate::guest_mounts::directory(root, "run/ssal/fork-probe", 0o700)?;
    let path = std::ffi::CString::new(session.as_os_str().as_encoded_bytes())?;
    if unsafe { libc::chown(path.as_ptr(), 10000, 10000) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // shortcut: reuse the unused Guest am.jar slot for this probe; add a dedicated slot before Framework bring-up.
    let jar = root.join("system/framework/am.jar");
    mounts.bind(&bin.join("fork-probe.jar"), &jar, true, false)?;
    let evidence = root
        .parent()
        .unwrap()
        .join(if phase7i { "phase7fc" } else { "phase7fb" });
    fs::create_dir(&evidence)?;
    let contexts = evidence.join("plat_seapp_contexts");
    // Guest-only mapping to the existing experimental domain; no Host app domain reuse.
    fs::write(
        &contexts,
        "user=_app seinfo=ssal_probe domain=ssal_guest_probe\n",
    )?;
    mounts.bind(
        &contexts,
        &root.join("system/etc/selinux/plat_seapp_contexts"),
        true,
        false,
    )?;
    fs::write(
        evidence.join("request.txt"),
        format!("{}\n{}\n", REQUEST.len(), REQUEST.join("\n")),
    )?;
    Ok(())
}

fn starttime(stat: &str) -> io::Result<&str> {
    stat.rsplit_once(") ")
        .and_then(|(_, fields)| fields.split_whitespace().nth(19))
        .ok_or_else(|| io::Error::other("process starttime missing"))
}

fn validate_status(status: &str, parent: u32) -> io::Result<()> {
    for key in ["Uid:", "Gid:"] {
        let values: Vec<_> = status
            .lines()
            .find_map(|s| s.strip_prefix(key))
            .unwrap_or("")
            .split_whitespace()
            .collect();
        if values != ["10000"; 4] {
            return Err(io::Error::other(format!("child {key} {values:?}")));
        }
    }
    let value = |key| {
        status
            .lines()
            .find_map(|s| s.strip_prefix(key))
            .map(str::trim)
    };
    if value("PPid:") != Some(parent.to_string().as_str()) || value("Groups:") != Some("") {
        return Err(io::Error::other(
            "child parent or supplementary groups mismatch",
        ));
    }
    for key in ["CapInh:", "CapPrm:", "CapEff:", "CapAmb:"] {
        if value(key).and_then(|v| u64::from_str_radix(v, 16).ok()) != Some(0) {
            return Err(io::Error::other(format!(
                "child capability {key} is nonzero/missing"
            )));
        }
    }
    Ok(())
}

pub(super) fn run(root: &Path, zygote: &mut Service, phase7i: bool) -> io::Result<()> {
    let parent = zygote.child.id();
    let evidence = root
        .parent()
        .unwrap()
        .join(if phase7i { "phase7fc" } else { "phase7fb" });
    let session = root.join("run/ssal/fork-probe");
    if phase7i {
        let local_tmp = crate::guest_mounts::directory(root, "data/local/tmp", 0o1771)?;
        let relative = format!("data/local/tmp/ssal-phase7i-{parent}");
        let data_dir = root.join(&relative);
        let ownership_record = session.join("data-probe-dir");
        fs::write(&ownership_record, &relative)?;
        if let Err(error) = fs::create_dir(&data_dir) {
            let _ = fs::remove_file(ownership_record);
            return Err(error);
        }
        fs::set_permissions(&data_dir, fs::Permissions::from_mode(0o700))?;
        let data_dir_c = std::ffi::CString::new(data_dir.as_os_str().as_encoded_bytes())?;
        if unsafe { libc::chown(data_dir_c.as_ptr(), 10000, 10000) } != 0 {
            return Err(io::Error::last_os_error());
        }
        fs::set_permissions(&data_dir, fs::Permissions::from_mode(0o700))?;
        let data_file = data_dir.join("probe");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o444)
            .open(&data_file)?;
        file.write_all(b"guest-userdata-v1")?;
        file.sync_all()?;
        drop(file);
        fs::set_permissions(&data_file, fs::Permissions::from_mode(0o444))?;
        let data_path = format!("/data/local/tmp/ssal-phase7i-{parent}/probe\n");
        let data_path_file = session.join("data-probe-path");
        fs::write(&data_path_file, data_path)?;
        fs::set_permissions(&data_path_file, fs::Permissions::from_mode(0o444))?;
        let data_identity = fs::metadata(&data_dir)?;
        if data_identity.dev() != fs::metadata(root.join("data"))?.dev() {
            return Err(io::Error::other("Java data probe is not on Guest userdata"));
        }
        println!(
            "Guest Java data probe prepared path={} dev={} parent={}",
            local_tmp.join(data_dir.file_name().unwrap()).display(),
            data_identity.dev(),
            parent
        );
    }
    let mut descriptors = String::new();
    for entry in fs::read_dir(format!("/proc/{parent}/fd"))? {
        let entry = entry?;
        let meta = fs::metadata(entry.path())?;
        descriptors.push_str(&format!(
            "fd={} target={} dev={} ino={} mode={:o}\n{}",
            entry.file_name().to_string_lossy(),
            fs::read_link(entry.path())?.display(),
            meta.dev(),
            meta.ino(),
            meta.mode(),
            fs::read_to_string(format!(
                "/proc/{parent}/fdinfo/{}",
                entry.file_name().to_string_lossy()
            ))?
        ));
    }
    fs::write(evidence.join("zygote-fds.txt"), descriptors)?;
    let client_log = File::create(evidence.join("client.txt"))?;
    let mut command = Command::new("/proc/self/exe");
    command
        .arg("--zygote-fork-client")
        .current_dir(root.join("dev/socket"))
        .stdin(Stdio::null())
        .stdout(client_log.try_clone()?)
        .stderr(client_log);
    unsafe {
        command.pre_exec(move || {
            ssal::unix::cloexec_unexpected_fds()?;
            // handleParentProc adopts the peer PGID: keep the child in our owned Guest group.
            if libc::setpgid(0, parent as i32) != 0
                || libc::setgroups(0, std::ptr::null()) != 0
                || libc::setresgid(1000, 1000, 1000) != 0
                || libc::setresuid(1000, 1000, 1000) != 0
                || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut client = command.spawn()?;
    let deadline = Instant::now() + Duration::from_secs(15);
    let client_result = (|| loop {
        crate::memory_cgroup::check_interrupted()?;
        if let Some(diagnostics) = &mut zygote.diagnostics {
            diagnostics.tick()?;
        }
        if let Some(status) = client.try_wait()? {
            return if status.success() {
                Ok(())
            } else {
                Err(io::Error::other(format!("fork client {status}")))
            };
        }
        if zygote.exited()? || Instant::now() >= deadline {
            return Err(io::Error::other("fork client timeout or Zygote exit"));
        }
        std::thread::sleep(Duration::from_millis(20));
    })();
    if client_result.is_err() {
        // This direct child remains unreaped if still alive; its PID cannot be reused.
        if client.try_wait()?.is_none() {
            client.kill()?;
            client.wait()?;
        }
    }
    let report = fs::read_to_string(evidence.join("client.txt"))?;
    print!("{report}");
    client_result?;
    let pid: i32 = report
        .lines()
        .find_map(|s| s.strip_prefix("FORK_CHILD_PID="))
        .ok_or_else(|| io::Error::other("fork response PID missing"))?
        .parse()
        .map_err(io::Error::other)?;
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32;
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    let pidfd = unsafe { OwnedFd::from_raw_fd(raw) };
    let proc = std::path::PathBuf::from(format!("/proc/{pid}"));
    let initial_stat = fs::read_to_string(proc.join("stat"))?;
    let identity = starttime(&initial_stat)?.to_owned();
    fs::write(evidence.join("child-stat.txt"), &initial_stat)?;
    println!("Guest fork child pid={pid} starttime={identity} zygote_pid={parent} pidfd=opened");
    let deadline = Instant::now() + Duration::from_secs(12);
    while !session.join("ready").is_file() {
        crate::memory_cgroup::check_interrupted()?;
        if let Some(diagnostics) = &mut zygote.diagnostics {
            diagnostics.tick()?;
        }
        if !proc.exists() || Instant::now() >= deadline || zygote.exited()? {
            return Err(io::Error::other(
                "child entrypoint marker absent (exit or timeout)",
            ));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    for name in [
        "stat",
        "status",
        "cgroup",
        "attr/current",
        "maps",
        "mountinfo",
    ] {
        fs::copy(
            proc.join(name),
            evidence.join(format!("child-{}.txt", name.replace('/', "-"))),
        )?;
    }
    let mut namespaces = String::new();
    for name in ["mnt", "net", "pid", "user", "uts", "ipc", "cgroup"] {
        let namespace = |path: &Path| match fs::read_link(path) {
            Ok(value) => Ok(Some(value)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        };
        let child = namespace(&proc.join(format!("ns/{name}")))?;
        let zygote_ns = namespace(Path::new(&format!("/proc/{parent}/ns/{name}")))?;
        let host = namespace(Path::new(&format!("/proc/1/ns/{name}")))?;
        namespaces.push_str(&format!(
            "{name} child={child:?} zygote={zygote_ns:?} host={host:?}\n"
        ));
        if (name == "net" && child != zygote_ns)
            || (["mnt", "net"].contains(&name) && (child.is_none() || child == host))
            || (name == "pid" && child != host)
        {
            return Err(io::Error::other(format!(
                "child namespace mismatch: {namespaces}"
            )));
        }
    }
    fs::write(evidence.join("namespaces.txt"), &namespaces)?;
    for entry in fs::read_dir(&session)? {
        let entry = entry?;
        fs::copy(entry.path(), evidence.join(entry.file_name()))?;
    }
    if phase7i {
        let properties = fs::read_to_string(session.join("properties.txt"))?;
        let binder = fs::read_to_string(session.join("binder.txt"))?;
        let integration = fs::read_to_string(session.join("integration"))?;
        if !properties.contains("sdk=36")
            || !properties.contains("persist.ssal_probe=7")
            || !binder.contains("\"event\":\"ipc_passed\"")
            || integration != "property=PASS private_binder=PASS userdata_read_write=PASS\n"
        {
            return Err(io::Error::other(
                "Java child property or private Binder evidence missing",
            ));
        }
        let relative = fs::read_to_string(session.join("data-probe-dir"))?;
        let data_dir = crate::guest_mounts::guest_path(root, relative.trim())?;
        let data_result = fs::read_to_string(data_dir.join("java-child"))?;
        if data_result != "Java child reached Guest userdata\n" {
            return Err(io::Error::other("Java Guest userdata write evidence mismatch"));
        }
        fs::write(session.join("data-result"), data_result)?;
        fs::copy(session.join("data-result"), evidence.join("data-result"))?;
        println!("Guest Java child property=PASS private_binder=PASS userdata_read_write=PASS");
    }
    let status = fs::read_to_string(proc.join("status"))?;
    validate_status(&status, parent)?;
    if fs::read_to_string(proc.join("attr/current"))?
        .trim_matches('\0')
        .trim()
        != "u:r:ssal_guest_probe:s0"
    {
        return Err(io::Error::other("child escaped Guest SELinux domain"));
    }
    crate::memory_cgroup::verify_membership(
        pid as u32,
        Path::new("/sys/fs/cgroup"),
        Path::new(crate::guest_mounts::GUEST_CGROUPS[0].0),
    )?;
    let cgroups = fs::read_to_string(proc.join("cgroup"))?;
    for (_, target) in crate::guest_mounts::GUEST_CGROUPS.iter().skip(1) {
        let controller = match *target {
            "dev/cpuset" => "cpuset",
            "dev/cpuctl" => "cpu",
            _ => "blkio",
        };
        let member = cgroups
            .lines()
            .filter_map(|s| {
                let mut fields = s.splitn(3, ':');
                fields.next()?;
                Some((fields.next()?, fields.next()?))
            })
            .find(|(names, _)| names.split(',').any(|name| name == controller))
            .ok_or_else(|| io::Error::other("child v1 cgroup missing"))?
            .1;
        if !Path::new(member).starts_with("/ssal_guest") {
            return Err(io::Error::other("child left Guest v1 cgroup"));
        }
    }
    let expected = fs::metadata(root)?;
    let actual = fs::metadata(proc.join("root"))?;
    if (expected.dev(), expected.ino()) != (actual.dev(), actual.ino())
        || starttime(&fs::read_to_string(proc.join("stat"))?)? != identity
        || starttime(&fs::read_to_string(session.join("stat"))?)? != identity
    {
        return Err(io::Error::other("child root or PID/starttime changed"));
    }
    println!("Guest fork entrypoint=executed uid=10000 gid=10000 groups=empty capabilities=0 domain=ssal_guest_probe root=Guest namespaces=verified cgroups=verified\n{namespaces}");
    fs::write(session.join("release"), "exit\n")?;
    let deadline = Instant::now() + Duration::from_secs(5);
    let exit_line = format!("Process {pid} exited cleanly (0)");
    loop {
        crate::memory_cgroup::check_interrupted()?;
        if let Some(diagnostics) = &mut zygote.diagnostics {
            diagnostics.tick()?;
        }
        let mut poll = libc::pollfd {
            fd: pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let exited = unsafe { libc::poll(&mut poll, 1, 0) };
        if exited < 0 {
            return Err(io::Error::last_os_error());
        }
        let log = fs::read_to_string(root.parent().unwrap().join("phase7b/stderr.log"))?;
        if exited > 0 && log.contains(&exit_line) && !proc.exists() {
            if fs::read_to_string(session.join("completed"))? != "SSAL_FORK_PROBE_EXIT=0\n" {
                return Err(io::Error::other("child completion marker invalid"));
            }
            fs::copy(session.join("completed"), evidence.join("completed"))?;
            println!("PHASE7FB_FORK=PASS child_pid={pid} starttime={identity} exit=0 reaped_by=zygote pidfd=exited");
            return Ok(());
        }
        if Instant::now() >= deadline || zygote.exited()? {
            return Err(io::Error::other("child clean exit/reap evidence missing"));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

pub(super) fn cleanup(root: &Path) -> io::Result<()> {
    let session = root.join("run/ssal/fork-probe");
    let metadata_path = session.join("data-probe-dir");
    let relative = match fs::read_to_string(&metadata_path) {
        Ok(relative) => relative,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    let relative = relative.trim();
    if !relative.starts_with("data/local/tmp/ssal-phase7i-") || relative.contains("..") {
        return Err(io::Error::other("refusing unowned Guest data cleanup path"));
    }
    let data_dir = crate::guest_mounts::guest_path(root, relative)?;
    let metadata = fs::symlink_metadata(&data_dir)?;
    if !metadata.is_dir()
        || !matches!(metadata.uid(), 0 | 10000)
        || metadata.mode() & 0o077 != 0
        || metadata.dev() != fs::metadata(root.join("data"))?.dev()
    {
        return Err(io::Error::other("Guest data probe ownership changed"));
    }
    fs::remove_dir_all(&data_dir)?;
    fs::remove_file(metadata_path)?;
    println!("Guest Java userdata probe cleanup=PASS");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn protocol_request_and_response_are_exact_and_reject_failure() -> io::Result<()> {
        use std::io::BufRead;
        for response in [
            [0, 0, 1, 42, 0],
            [255, 255, 255, 255, 0],
            [0, 0, 1, 42, 1],
            [0, 0, 0, 1, 0],
        ] {
            let (mut client, mut server) = UnixStream::pair()?;
            let peer = std::thread::spawn(move || -> io::Result<()> {
                let mut reader = io::BufReader::new(server.try_clone()?);
                let mut line = String::new();
                reader.read_line(&mut line)?;
                assert_eq!(line, "7\n");
                for expected in REQUEST {
                    line.clear();
                    reader.read_line(&mut line)?;
                    assert_eq!(line.trim_end_matches('\n'), *expected);
                }
                server.write_all(&response)
            });
            let result = request(&mut client);
            assert_eq!(result.is_ok(), response == [0, 0, 1, 42, 0]);
            if let Ok(pid) = result {
                assert_eq!(pid, 298);
            }
            peer.join().unwrap()?;
        }
        assert!(starttime("not a stat").is_err());
        let status = "Uid:\t10000 10000 10000 10000\nGid:\t10000 10000 10000 10000\nPPid:\t42\nGroups:\t\nCapInh:\t0000\nCapPrm:\t0000\nCapEff:\t0000\nCapAmb:\t0000\n";
        validate_status(status, 42)?;
        assert!(validate_status(&status.replace("CapEff:\t0000", "CapEff:\t0001"), 42).is_err());
        assert!(validate_status(&status.replace("Groups:\t", "Groups:\t1000"), 42).is_err());
        assert!(validate_status(status, 43).is_err());
        Ok(())
    }
}
