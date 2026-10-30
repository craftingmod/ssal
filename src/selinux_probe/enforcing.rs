//! Opt-in fixed Binder experiment. Does not launch any Android service.
use super::runtime_preflight::{environment, host_resources, ServiceExecutionSpec};
use super::*;
use serde_json::{json, Value};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};

fn contexts(root: &Path) -> io::Result<Value> {
    let mut entries = std::collections::BTreeMap::<String, Vec<String>>::new();
    let mut files = Vec::new();
    for path in [
        "system/etc/selinux/plat_service_contexts",
        "system_ext/etc/selinux/system_ext_service_contexts",
        "product/etc/selinux/product_service_contexts",
        "vendor/etc/selinux/vendor_service_contexts",
        "odm/etc/selinux/odm_service_contexts",
    ] {
        let file = crate::guest_mounts::guest_path(root, path);
        match file.and_then(fs::read_to_string) {
            Ok(text) => {
                files.push(json!({"path":path,"status":"read","sha256":crate::guest_mounts::guest_path(root,path).and_then(|p|super::preflight::digest(&p)).ok()}));
                for line in text
                    .lines()
                    .map(|l| l.split('#').next().unwrap_or("").trim())
                    .filter(|l| !l.is_empty())
                {
                    let fields: Vec<_> = line.split_whitespace().collect();
                    if fields.len() != 2 || fields[1].split(':').count() != 4 {
                        return Err(io::Error::other(format!(
                            "malformed service_contexts entry in {path}"
                        )));
                    }
                    entries
                        .entry(fields[1].into())
                        .or_default()
                        .push(fields[0].into());
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                files.push(json!({"path":path,"status":"absent","errno":e.raw_os_error()}))
            }
            Err(e) => return Err(e),
        }
    }
    if entries.is_empty() {
        return Err(io::Error::other("no Guest service_contexts entries"));
    }
    let mut decisions = Vec::new();
    let mut compatible = true;
    for (label, names) in entries {
        let validation = (|| -> io::Result<()> {
            let mut check = OpenOptions::new()
                .read(true)
                .write(true)
                .open("/sys/fs/selinux/context")?;
            let context = std::ffi::CString::new(label.as_str()).map_err(io::Error::other)?;
            check.write_all(context.as_bytes_with_nul())?;
            Ok(())
        })();
        if validation.is_err() {
            compatible = false;
        }
        let mut av = Vec::new();
        for permission in ["add", "find"] {
            match query(TARGET, &label, "service_manager", permission) {
                Ok(d) => av.push(json!({"context_valid_in_effective_policy":true,"decision":d})),
                Err(e) => {
                    compatible = false;
                    av.push(json!({"context_valid_in_effective_policy":"unproven","syscall":"selinuxfs/access","errno":e.raw_os_error(),"error":e.to_string()}));
                }
            }
        }
        decisions.push(json!({"label":label,"services":names,"context_validation":{"syscall":"write(/sys/fs/selinux/context)","status":if validation.is_ok(){"passed"}else{"blocked"},"errno":validation.as_ref().err().and_then(io::Error::raw_os_error),"error":validation.err().map(|e|e.to_string())},"av":av}));
    }
    Ok(
        json!({"status":if compatible{"passed"}else{"blocked"},"files":files,"contexts":decisions,"scope":"context validity and add/find AV queries in current effective policy only; denied add/find remains denied; no actual AOSP registration"}),
    )
}

fn command(root: &Path, identity: [u64; 4], order: &str, engine: &str) -> io::Result<Command> {
    let helper = std::env::current_exe()?
        .parent()
        .ok_or_else(|| io::Error::other("worker parent"))?
        .join("ssal-enforcing-binder");
    let mut command = Command::new(helper);
    command
        .arg("launch")
        .arg(root)
        .args(identity.map(|v| v.to_string()))
        .arg(order)
        .arg(engine)
        .env_clear()
        .env("PATH", "/system/bin")
        .env("ANDROID_ROOT", "/system")
        .env("ANDROID_DATA", "/data")
        .stdin(Stdio::null());
    unsafe {
        command.pre_exec(|| {
            if libc::setpgid(0, 0) != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    Ok(command)
}

fn trial(root: &Path, identity: [u64; 4], order: &str, engine: &str) -> io::Result<Value> {
    let mut command = command(root, identity, order, engine)?;
    let output = crate::guest_probe::run_with_timeout(
        &mut command,
        "enforcing Binder fixed helper",
        Duration::from_secs(20),
    )?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let events: Vec<Value> = stdout
        .lines()
        .filter(|line| line.starts_with('{'))
        .map(serde_json::from_str::<Value>)
        .collect::<Result<_, _>>()
        .map_err(io::Error::other)?;
    Ok(
        json!({"engine":engine,"exit_code":output.status.code(),"success":output.status.success(),"events":events,"stdout":stdout,"stderr":String::from_utf8_lossy(&output.stderr),"nnp_order":order,"child_reaped":true,"library_scope":if engine.starts_with("lib"){"Guest platform libbinder and dynamic linker; see library manifest/runtime location"}else{"Rust raw UAPI through Guest linker/Bionic; no libbinder"}}),
    )
}

fn labeled_copy(source: &Path, target: &Path, label: &str) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o755)
        .open(target)?;
    io::copy(&mut fs::File::open(source)?, &mut file)?;
    if unsafe { libc::fchown(file.as_raw_fd(), 1000, 1000) } != 0
        || unsafe {
            libc::fsetxattr(
                file.as_raw_fd(),
                c"security.selinux".as_ptr(),
                label.as_ptr().cast(),
                label.len(),
                0,
            )
        } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn pair_trial(root: &Path, identity: [u64; 4], library: bool) -> io::Result<Value> {
    use std::io::BufRead;
    let mut cmd = command(
        root,
        identity,
        "before",
        if library { "libserver" } else { "server" },
    )?;
    let mut child = cmd.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?;
    let stdout = child.stdout.take().unwrap();
    let mut stderr = child.stderr.take().unwrap();
    let (sender, receiver) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        let mut lines = Vec::new();
        let mut ready = false;
        for line in io::BufReader::new(stdout.take(256 * 1024)).lines() {
            let line = line?;
            if let Ok(v) = serde_json::from_str::<Value>(&line) {
                if v["event"] == "private_context_manager" && v["status"] == "passed" {
                    ready = true;
                    let _ = sender.send(true);
                }
            }
            lines.push(line);
        }
        if !ready {
            let _ = sender.send(false);
        }
        Ok::<_, io::Error>(lines)
    });
    let errors = std::thread::spawn(move || {
        let mut text = String::new();
        stderr.read_to_string(&mut text).map(|_| text)
    });
    let ready = receiver
        .recv_timeout(Duration::from_secs(5))
        .unwrap_or(false);
    let client = if ready {
        trial(
            root,
            identity,
            "before",
            if library { "libclient" } else { "client" },
        )
    } else {
        Err(io::Error::other("private server not ready"))
    };
    unsafe {
        libc::kill(-(child.id() as i32), libc::SIGKILL);
    }
    let waited = child.wait();
    let lines = reader
        .join()
        .map_err(|_| io::Error::other("server reader panic"))??;
    let stderr = errors
        .join()
        .map_err(|_| io::Error::other("server stderr panic"))??;
    let events: Vec<Value> = lines
        .iter()
        .filter(|l| l.starts_with('{'))
        .map(|l| serde_json::from_str(l))
        .collect::<Result<_, _>>()
        .map_err(io::Error::other)?;
    let server_admitted = events.iter().any(|v| {
        ["post_exec", "libbinder_post_exec"].contains(&v["event"].as_str().unwrap_or(""))
            && v["context"] == TARGET
            && v["credentials_valid"] == true
    });
    let passed =
        server_admitted && client.as_ref().is_ok_and(|v| v["success"] == true) && waited.is_ok();
    Ok(
        json!({"engine":if library{"guest_libbinder_cross_domain"}else{"raw_cross_domain"},"status":if passed{"passed"}else{"blocked"},"server":{"pid":child.id(),"events":events,"stdout":lines,"stderr":stderr,"reaped":waited.is_ok(),"termination":"owned server process group killed after trial"},"client":client.as_ref().ok(),"error":client.err().map(|e|e.to_string()),"scope":"fixed servicemanager-domain server and shell-domain client; UID/GID 1000/1000; Private Binder only"}),
    )
}

pub fn verify(root: &Path) -> io::Result<()> {
    let names = [
        "private_binder_identity",
        "servicemanager_domain_transition",
        "enforcing_binder_open",
        "enforcing_binder_transaction",
        "private_context_manager",
        "guest_libbinder_ipc",
        "service_contexts_compatibility",
        "host_binder_nonexposure",
        "host_unchanged",
        "cleanup",
    ];
    let mut report = json!({"schema":1,"validation_scope":"enforcing_binder_fixed_probe","launch_enabled":false,"android_framework_services_executed":false,"policy_modified":false,"host_labels_modified":false,"checks":{},"execution_spec":ServiceExecutionSpec::servicemanager(),"remaining_environment_blockers":["PID/IPC namespace support","functional private proc","Guest property service/area initialization","Guest task profile/cgroup destinations"],"host_registry_observation":"not_run; no Host Binder opened; bidirectional registry nonvisibility not proven"});
    for name in names {
        report["checks"][name] = json!({"status":"not_run"});
    }
    let before = host_services()?;
    let resources = host_resources()?;
    let initial = query(TARGET, TARGET, "process", "getattr")?;
    let policy_before = policy_hash();
    let mut binder = crate::binder_probe::Session::new();
    let mut masks = environment::Masks { paths: Vec::new() };
    let helper = root.join("data/local/tmp/ssal-enforcing-binder");
    let mut helper_owned = false;
    let lib_helper = root.join("data/local/tmp/ssal-binder-probe");
    let mut lib_owned = false;
    let result = (|| -> io::Result<()> {
        if context("/sys/fs/selinux/enforce")? != "1"
            || initial.permissive_domain
            || fs::read_link("/proc/self/ns/mnt")? == fs::read_link("/proc/1/ns/mnt")?
        {
            return Err(io::Error::other("Enforcing/private mount admission gate"));
        }
        binder.provision(root)?;
        let device = binder.private_device()?;
        if file_label(device)? != "u:object_r:binder_device:s0" {
            return Err(io::Error::other(
                "original binder label mismatch; no relabel/context fallback",
            ));
        }
        report["private_binder_av"] = json!([
            query(TARGET, "u:object_r:binder_device:s0", "chr_file", "open")?,
            query(TARGET, "u:object_r:binder_device:s0", "chr_file", "ioctl")?,
            query(TARGET, TARGET, "binder", "set_context_mgr")?,
            query(TARGET, TARGET, "binder", "call")?,
            query(TARGET, TARGET, "binder", "transfer")?
        ]);
        report["guest_labels"] = environment::prepare_labels(root, &mut binder)?;
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
        report["checks"]["private_binder_identity"] = json!({"status":"passed","dev":meta.dev(),"inode":meta.ino(),"rdev":meta.rdev(),"host_rdev":identity[3],"uid":meta.uid(),"gid":meta.gid(),"mode":meta.mode(),"label":file_label(device)?,"fdinfo":fs::read_to_string(format!("/proc/self/fdinfo/{}",device.as_raw_fd()))?,"scope":"fresh binderfs/control mount identity plus original node and alias equality; functional context isolation requires transaction evidence"});
        report["checks"]["service_contexts_compatibility"] = contexts(root)?;
        // Dedicated executable tmpfs: never relabel a userdata or Host inode.
        // No suid bits or file capabilities are installed. The probe drops all
        // credentials before exec and measures NNP ordering separately.
        masks.mount(
            "tmpfs",
            &root.join("data"),
            Some("tmpfs"),
            libc::MS_NODEV,
            "mode=0755",
        )?;
        fs::create_dir_all(helper.parent().unwrap())?;
        report["data_view"] = json!({"kind":"session-only empty tmpfs","reason":"profile userdata root is 0700/root; test executable requires a traversable Guest-owned path without changing persisted DAC","host_data_exposed":false});
        let source = std::env::current_exe()?
            .parent()
            .unwrap()
            .join("ssal-enforcing-binder");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o700)
            .open(&helper)?;
        helper_owned = true;
        io::copy(&mut fs::File::open(&source)?, &mut file)?;
        let mut helper_fs: libc::statfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstatfs(file.as_raw_fd(), &mut helper_fs) } != 0 {
            return Err(io::Error::last_os_error());
        }
        if file.metadata()?.nlink() != 1 || helper_fs.f_type as u64 != 0x01021994 {
            return Err(io::Error::other(
                "Guest temporary executable ownership gate",
            ));
        }
        let label = b"u:object_r:servicemanager_exec:s0";
        if unsafe {
            libc::fsetxattr(
                file.as_raw_fd(),
                c"security.selinux".as_ptr(),
                label.as_ptr().cast(),
                label.len(),
                0,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        file.set_permissions(fs::Permissions::from_mode(0o755))?;
        if unsafe { libc::fchown(file.as_raw_fd(), 1000, 1000) } != 0 {
            return Err(io::Error::last_os_error());
        }
        report["entrypoint"] = json!({"label":file_label(&file)?,"sha256":super::preflight::digest(&helper)?,"source_sha256":super::preflight::digest(&source)?,"av":query(TARGET,"u:object_r:servicemanager_exec:s0","file","entrypoint")?,"transition_av":query("u:r:ksu:s0",TARGET,"process","transition")?});
        drop(file);
        labeled_copy(
            &source,
            &root.join("data/local/tmp/ssal-enforcing-client"),
            "u:object_r:shell_exec:s0",
        )?;
        let shell = "u:r:shell:s0";
        let shell_flags = query(shell, shell, "process", "getattr")?;
        report["cross_domain_av"] = json!({"client_enforcing":shell_flags,"call":query(shell,TARGET,"binder","call")?,"transfer":query(shell,TARGET,"binder","transfer")?,"reply_transfer":query(TARGET,shell,"binder","transfer")?,"entrypoint":query(shell,"u:object_r:shell_exec:s0","file","entrypoint")?});
        environment::minimal_devices(root, &binder, &mut masks)?;
        let mut trials = Vec::new();
        for order in ["before", "after"] {
            trials.push(trial(root, identity, order, "raw")?);
        }
        let events: Vec<_> = trials
            .iter()
            .flat_map(|v| v["events"].as_array().into_iter().flatten())
            .collect();
        for (name, event) in [
            ("servicemanager_domain_transition", "post_exec"),
            ("enforcing_binder_open", "open"),
            ("private_context_manager", "private_context_manager"),
            ("enforcing_binder_transaction", "raw_ipc_complete"),
            ("host_binder_nonexposure", "nonexposure"),
        ] {
            let passed = events.iter().any(|v| {
                v["event"] == event
                    && match event {
                        "post_exec" => v["context"] == TARGET && v["credentials_valid"] == true,
                        "open" => v["errno"].is_null(),
                        "raw_ipc_complete" | "private_context_manager" => v["status"] == "passed",
                        "nonexposure" => v["paths"]
                            .as_object()
                            .is_some_and(|p| p.values().all(|e| e["opened"] == false)),
                        _ => false,
                    }
            });
            report["checks"][name] = json!({"status":if passed{"passed"}else{"blocked"},"evidence":"trials/events; dependent operations stop at the first failed gate","scope":if name=="host_binder_nonexposure"{"listed aliases under applied credentials, empty proc/minimal dev, closed inherited FDs; Host registry lookup not_run"}else{"fixed helper only"}});
        }
        let admitted = report["checks"]["servicemanager_domain_transition"]["status"] == "passed";
        if admitted {
            if !report["cross_domain_av"]["client_enforcing"]["permissive_domain"]
                .as_bool()
                .unwrap_or(true)
            {
                let pair = pair_trial(root, identity, false)?;
                if pair["status"] == "passed" {
                    report["checks"]["enforcing_binder_transaction"]["status"] = json!("passed");
                }
                report["raw_cross_domain"] = pair;
            }
            let libs = (|| -> io::Result<Value> {
                let dir = std::env::current_exe()?.parent().unwrap().to_owned();
                let manifest: Value =
                    serde_json::from_slice(&fs::read(dir.join("ssal-binder-probe.json"))?)?;
                let source = dir.join("ssal-binder-probe");
                if manifest["header_revision"] != "android-16.0.0_r2"
                    || manifest["helper_sha256"] != super::preflight::digest(&source)?
                {
                    return Err(io::Error::other("Guest libbinder helper manifest mismatch"));
                }
                let mut libraries = Vec::new();
                for name in ["libbinder.so", "libutils.so", "libc++.so"] {
                    let path =
                        crate::guest_mounts::guest_path(root, &format!("system/lib64/{name}"))?;
                    let hash = super::preflight::digest(&path)?;
                    if manifest["guest_library_sha256"][name] != hash {
                        return Err(io::Error::other(format!("Guest library mismatch: {name}")));
                    }
                    libraries.push(json!({"path":format!("/system/lib64/{name}"),"sha256":hash}));
                }
                let mut target = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o755)
                    .open(&lib_helper)?;
                lib_owned = true;
                io::copy(&mut fs::File::open(&source)?, &mut target)?;
                let label = b"u:object_r:servicemanager_exec:s0";
                if unsafe {
                    libc::fsetxattr(
                        target.as_raw_fd(),
                        c"security.selinux".as_ptr(),
                        label.as_ptr().cast(),
                        label.len(),
                        0,
                    )
                } != 0
                    || unsafe { libc::fchown(target.as_raw_fd(), 1000, 1000) } != 0
                {
                    return Err(io::Error::last_os_error());
                }
                drop(target);
                labeled_copy(
                    &source,
                    &root.join("data/local/tmp/ssal-binder-client"),
                    "u:object_r:shell_exec:s0",
                )?;
                Ok(
                    json!({"manifest":manifest,"libraries":libraries,"linker_sha256":super::preflight::digest(&crate::guest_mounts::guest_path(root,"system/bin/linker64")?)?,"exec_label":"u:object_r:servicemanager_exec:s0"}),
                )
            })();
            match libs {
                Ok(libraries) => {
                    report["guest_libraries"] = libraries;
                    let lib = trial(root, identity, "before", "libbinder")?;
                    report["checks"]["guest_libbinder_ipc"] = json!({"status":if lib["success"]==true{"passed"}else{"blocked"},"scope":"separate Guest libbinder helper, actual post-exec credentials and private FD verified; see transaction status_t"});
                    trials.push(lib);
                    if !report["cross_domain_av"]["client_enforcing"]["permissive_domain"]
                        .as_bool()
                        .unwrap_or(true)
                    {
                        let pair = pair_trial(root, identity, true)?;
                        report["checks"]["guest_libbinder_ipc"]["status"] = pair["status"].clone();
                        report["libbinder_cross_domain"] = pair;
                    }
                }
                Err(e) => {
                    report["checks"]["guest_libbinder_ipc"] =
                        json!({"status":"blocked","errno":e.raw_os_error(),"error":e.to_string()})
                }
            }
            let denied = root.join("data/local/tmp/denied-binder");
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o000)
                .open(&denied)?;
            masks.mount(
                denied
                    .to_str()
                    .ok_or_else(|| io::Error::other("deny path"))?,
                &root.join("dev/binder"),
                None,
                libc::MS_BIND,
                "",
            )?;
            let negative = trial(root, identity, "before", "negative")?;
            if negative["success"] != true {
                report["checks"]["host_binder_nonexposure"]["status"] = json!("blocked");
            }
            trials.push(negative);
        }
        report["trials"] = json!(trials);
        report["checks"]["enforcing_binder_transaction"]["evidence"] = json!(
            "raw_cross_domain (positive); trials raw before/after (intentional same-domain denial)"
        );
        report["checks"]["guest_libbinder_ipc"]["evidence"]=json!("libbinder_cross_domain (positive); trials libbinder (same-domain denial control); guest_libraries");
        report["checks"]["host_binder_nonexposure"]["negative_control"] =
            json!("trials engine=negative; no Host open or ioctl");
        Ok(())
    })();
    report["diagnostic_error"] = json!(result.as_ref().err().map(ToString::to_string));
    let lib_cleanup = if lib_owned {
        fs::remove_file(&lib_helper)
    } else {
        Ok(())
    };
    let helper_cleanup = if helper_owned {
        fs::remove_file(&helper)
    } else {
        Ok(())
    };
    let masks_cleanup = masks.cleanup();
    let binder_cleanup = if masks_cleanup.is_ok() {
        binder.cleanup()
    } else {
        Err(io::Error::other("mask cleanup failed"))
    };
    let cleanup = masks_cleanup
        .and(binder_cleanup)
        .and(helper_cleanup)
        .and(lib_cleanup);
    report["checks"]["cleanup"] = json!({"status":if cleanup.is_ok(){"passed"}else{"failed"},"error":cleanup.as_ref().err().map(ToString::to_string),"scope":"probe mounts/FDs/temporary executable; enclosing worker rootfs/loops/scratch must also be verified","recovery_required":cleanup.is_err()});
    let after = host_services();
    let resources_after = host_resources();
    let final_av = query(TARGET, TARGET, "process", "getattr");
    let policy_after = policy_hash();
    let unchanged = after.as_ref().is_ok_and(|v| *v == before)
        && resources_after.as_ref().is_ok_and(|v| *v == resources)
        && context("/sys/fs/selinux/enforce").is_ok_and(|v| v == "1")
        && final_av
            .as_ref()
            .is_ok_and(|v| !v.permissive_domain && v.sequence == initial.sequence)
        && policy_before
            .as_ref()
            .ok()
            .zip(policy_after.as_ref().ok())
            .is_none_or(|(a, b)| a == b);
    report["checks"]["host_unchanged"] = json!({"status":if unchanged{"passed"}else{"failed"},"before":before,"after":after.ok(),"initial_av":initial,"final_av":final_av.ok(),"resources_identical":resources_after.as_ref().is_ok_and(|v|*v==resources),"policy_hash_before":policy_before.as_ref().ok(),"policy_hash_after":policy_after.as_ref().ok(),"policy_hash_error":policy_before.err().map(|e|e.to_string()),"scope":"key process PID/starttime/context, resource metadata/init mountinfo, global enforce and AV sequence; no claim about all intermediate Host state"});
    report["recommendation"] = json!(
        if report["checks"]["enforcing_binder_transaction"]["status"] == "passed"
            && report["checks"]["service_contexts_compatibility"]["status"] == "blocked"
        {
            "최소 SELinux 정책 확장 검토"
        } else {
            "Binder 외 실행 환경 차단 요인 해결 우선"
        }
    );
    println!("Enforcing Binder summary: {report}");
    cleanup?;
    if !unchanged {
        return Err(io::Error::other(
            "RECOVERY_REQUIRED: Host observation changed",
        ));
    }
    result?;
    Err(io::Error::other(
        "fixed experiment complete; Android service launch remains disabled",
    ))
}
