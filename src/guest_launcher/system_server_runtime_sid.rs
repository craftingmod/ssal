//! One diagnostic fork; the pinned runtime terminates after the final setter even without preload.
use super::*;
use sha2::{Digest, Sha256};

pub(super) fn enabled(properties: bool) -> io::Result<bool> {
    let Some(value) = std::env::var_os("SSAL_PHASE8B5_ONCE") else {
        return Ok(false);
    };
    if value != "1"
        || !properties
        || std::env::var_os("SSAL_PHASE7FB_FORK").is_none()
        || [
            "SSAL_PHASE7FC_BYPASS_SETCONTEXT",
            "SSAL_PHASE8B3B_NOOP",
            "SSAL_PHASE8B3D_TRACE",
            "SSAL_PHASE8B3D_SAME_CONTEXT",
            "SSAL_PHASE8B4B1_ONCE",
        ]
        .iter()
        .any(|key| std::env::var_os(key).is_some())
    {
        return Err(io::Error::other(
            "8B-5 requires isolated 7I fork setup without other diagnostic/bypass flags",
        ));
    }
    Err(io::Error::other(
        "8B-5 disabled after device power-off during the first attempt; investigate before re-enabling",
    ))
}

fn checked_runtime(data: &[u8]) -> io::Result<()> {
    // Reconstruct the already pinned SID artifact to validate every other byte too.
    let mut original = data.to_vec();
    if original.get(0x260dd4..0x260dd8) != Some(&0x1400ec67_u32.to_le_bytes()) {
        return Err(io::Error::other("8B-5 independent terminal gate missing"));
    }
    original[0x260dd4..0x260dd8].copy_from_slice(&0x34000560_u32.to_le_bytes());
    if Sha256::digest(&original)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>()
        != "aa9ba993930cdf961c2d2a8e5022a87fca79283688faa8135d414cf7c656a923"
    {
        return Err(io::Error::other("unsupported 8B-5 runtime"));
    }
    Ok(())
}

pub(super) fn prepare(mounts: &mut Mounts, root: &Path, bin: &Path) -> io::Result<()> {
    let evidence = root.parent().unwrap().join("phase8b5");
    fs::create_dir(&evidence)?;
    File::options()
        .create_new(true)
        .write(true)
        .open(evidence.join("consumed"))?;
    if fs::read_link("/proc/self/ns/mnt")? == fs::read_link("/proc/1/ns/mnt")? {
        return Err(io::Error::other("8B-5 requires a distinct mount namespace"));
    }
    ssal::namespace_mounts::require_private_mounts(&fs::read_to_string("/proc/self/mountinfo")?)?;
    checked_runtime(&fs::read(bin.join("runtime-sid-libandroid_runtime.so"))?)?;
    let contexts = fs::read(bin.join("runtime-sid-plat_seapp_contexts"))?;
    if Sha256::digest(&contexts)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>()
        != "5dedabe4fc84cb3344f55bb9e054e92b008fedee847deae7f6f4ad7c7b639d0b"
    {
        return Err(io::Error::other("unsupported Guest seapp contexts"));
    }
    for (source, target) in [
        (
            "runtime-sid-libandroid_runtime.so",
            "system/lib64/libandroid_runtime.so",
        ),
        (
            "runtime-sid-plat_seapp_contexts",
            "system/etc/selinux/plat_seapp_contexts",
        ),
    ] {
        mounts.bind(&bin.join(source), &root.join(target), true, false)?;
    }
    let library = root.join("run/ssal/ssal-system-server-runtime-sid.so");
    File::create(&library)?;
    mounts.bind(
        &bin.join("ssal-system-server-runtime-sid.so"),
        &library,
        true,
        false,
    )?;
    File::options()
        .create_new(true)
        .write(true)
        .open(root.join("run/ssal/runtime-sid.bin"))?
        .set_len(65536)?;
    println!("SSAL_PHASE8B5 admission=PASS private_mounts=true pinned_runtime=true independent_terminal_gate=true");
    Ok(())
}

pub(super) fn run(root: &Path, bin: &Path, env: &[(&str, &str)]) -> io::Result<()> {
    let evidence = root.parent().unwrap().join("phase8b5");
    let canary_report = evidence.join("canary.bin");
    File::options()
        .create_new(true)
        .write(true)
        .open(&canary_report)?
        .set_len(65536)?;
    let child = Command::new(bin.join("ssal-runtime-canary"))
        .arg(&canary_report)
        .env_clear()
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let log = evidence.join("canary.log");
    File::create(&log)?;
    let mut canary = Service {
        child,
        log,
        stopped: false,
        diagnostics: None,
    };
    let deadline = Instant::now() + Duration::from_secs(5);
    while !fs::read(&canary_report)?
        .windows(12)
        .any(|s| s == b"CANARY_READY")
    {
        if canary.exited()? || Instant::now() >= deadline {
            return Err(io::Error::other("disposable canary did not become ready"));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let canary_pid = canary.child.id().to_string();
    let mut env = env.to_vec();
    env.push(("SSAL_RUNTIME_CANARY", &canary_pid));
    let mut zygote = Service::start(
        root,
        "/system/bin/app_process64",
        &[
            "-Xzygote",
            "-XX:ForceJavaZygoteForkLoop=true",
            "/system/bin",
            "--zygote",
            "--start-system-server",
            "--socket-name=zygote",
        ],
        "guest-zygote",
        0,
        Some(GUEST_PROBE_CONTEXT),
        &env,
    )?;
    let deadline = Instant::now() + Duration::from_secs(90);
    let outcome = (|| {
        loop {
            crate::memory_cgroup::check_interrupted()?;
            if let Some(diagnostics) = &mut zygote.diagnostics {
                diagnostics.tick()?;
            }
            let report = fs::read(root.join("run/ssal/runtime-sid.bin"))?;
            if report.windows(12).any(|s| s == b"RUNTIME_SID ") || zygote.exited()? {
                break;
            }
            if Instant::now() >= deadline {
                return Err(io::Error::other("8B-5 Zygote deadline"));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        Ok(())
    })();
    zygote.stop()?;
    let alive = !canary.exited()?;
    let proc_reference = File::open(format!("/proc/{canary_pid}/root")).is_ok();
    println!(
        "SSAL_PHASE8B5 canary_pid={canary_pid} live={alive} parent_proc_root={proc_reference}"
    );
    canary.stop()?;
    let report = fs::read(root.join("run/ssal/runtime-sid.bin"))?;
    let text = String::from_utf8_lossy(&report)
        .trim_end_matches('\0')
        .to_string();
    fs::write(evidence.join("runtime.txt"), &text)?;
    println!(
        "SSAL_PHASE8B5 runtime evidence={}\n{text}",
        evidence.display()
    );
    outcome?;
    // Report success only after the independent terminal path and owned-process cleanup.
    if !alive || !proc_reference || !text.contains("RUNTIME_SID acquired=1 boundary=1 checks=1") {
        return Err(io::Error::other(
            "8B-5 runtime SID/boundary diagnostic incomplete or failed",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ungated_or_corrupt_runtime_is_refused() {
        assert!(checked_runtime(b"bad").is_err());
        let mut fake = vec![0; 0x260dd8];
        fake[0x260dd4..].copy_from_slice(&0x1400ec67_u32.to_le_bytes());
        assert!(checked_runtime(&fake).is_err());
    }
}
