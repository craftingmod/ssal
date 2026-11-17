use crate::guest::cgroup::{change, has_memory, read, require, Hierarchy};
use std::fs;
use std::io;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

const ROOT: &str = "/sys/fs/cgroup";
const HIGH: u64 = 24 * 1024 * 1024;
const MAX: u64 = 32 * 1024 * 1024;
static INTERRUPTED: AtomicBool = AtomicBool::new(false);
extern "C" fn interrupted(_: libc::c_int) {
    INTERRUPTED.store(true, Ordering::Relaxed);
}

struct OwnedChild(Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn event(text: &str, name: &str) -> io::Result<u64> {
    text.lines()
        .find_map(|line| {
            let (key, value) = line.split_once(' ')?;
            (key == name).then(|| value.parse::<u64>().ok()).flatten()
        })
        .ok_or_else(|| io::Error::other(format!("missing event {name}")))
}

fn allocate() -> io::Result<()> {
    println!(
        "allocator pid={} membership={}",
        std::process::id(),
        read("/proc/self/cgroup")?
    );
    unsafe {
        libc::raise(libc::SIGSTOP);
    }
    // Bound the attempted allocation even if a broken controller fails to kill it.
    let bytes = 64 * 1024 * 1024;
    let p = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            bytes,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if p == libc::MAP_FAILED {
        return Err(io::Error::last_os_error());
    }
    for offset in (0..bytes).step_by(4096) {
        unsafe {
            (p as *mut u8).add(offset).write_volatile(1);
        }
    }
    unsafe {
        libc::munmap(p, bytes);
    }
    Err(io::Error::other(
        "allocator survived 64 MiB: memory.max was not demonstrated",
    ))
}

fn exercise(group: &Path, directory: &Path) -> io::Result<()> {
    for (file, value) in [
        ("memory.high", HIGH.to_string()),
        ("memory.max", MAX.to_string()),
        ("memory.swap.max", "0".into()),
    ] {
        change(group.join(file), &value)?;
        require(
            read(group.join(file))? == value,
            "Guest memory limit readback mismatch",
        )?;
    }
    require(
        read(group.join("cgroup.procs"))?.is_empty(),
        "Guest leaf not empty before spawn",
    )?;
    let before = read(group.join("memory.events"))?;
    let mut command = Command::new(std::env::current_exe()?);
    command
        .arg("--allocate")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let membership = fs::OpenOptions::new()
        .write(true)
        .open(group.join("cgroup.procs"))?;
    use std::os::fd::AsRawFd;
    let fd = membership.as_raw_fd();
    unsafe {
        command.pre_exec(move || {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                return Err(io::Error::last_os_error());
            }
            // cgroup.procs accepts zero for the caller; join before exec and any allocation.
            if libc::write(fd, b"0".as_ptr().cast(), 1) != 1 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let started = Instant::now();
    let launch_ms = crate::diagnostics::zygote::launch_time();
    let mut child = OwnedChild(command.spawn()?);
    drop(membership);
    let mut diagnostics = crate::diagnostics::zygote::Diagnostics::attach(
        &mut child.0,
        directory,
        group,
        launch_ms,
        started,
    )?;
    // Bounded wait for the stopped allocator; no external PID is ever moved or killed.
    loop {
        require(!INTERRUPTED.load(Ordering::Relaxed), "probe interrupted")?;
        // Keep all reaping in Child so its cached status prevents a reused-PID kill.
        require(
            child.0.try_wait()?.is_none(),
            "allocator exited before membership verification",
        )?;
        let status = read(format!("/proc/{}/status", child.0.id()))?;
        if status
            .lines()
            .any(|line| line.starts_with("State:") && line.split_whitespace().nth(1) == Some("T"))
        {
            break;
        }
        require(
            started.elapsed() < Duration::from_secs(3),
            "allocator stop timeout",
        )?;
        std::thread::sleep(Duration::from_millis(10));
    }
    let pid = child.0.id().to_string();
    require(
        read(group.join("cgroup.procs"))? == pid,
        "Guest leaf contains a process other than owned allocator",
    )?;
    let expected = format!("0::/{}", group.file_name().unwrap().to_str().unwrap());
    require(
        read(format!("/proc/{pid}/cgroup"))?
            .lines()
            .any(|line| line == expected),
        "allocator membership mismatch",
    )?;
    println!(
        "MEMBERSHIP PASS: only owned allocator {pid}; parent={}",
        read("/proc/self/cgroup")?
    );
    require(
        unsafe { libc::kill(child.0.id() as i32, libc::SIGCONT) } == 0,
        "resume allocator failed",
    )?;
    let mut high_observed = false;
    let status = loop {
        require(!INTERRUPTED.load(Ordering::Relaxed), "probe interrupted")?;
        diagnostics.tick()?;
        if let Some(status) = child.0.try_wait()? {
            break status;
        }
        if !high_observed
            && event(&read(group.join("memory.events"))?, "high")? > event(&before, "high")?
        {
            high_observed = true;
            // Throttling can prevent reaching max: release high only after proving its event.
            change(group.join("memory.high"), &MAX.to_string())?;
            require(
                read(group.join("memory.high"))? == MAX.to_string(),
                "OOM-stage high readback",
            )?;
            println!("HIGH_STAGE PASS; high raised to max for bounded OOM-stage test");
        }
        if started.elapsed() >= Duration::from_secs(5) {
            child.0.kill()?;
            let status = child.0.wait()?;
            diagnostics.finish(status)?;
            return Err(io::Error::other(
                "allocator limit timeout; owned child killed and diagnostics finalized",
            ));
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    diagnostics.finish(status)?;
    require(high_observed, "high throttling stage was not observed")?;
    let after = read(group.join("memory.events"))?;
    println!("allocator status={status}; events before={before:?} after={after:?}");
    require(
        status.signal() == Some(libc::SIGKILL),
        "expected memcg OOM SIGKILL",
    )?;
    for name in ["high", "max", "oom", "oom_kill"] {
        require(
            event(&after, name)? > event(&before, name)?,
            &format!("no {name} event delta"),
        )?;
    }
    require(
        read(group.join("cgroup.procs"))?.is_empty(),
        "Guest membership not empty after reap",
    )?;
    println!("PASS: memory.high throttled; memory.max caused local OOM kill; Guest empty");
    Ok(())
}

fn run(directory: &Path) -> io::Result<()> {
    unsafe {
        libc::signal(
            libc::SIGTERM,
            interrupted as *const () as libc::sighandler_t,
        );
        libc::signal(libc::SIGINT, interrupted as *const () as libc::sighandler_t);
        libc::signal(libc::SIGHUP, interrupted as *const () as libc::sighandler_t);
    }
    require(
        read("/sys/fs/selinux/enforce")? == "1",
        "Host must remain Enforcing",
    )?;
    require(
        fs::canonicalize(ROOT)? == Path::new(ROOT),
        "cgroup root contains symlink",
    )?;
    use std::os::unix::ffi::OsStrExt;
    let root = std::ffi::CString::new(Path::new(ROOT).as_os_str().as_bytes()).unwrap();
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    require(
        unsafe { libc::statfs(root.as_ptr(), &mut stat) } == 0 && stat.f_type as u64 == 0x63677270,
        "expected cgroup2 mount",
    )?;
    require(
        has_memory(&read(format!("{ROOT}/cgroup.controllers"))?),
        "root memory controller unavailable",
    )?;
    require(
        read(format!("{ROOT}/cgroup.subtree_control"))?.is_empty(),
        "probe only supports initially empty root subtree_control",
    )?;
    let available = read("/proc/meminfo")?
        .lines()
        .find_map(|l| {
            l.strip_prefix("MemAvailable:")?
                .split_whitespace()
                .next()?
                .parse::<u64>()
                .ok()
        })
        .unwrap_or(0);
    require(
        available >= 512 * 1024,
        "less than 512 MiB available; defer test",
    )?;
    crate::diagnostics::zygote::Diagnostics::prepare(directory)?;
    let mut hierarchy = Hierarchy {
        leaf: Path::new(ROOT).join(format!("ssal_memory_7c_{}", std::process::id())),
        created: false,
        enabled: false,
    };
    // Prove the shared-ancestor change can be reversed before creating a Guest or limit.
    hierarchy.enable()?;
    hierarchy.cleanup()?;
    println!("ANCESTOR_ROUNDTRIP PASS: +memory/-memory; no Host limits or membership writes");
    hierarchy.enable()?;
    fs::create_dir(&hierarchy.leaf)?;
    hierarchy.created = true;
    let result = exercise(&hierarchy.leaf, directory);
    let cleanup = hierarchy.cleanup();
    result?;
    cleanup?;
    require(
        read("/sys/fs/selinux/enforce")? == "1",
        "Host Enforcing changed",
    )?;
    println!("CLEANUP PASS: Guest removed; root subtree_control restored empty");
    Ok(())
}
#[allow(dead_code)]
pub(crate) fn entrypoint() -> io::Result<()> {
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() == 2 && args[1] == "--allocate" {
        return allocate();
    }
    require(
        args.len() == 2,
        "usage: ssal-memory-probe NEW_DIAGNOSTIC_DIRECTORY",
    )?;
    run(Path::new(&args[1]))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_controller_and_event_parsing() {
        assert!(has_memory("cpu memory\n"));
        assert!(!has_memory("memory_recursiveprot"));
        assert_eq!(
            event("high 2\nmax 3\noom 1\noom_kill 1", "oom_kill").unwrap(),
            1
        );
        assert!(event("oom 1", "oom_kill").is_err());
        assert!(event("max invalid", "max").is_err());
        assert!(HIGH < MAX && MAX < 64 * 1024 * 1024);
    }
}
