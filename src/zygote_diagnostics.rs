//! Bounded, nonblocking diagnostics owned by the disposable launcher session.
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::{Child, ExitStatus};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const LIMIT: usize = 1024 * 1024;

struct Stream {
    input: Box<dyn Read + Send>,
    output: File,
    seen: u64,
    saved: usize,
}
impl Stream {
    fn new(input: impl Read + AsRawFd + Send + 'static, output: File) -> io::Result<Self> {
        let fd = input.as_raw_fd();
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            input: Box::new(input),
            output,
            seen: 0,
            saved: 0,
        })
    }
    fn drain(&mut self) -> io::Result<()> {
        let mut buffer = [0; 8192];
        // A writer or descendant holding the pipe cannot stall cleanup indefinitely.
        for _ in 0..32 {
            match self.input.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => {
                    self.seen += n as u64;
                    // shortcut: retain the first MiB, add a tail ring if real runs exceed it.
                    let keep = n.min(LIMIT - self.saved);
                    self.output.write_all(&buffer[..keep])?;
                    self.saved += keep;
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

pub(crate) struct Diagnostics {
    stdout: Stream,
    stderr: Stream,
    metadata: File,
    memory: File,
    maps: std::path::PathBuf,
    cgroup: std::path::PathBuf,
    pid: u32,
    started: Instant,
    sample_at: Instant,
}

fn unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn reading(path: impl AsRef<Path>) -> serde_json::Value {
    match fs::read_to_string(path) {
        Ok(value) => serde_json::json!({"value": value}),
        Err(e) => serde_json::json!({"unavailable": e.to_string()}),
    }
}

impl Diagnostics {
    pub(crate) fn prepare(directory: &Path) -> io::Result<()> {
        fs::DirBuilder::new().mode(0o700).create(directory)?;
        Ok(())
    }

    pub(crate) fn attach(
        child: &mut Child,
        directory: &Path,
        cgroup: &Path,
        launch_ms: u128,
        started: Instant,
    ) -> io::Result<Self> {
        let mut result = Self {
            stdout: Stream::new(
                child
                    .stdout
                    .take()
                    .ok_or_else(|| io::Error::other("stdout pipe missing"))?,
                File::create(directory.join("stdout.log"))?,
            )?,
            stderr: Stream::new(
                child
                    .stderr
                    .take()
                    .ok_or_else(|| io::Error::other("stderr pipe missing"))?,
                File::create(directory.join("stderr.log"))?,
            )?,
            metadata: File::create(directory.join("metadata.jsonl"))?,
            memory: File::create(directory.join("memory.jsonl"))?,
            maps: directory.join("process-maps.txt"),
            cgroup: cgroup.to_owned(),
            pid: child.id(),
            started,
            sample_at: Instant::now(),
        };
        writeln!(
            result.metadata,
            "{}",
            serde_json::json!({
                "event": "launch", "unix_ms": launch_ms, "pid": child.id(),
                "cgroup": cgroup, "stream_limit_bytes": LIMIT,
                "native_capture": "Guest-only abort interposer + SIGSEGV ucontext/maps/bounded stack/FP capture + liblog stderr logger; offline symbolization",
                "host_debuggerd_tombstoned": "unchanged; not connected",
            })
        )?;
        result.sample(true)?;
        Ok(result)
    }

    pub(crate) fn tick(&mut self) -> io::Result<()> {
        self.stdout.drain()?;
        self.stderr.drain()?;
        if self.sample_at.elapsed() >= Duration::from_millis(250) {
            self.sample(true)?;
        }
        Ok(())
    }

    fn sample(&mut self, process_owned: bool) -> io::Result<()> {
        self.sample_at = Instant::now();
        if self.memory.metadata()?.len() >= (8 * LIMIT) as u64 {
            return Ok(());
        }
        if process_owned {
            if let Ok(mut source) = File::open(format!("/proc/{}/maps", self.pid)) {
                let mut maps = Vec::new();
                Read::by_ref(&mut source)
                    .take(LIMIT as u64)
                    .read_to_end(&mut maps)?;
                if !maps.is_empty() {
                    fs::write(&self.maps, maps)?;
                }
            }
        }
        let mut values = serde_json::Map::new();
        for name in [
            "cgroup.controllers",
            "cgroup.subtree_control",
            "cgroup.procs",
            "memory.current",
            "memory.peak",
            "memory.max",
            "memory.high",
            "memory.events",
            "memory.events.local",
            "memory.stat",
            "memory.pressure",
        ] {
            values.insert(name.into(), reading(self.cgroup.join(name)));
        }
        writeln!(
            self.memory,
            "{}",
            serde_json::json!({
                "unix_ms": unix_ms(), "elapsed_ms": self.started.elapsed().as_millis(),
                "pid": self.pid, "guest": values,
                "host_pressure": reading("/proc/pressure/memory"),
                "host_meminfo": reading("/proc/meminfo"),
                "process_cgroup": if process_owned { reading(format!("/proc/{}/cgroup", self.pid)) } else { serde_json::Value::Null },
                "process_status": if process_owned { reading(format!("/proc/{}/status", self.pid)) } else { serde_json::Value::Null },
            })
        )?;
        self.sample_at = Instant::now();
        Ok(())
    }

    pub(crate) fn finish(&mut self, status: ExitStatus) -> io::Result<()> {
        self.stdout.drain()?;
        self.stderr.drain()?;
        // The reaped PID may already belong to another process.
        self.sample(false)?;
        writeln!(
            self.metadata,
            "{}",
            serde_json::json!({
                "event": "exit", "unix_ms": unix_ms(), "elapsed_ms": self.started.elapsed().as_millis(),
                "pid": self.pid, "raw_status": status.into_raw(), "exit_code": status.code(),
                "signal": status.signal(), "core_dumped": status.core_dumped(),
                "stdout_bytes_drained": self.stdout.seen, "stdout_bytes_saved": self.stdout.saved,
                "stderr_bytes_drained": self.stderr.seen, "stderr_bytes_saved": self.stderr.saved,
                "memory_log_capped": self.memory.metadata()?.len() >= (8 * LIMIT) as u64,
                "tail_may_be_incomplete": true,
            })
        )?;
        Ok(())
    }
}

pub(crate) fn launch_time() -> u128 {
    unix_ms()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};

    #[test]
    fn pipes_are_bounded_reaped_and_record_signal_without_controller() -> io::Result<()> {
        let dir = std::env::temp_dir().join(format!("ssal-7b-{}", std::process::id()));
        Diagnostics::prepare(&dir)?;
        let mut child = Command::new("/bin/sh")
            .args([
                "-c",
                "ulimit -c 0; head -c 1200000 /dev/zero; printf 'ART fatal test\\n' >&2; kill -ABRT $$",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let mut diag = Diagnostics::attach(
            &mut child,
            &dir,
            &dir.join("absent"),
            unix_ms(),
            Instant::now(),
        )?;
        let deadline = Instant::now() + Duration::from_secs(10);
        let status = loop {
            diag.tick()?;
            if let Some(status) = child.try_wait()? {
                break status;
            }
            if Instant::now() > deadline {
                child.kill()?;
                child.wait()?;
                panic!("pipe deadlock");
            }
            std::thread::sleep(Duration::from_millis(1));
        };
        diag.finish(status)?;
        assert_eq!(status.signal(), Some(libc::SIGABRT));
        assert_eq!(fs::metadata(dir.join("stdout.log"))?.len(), LIMIT as u64);
        assert!(fs::read_to_string(dir.join("stderr.log"))?.contains("ART fatal test"));
        let events = fs::read_to_string(dir.join("metadata.jsonl"))?;
        let exit: serde_json::Value = serde_json::from_str(events.lines().last().unwrap())?;
        assert_eq!(exit["signal"], libc::SIGABRT);
        assert_eq!(exit["stdout_bytes_drained"], 1200000);
        assert!(fs::read_to_string(dir.join("memory.jsonl"))?.contains("unavailable"));
        drop(diag);
        fs::remove_dir_all(dir)?;
        Ok(())
    }

    #[test]
    fn inherited_writer_cannot_block_final_drain_and_exit_code_is_preserved() -> io::Result<()> {
        let dir = std::env::temp_dir().join(format!("ssal-7b-writer-{}", std::process::id()));
        Diagnostics::prepare(&dir)?;
        let mut command = Command::new("/bin/sh");
        command
            .args([
                "-c",
                "sleep 30 & printf 'stdout marker'; printf 'stderr marker' >&2; exit 23",
            ])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        unsafe {
            use std::os::unix::process::CommandExt;
            command.pre_exec(|| {
                if libc::setsid() < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = command.spawn()?;
        let mut diag = Diagnostics::attach(
            &mut child,
            &dir,
            &dir.join("absent"),
            unix_ms(),
            Instant::now(),
        )?;
        let status = child.wait()?;
        let started = Instant::now();
        let result = diag.finish(status);
        // The owned test group includes the inherited pipe writer, even after leader exit.
        unsafe {
            libc::kill(-(child.id() as i32), libc::SIGKILL);
        }
        result?;
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_eq!(status.code(), Some(23));
        let events = fs::read_to_string(dir.join("metadata.jsonl"))?;
        let exit: serde_json::Value = serde_json::from_str(events.lines().last().unwrap())?;
        assert_eq!(exit["exit_code"], 23);
        assert!(exit["signal"].is_null());
        assert_eq!(fs::read_to_string(dir.join("stdout.log"))?, "stdout marker");
        assert_eq!(fs::read_to_string(dir.join("stderr.log"))?, "stderr marker");
        drop(diag);
        fs::remove_dir_all(dir)?;
        Ok(())
    }
}
