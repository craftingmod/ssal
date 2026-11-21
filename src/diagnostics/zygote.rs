//! Bounded, nonblocking diagnostics owned by the disposable launcher session.
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::{Child, ExitStatus};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex, OnceLock, Weak,
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const LIMIT: usize = 1024 * 1024;
const SESSION_LOG_LIMIT: u64 = 100 * 1024 * 1024;
static SESSION_LOG: OnceLock<File> = OnceLock::new();
static SESSION_LOG_BYTES: AtomicU64 = AtomicU64::new(0);
static DRAINER: OnceLock<LogDrainer> = OnceLock::new();

struct LogDrainer {
    epoll_fd: RawFd,
    streams: Arc<Mutex<HashMap<RawFd, Weak<Mutex<StreamState>>>>>,
}

impl LogDrainer {
    fn global() -> io::Result<&'static Self> {
        if let Some(drainer) = DRAINER.get() {
            return Ok(drainer);
        }
        let epoll_fd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
        if epoll_fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let streams: Arc<Mutex<HashMap<RawFd, Weak<Mutex<StreamState>>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let worker_streams = Arc::clone(&streams);
        std::thread::Builder::new()
            .name("ssal-log-drain".into())
            .spawn(move || Self::run(epoll_fd, worker_streams))
            .map_err(|err| {
                unsafe { libc::close(epoll_fd) };
                err
            })?;
        let drainer = Self { epoll_fd, streams };
        if DRAINER.set(drainer).is_err() {
            unsafe { libc::close(epoll_fd) };
        }
        Ok(DRAINER.get().expect("drainer initialized"))
    }

    fn register(&self, fd: RawFd, state: &Arc<Mutex<StreamState>>) -> io::Result<()> {
        let mut streams = self
            .streams
            .lock()
            .map_err(|_| io::Error::other("log drainer lock poisoned"))?;
        streams.insert(fd, Arc::downgrade(state));
        let mut event = libc::epoll_event {
            events: libc::EPOLLIN as u32,
            u64: fd as u64,
        };
        if unsafe { libc::epoll_ctl(self.epoll_fd, libc::EPOLL_CTL_ADD, fd, &mut event) } < 0 {
            streams.remove(&fd);
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn unregister(&self, fd: RawFd) {
        if let Ok(mut streams) = self.streams.lock() {
            streams.remove(&fd);
        }
        unsafe {
            libc::epoll_ctl(self.epoll_fd, libc::EPOLL_CTL_DEL, fd, std::ptr::null_mut());
        }
    }

    fn run(epoll_fd: RawFd, streams: Arc<Mutex<HashMap<RawFd, Weak<Mutex<StreamState>>>>>) {
        let mut events = [libc::epoll_event { events: 0, u64: 0 }; 64];
        loop {
            let n = unsafe {
                libc::epoll_wait(epoll_fd, events.as_mut_ptr(), events.len() as i32, -1)
            };
            if n < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                break;
            }
            for event in &events[..n as usize] {
                let fd = event.u64 as RawFd;
                let weak = streams
                    .lock()
                    .ok()
                    .and_then(|map| map.get(&fd).cloned());
                let Some(weak) = weak else {
                    unsafe {
                        libc::epoll_ctl(epoll_fd, libc::EPOLL_CTL_DEL, fd, std::ptr::null_mut());
                    }
                    continue;
                };
                let Some(state_arc) = weak.upgrade() else {
                    if let Ok(mut map) = streams.lock() {
                        map.remove(&fd);
                    }
                    unsafe {
                        libc::epoll_ctl(epoll_fd, libc::EPOLL_CTL_DEL, fd, std::ptr::null_mut());
                    }
                    continue;
                };
                let done = match state_arc.lock() {
                    Ok(mut state) => {
                        let _ = state.drain_nonblocking();
                        state.eof
                    }
                    Err(_) => true,
                };
                if done {
                    if let Ok(mut map) = streams.lock() {
                        if map.get(&fd).is_some_and(|w| w.ptr_eq(&weak)) {
                            map.remove(&fd);
                        }
                    }
                    unsafe {
                        libc::epoll_ctl(epoll_fd, libc::EPOLL_CTL_DEL, fd, std::ptr::null_mut());
                    }
                }
            }
        }
    }
}

pub(crate) fn open_session_log(base: &Path) -> io::Result<()> {
    let file = match File::options()
        .append(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(base.join("logcat"))
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    SESSION_LOG
        .set(file)
        .map_err(|_| io::Error::other("Guest logcat already open"))
}

struct StreamState {
    input: Box<dyn Read + Send>,
    output: File,
    seen: u64,
    saved: usize,
    limit: usize,
    session_log: Option<&'static File>,
    eof: bool,
}

impl StreamState {
    fn drain_nonblocking(&mut self) -> io::Result<()> {
        if self.eof {
            return Ok(());
        }
        let mut buffer = [0; 8192];
        // A writer or descendant holding the pipe cannot stall cleanup indefinitely.
        for _ in 0..32 {
            match self.input.read(&mut buffer) {
                Ok(0) => {
                    self.eof = true;
                    break;
                }
                Ok(n) => {
                    self.seen += n as u64;
                    // shortcut: keep the first bytes, add a tail ring if boot exceeds the cap.
                    let keep = n.min(self.limit.saturating_sub(self.saved));
                    self.output.write_all(&buffer[..keep])?;
                    self.saved += keep;
                    if let Some(mut log) = self.session_log {
                        let written = SESSION_LOG_BYTES.load(Ordering::Relaxed);
                        let keep_session =
                            n.min(SESSION_LOG_LIMIT.saturating_sub(written) as usize);
                        if keep_session > 0 {
                            if log.write_all(&buffer[..keep_session]).is_err() {
                                self.session_log = None;
                            } else {
                                SESSION_LOG_BYTES
                                    .fetch_add(keep_session as u64, Ordering::Relaxed);
                            }
                        }
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    self.eof = true;
                    return Err(e);
                }
            }
        }
        Ok(())
    }
}

pub(crate) struct Stream {
    state: Arc<Mutex<StreamState>>,
    fd: RawFd,
}
impl Stream {
    pub(crate) fn new(
        input: impl Read + AsRawFd + Send + 'static,
        output: File,
    ) -> io::Result<Self> {
        let fd = input.as_raw_fd();
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let state = Arc::new(Mutex::new(StreamState {
            input: Box::new(input),
            output,
            seen: 0,
            saved: 0,
            limit: LIMIT,
            session_log: None,
            eof: false,
        }));
        LogDrainer::global()?.register(fd, &state)?;
        Ok(Self { state, fd })
    }

    pub(crate) fn with_session_log(self) -> Self {
        if let Ok(mut state) = self.state.lock() {
            state.session_log = SESSION_LOG.get();
        }
        self
    }

    pub(crate) fn set_limit(&mut self, limit: usize) {
        if let Ok(mut state) = self.state.lock() {
            state.limit = limit;
        }
    }

    pub(crate) fn seen(&self) -> u64 {
        self.state.lock().map_or(0, |s| s.seen)
    }

    pub(crate) fn saved(&self) -> usize {
        self.state.lock().map_or(0, |s| s.saved)
    }

    pub(crate) fn drain(&mut self) -> io::Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("stream lock poisoned"))?;
        state.drain_nonblocking()
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        if let Some(drainer) = DRAINER.get() {
            drainer.unregister(self.fd);
        }
        if let Ok(mut state) = self.state.lock() {
            let _ = state.drain_nonblocking();
        }
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
        stderr_limit: Option<usize>,
    ) -> io::Result<Self> {
        let mut result = Self {
            stdout: Stream::new(
                child
                    .stdout
                    .take()
                    .ok_or_else(|| io::Error::other("stdout pipe missing"))?,
                File::create(directory.join("stdout.log"))?,
            )?
            .with_session_log(),
            stderr: Stream::new(
                child
                    .stderr
                    .take()
                    .ok_or_else(|| io::Error::other("stderr pipe missing"))?,
                File::create(directory.join("stderr.log"))?,
            )?
            .with_session_log(),
            metadata: File::create(directory.join("metadata.jsonl"))?,
            memory: File::create(directory.join("memory.jsonl"))?,
            maps: directory.join("process-maps.txt"),
            cgroup: cgroup.to_owned(),
            pid: child.id(),
            started,
            sample_at: Instant::now(),
        };
        let stderr_cap = stderr_limit.unwrap_or(LIMIT);
        result.stderr.set_limit(stderr_cap);
        writeln!(
            result.metadata,
            "{}",
            serde_json::json!({
                "event": "launch", "unix_ms": launch_ms, "pid": child.id(),
                "cgroup": cgroup, "stream_limit_bytes": LIMIT, "stderr_limit_bytes": stderr_cap,
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
            "memory.usage_in_bytes",
            "memory.limit_in_bytes",
            "memory.soft_limit_in_bytes",
            "memory.failcnt",
            "memory.oom_control",
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
                "stdout_bytes_drained": self.stdout.seen(), "stdout_bytes_saved": self.stdout.saved(),
                "stderr_bytes_drained": self.stderr.seen(), "stderr_bytes_saved": self.stderr.saved(),
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
            None,
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
            None,
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

    #[test]
    fn stream_drains_continuously_without_manual_polling() -> io::Result<()> {
        let dir = std::env::temp_dir().join(format!("ssal-drain-{}", std::process::id()));
        fs::create_dir_all(&dir)?;
        let log_path = dir.join("service.log");
        let mut child = Command::new("/bin/sh")
            .args(["-c", "head -c 262144 /dev/zero"])
            .stdout(Stdio::piped())
            .spawn()?;
        let stream = Stream::new(
            child.stdout.take().unwrap(),
            File::create(&log_path)?,
        )?;
        let status = child.wait()?;
        assert!(status.success());
        drop(stream);
        assert_eq!(fs::metadata(&log_path)?.len(), 262144);
        fs::remove_dir_all(dir)?;
        Ok(())
    }
}
