//! Fixed-target transition probe. It never changes SELinux policy or labels.
const TARGET: &str = "u:r:ssal_guest_probe:s0";

#[derive(Debug, PartialEq)]
enum Mode<'a> {
    DryRun,
    Control { helper: &'a str, sha256: &'a str },
    Run { helper: &'a str, sha256: &'a str },
    BareControl { helper: &'a str, sha256: &'a str },
    BareRun { helper: &'a str, sha256: &'a str },
    BarePtraceControl { helper: &'a str, sha256: &'a str },
    BarePtraceRun { helper: &'a str, sha256: &'a str },
}
fn parse_args(args: &[String]) -> Result<Mode<'_>, &'static str> {
    if args.is_empty() || args == ["--dry-run"] {
        return Ok(Mode::DryRun);
    }
    if args.len() == 4
        && [
            "--run-after-approval",
            "--control",
            "--bare-transition",
            "--bare-control",
            "--bare-ptrace-transition",
            "--bare-ptrace-control",
        ]
        .contains(&args[0].as_str())
        && !args[1].starts_with('-')
        && args[2] == "--sha256"
        && args[3].len() == 64
        && args[3].bytes().all(|b| b.is_ascii_hexdigit())
    {
        let mode = match args[0].as_str() {
            "--control" => Mode::Control {
                helper: &args[1],
                sha256: &args[3],
            },
            "--run-after-approval" => Mode::Run {
                helper: &args[1],
                sha256: &args[3],
            },
            "--bare-control" => Mode::BareControl {
                helper: &args[1],
                sha256: &args[3],
            },
            "--bare-ptrace-control" => Mode::BarePtraceControl {
                helper: &args[1],
                sha256: &args[3],
            },
            "--bare-ptrace-transition" => Mode::BarePtraceRun {
                helper: &args[1],
                sha256: &args[3],
            },
            _ => Mode::BareRun {
                helper: &args[1],
                sha256: &args[3],
            },
        };
        return Ok(mode);
    }
    Err("usage: --control|--run-after-approval|--bare-control|--bare-transition|--bare-ptrace-control|--bare-ptrace-transition /path --sha256 HASH")
}
#[cfg(any(unix, test))]
fn target_state_allowed(permissive: bool) -> bool {
    !permissive
}

#[cfg(any(unix, test))]
fn write_access_request<W: std::io::Write>(
    writer: &mut W,
    source: &str,
    target: &str,
    index: u32,
    mask: u32,
) -> std::io::Result<()> {
    let request = format!("{source} {target} {index} {mask:x}");
    let n = writer.write(request.as_bytes())?;
    if n != request.len() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::WriteZero,
            "short SELinux access transaction",
        ));
    }
    Ok(())
}

const TRACE_CHILD: u32 = 1;
const TRACE_STDIN_OPEN: u32 = 2;
const TRACE_STDOUT: u32 = 3;
const TRACE_STDERR: u32 = 4;
const TRACE_FD_FLAGS: u32 = 5;
const TRACE_SETEXEC_OPEN: u32 = 6;
const TRACE_SETEXEC_WRITE: u32 = 7;
const TRACE_EXECVEAT_ENTERED: u32 = 8;
const TRACE_EXECVEAT_RETURNED: u32 = 9;
const TRACE_REPORTER_MAIN: u32 = 10;
const TRACE_STDIN_DUP: u32 = 11;
const TRACE_PTRACE_TRACEME: u32 = 12;
const TRACE_PTRACE_STOP: u32 = 13;

#[repr(C)]
#[derive(Clone, Copy)]
struct TraceEvent {
    stage: u32,
    errno: i32,
}

fn trace_stage_name(stage: u32) -> &'static str {
    match stage {
        TRACE_CHILD => "child_started",
        TRACE_STDIN_OPEN => "open_stdin",
        TRACE_STDIN_DUP => "dup2_stdin",
        TRACE_STDOUT => "dup2_stdout",
        TRACE_STDERR => "dup2_stderr",
        TRACE_FD_FLAGS => "fcntl_cloexec",
        TRACE_SETEXEC_OPEN => "setexec_open",
        TRACE_SETEXEC_WRITE => "setexec_write",
        TRACE_EXECVEAT_ENTERED => "execveat_entered",
        TRACE_EXECVEAT_RETURNED => "execveat_returned",
        TRACE_REPORTER_MAIN => "reporter_main",
        TRACE_PTRACE_TRACEME => "ptrace_traceme",
        TRACE_PTRACE_STOP => "ptrace_initial_stop",
        _ => "unknown",
    }
}

fn trace_syscall_name(stage: u32) -> &'static str {
    match stage {
        TRACE_STDIN_OPEN => "open",
        TRACE_STDIN_DUP => "dup2",
        TRACE_STDOUT | TRACE_STDERR => "dup2",
        TRACE_FD_FLAGS => "fcntl",
        TRACE_SETEXEC_OPEN => "open",
        TRACE_SETEXEC_WRITE => "write",
        TRACE_PTRACE_TRACEME => "ptrace",
        TRACE_PTRACE_STOP => "kill",
        TRACE_EXECVEAT_RETURNED => "execveat",
        _ => "none",
    }
}

fn decode_trace_events(bytes: &[u8]) -> Result<Vec<TraceEvent>, &'static str> {
    if bytes.len() % std::mem::size_of::<TraceEvent>() != 0 {
        return Err("truncated child trace record");
    }
    Ok(bytes
        .chunks_exact(std::mem::size_of::<TraceEvent>())
        .map(|chunk| TraceEvent {
            stage: u32::from_ne_bytes(chunk[..4].try_into().unwrap()),
            errno: i32::from_ne_bytes(chunk[4..8].try_into().unwrap()),
        })
        .collect())
}

fn bare_output_matches_context(output: &str, context: &str) -> bool {
    output == format!("BARE_ENTRY\ncontext={context}\0\n")
}

fn bare_exit_probe_succeeded(status: i32, output: &str) -> bool {
    status == (42 << 8) && output.is_empty()
}

fn ptrace_wait_stop(status: i32) -> Option<(i32, u32)> {
    (status & 0xff == 0x7f).then_some(((status >> 8) & 0xff, (status as u32) >> 16))
}

fn decode_siginfo(raw: &[u8; 128]) -> (i32, u64) {
    (
        i32::from_ne_bytes(raw[8..12].try_into().unwrap()),
        u64::from_ne_bytes(raw[16..24].try_into().unwrap()),
    )
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match parse_args(&args) {
        Ok(Mode::DryRun) => {
            println!("dry-run: target={TARGET}; policy=unchanged; exec=not_run; default=enforcing; diagnostic=off");
            return;
        }
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2);
        }
        Ok(
            Mode::Control { .. }
            | Mode::Run { .. }
            | Mode::BareControl { .. }
            | Mode::BareRun { .. }
            | Mode::BarePtraceControl { .. }
            | Mode::BarePtraceRun { .. },
        ) => {}
    }
    #[cfg(unix)]
    if let Err(e) = unix::run(&args) {
        eprintln!("blocked or failed: {e}");
        std::process::exit(1);
    }
    #[cfg(not(unix))]
    {
        eprintln!("device execution requires Android/Linux; no action performed");
        std::process::exit(2);
    }
}

#[cfg(unix)]
mod unix {
    use super::{
        bare_exit_probe_succeeded, bare_output_matches_context, decode_siginfo,
        decode_trace_events, parse_args, ptrace_wait_stop, target_state_allowed, trace_stage_name,
        trace_syscall_name, write_access_request, Mode, TraceEvent, TARGET, TRACE_CHILD,
        TRACE_EXECVEAT_ENTERED, TRACE_EXECVEAT_RETURNED, TRACE_FD_FLAGS, TRACE_PTRACE_STOP,
        TRACE_PTRACE_TRACEME, TRACE_REPORTER_MAIN, TRACE_SETEXEC_OPEN, TRACE_SETEXEC_WRITE,
        TRACE_STDERR, TRACE_STDIN_DUP, TRACE_STDIN_OPEN, TRACE_STDOUT,
    };
    use std::{
        ffi::CString,
        fs::{self, File, OpenOptions},
        io::{self, Read},
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::fs::{FileExt, MetadataExt},
        },
        time::{Duration, Instant},
    };

    const PTRACE_TRACEME: libc::c_int = 0;
    const PTRACE_CONT: libc::c_int = 7;
    const PTRACE_SETOPTIONS: libc::c_int = 0x4200;
    const PTRACE_GETSIGINFO: libc::c_int = 0x4202;
    const PTRACE_GETREGSET: libc::c_int = 0x4204;
    const PTRACE_O_TRACEEXEC: usize = 0x10;
    const PTRACE_EVENT_EXEC: u32 = 4;
    const NT_PRSTATUS: usize = 1;

    fn read(path: &str) -> io::Result<String> {
        Ok(fs::read_to_string(path)?.trim_matches('\0').trim().into())
    }
    fn decision(
        source: &str,
        target: &str,
        class: &str,
        permission: &str,
    ) -> io::Result<(bool, bool, u32)> {
        let base = format!("/sys/fs/selinux/class/{class}");
        let idx: u32 = read(&format!("{base}/index"))?
            .parse()
            .map_err(io::Error::other)?;
        let bit: u32 = read(&format!("{base}/perms/{permission}"))?
            .parse()
            .map_err(io::Error::other)?;
        let mask = bit
            .checked_sub(1)
            .and_then(|b| 1u32.checked_shl(b))
            .ok_or_else(|| io::Error::other("invalid permission bit"))?;
        let mut f = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/sys/fs/selinux/access")?;
        write_access_request(&mut f, source, target, idx, mask)?;
        let mut s = String::new();
        f.read_to_string(&mut s)?;
        let a: Vec<_> = s.split_whitespace().collect();
        if a.len() != 6 {
            return Err(io::Error::other("invalid AV response"));
        }
        let hex = |x: &str| u32::from_str_radix(x, 16).map_err(io::Error::other);
        let allowed = hex(a[0])?;
        if hex(a[1])? & mask != mask {
            return Err(io::Error::other("undecided AV"));
        }
        let flags = hex(a[5])?;
        let seq = a[4].parse().map_err(io::Error::other)?;
        println!(
            "AV {source} {target} {class}:{permission} allowed={} flags={flags} sequence={seq}",
            allowed & mask == mask
        );
        Ok((allowed & mask == mask, flags & 1 != 0, seq))
    }
    fn label(f: &File) -> io::Result<String> {
        let mut b = [0u8; 512];
        let n = unsafe {
            libc::fgetxattr(
                f.as_raw_fd(),
                c"security.selinux".as_ptr(),
                b.as_mut_ptr().cast(),
                b.len(),
            )
        };
        if n <= 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(std::str::from_utf8(&b[..n as usize])
            .map_err(io::Error::other)?
            .trim_matches('\0')
            .into())
    }
    fn file_hash(f: &File) -> io::Result<String> {
        use sha2::{Digest, Sha256};
        let mut digest = Sha256::new();
        let mut buf = [0u8; 65536];
        let mut offset = 0u64;
        loop {
            let n = f.read_at(&mut buf, offset)?;
            if n == 0 {
                break;
            }
            digest.update(&buf[..n]);
            offset += n as u64;
        }
        Ok(digest
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect())
    }

    fn pipe_pair() -> io::Result<(File, File)> {
        let mut fds = [-1; 2];
        if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { (File::from_raw_fd(fds[0]), File::from_raw_fd(fds[1])) })
    }

    #[cfg(target_os = "android")]
    unsafe fn errno() -> i32 {
        *libc::__errno()
    }
    #[cfg(target_os = "linux")]
    unsafe fn errno() -> i32 {
        *libc::__errno_location()
    }

    unsafe fn record(fd: i32, stage: u32, error: i32) {
        let event = TraceEvent {
            stage,
            errno: error,
        };
        let mut offset = 0;
        let bytes = (&event as *const TraceEvent).cast::<u8>();
        while offset < std::mem::size_of::<TraceEvent>() {
            let result = libc::write(
                fd,
                bytes.add(offset).cast(),
                std::mem::size_of::<TraceEvent>() - offset,
            );
            if result > 0 {
                offset += result as usize;
            } else if result < 0 && errno() == libc::EINTR {
                continue;
            } else {
                break;
            }
        }
    }

    unsafe fn child_fail(trace_fd: i32, stage: u32, error: i32) -> ! {
        record(trace_fd, stage, error);
        libc::_exit(126)
    }

    unsafe fn child_exec(
        helper_fd: i32,
        argv0: *const libc::c_char,
        env: *const *const libc::c_char,
        transition: bool,
        ptrace: bool,
        fds: &[i32],
        stdout_read: i32,
        stdout_write: i32,
        stderr_read: i32,
        stderr_write: i32,
        trace_read: i32,
        trace_write: i32,
    ) -> ! {
        libc::close(stdout_read);
        libc::close(stderr_read);
        libc::close(trace_read);
        record(trace_write, TRACE_CHILD, 0);

        let null_fd = libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC);
        if null_fd < 0 {
            child_fail(trace_write, TRACE_STDIN_OPEN, errno());
        }
        record(trace_write, TRACE_STDIN_OPEN, 0);
        if null_fd != libc::STDIN_FILENO && libc::dup2(null_fd, libc::STDIN_FILENO) < 0 {
            child_fail(trace_write, TRACE_STDIN_DUP, errno());
        }
        if null_fd != libc::STDIN_FILENO {
            libc::close(null_fd);
        }
        record(trace_write, TRACE_STDIN_DUP, 0);

        if stdout_write != libc::STDOUT_FILENO && libc::dup2(stdout_write, libc::STDOUT_FILENO) < 0
        {
            child_fail(trace_write, TRACE_STDOUT, errno());
        }
        record(trace_write, TRACE_STDOUT, 0);
        if stderr_write != libc::STDERR_FILENO && libc::dup2(stderr_write, libc::STDERR_FILENO) < 0
        {
            child_fail(trace_write, TRACE_STDERR, errno());
        }
        record(trace_write, TRACE_STDERR, 0);

        for &fd in fds {
            if fd <= libc::STDERR_FILENO || fd == trace_write {
                continue;
            }
            let flags = libc::fcntl(fd, libc::F_GETFD);
            if flags < 0 {
                let error = errno();
                if error == libc::EBADF {
                    continue;
                }
                child_fail(trace_write, TRACE_FD_FLAGS, error);
            }
            if libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) < 0 {
                child_fail(trace_write, TRACE_FD_FLAGS, errno());
            }
        }
        let trace_flags = libc::fcntl(trace_write, libc::F_GETFD);
        if trace_flags < 0
            || libc::fcntl(trace_write, libc::F_SETFD, trace_flags & !libc::FD_CLOEXEC) < 0
        {
            child_fail(trace_write, TRACE_FD_FLAGS, errno());
        }
        record(trace_write, TRACE_FD_FLAGS, 0);

        if transition {
            let fd = libc::open(
                c"/proc/thread-self/attr/exec".as_ptr(),
                libc::O_WRONLY | libc::O_CLOEXEC,
            );
            if fd < 0 {
                child_fail(trace_write, TRACE_SETEXEC_OPEN, errno());
            }
            record(trace_write, TRACE_SETEXEC_OPEN, 0);
            let n = libc::write(
                fd,
                c"u:r:ssal_guest_probe:s0".as_ptr().cast(),
                TARGET.len() + 1,
            );
            let error = if n < 0 {
                errno()
            } else if n != (TARGET.len() + 1) as isize {
                libc::EIO
            } else {
                0
            };
            libc::close(fd);
            record(trace_write, TRACE_SETEXEC_WRITE, error);
            if error != 0 {
                libc::_exit(126);
            }
        }

        if ptrace {
            if libc::ptrace(
                PTRACE_TRACEME,
                0,
                std::ptr::null_mut::<libc::c_void>(),
                std::ptr::null_mut::<libc::c_void>(),
            ) < 0
            {
                child_fail(trace_write, TRACE_PTRACE_TRACEME, errno());
            }
            record(trace_write, TRACE_PTRACE_TRACEME, 0);
            if libc::kill(libc::getpid(), libc::SIGSTOP) < 0 {
                child_fail(trace_write, TRACE_PTRACE_STOP, errno());
            }
        }

        record(trace_write, TRACE_EXECVEAT_ENTERED, 0);
        libc::syscall(
            libc::SYS_execveat,
            helper_fd as libc::c_long,
            c"".as_ptr(),
            [argv0, std::ptr::null()].as_ptr(),
            env,
            libc::AT_EMPTY_PATH as libc::c_long,
        );
        let error = errno();
        record(trace_write, TRACE_EXECVEAT_RETURNED, error);
        libc::_exit(127)
    }

    fn collect_pipe(file: File) -> io::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        file.take(16384).read_to_end(&mut bytes)?;
        Ok(bytes)
    }

    fn ptrace_request(
        request: libc::c_int,
        pid: libc::pid_t,
        addr: *mut libc::c_void,
        data: *mut libc::c_void,
    ) -> io::Result<()> {
        if unsafe { libc::ptrace(request, pid, addr, data) } == -1 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    fn stop_and_reap(pid: libc::pid_t, status: &mut i32) {
        unsafe {
            libc::kill(pid, libc::SIGKILL);
            while libc::waitpid(pid, status, 0) < 0 && errno() == libc::EINTR {}
        }
    }

    fn read_siginfo(pid: libc::pid_t) -> io::Result<(i32, u64)> {
        #[repr(align(8))]
        struct AlignedSiginfo([u8; 128]);
        let mut raw = AlignedSiginfo([0; 128]);
        ptrace_request(
            PTRACE_GETSIGINFO,
            pid,
            std::ptr::null_mut(),
            raw.0.as_mut_ptr().cast(),
        )?;
        Ok(decode_siginfo(&raw.0))
    }

    #[cfg(target_arch = "aarch64")]
    fn read_aarch64_pc(pid: libc::pid_t) -> io::Result<u64> {
        let mut regs = [0u64; 34];
        let mut iov = libc::iovec {
            iov_base: regs.as_mut_ptr().cast(),
            iov_len: std::mem::size_of_val(&regs),
        };
        ptrace_request(
            PTRACE_GETREGSET,
            pid,
            NT_PRSTATUS as *mut libc::c_void,
            (&mut iov as *mut libc::iovec).cast(),
        )?;
        if iov.iov_len < 33 * std::mem::size_of::<u64>() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "short AArch64 NT_PRSTATUS regset",
            ));
        }
        Ok(regs[32])
    }

    #[cfg(not(target_arch = "aarch64"))]
    fn read_aarch64_pc(_pid: libc::pid_t) -> io::Result<u64> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "PTRACE_GETREGSET PC decode requires AArch64",
        ))
    }

    fn wait_ptraced(
        pid: libc::pid_t,
        deadline: Instant,
    ) -> io::Result<(i32, bool, bool)> {
        let mut status = 0;
        let mut options_set = false;
        let mut exec_event = false;
        loop {
            let result = unsafe {
                libc::waitpid(pid, &mut status, libc::WNOHANG | libc::WUNTRACED)
            };
            if result == pid {
                let Some((signal, event)) = ptrace_wait_stop(status) else {
                    return Ok((status, false, exec_event));
                };
                if !options_set {
                    if signal != libc::SIGSTOP || event != 0 {
                        stop_and_reap(pid, &mut status);
                        return Err(io::Error::other(format!(
                            "unexpected initial ptrace stop: signal={signal} event={event}"
                        )));
                    }
                    if let Err(error) = ptrace_request(
                        PTRACE_SETOPTIONS,
                        pid,
                        std::ptr::null_mut(),
                        PTRACE_O_TRACEEXEC as *mut libc::c_void,
                    ) {
                        stop_and_reap(pid, &mut status);
                        return Err(io::Error::other(format!(
                            "PTRACE_SETOPTIONS(PTRACE_O_TRACEEXEC): {error}"
                        )));
                    }
                    options_set = true;
                    if let Err(error) = ptrace_request(
                        PTRACE_CONT,
                        pid,
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                    ) {
                        stop_and_reap(pid, &mut status);
                        return Err(io::Error::other(format!("PTRACE_CONT: {error}")));
                    }
                    continue;
                }

                if event == PTRACE_EVENT_EXEC {
                    exec_event = true;
                    let context = match read(&format!("/proc/{pid}/attr/current")) {
                        Ok(context) => format!("context={context}"),
                        Err(error) => format!("context_read_error={error}"),
                    };
                    match read_aarch64_pc(pid) {
                        Ok(pc) => println!("ptrace_event=EXEC pid={pid} pc=0x{pc:x} {context}"),
                        Err(error) => println!("ptrace_event=EXEC pid={pid} getregset=failed error={error} {context}"),
                    }
                } else if signal == libc::SIGSEGV {
                    println!("ptrace_signal=SIGSEGV pid={pid}");
                    match read_siginfo(pid) {
                        Ok((si_code, fault_addr)) => {
                            println!("ptrace_siginfo si_code={si_code} fault_addr=0x{fault_addr:x}");
                        }
                        Err(error) => println!("ptrace_getsiginfo=failed error={error}"),
                    }
                    match read_aarch64_pc(pid) {
                        Ok(pc) => println!("ptrace_sigsegv_pc=0x{pc:x}"),
                        Err(error) => println!("ptrace_sigsegv_getregset=failed error={error}"),
                    }
                }

                let deliver = if event != 0 || signal == libc::SIGTRAP {
                    0
                } else {
                    signal
                };
                if let Err(error) = ptrace_request(
                    PTRACE_CONT,
                    pid,
                    std::ptr::null_mut(),
                    deliver as usize as *mut libc::c_void,
                ) {
                    stop_and_reap(pid, &mut status);
                    return Err(io::Error::other(format!("PTRACE_CONT: {error}")));
                }
                continue;
            }
            if result < 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                stop_and_reap(pid, &mut status);
                return Err(error);
            }
            if Instant::now() >= deadline {
                stop_and_reap(pid, &mut status);
                return Ok((status, true, exec_event));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    pub fn run(args: &[String]) -> io::Result<()> {
        let (helper_path, sha256, transition, identity_report, ptrace) =
            match parse_args(args).map_err(io::Error::other)? {
                Mode::Control { helper, sha256 } => (helper, sha256, false, true, false),
                Mode::Run { helper, sha256 } => (helper, sha256, true, true, false),
                Mode::BareControl { helper, sha256 } => (helper, sha256, false, false, false),
                Mode::BareRun { helper, sha256 } => (helper, sha256, true, false, false),
                Mode::BarePtraceControl { helper, sha256 } => {
                    (helper, sha256, false, false, true)
                }
                Mode::BarePtraceRun { helper, sha256 } => {
                    (helper, sha256, true, false, true)
                }
                Mode::DryRun => return Err(io::Error::other("dry-run cannot execute")),
            };
        if read("/sys/fs/selinux/enforce")? != "1" {
            return Err(io::Error::other("global Enforcing required"));
        }
        let source = read("/proc/thread-self/attr/current")?;
        if source != "u:r:ksu:s0" {
            return Err(io::Error::other("expected ksu source"));
        }
        let helper = File::open(helper_path)?;
        let meta = helper.metadata()?;
        if !meta.is_file() {
            return Err(io::Error::other("helper must be a regular file"));
        }
        if file_hash(&helper)? != sha256.to_ascii_lowercase() {
            return Err(io::Error::other("helper SHA-256 mismatch"));
        }
        let mut sequence = None;
        let permissive = if transition {
            let file_label = label(&helper)?;
            if file_label != "u:object_r:ssal_guest_probe_exec:s0" {
                return Err(io::Error::other(format!(
                    "unexpected helper label: {file_label}"
                )));
            }
            let mut checks = vec![
                (source.as_str(), source.as_str(), "process", "setexec"),
                (source.as_str(), TARGET, "process", "transition"),
                (TARGET, file_label.as_str(), "file", "entrypoint"),
            ];
            for permission in ["open", "read", "getattr", "execute", "map"] {
                checks.push((&source, &file_label, "file", permission));
            }
            for (s, t, class, permission) in checks {
                let (allowed, _, seq) = decision(s, t, class, permission)?;
                if !allowed {
                    return Err(io::Error::other("required AV denied"));
                }
                if sequence.replace(seq).is_some_and(|old| old != seq) {
                    return Err(io::Error::other("policy sequence changed"));
                }
            }
            let (_, permissive, seq) = decision(TARGET, TARGET, "process", "getattr")?;
            if Some(seq) != sequence || !target_state_allowed(permissive) {
                return Err(io::Error::other(
                    "target permissive or policy sequence changed",
                ));
            }
            Some(permissive)
        } else {
            None
        };
        println!(
            "mode={}; transition={}; reporter={}; helper_dev={} helper_ino={}",
            if transition { "transition" } else { "control" },
            if transition { "requested" } else { "not_run" },
            if identity_report { "identity" } else { "bare" },
            meta.dev(),
            meta.ino()
        );
        if transition {
            // AV queries cannot prove the label of future procfs entries.
            println!("reporter_paths=/proc/self/exe,/proc/self/ns,/proc/self/attr/current,/proc/self/status; target_proc_labels=unknown_before_exec");
        }

        let argv0 = CString::new(helper_path.as_bytes()).map_err(io::Error::other)?;
        let (stdout_read, stdout_write) = pipe_pair()?;
        let (stderr_read, stderr_write) = pipe_pair()?;
        let (trace_read, trace_write) = pipe_pair()?;
        let stage_env = CString::new(format!("SSAL_STAGE_FD={}", trace_write.as_raw_fd()))
            .map_err(io::Error::other)?;
        let env = [stage_env.as_ptr(), std::ptr::null()];
        let fds: Vec<i32> = fs::read_dir("/proc/self/fd")?
            .filter_map(|e| e.ok()?.file_name().to_str()?.parse().ok())
            .filter(|&n| n > 2)
            .collect();
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            let error = io::Error::last_os_error();
            println!(
                "syscall=fork errno={}",
                error.raw_os_error().unwrap_or_default()
            );
            return Err(error);
        }
        if pid == 0 {
            unsafe {
                child_exec(
                    helper.as_raw_fd(),
                    argv0.as_ptr(),
                    env.as_ptr(),
                    transition,
                    ptrace,
                    &fds,
                    stdout_read.as_raw_fd(),
                    stdout_write.as_raw_fd(),
                    stderr_read.as_raw_fd(),
                    stderr_write.as_raw_fd(),
                    trace_read.as_raw_fd(),
                    trace_write.as_raw_fd(),
                )
            }
        }
        drop(stdout_write);
        drop(stderr_write);
        drop(trace_write);
        println!("child_pid={pid}; fork=ok");
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut status = 0;
        let (status, timed_out, exec_event_seen) = if ptrace {
            wait_ptraced(pid, deadline)?
        } else {
            let mut timed_out = false;
            loop {
                let result = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
                if result == pid {
                    break;
                }
                if result < 0 {
                    let error = io::Error::last_os_error();
                    if error.raw_os_error() == Some(libc::EINTR) {
                        continue;
                    }
                    return Err(error);
                }
                if Instant::now() >= deadline {
                    timed_out = true;
                    unsafe {
                        libc::kill(pid, libc::SIGKILL);
                        while libc::waitpid(pid, &mut status, 0) < 0 && errno() == libc::EINTR {}
                    }
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            (status, timed_out, false)
        };
        println!("child_wait_status=0x{status:04x}; timed_out={timed_out}");
        if ptrace {
            println!(
                "ptrace_exec_event={}",
                if exec_event_seen { "seen" } else { "not_seen" }
            );
        }
        let trace = collect_pipe(trace_read)?;
        let events = decode_trace_events(&trace).map_err(io::Error::other)?;
        let mut reporter_main = false;
        for event in events {
            println!(
                "child_stage={} syscall={} errno={}",
                trace_stage_name(event.stage),
                trace_syscall_name(event.stage),
                event.errno
            );
            reporter_main |= event.stage == TRACE_REPORTER_MAIN;
            if event.stage == TRACE_EXECVEAT_RETURNED {
                println!("syscall=execveat errno={}", event.errno);
            }
        }
        println!(
            "reporter_main={}",
            if reporter_main { "seen" } else { "not_seen" }
        );

        let mut output = String::new();
        stdout_read.take(16384).read_to_string(&mut output)?;
        let expected_context = if transition { TARGET } else { source.as_str() };
        let reporter_valid = if identity_report {
            let identity: serde_json::Value = match serde_json::from_str(&output) {
                Ok(identity) => identity,
                Err(error) => {
                    let stderr = String::from_utf8_lossy(&collect_pipe(stderr_read)?).into_owned();
                    let outcome = if status & 0x7f != 0 {
                        format!("signal={}", status & 0x7f)
                    } else {
                        format!("exit={}", (status >> 8) & 0xff)
                    };
                    return Err(io::Error::other(format!(
                        "child pid={pid} {outcome}; reporter_main={reporter_main}; invalid identity output ({error}); stderr={stderr:?}"
                    )));
                }
            };
            println!("child={identity}");
            identity["protocol"] == 1
                && identity["pid"] == pid as u32
                && identity["context"] == expected_context
                && identity["executable_dev"] == meta.dev()
                && identity["executable_ino"] == meta.ino()
        } else {
            let exit_probe = bare_exit_probe_succeeded(status, &output);
            let entered = exit_probe || bare_output_matches_context(&output, expected_context);
            println!(
                "bare_entry={}; proof={}; output={output:?}",
                if entered { "seen" } else { "not_seen" },
                if exit_probe {
                    "exit_42"
                } else {
                    "context_output"
                }
            );
            entered
        };
        let status_valid = (status & 0x7f == 0 && (status >> 8) & 0xff == 0)
            || bare_exit_probe_succeeded(status, &output);
        let valid = status_valid && !timed_out && reporter_valid;
        let enforcing_after = read("/sys/fs/selinux/enforce")? == "1";
        let state_matches = if transition {
            let (_, after, after_seq) = decision(TARGET, TARGET, "process", "getattr")?;
            Some(after) == permissive && Some(after_seq) == sequence
        } else {
            true
        };
        let stderr = String::from_utf8_lossy(&collect_pipe(stderr_read)?).into_owned();
        if !valid
            || !enforcing_after
            || !state_matches
            || file_hash(&helper)? != sha256.to_ascii_lowercase()
        {
            if status & 0x7f != 0 || timed_out {
                let outcome = if timed_out {
                    "timed_out".to_string()
                } else {
                    format!("signal={}", status & 0x7f)
                };
                return Err(io::Error::other(format!(
                    "child pid={pid} {outcome}; reporter_main={reporter_main}; stderr={stderr:?}"
                )));
            }
            return Err(io::Error::other(
                "identity, process status, or post-exec policy state mismatch",
            ));
        }
        if transition {
            if identity_report {
                println!("PASS: child reaped; actual target SID confirmed; global Enforcing retained; target_permissive={}", permissive.unwrap_or(false));
            } else if bare_exit_probe_succeeded(status, &output) {
                println!(
                    "PASS: bare ELF entry confirmed by exit code 42; global Enforcing retained"
                );
            } else {
                println!(
                    "PASS: bare ELF entry and target context confirmed; global Enforcing retained"
                );
            }
        } else if identity_report {
            println!("PASS: no-transition control; child reaped in source SID; global Enforcing retained");
        } else if bare_exit_probe_succeeded(status, &output) {
            println!("PASS: bare ELF entry confirmed by exit code 42; source SID retained; global Enforcing retained");
        } else {
            println!(
                "PASS: bare ELF entry and source context confirmed; global Enforcing retained"
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args(xs: &[&str]) -> Vec<String> {
        xs.iter().map(|x| x.to_string()).collect()
    }
    #[test]
    fn access_query_is_one_complete_transaction_and_rejects_short_write() {
        struct Writer {
            chunks: Vec<Vec<u8>>,
            short: bool,
        }
        impl std::io::Write for Writer {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.chunks.push(buf.to_vec());
                Ok(if self.short { buf.len() - 1 } else { buf.len() })
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut good = Writer {
            chunks: vec![],
            short: false,
        };
        write_access_request(&mut good, "u:r:ksu:s0", "u:r:ksu:s0", 1, 0x20000).unwrap();
        assert_eq!(good.chunks, vec![b"u:r:ksu:s0 u:r:ksu:s0 1 20000".to_vec()]);
        let mut short = Writer {
            chunks: vec![],
            short: true,
        };
        assert!(write_access_request(&mut short, "a", "b", 1, 2).is_err());
        assert_eq!(short.chunks.len(), 1);
    }
    #[test]
    fn defaults_are_dry_and_diagnostic_alone_never_executes() {
        assert_eq!(parse_args(&args(&[])), Ok(Mode::DryRun));
        assert_eq!(parse_args(&args(&["--dry-run"])), Ok(Mode::DryRun));
        for a in [
            &["--diagnostic-permissive"][..],
            &["--run-after-approval"][..],
            &["--run-after-approval", "--diagnostic-permissive"][..],
            &["--run-after-approval", "/x", "--sha256", "abc"][..],
            &["--run-after-approval", "/x"][..],
            &["--dry-run", "x"][..],
        ] {
            assert!(parse_args(&args(a)).is_err());
        }
    }

    #[test]
    fn control_mode_is_explicit_and_trace_records_are_checked() {
        let hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        assert_eq!(
            parse_args(&args(&["--control", "/x", "--sha256", hash])),
            Ok(Mode::Control {
                helper: "/x",
                sha256: hash
            })
        );
        assert_eq!(
            parse_args(&args(&["--bare-control", "/x", "--sha256", hash])),
            Ok(Mode::BareControl {
                helper: "/x",
                sha256: hash
            })
        );
        assert_eq!(
            parse_args(&args(&["--bare-ptrace-control", "/x", "--sha256", hash])),
            Ok(Mode::BarePtraceControl {
                helper: "/x",
                sha256: hash
            })
        );
        assert_eq!(
            parse_args(&args(&["--bare-ptrace-transition", "/x", "--sha256", hash])),
            Ok(Mode::BarePtraceRun {
                helper: "/x",
                sha256: hash
            })
        );
        assert_eq!(
            parse_args(&args(&["--bare-transition", "/x", "--sha256", hash])),
            Ok(Mode::BareRun {
                helper: "/x",
                sha256: hash
            })
        );
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&TRACE_SETEXEC_WRITE.to_ne_bytes());
        bytes.extend_from_slice(&libc::EACCES.to_ne_bytes());
        let events = decode_trace_events(&bytes).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(trace_stage_name(events[0].stage), "setexec_write");
        assert_eq!(trace_syscall_name(events[0].stage), "write");
        assert_eq!(events[0].errno, libc::EACCES);
        assert!(decode_trace_events(&bytes[..bytes.len() - 1]).is_err());
    }

    #[test]
    fn bare_reporter_requires_entry_marker_and_exact_context() {
        assert!(bare_output_matches_context(
            "BARE_ENTRY\ncontext=u:r:ksu:s0\0\n",
            "u:r:ksu:s0"
        ));
        assert!(!bare_output_matches_context(
            "BARE_ENTRY\ncontext=u:r:other:s0\0\n",
            "u:r:ksu:s0"
        ));
        assert!(!bare_output_matches_context("", "u:r:ksu:s0"));
    }

    #[test]
    fn exit_probe_requires_expected_status_and_no_output() {
        assert!(bare_exit_probe_succeeded(42 << 8, ""));
        assert!(!bare_exit_probe_succeeded(0, ""));
        assert!(!bare_exit_probe_succeeded(42 << 8, "unexpected"));
        assert!(!bare_exit_probe_succeeded(0x000b, ""));
    }

    #[test]
    fn ptrace_wait_status_and_siginfo_fields_are_decoded() {
        assert_eq!(ptrace_wait_stop((4 << 16) | (5 << 8) | 0x7f), Some((5, 4)));
        assert_eq!(ptrace_wait_stop(0x000b), None);

        let mut raw = [0u8; 128];
        raw[8..12].copy_from_slice(&1i32.to_ne_bytes());
        raw[16..24].copy_from_slice(&0x1234u64.to_ne_bytes());
        assert_eq!(decode_siginfo(&raw), (1, 0x1234));
    }

    #[test]
    fn permissive_is_always_rejected() {
        assert!(target_state_allowed(false));
        assert!(!target_state_allowed(true));
        assert_eq!(
            parse_args(&args(&[
                "--run-after-approval",
                "/x",
                "--sha256",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            ])),
            Ok(Mode::Run {
                helper: "/x",
                sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            })
        );
        assert!(parse_args(&args(&[
            "--run-after-approval",
            "/x",
            "--sha256",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--diagnostic-permissive"
        ]))
        .is_err());
    }
}
