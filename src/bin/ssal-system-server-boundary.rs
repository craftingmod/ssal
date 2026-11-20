//! Probes Host boundary isolation from a UID 1000 / stock system_server SID process.
use std::env;
use std::fmt::Write as _;
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::process::ExitCode;

type SetConFn = unsafe extern "C" fn(*const libc::c_char) -> libc::c_int;

struct SharedOutput {
    ptr: *mut u8,
    used: usize,
}

impl SharedOutput {
    fn write_str(&mut self, s: &str) {
        let bytes = s.as_bytes();
        if self.used + bytes.len() >= 16383 {
            unsafe { libc::_exit(16) };
        }
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), self.ptr.add(self.used), bytes.len());
        }
        self.used += bytes.len();
    }

    fn log(&mut self, args: std::fmt::Arguments<'_>) {
        let mut buf = String::new();
        let _ = buf.write_fmt(args);
        self.write_str(&buf);
    }
}

fn identity(out: &mut SharedOutput) {
    for path in ["/proc/self/attr/current", "/proc/self/status"] {
        let Ok(content) = fs::read_to_string(path) else {
            unsafe { libc::_exit(12) };
        };
        let trimmed = content.trim_end_matches('\0');
        out.log(format_args!("identity {path}\n{trimmed}\n"));
    }
}

fn main() -> ExitCode {
    let args: Vec<_> = env::args().collect();
    if args.len() != 2 {
        return ExitCode::from(2);
    }
    let canary = args[1] == "--canary";
    if !canary && args[1] != "--probe" {
        return ExitCode::from(2);
    }
    if unsafe { libc::ftruncate(libc::STDOUT_FILENO, 16384) } != 0 {
        return ExitCode::from(17);
    }
    let mapped = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            16384,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            libc::STDOUT_FILENO,
            0,
        )
    };
    if mapped == libc::MAP_FAILED {
        return ExitCode::from(18);
    }
    let mut out = SharedOutput {
        ptr: mapped.cast(),
        used: 0,
    };

    let lib = unsafe { libc::dlopen(c"libselinux.so".as_ptr(), libc::RTLD_NOW) };
    let setcon_sym = if lib.is_null() {
        std::ptr::null_mut()
    } else {
        unsafe { libc::dlsym(lib, c"setcon".as_ptr()) }
    };

    // Match specialization order: credentials before the final SID.
    if unsafe { libc::setgroups(0, std::ptr::null()) } != 0
        || unsafe { libc::setresgid(1000, 1000, 1000) } != 0
        || unsafe { libc::setresuid(1000, 1000, 1000) } != 0
    {
        let err = io::Error::last_os_error().raw_os_error().unwrap_or(0);
        out.log(format_args!("boundary_credentials_failed errno={err}\n"));
        return ExitCode::from(11);
    }
    if setcon_sym.is_null() {
        let err = io::Error::last_os_error().raw_os_error().unwrap_or(0);
        out.log(format_args!("boundary_sid_failed errno={err}\n"));
        return ExitCode::from(10);
    }
    let setcon: SetConFn = unsafe { std::mem::transmute(setcon_sym) };
    if unsafe { setcon(c"u:r:system_server:s0".as_ptr()) } != 0 {
        let err = io::Error::last_os_error().raw_os_error().unwrap_or(0);
        out.log(format_args!("boundary_sid_failed errno={err}\n"));
        return ExitCode::from(10);
    }
    out.write_str("boundary_sid_set=PASS\n");
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return ExitCode::from(12);
    }
    identity(&mut out);

    if canary {
        // An expendable, dumpable process; no real Host service is targeted.
        if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 1) } != 0 {
            return ExitCode::from(13);
        }
        out.log(format_args!(
            "SSAL_HOST_CANARY_READY pid={}\n",
            unsafe { libc::getpid() }
        ));
        unsafe { libc::sleep(12) };
        return ExitCode::SUCCESS;
    }

    let Ok(pid) = env::var("SSAL_CANARY_PID")
        .ok()
        .and_then(|v| v.parse::<libc::pid_t>().ok())
        .ok_or(())
    else {
        return ExitCode::from(14);
    };
    if pid <= 1 {
        return ExitCode::from(14);
    }

    let rc = unsafe { libc::kill(pid, 0) };
    let err = if rc == 0 {
        0
    } else {
        io::Error::last_os_error().raw_os_error().unwrap_or(0)
    };
    out.log(format_args!("boundary signal0 result={rc} errno={err}\n"));
    let mut allowed = rc == 0;

    for suffix in ["root", "fd", "fd/0"] {
        let path = format!("/proc/{pid}/{suffix}");
        let cpath = std::ffi::CString::new(path.as_bytes()).unwrap();
        let fd = unsafe {
            libc::open(
                cpath.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        };
        let err = if fd < 0 {
            io::Error::last_os_error().raw_os_error().unwrap_or(0)
        } else {
            0
        };
        out.log(format_args!(
            "boundary path={path} result={} errno={err}\n",
            if fd >= 0 { 0 } else { -1 }
        ));
        if fd >= 0 {
            allowed = true;
            unsafe { libc::close(fd) };
        }
    }

    let rc = unsafe { libc::ptrace(libc::PTRACE_ATTACH, pid, std::ptr::null_mut::<u8>(), std::ptr::null_mut::<u8>()) };
    let err = if rc == 0 {
        0
    } else {
        io::Error::last_os_error().raw_os_error().unwrap_or(0)
    };
    out.log(format_args!("boundary ptrace_attach result={rc} errno={err}\n"));
    if rc == 0 {
        allowed = true;
        let mut status: libc::c_int = 0;
        loop {
            let waited = unsafe { libc::waitpid(pid, &mut status, libc::__WALL) };
            if waited < 0 {
                if io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return ExitCode::from(15);
            }
            if waited != pid || !libc::WIFSTOPPED(status) {
                return ExitCode::from(15);
            }
            break;
        }
        if unsafe {
            libc::ptrace(
                libc::PTRACE_DETACH,
                pid,
                std::ptr::null_mut::<u8>(),
                std::ptr::null_mut::<u8>(),
            )
        } != 0
        {
            return ExitCode::from(15);
        }
        out.write_str("boundary ptrace_detach=PASS\n");
    }

    let _ = std::path::Path::new("/proc").as_os_str().as_bytes();
    out.log(format_args!(
        "SSAL_SS_BOUNDARY={} credential_model=uid1000-groups0-caps0-stock_sid\n",
        if allowed { "FAIL" } else { "PASS" }
    ));
    if allowed {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}
