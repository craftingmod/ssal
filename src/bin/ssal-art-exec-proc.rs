//! Phase 2 only: ask the supervisor for this compiler's own proc view, then run stock art_exec.
use std::env;
use std::ffi::{CStr, CString};
use std::os::unix::ffi::OsStrExt;
use std::process::ExitCode;

#[repr(C)]
struct CapUserHeader {
    version: u32,
    pid: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CapUserData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
const PR_CAP_AMBIENT: libc::c_int = 47;
const PR_CAP_AMBIENT_LOWER: libc::c_ulong = 3;
const CAP_SYS_ADMIN: u32 = 21;
const CONTROL_FD: libc::c_int = 198;

fn main() -> ExitCode {
    let args: Vec<_> = env::args_os().collect();
    if args.len() < 2 || unsafe { libc::unshare(libc::CLONE_NEWNS) } != 0 {
        eprintln!("phase2 compiler unshare: {}", std::io::Error::last_os_error());
        return ExitCode::from(120);
    }

    let pid = unsafe { libc::getpid() };
    let pid_bytes = pid.to_ne_bytes();
    let mut ack = [0u8; 1];

    if unsafe {
        libc::send(
            CONTROL_FD,
            pid_bytes.as_ptr().cast(),
            pid_bytes.len(),
            libc::MSG_NOSIGNAL,
        )
    } != pid_bytes.len() as isize
        || unsafe { libc::recv(CONTROL_FD, ack.as_mut_ptr().cast(), 1, 0) } != 1
        || ack[0] != 1
    {
        return ExitCode::from(121);
    }

    let mut header = CapUserHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut caps = [CapUserData::default(); 2];
    if unsafe { libc::syscall(libc::SYS_capget, &mut header as *mut _, caps.as_mut_ptr()) } != 0 {
        return ExitCode::from(122);
    }
    let bit = 1u32 << CAP_SYS_ADMIN;
    caps[0].effective &= !bit;
    caps[0].permitted &= !bit;
    caps[0].inheritable &= !bit;
    if unsafe { libc::syscall(libc::SYS_capset, &mut header as *mut _, caps.as_ptr()) } != 0
        || unsafe { libc::prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_LOWER, CAP_SYS_ADMIN, 0, 0) } != 0
    {
        return ExitCode::from(123);
    }

    if unsafe {
        libc::send(
            CONTROL_FD,
            pid_bytes.as_ptr().cast(),
            pid_bytes.len(),
            libc::MSG_NOSIGNAL,
        )
    } != pid_bytes.len() as isize
        || unsafe { libc::recv(CONTROL_FD, ack.as_mut_ptr().cast(), 1, 0) } != 1
        || ack[0] != 2
        || unsafe { libc::close(CONTROL_FD) } != 0
    {
        return ExitCode::from(125);
    }

    // NNP remains set; the compiler cannot regain the dropped mount capability.
    let target = c"/run/ssal/phase2-real-art-exec";
    let mut c_args = Vec::with_capacity(args.len() + 1);
    c_args.push(target.to_owned());
    for arg in &args[1..] {
        let Ok(s) = CString::new(arg.as_bytes()) else {
            return ExitCode::from(124);
        };
        c_args.push(s);
    }
    let mut argv: Vec<*const libc::c_char> = c_args.iter().map(|s| s.as_ptr()).collect();
    argv.push(std::ptr::null());

    unsafe {
        libc::execv(target.as_ptr(), argv.as_ptr());
    }
    eprintln!(
        "phase2 stock art_exec ({}): {}",
        CStr::from_bytes_with_nul(target.to_bytes_with_nul())
            .unwrap()
            .to_string_lossy(),
        std::io::Error::last_os_error()
    );
    ExitCode::from(124)
}
