//! Probes Guest libselinux startup/final context transitions without invoking SystemServer.
use std::ffi::CStr;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::process::ExitCode;

type SetContextFn =
    unsafe extern "C" fn(libc::uid_t, bool, *const libc::c_char, *const libc::c_char) -> libc::c_int;
type SetConFn = unsafe extern "C" fn(*const libc::c_char) -> libc::c_int;

fn main() -> ExitCode {
    unsafe {
        if libc::getuid() != 1000 || libc::getgid() != 1000 {
            return ExitCode::from(2);
        }
        let library = libc::dlopen(c"libselinux.so".as_ptr(), libc::RTLD_NOW | libc::RTLD_GLOBAL);
        if library.is_null() {
            let err = libc::dlerror();
            let msg = if err.is_null() {
                "unknown".into()
            } else {
                CStr::from_ptr(err).to_string_lossy()
            };
            eprintln!("SSAL_STARTUP_DLOPEN error={msg}");
            return ExitCode::from(2);
        }
        let startup_sym = libc::dlsym(libc::RTLD_DEFAULT, c"selinux_android_setcontext".as_ptr());
        let final_sym = libc::dlsym(libc::RTLD_DEFAULT, c"selinux_android_setcon".as_ptr());
        if startup_sym.is_null() || final_sym.is_null() {
            eprintln!(
                "SSAL_STARTUP_SYMBOLS startup={} final={}",
                usize::from(!startup_sym.is_null()),
                usize::from(!final_sym.is_null())
            );
            return ExitCode::from(2);
        }
        let startup: SetContextFn = std::mem::transmute(startup_sym);
        let final_setcon: SetConFn = std::mem::transmute(final_sym);

        let context = "u:r:system_server_startup:s0";
        let (valid, error) = match OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_CLOEXEC)
            .open("/sys/fs/selinux/context")
        {
            Ok(mut file) => match file.write(context.as_bytes()) {
                Ok(n) => (n as isize, 0),
                Err(e) => (-1, e.raw_os_error().unwrap_or(0)),
            },
            Err(e) => (-1, e.raw_os_error().unwrap_or(0)),
        };
        eprintln!("SSAL_STARTUP_CONTEXT_CHECK context={context} result={valid} errno={error}");

        let mut result = startup(1000, true, std::ptr::null(), std::ptr::null());
        let mut err = if result == 0 {
            0
        } else {
            std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
        };
        eprintln!(
            "SSAL_STARTUP_PROBE result={result} errno={err} final_reached={} SystemServer_main=never",
            usize::from(result == 0)
        );
        if result == 0 {
            result = final_setcon(c"u:r:system_server:s0".as_ptr());
            err = if result == 0 {
                0
            } else {
                std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
            };
            eprintln!("SSAL_FINAL_PROBE result={result} errno={err}");
        }
    }
    ExitCode::SUCCESS
}
