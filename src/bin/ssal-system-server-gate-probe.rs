//! Preflight harness for ssal-system-server-gate.so without invoking JVM/SystemServer.
use std::env;
use std::ffi::{CStr, CString};
use std::process::ExitCode;

type VersionFn = unsafe extern "C" fn() -> libc::c_int;
type SetConFn = unsafe extern "C" fn(*const libc::c_char) -> libc::c_int;
type SetContextFn =
    unsafe extern "C" fn(libc::uid_t, bool, *const libc::c_char, *const libc::c_char) -> libc::c_int;

fn get_prop(key: &str) -> Option<String> {
    type PropGetFn = unsafe extern "C" fn(*const libc::c_char, *mut libc::c_char) -> libc::c_int;
    let sym = unsafe { libc::dlsym(libc::RTLD_DEFAULT, c"__system_property_get".as_ptr()) };
    if sym.is_null() {
        return None;
    }
    let prop_get: PropGetFn = unsafe { std::mem::transmute(sym) };
    let ckey = CString::new(key).unwrap();
    let mut buf = [0u8; 92];
    let len = unsafe { prop_get(ckey.as_ptr(), buf.as_mut_ptr().cast()) };
    if len <= 0 {
        return None;
    }
    Some(
        unsafe { CStr::from_ptr(buf.as_ptr().cast()) }
            .to_string_lossy()
            .into_owned(),
    )
}

fn main() -> ExitCode {
    let args: Vec<_> = env::args().collect();
    if args.len() != 2 {
        return ExitCode::from(2);
    }
    let mode = args[1].as_str();
    if mode == "timeout" {
        loop {
            unsafe { libc::pause() };
        }
    }
    if mode == "early-exit" {
        return ExitCode::from(86);
    }
    let path = match mode {
        "hook-missing" => c"/ssal-missing-hook.so",
        "hook-wrong" => c"libm.so",
        _ => c"/run/ssal/ssal-system-server-gate.so",
    };
    let gate = unsafe { libc::dlopen(path.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    let version_sym = if gate.is_null() {
        std::ptr::null_mut()
    } else {
        unsafe { libc::dlsym(gate, c"ssal_system_server_gate_version".as_ptr()) }
    };
    if version_sym.is_null() {
        return ExitCode::from(83);
    }
    let version: VersionFn = unsafe { std::mem::transmute(version_sym) };
    if unsafe { version() } != 1 {
        return ExitCode::from(83);
    }

    match mode {
        "wrapper" => {
            let Some(prop) = get_prop("wrap.system_server") else {
                return ExitCode::from(87);
            };
            if prop != "/run/ssal/ssal-system-server-wrapper" {
                return ExitCode::from(87);
            }
            let cprop = CString::new(prop).unwrap();
            unsafe {
                libc::execl(
                    cprop.as_ptr(),
                    c"ssal-system-server-wrapper".as_ptr(),
                    c"ignored".as_ptr(),
                    std::ptr::null::<libc::c_char>(),
                );
                libc::_exit(84);
            }
        }
        "exec-failure" => unsafe {
            libc::execl(
                c"/ssal-nonexistent-wrapper".as_ptr(),
                c"missing".as_ptr(),
                std::ptr::null::<libc::c_char>(),
            );
            libc::_exit(84);
        },
        "wrapper-failure" => unsafe {
            libc::execl(
                c"/system/bin/false".as_ptr(),
                c"false".as_ptr(),
                std::ptr::null::<libc::c_char>(),
            );
            libc::_exit(84);
        },
        "property-missing" | "control-disconnected" => {
            if get_prop("wrap.system_server").is_some() {
                return ExitCode::from(87);
            }
            if mode == "control-disconnected" {
                unsafe { libc::close(libc::STDERR_FILENO) };
            }
            let final_sym = unsafe { libc::dlsym(gate, c"selinux_android_setcon".as_ptr()) };
            if final_sym.is_null() {
                return ExitCode::from(83);
            }
            let final_fn: SetConFn = unsafe { std::mem::transmute(final_sym) };
            unsafe { final_fn(c"u:r:system_server:s0".as_ptr()) };
        }
        "startup" => {
            let startup_sym = unsafe { libc::dlsym(gate, c"selinux_android_setcontext".as_ptr()) };
            if startup_sym.is_null() {
                return ExitCode::from(83);
            }
            let startup: SetContextFn = unsafe { std::mem::transmute(startup_sym) };
            unsafe { startup(1000, true, std::ptr::null(), std::ptr::null()) };
        }
        _ => return ExitCode::from(2),
    }

    eprintln!("SSAL_SS_GATE_RETURNED_UNSAFE");
    ExitCode::from(99)
}
