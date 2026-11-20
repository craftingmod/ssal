//! Kernel and libcutils ashmem/memfd diagnostic probe.
use std::env;
use std::ffi::{CStr, CString};
use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::process::ExitCode;

const ASHMEM_GET_SIZE: libc::c_ulong = 0x7704;
const F_ADD_SEALS: libc::c_int = 1033;
const F_GET_SEALS: libc::c_int = 1034;
const F_SEAL_FUTURE_WRITE: libc::c_int = 0x0010;
const MFD_CLOEXEC: libc::c_uint = 0x0001;
const MFD_ALLOW_SEALING: libc::c_uint = 0x0002;

fn log_result(operation: &str, value: libc::c_long) {
    let error = if value < 0 {
        io::Error::last_os_error().raw_os_error().unwrap_or(0)
    } else {
        0
    };
    let desc = io::Error::from_raw_os_error(error);
    println!("{operation} result={value} errno={error} ({desc})");
}

fn path_probe(path: &str) {
    let cpath = CString::new(path).unwrap();
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::stat(cpath.as_ptr(), &mut st) };
    log_result(path, rc as libc::c_long);
    if rc == 0 {
        println!(
            "device mode={:o} uid={} gid={} rdev={}",
            st.st_mode, st.st_uid, st.st_gid, st.st_rdev
        );
    }
    let fd = unsafe { libc::open(cpath.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    log_result("open(O_RDWR|O_CLOEXEC)", fd as libc::c_long);
    if fd >= 0 {
        unsafe { libc::close(fd) };
    }
}

fn get_prop(key: &str) -> String {
    type PropGetFn = unsafe extern "C" fn(*const libc::c_char, *mut libc::c_char) -> libc::c_int;
    let sym = unsafe { libc::dlsym(libc::RTLD_DEFAULT, c"__system_property_get".as_ptr()) };
    if sym.is_null() {
        return String::new();
    }
    let prop_get: PropGetFn = unsafe { std::mem::transmute(sym) };
    let ckey = CString::new(key).unwrap();
    let mut buf = [0u8; 92];
    unsafe { prop_get(ckey.as_ptr(), buf.as_mut_ptr().cast()) };
    unsafe { CStr::from_ptr(buf.as_ptr().cast()) }
        .to_string_lossy()
        .into_owned()
}

fn main() -> ExitCode {
    let args: Vec<_> = env::args().collect();
    for key in ["ro.treble.enabled", "sys.use_memfd"] {
        println!("property {key}={}", get_prop(key));
    }
    let context = fs::read_to_string("/proc/self/attr/current").unwrap();
    let context = context.trim_end_matches('\0');
    println!("context={context} uid={}", unsafe { libc::getuid() });
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap();
    let boot = boot.trim_end_matches('\n');
    let path = format!("/dev/ashmem{boot}");
    path_probe("/dev/ashmem");
    path_probe(&path);

    let memfd = unsafe {
        libc::syscall(
            libc::SYS_memfd_create,
            c"ssal-kernel-check".as_ptr(),
            MFD_CLOEXEC | MFD_ALLOW_SEALING,
        )
    };
    log_result("memfd_create", memfd);
    if memfd >= 0 {
        let fd = memfd as libc::c_int;
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as libc::off_t;
        log_result(
            "F_SEAL_FUTURE_WRITE",
            unsafe { libc::fcntl(fd, F_ADD_SEALS, F_SEAL_FUTURE_WRITE) } as libc::c_long,
        );
        log_result(
            "ftruncate",
            unsafe { libc::ftruncate(fd, page) } as libc::c_long,
        );
        log_result(
            "memfd ASHMEM_GET_SIZE",
            unsafe { libc::ioctl(fd, ASHMEM_GET_SIZE as _, 0) } as libc::c_long,
        );
        log_result(
            "F_GET_SEALS",
            unsafe { libc::fcntl(fd, F_GET_SEALS) } as libc::c_long,
        );
        unsafe { libc::close(fd) };
    }
    if args.len() == 2 && args[1] == "--kernel-only" {
        return ExitCode::SUCCESS;
    }

    let lib = unsafe { libc::dlopen(c"libcutils.so".as_ptr(), libc::RTLD_NOW) };
    if lib.is_null() {
        let err = unsafe { libc::dlerror() };
        let msg = if err.is_null() {
            "unknown".into()
        } else {
            unsafe { CStr::from_ptr(err) }.to_string_lossy()
        };
        eprintln!("dlopen: {msg}");
        return ExitCode::from(1);
    }

    type CreateFn = unsafe extern "C" fn(*const libc::c_char, libc::size_t) -> libc::c_int;
    type ProtectFn = unsafe extern "C" fn(libc::c_int, libc::c_int) -> libc::c_int;
    type SizeFn = unsafe extern "C" fn(libc::c_int) -> libc::c_int;
    type SupportedFn = unsafe extern "C" fn() -> bool;

    let create: CreateFn =
        unsafe { std::mem::transmute(libc::dlsym(lib, c"ashmem_create_region".as_ptr())) };
    let protect: ProtectFn =
        unsafe { std::mem::transmute(libc::dlsym(lib, c"ashmem_set_prot_region".as_ptr())) };
    let size_fn: SizeFn =
        unsafe { std::mem::transmute(libc::dlsym(lib, c"ashmem_get_size_region".as_ptr())) };
    let supported: SupportedFn =
        unsafe { std::mem::transmute(libc::dlsym(lib, c"_Z17has_memfd_supportv".as_ptr())) };

    println!("libcutils has_memfd_support={}", u8::from(unsafe { supported() }));
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
    let fd = unsafe { create(c"ApplicationSharedMemory-ssal-probe".as_ptr(), page) };
    log_result("libcutils ashmem_create_region", fd as libc::c_long);
    if fd < 0 {
        println!("SSAL_ASHMEM_MEMORY=FAIL");
        unsafe { libc::dlclose(lib) };
        return ExitCode::SUCCESS;
    }
    assert_eq!(unsafe { size_fn(fd) } as usize, page);
    let shared = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            page,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd,
            0,
        )
    };
    assert_ne!(shared, libc::MAP_FAILED);
    unsafe {
        std::ptr::copy_nonoverlapping(b"parent\0".as_ptr(), shared.cast::<u8>(), 7);
    }
    let child = unsafe { libc::fork() };
    assert!(child >= 0);
    if child == 0 {
        assert_eq!(unsafe { libc::munmap(shared, page) }, 0);
        let received = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                page,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };
        assert_ne!(received, libc::MAP_FAILED);
        assert_eq!(
            unsafe { CStr::from_ptr(received.cast()).to_bytes() },
            b"parent"
        );
        unsafe {
            std::ptr::copy_nonoverlapping(b"child\0".as_ptr(), received.cast::<u8>(), 6);
        }
        assert_eq!(unsafe { libc::munmap(received, page) }, 0);
        unsafe { libc::close(fd) };
        unsafe { libc::_exit(0) };
    }
    let mut status: libc::c_int = 0;
    assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
    assert!(libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0);
    assert_eq!(
        unsafe { CStr::from_ptr(shared.cast()).to_bytes() },
        b"child"
    );
    assert_eq!(unsafe { protect(fd, libc::PROT_READ) }, 0);
    let write_map = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            page,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd,
            0,
        )
    };
    let err = io::Error::last_os_error().raw_os_error().unwrap_or(0);
    assert!(write_map == libc::MAP_FAILED && (err == libc::EPERM || err == libc::EACCES));
    let readonly = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            page,
            libc::PROT_READ,
            libc::MAP_SHARED,
            fd,
            0,
        )
    };
    assert_ne!(readonly, libc::MAP_FAILED);
    assert_eq!(
        unsafe { CStr::from_ptr(readonly.cast()).to_bytes() },
        b"child"
    );
    assert_eq!(unsafe { libc::munmap(readonly, page) }, 0);
    assert_eq!(unsafe { libc::munmap(shared, page) }, 0);
    unsafe {
        libc::close(fd);
        libc::dlclose(lib);
    }
    let _ = fs::metadata("/proc/self").map(|m| m.ino());
    println!("SSAL_ASHMEM_MEMORY=PASS create=PASS mmap=PASS fork_share=PASS protect=PASS");
    ExitCode::SUCCESS
}
