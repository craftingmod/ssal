//! Disposable ioctl/label diagnostic. Never opens Host Binder for IPC.
#[cfg(unix)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::ffi::CString;
    use std::fs::{self, OpenOptions};
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let args: Vec<String> = std::env::args().collect();
    let context = fs::read_to_string("/proc/self/attr/current")?;
    if args.len() == 4 && args[1] == "mount" {
        if context.trim_matches('\0').trim() != "u:r:ksu:s0" {
            return Err("mount diagnostic requires management domain".into());
        }
        let target = CString::new(args[2].as_str())?;
        let options = CString::new(args[3].as_str())?;
        let rc = unsafe {
            libc::mount(
                c"binder".as_ptr(),
                target.as_ptr(),
                c"binder".as_ptr(),
                libc::MS_NOSUID | libc::MS_NOEXEC,
                options.as_ptr().cast(),
            )
        };
        let errno = if rc == 0 {
            None
        } else {
            std::io::Error::last_os_error().raw_os_error()
        };
        println!(
            "{}",
            serde_json::json!({"mount_options":args[3],"rc":rc,"errno":errno,"context":context,"user_namespace":fs::read_link("/proc/self/ns/user").ok().map(|p|p.to_string_lossy().into_owned())})
        );
        std::process::exit(if rc == 0 { 0 } else { 1 });
    }
    if args.len() != 5
        || args[1] != "access"
        || context.trim_matches('\0').trim() != "u:r:servicemanager:s0"
    {
        return Err("usage: enforcing servicemanager access PRIVATE_PATH MAJOR MINOR".into());
    }
    if fs::read_to_string("/sys/fs/selinux/enforce")?.trim() != "1" {
        return Err("global SELinux not enforcing".into());
    }
    let meta = fs::metadata(&args[2])?;
    let expected = libc::makedev(args[3].parse()?, args[4].parse()?);
    if !meta.file_type().is_char_device()
        || meta.rdev() != expected
        || meta.rdev() == fs::metadata("/dev/binder")?.rdev()
    {
        return Err("private device identity mismatch".into());
    }
    let file = OpenOptions::new().read(true).write(true).open(&args[2])?;
    let actual = file.metadata()?;
    if (actual.dev(), actual.ino(), actual.rdev()) != (meta.dev(), meta.ino(), meta.rdev()) {
        return Err("opened identity mismatch".into());
    }
    println!(
        "{}",
        serde_json::json!({"context":context,"pid":std::process::id(),"uid":unsafe{libc::getuid()},"open":"passed","rdev":actual.rdev()})
    );
    let mut version: i32 = 0;
    let mut write_read = [0u64; 6];
    let mut manager = [0u64; 3];
    for (name, command, data) in [
        (
            "BINDER_VERSION",
            0xc0046209u32,
            (&mut version as *mut i32).cast::<libc::c_void>(),
        ),
        (
            "BINDER_WRITE_READ_EMPTY",
            0xc0306201u32,
            write_read.as_mut_ptr().cast(),
        ),
        (
            "BINDER_SET_CONTEXT_MGR_EXT",
            0x4018620du32,
            manager.as_mut_ptr().cast(),
        ),
    ] {
        let rc = unsafe { libc::ioctl(file.as_raw_fd(), command as _, data) };
        let errno = if rc == 0 {
            None
        } else {
            std::io::Error::last_os_error().raw_os_error()
        };
        println!(
            "{}",
            serde_json::json!({"ioctl":name,"rc":rc,"errno":errno,"scope":"ioctl_dispatch_only_not_ipc_or_service_contexts"})
        );
    }
    let mapping = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_READ,
            libc::MAP_PRIVATE,
            file.as_raw_fd(),
            0,
        )
    };
    let errno = if mapping == libc::MAP_FAILED {
        std::io::Error::last_os_error().raw_os_error()
    } else {
        unsafe { libc::munmap(mapping, 4096) };
        None
    };
    println!(
        "{}",
        serde_json::json!({"mmap_errno":errno,"version":version,"ipc":"not_run","service_contexts":"not_run"})
    );
    Ok(())
}
#[cfg(not(unix))]
fn main() {
    std::process::exit(1);
}
