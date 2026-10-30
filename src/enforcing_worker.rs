use serde_json::json;
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::process::CommandExt;
use std::process::Command;

#[path = "binder_wire.rs"]
mod wire;
const MANAGER: &str = "u:r:servicemanager:s0";
const CLIENT: &str = "u:r:shell:s0";
fn check(rc: i32) -> io::Result<()> {
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}
fn cpath(path: &str) -> io::Result<CString> {
    CString::new(path).map_err(io::Error::other)
}
#[repr(C)]
struct Header {
    version: u32,
    pid: i32,
}
#[repr(C)]
#[derive(Default, Clone, Copy)]
struct Cap {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}
fn read_fd(fd: i32) -> io::Result<String> {
    let mut file = unsafe { File::from_raw_fd(fd) };
    let mut out = String::new();
    file.read_to_string(&mut out)?;
    Ok(out.trim_matches('\0').trim().into())
}

pub fn main() -> io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 9 && args[1] == "launch" {
        return launch(&args);
    }
    if args.len() != 14 || args[1] != "observe" {
        return Err(io::Error::other("fixed probe arguments required"));
    }
    let number = |i: usize| args[i].parse::<u64>().map_err(io::Error::other);
    let target = if args[11] == "client" {
        CLIENT
    } else {
        MANAGER
    };
    let current = read_fd(number(7)? as i32)?;
    let status = read_fd(number(8)? as i32)?;
    let enforcing = read_fd(number(9)? as i32)?;
    // The only inherited observation FDs are now closed. No proc/root/driver FD remains.
    let mut header = Header {
        version: 0x20080522,
        pid: 0,
    };
    let mut caps = [Cap::default(); 2];
    check(unsafe { libc::syscall(libc::SYS_capget, &mut header, caps.as_mut_ptr()) } as i32)?;
    let cap_last = number(10)? as i32;
    let mut groups = [0; 64];
    let n = unsafe { libc::getgroups(64, groups.as_mut_ptr()) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    let extras: Vec<_> = (3..1024)
        .filter(|fd| unsafe { libc::fcntl(*fd, libc::F_GETFD) } >= 0)
        .collect();
    let actual_root = fs::metadata("/")?;
    let root_matches = actual_root.dev() == number(12)? && actual_root.ino() == number(13)?;
    let limit = |resource| -> io::Result<[u64; 2]> {
        let mut value = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        check(unsafe { libc::getrlimit(resource, &mut value) })?;
        Ok([value.rlim_cur, value.rlim_max])
    };
    let nofile = limit(libc::RLIMIT_NOFILE)?;
    let core = limit(libc::RLIMIT_CORE)?;
    let mut stdio = Vec::new();
    for fd in 0..=2 {
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        check(unsafe { libc::fstat(fd, &mut stat) })?;
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        stdio.push(json!({"fd":fd,"mode":stat.st_mode,"rdev":stat.st_rdev,"access_mode":flags&libc::O_ACCMODE,"fd_flags":unsafe{libc::fcntl(fd,libc::F_GETFD)}}));
    }
    let stdio_valid = stdio[0]["rdev"] == libc::makedev(1, 3)
        && stdio[0]["access_mode"] == libc::O_RDONLY
        && stdio[1..].iter().all(|v| {
            v["mode"]
                .as_u64()
                .is_some_and(|m| m & u64::from(libc::S_IFMT) == u64::from(libc::S_IFIFO))
                && v["access_mode"] == libc::O_WRONLY
        });
    let environment = std::env::vars().collect::<std::collections::BTreeMap<_, _>>();
    let environment_valid = json!(environment)
        == json!({"PATH":"/system/bin","ANDROID_ROOT":"/system","ANDROID_DATA":"/data"});
    let credentials = unsafe { libc::getuid() == 1000 && libc::geteuid() == 1000 && libc::getgid() == 1000 && libc::getegid() == 1000 }
        && groups[..n as usize] == [3009]
        && caps.iter().all(|c| c.effective == 0 && c.permitted == 0 && c.inheritable == 0)
        && (0..=cap_last).all(|c| unsafe { libc::prctl(libc::PR_CAPBSET_READ, c, 0, 0, 0) } == 0)
        && (0..=cap_last).all(|c| unsafe { libc::prctl(libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_IS_SET, c, 0, 0) } == 0)
        && extras.is_empty() && root_matches && nofile==[1024,1024] && core==[0,0] && stdio_valid && environment_valid;
    println!(
        "{}",
        json!({"event":"post_exec","context":current,"status":status,"global_enforcing":enforcing,"uid":unsafe{libc::getuid()},"gid":unsafe{libc::getgid()},"groups":&groups[..n as usize],"extra_fds":extras,"root_matches":root_matches,"nofile":nofile,"core":core,"stdio":stdio,"stdio_valid":stdio_valid,"environment":environment,"credentials_valid":credentials,"nnp_order":args[6],"no_new_privs_at_exec":unsafe{libc::prctl(libc::PR_GET_NO_NEW_PRIVS,0,0,0,0)}})
    );
    if current != target || enforcing != "1" || !credentials {
        return Err(io::Error::other(
            "post-exec domain/enforcing/credentials gate",
        ));
    }
    check(unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) })?;
    if unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) } != 1 {
        return Err(io::Error::other("NoNewPrivs gate"));
    }
    let mut access = json!({});
    for path in [
        "/proc/1/root/dev/binder",
        "/proc/self/root/dev/binder",
        "/proc/1/fd",
        "/proc/self/fd",
        "/dev/binderfs/binder",
        "/dev/hwbinder",
        "/dev/vndbinder",
        "/dev/kmsg",
        "/dev/__properties__/properties_serial",
        "/dev/socket/property_service",
        "/dev/socket/property_service_for_system",
    ] {
        let flags = if path == "/dev/kmsg" {
            libc::O_WRONLY | libc::O_NONBLOCK
        } else {
            libc::O_PATH
        };
        let fd = unsafe { libc::open(cpath(path)?.as_ptr(), flags | libc::O_CLOEXEC) };
        let errno = if fd < 0 {
            io::Error::last_os_error().raw_os_error()
        } else {
            unsafe {
                libc::close(fd);
            }
            None
        };
        access[path] = json!({"syscall":"open","flags":flags,"errno":errno,"opened":fd>=0});
    }
    println!(
        "{}",
        json!({"event":"nonexposure","paths":access,"scope":"listed paths in empty proc/minimal dev; no Host driver open or ioctl","no_new_privs":1})
    );
    if access
        .as_object()
        .unwrap()
        .values()
        .any(|v| v["opened"] == true)
    {
        return Err(io::Error::other(
            "unexpected exposed alias or Host resource",
        ));
    }
    let identity = [number(2)?, number(3)?, number(4)?, number(5)?];
    if args[11] == "negative" {
        return wire::reject_default(identity);
    }
    for fd in 0..=2 {
        check(unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) })?;
    }
    match args[11].as_str() {
        "server" => wire::serve(identity),
        "client" => wire::request(identity),
        "raw" => wire::selftest(identity),
        _ => Err(io::Error::other("fixed worker role")),
    }
}

fn launch(args: &[String]) -> io::Result<()> {
    if unsafe { libc::geteuid() } != 0
        || fs::read_to_string("/proc/self/attr/current")?
            .trim_matches('\0')
            .trim()
            != "u:r:ksu:s0"
    {
        return Err(io::Error::other("management launch credentials"));
    }
    if !["before", "after"].contains(&args[7].as_str()) {
        return Err(io::Error::other("NNP order"));
    }
    if ![
        "raw",
        "libbinder",
        "negative",
        "server",
        "client",
        "libserver",
        "libclient",
    ]
    .contains(&args[8].as_str())
    {
        return Err(io::Error::other("fixed engine"));
    }
    let client = ["client", "libclient"].contains(&args[8].as_str());
    let target = if client { CLIENT } else { MANAGER };
    let root = &args[2];
    let root_meta = fs::metadata(root)?;
    let meta = fs::metadata(format!("{root}/dev/binder"))?;
    let nums = args[3..7]
        .iter()
        .map(|s| s.parse::<u64>().map_err(io::Error::other))
        .collect::<io::Result<Vec<_>>>()?;
    if args[8] != "negative"
        && (!meta.file_type().is_char_device()
            || [meta.dev(), meta.ino(), meta.rdev()] != nums[..3]
            || meta.rdev() == nums[3])
    {
        return Err(io::Error::other("private identity launch gate"));
    }
    if args[8] == "negative" && (!meta.is_file() || meta.mode() & 0o777 != 0) {
        return Err(io::Error::other(
            "negative control must be private mode 000 regular file",
        ));
    }
    let cap_last: i32 = fs::read_to_string("/proc/sys/kernel/cap_last_cap")?
        .trim()
        .parse()
        .map_err(io::Error::other)?;
    if !(0..=63).contains(&cap_last) {
        return Err(io::Error::other("cap_last_cap"));
    }
    // These refer to this same PID across exec, are read-only, and close before Binder.
    let observations = [
        File::open("/proc/self/attr/current")?,
        File::open("/proc/self/status")?,
        File::open("/sys/fs/selinux/enforce")?,
    ];
    let mut transition = OpenOptions::new()
        .write(true)
        .open("/proc/self/attr/exec")?;
    transition.write_all(cpath(target)?.as_bytes_with_nul())?;
    drop(transition);
    check(unsafe { libc::unshare(libc::CLONE_NEWNS) })?;
    check(unsafe {
        libc::mount(
            std::ptr::null(),
            c"/".as_ptr(),
            std::ptr::null(),
            libc::MS_PRIVATE | libc::MS_REC,
            std::ptr::null(),
        )
    })?;
    for (name, flag) in [
        ("net", libc::CLONE_NEWNET),
        ("uts", libc::CLONE_NEWUTS),
        ("ipc", libc::CLONE_NEWIPC),
    ] {
        let rc = unsafe { libc::unshare(flag) };
        let errno = if rc < 0 {
            io::Error::last_os_error().raw_os_error()
        } else {
            None
        };
        println!(
            "{}",
            json!({"event":"namespace","name":name,"rc":rc,"errno":errno})
        );
        if rc != 0 && name != "ipc" {
            return Err(io::Error::other("required namespace failed"));
        }
    }
    for (resource, limit) in [(libc::RLIMIT_NOFILE, 1024), (libc::RLIMIT_CORE, 0)] {
        check(unsafe {
            libc::setrlimit(
                resource,
                &libc::rlimit {
                    rlim_cur: limit,
                    rlim_max: limit,
                },
            )
        })?;
    }
    // Set CLOEXEC for every inherited descriptor, including any above the new rlimit.
    for entry in fs::read_dir("/proc/self/fd")? {
        let fd: i32 = entry?
            .file_name()
            .to_string_lossy()
            .parse()
            .map_err(io::Error::other)?;
        if fd > 2 && unsafe { libc::fcntl(fd, libc::F_GETFD) } >= 0 {
            check(unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) })?;
        }
    }
    for file in &observations {
        check(unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFD, 0) })?;
    }
    check(unsafe { libc::chroot(cpath(root)?.as_ptr()) })?;
    check(unsafe { libc::chdir(c"/".as_ptr()) })?;
    check(unsafe {
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL,
            0,
            0,
            0,
        )
    })?;
    for cap in 0..=cap_last {
        check(unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0) })?;
    }
    check(unsafe { libc::prctl(libc::PR_SET_KEEPCAPS, 0, 0, 0, 0) })?;
    check(unsafe { libc::setgroups(1, [3009 as libc::gid_t].as_ptr()) })?;
    check(unsafe { libc::setresgid(1000, 1000, 1000) })?;
    check(unsafe { libc::setresuid(1000, 1000, 1000) })?;
    check(unsafe {
        libc::syscall(
            libc::SYS_capset,
            &Header {
                version: 0x20080522,
                pid: 0,
            },
            [Cap::default(); 2].as_ptr(),
        )
    } as i32)?;
    if args[7] == "before" {
        check(unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) })?;
    }
    let mut command = if ["libbinder", "libserver", "libclient"].contains(&args[8].as_str()) {
        let mut cmd = Command::new(if client {
            "/data/local/tmp/ssal-binder-client"
        } else {
            "/data/local/tmp/ssal-binder-probe"
        });
        cmd.args([
            match args[8].as_str() {
                "libserver" => "enforcing-server",
                "libclient" => "enforcing-client",
                _ => "enforcing-selftest",
            },
            "/dev/binder",
            &libc::major(nums[2]).to_string(),
            &libc::minor(nums[2]).to_string(),
        ]);
        for file in &observations {
            cmd.arg(file.as_raw_fd().to_string());
        }
        cmd.arg(root_meta.dev().to_string())
            .arg(root_meta.ino().to_string());
        cmd
    } else {
        let mut cmd = Command::new(if client {
            "/data/local/tmp/ssal-enforcing-client"
        } else {
            "/data/local/tmp/ssal-enforcing-binder"
        });
        cmd.arg("observe").args(&args[3..7]).arg(&args[7]);
        for file in &observations {
            cmd.arg(file.as_raw_fd().to_string());
        }
        cmd.arg(cap_last.to_string())
            .arg(&args[8])
            .arg(root_meta.dev().to_string())
            .arg(root_meta.ino().to_string());
        cmd
    };
    command
        .env_clear()
        .env("PATH", "/system/bin")
        .env("ANDROID_ROOT", "/system")
        .env("ANDROID_DATA", "/data");
    let error = command.exec();
    println!(
        "{}",
        json!({"event":"execve","syscall":"execve","errno":error.raw_os_error(),"error":error.to_string(),"target":target,"entrypoint":if client{"u:object_r:shell_exec:s0"}else{"u:object_r:servicemanager_exec:s0"},"nnp_order":args[7]})
    );
    Err(error)
}
