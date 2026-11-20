//! Validates private mount namespace procfs hidepid=4 isolation without touching Host /proc.
use std::env;
use std::ffi::{CStr, CString};
use std::fmt::Write as _;
use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::process::ExitCode;
use std::sync::atomic::{AtomicI32, Ordering};

const REPORT_TEXT_CAP: usize = 16384;
const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

#[repr(C)]
struct Report {
    ready: AtomicI32,
    used: usize,
    text: [u8; REPORT_TEXT_CAP],
}

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

type SetConFn = unsafe extern "C" fn(*const libc::c_char) -> libc::c_int;

unsafe fn append_report(out: *mut Report, args: std::fmt::Arguments<'_>) {
    let mut buf = String::new();
    let _ = buf.write_fmt(args);
    let bytes = buf.as_bytes();
    let r = &mut *out;
    if r.used + bytes.len() >= REPORT_TEXT_CAP {
        libc::_exit(20);
    }
    std::ptr::copy_nonoverlapping(bytes.as_ptr(), r.text.as_mut_ptr().add(r.used), bytes.len());
    r.used += bytes.len();
}

unsafe fn blocked(out: *mut Report, stage: &str) -> ! {
    let err = io::Error::last_os_error().raw_os_error().unwrap_or(0);
    append_report(out, format_args!("BLOCKED stage={stage} errno={err}\n"));
    libc::_exit(3);
}

fn option(list: &str, key: &str) -> bool {
    list.split(',').any(|entry| entry == key)
}

/// Inspect only optional propagation fields, never substrings in path names.
fn private_line(line: &str) -> bool {
    for field in line.split(' ').skip(6) {
        if field == "-" {
            return true;
        }
        if field.starts_with("shared:")
            || field.starts_with("master:")
            || field.starts_with("propagate_from:")
        {
            return false;
        }
    }
    false
}

unsafe fn mount_check(out: *mut Report, path: &str, require_private: bool, guest: bool) -> bool {
    let Ok(content) = fs::read_to_string("/proc/self/mountinfo") else {
        return false;
    };
    let mut found = 0usize;
    let mut ok = true;
    let mut count = 0usize;
    for line in content.lines() {
        count += 1;
        if require_private && !private_line(line) {
            ok = false;
        }
        let Some((before, after)) = line.split_once(" - ") else {
            ok = false;
            continue;
        };
        let Some(target) = before.split_whitespace().nth(4) else {
            ok = false;
            continue;
        };
        if target != path {
            continue;
        }
        let mut tail = after.split_whitespace();
        let (Some(fs_type), Some(_source), Some(opts)) = (tail.next(), tail.next(), tail.next())
        else {
            ok = false;
            continue;
        };
        append_report(out, format_args!("mount_record {line}\n"));
        found += 1;
        if fs_type != "proc" {
            ok = false;
        }
        if guest {
            if !(option(opts, "hidepid=4") || option(opts, "hidepid=ptraceable"))
                || option(opts, "gid=3009")
            {
                ok = false;
            }
        } else if !option(opts, "hidepid=invisible") || !option(opts, "gid=3009") {
            ok = false;
        }
    }
    append_report(
        out,
        format_args!(
            "propagation private_required={} records={count} result={}\n",
            u8::from(require_private),
            if ok { "PASS" } else { "FAIL" }
        ),
    );
    ok && count > 0 && found == 1
}

unsafe fn identity(out: *mut Report, setcon_fn: SetConFn) {
    if libc::setgroups(0, std::ptr::null()) != 0
        || libc::setresgid(1000, 1000, 1000) != 0
        || libc::setresuid(1000, 1000, 1000) != 0
        || setcon_fn(c"u:r:system_server:s0".as_ptr()) != 0
        || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
    {
        blocked(out, "credentials");
    }
    let (mut r, mut e, mut s) = (0, 0, 0);
    let (mut gr, mut ge, mut gs) = (0, 0, 0);
    let mut groups = [0 as libc::gid_t; 128];
    let mut hdr = CapUserHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut caps = [CapUserData::default(); 2];
    let Ok(sid) = fs::read_to_string("/proc/self/attr/current") else {
        blocked(out, "identity_readback");
    };
    let sid = sid.trim_end_matches('\0');
    let ng = libc::getgroups(groups.len() as libc::c_int, groups.as_mut_ptr());
    if libc::getresuid(&mut r, &mut e, &mut s) != 0
        || libc::getresgid(&mut gr, &mut ge, &mut gs) != 0
        || ng < 0
        || libc::syscall(libc::SYS_capget, &mut hdr as *mut _, caps.as_mut_ptr()) != 0
    {
        blocked(out, "identity_readback");
    }
    append_report(
        out,
        format_args!(
            "identity uid={r}/{e}/{s} gid={gr}/{ge}/{gs} sid={sid} CapEff={:08x}{:08x} groups=",
            caps[1].effective, caps[0].effective
        ),
    );
    let mut exception = gr == 3009 || ge == 3009 || gs == 3009;
    for &g in &groups[..ng as usize] {
        append_report(out, format_args!("{g},"));
        exception |= g == 3009;
    }
    append_report(
        out,
        format_args!(
            " count={ng} gid3009_exception={}\n",
            u8::from(exception)
        ),
    );
    let valid = r == 1000
        && e == 1000
        && s == 1000
        && gr == 1000
        && ge == 1000
        && gs == 1000
        && sid == "u:r:system_server:s0"
        && caps[0].effective == 0
        && caps[1].effective == 0
        && !exception
        && ng == 0;
    if !valid {
        blocked(out, "identity_mismatch");
    }
}

unsafe fn probe(
    out: *mut Report,
    dir: &str,
    canary: libc::pid_t,
    parent_ns: (u64, u64),
    host_ns: (u64, u64),
    setcon_fn: SetConFn,
) -> ! {
    let Ok(tasks) = fs::read_dir("/proc/self/task") else {
        blocked(out, "task_count");
    };
    let count = tasks.filter_map(Result::ok).count();
    if count != 1 {
        blocked(out, "single_thread");
    }
    if libc::unshare(libc::CLONE_NEWNS) != 0 {
        blocked(out, "unshare");
    }
    let Ok(ns_meta) = fs::metadata("/proc/self/ns/mnt") else {
        blocked(out, "namespace_stat");
    };
    let ns = (ns_meta.dev(), ns_meta.ino());
    append_report(
        out,
        format_args!(
            "namespace parent={} host={} child={} single_thread={count}\n",
            parent_ns.1, host_ns.1, ns.1
        ),
    );
    if ns == parent_ns || ns == host_ns {
        blocked(out, "namespace_independence");
    }
    if !mount_check(out, "/proc", false, false) {
        blocked(out, "pre_private_mountinfo");
    }
    // This is the only propagation mutation, after proving namespace separation.
    if libc::mount(
        std::ptr::null(),
        c"/".as_ptr(),
        std::ptr::null(),
        libc::MS_REC | libc::MS_PRIVATE,
        std::ptr::null(),
    ) != 0
    {
        blocked(out, "make_private");
    }
    if !mount_check(out, "/proc", true, false) {
        blocked(out, "pre_mount_propagation");
    }
    let cdir = CString::new(dir).unwrap();
    if libc::mount(
        c"proc".as_ptr(),
        cdir.as_ptr(),
        c"proc".as_ptr(),
        libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
        c"hidepid=4".as_ptr().cast(),
    ) != 0
    {
        blocked(out, "procfs_mount");
    }
    if !mount_check(out, dir, true, true) {
        blocked(out, "post_mount_verification");
    }
    append_report(out, format_args!("ENVIRONMENT=PASS\n"));
    identity(out, setcon_fn);

    let Ok(entries) = fs::read_dir(dir) else {
        blocked(out, "procfs_readdir");
    };
    let canary_str = canary.to_string();
    let seen = entries
        .filter_map(Result::ok)
        .any(|e| e.file_name().to_string_lossy() == canary_str);
    append_report(out, format_args!("canary readdir seen={} errno=0\n", u8::from(seen)));
    let mut hidden = !seen;
    for (i, suffix) in ["", "/root", "/fd", "/fd/0"].iter().enumerate() {
        let path = format!("{dir}/{canary}{suffix}");
        let cpath = CString::new(path.as_str()).unwrap();
        let mut st: libc::stat = std::mem::zeroed();
        let rc = libc::stat(cpath.as_ptr(), &mut st);
        let err = if rc == 0 {
            0
        } else {
            io::Error::last_os_error().raw_os_error().unwrap_or(0)
        };
        append_report(
            out,
            format_args!("canary stat suffix={suffix} rc={rc} errno={err}\n"),
        );
        hidden &= rc == -1 && err == libc::ENOENT;
        if i == 0 {
            continue;
        }
        let fd = libc::open(
            cpath.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK,
        );
        let err = if fd < 0 {
            io::Error::last_os_error().raw_os_error().unwrap_or(0)
        } else {
            0
        };
        append_report(
            out,
            format_args!(
                "canary open suffix={suffix} rc={} errno={err}\n",
                if fd < 0 { -1 } else { 0 }
            ),
        );
        hidden &= fd < 0 && err == libc::ENOENT;
        if fd >= 0 {
            libc::close(fd);
        }
    }
    append_report(
        out,
        format_args!("HIDEPID4={}\n", if hidden { "PASS" } else { "FAIL" }),
    );
    libc::_exit(i32::from(!hidden));
}

unsafe fn child_setup(parent: libc::pid_t) {
    if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 || libc::getppid() != parent {
        libc::_exit(3);
    }
    libc::alarm(15);
}

unsafe fn reap(pid: libc::pid_t) -> i32 {
    let mut status: libc::c_int = 0;
    for _ in 0..1000 {
        let rc = libc::waitpid(pid, &mut status, libc::WNOHANG);
        if rc == pid {
            return if libc::WIFEXITED(status) {
                libc::WEXITSTATUS(status)
            } else {
                3
            };
        }
        if rc < 0 && io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            return 3;
        }
        libc::usleep(10_000);
    }
    libc::kill(pid, libc::SIGKILL);
    while libc::waitpid(pid, &mut status, 0) < 0
        && io::Error::last_os_error().raw_os_error() == Some(libc::EINTR)
    {}
    3
}

fn self_test() -> ExitCode {
    assert!(option("rw,hidepid=4,gid=0", "hidepid=4"));
    assert!(!option("rw,hidepid=40", "hidepid=4"));
    assert!(private_line("1 0 0:1 / / rw - rootfs rootfs rw\n"));
    assert!(!private_line("1 0 0:1 / / rw shared:1 - rootfs rootfs rw\n"));
    assert!(!private_line("1 0 0:1 / / rw master:1 - rootfs rootfs rw\n"));
    assert!(!private_line(
        "1 0 0:1 / / rw propagate_from:1 - rootfs rootfs rw\n"
    ));
    assert!(!private_line("malformed"));
    println!("SELF_TEST=PASS");
    ExitCode::SUCCESS
}

fn main() -> ExitCode {
    let args: Vec<_> = env::args().collect();
    if args.len() == 2 && args[1] == "--self-test" {
        return self_test();
    }
    if args.len() != 1 {
        return ExitCode::from(2);
    }
    unsafe {
        let mapped = libc::mmap(
            std::ptr::null_mut(),
            3 * std::mem::size_of::<Report>(),
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        if mapped == libc::MAP_FAILED {
            return ExitCode::from(3);
        }
        let reports: *mut Report = mapped.cast();
        let before = fs::read_to_string("/proc/1/mountinfo").ok();
        let local = fs::read_to_string("/proc/self/mountinfo").ok();
        let enforce = fs::read_to_string("/sys/fs/selinux/enforce").ok();
        let parent_meta = fs::metadata("/proc/self/ns/mnt").ok();
        let host_meta = fs::metadata("/proc/1/ns/mnt").ok();
        if before.is_none()
            || local.is_none()
            || enforce.as_deref() != Some("1")
            || parent_meta.is_none()
            || host_meta.is_none()
            || !mount_check(reports.add(0), "/proc", false, false)
        {
            println!("BLOCKED stage=host_baseline no_children_no_mounts");
            return ExitCode::from(3);
        }
        let parent_ns = (parent_meta.as_ref().unwrap().dev(), parent_meta.as_ref().unwrap().ino());
        let host_ns = (host_meta.as_ref().unwrap().dev(), host_meta.as_ref().unwrap().ino());
        let lib = libc::dlopen(c"libselinux.so".as_ptr(), libc::RTLD_NOW);
        let setcon_sym = if lib.is_null() {
            std::ptr::null_mut()
        } else {
            libc::dlsym(lib, c"setcon".as_ptr())
        };
        let mut dir_tpl = *b"/dev/ssal-procfs-XXXXXX\0";
        let mkd = if setcon_sym.is_null() {
            std::ptr::null_mut()
        } else {
            libc::mkdtemp(dir_tpl.as_mut_ptr().cast())
        };
        if mkd.is_null() || libc::chmod(dir_tpl.as_ptr().cast(), 0o755) != 0 {
            println!("BLOCKED stage=setup");
            return ExitCode::from(3);
        }
        let setcon_fn: SetConFn = std::mem::transmute(setcon_sym);
        let dir = CStr::from_ptr(dir_tpl.as_ptr().cast()).to_str().unwrap().to_owned();

        let owner = libc::getpid();
        let canary = libc::fork();
        let mut child: libc::pid_t = -1;
        let mut result = 3;
        if canary == 0 {
            let out = reports.add(1);
            child_setup(owner);
            let fd = libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY);
            if fd < 0 || libc::dup2(fd, 0) < 0 {
                blocked(out, "canary_fd0");
            }
            if fd != 0 {
                libc::close(fd);
            }
            identity(out, setcon_fn);
            if libc::prctl(libc::PR_SET_DUMPABLE, 1) != 0 {
                blocked(out, "canary_dumpable");
            }
            append_report(out, format_args!("CANARY_READY pid={}\n", libc::getpid()));
            (*out).ready.store(1, Ordering::Release);
            loop {
                libc::pause();
            }
        }
        if canary > 0 {
            for _ in 0..200 {
                if (*reports.add(1)).ready.load(Ordering::Acquire) != 0 {
                    break;
                }
                libc::usleep(10_000);
            }
            if (*reports.add(1)).ready.load(Ordering::Acquire) != 0 {
                child = libc::fork();
                if child == 0 {
                    let out = reports.add(2);
                    child_setup(owner);
                    probe(out, &dir, canary, parent_ns, host_ns, setcon_fn);
                }
                if child > 0 {
                    result = reap(child);
                }
            }
            let mut info: libc::siginfo_t = std::mem::zeroed();
            if libc::waitid(libc::P_PID, canary as libc::id_t, &mut info, libc::WEXITED | libc::WNOHANG | libc::WNOWAIT) != 0
                || info.si_pid() != 0
            {
                println!("BLOCKED stage=canary_not_alive_at_completion");
                result = 3;
            }
            libc::kill(canary, libc::SIGKILL);
            reap(canary);
        }

        for i in 0..3 {
            let r = &*reports.add(i);
            let text = String::from_utf8_lossy(&r.text[..r.used]);
            print!("REPORT_{i}\n{text}");
        }
        println!("CHILDREN_REAPED probe={child} canary={canary}");
        if fs::remove_dir(&dir).is_err() {
            eprintln!("temporary_directory_cleanup: {}", io::Error::last_os_error());
            result = 3;
        }
        let after = fs::read_to_string("/proc/1/mountinfo").ok();
        let after_local = fs::read_to_string("/proc/self/mountinfo").ok();
        let after_enforce = fs::read_to_string("/sys/fs/selinux/enforce").ok();
        let unchanged = after.is_some()
            && after_local.is_some()
            && after_enforce.is_some()
            && before == after
            && local == after_local
            && enforce == after_enforce
            && mount_check(reports.add(0), "/proc", false, false);
        println!(
            "HOST_STATE={} init_mountinfo={} supervisor_mountinfo={} enforcing={}",
            if unchanged { "UNCHANGED" } else { "FAIL" },
            if after.is_some() && before == after { "SAME" } else { "FAIL" },
            if after_local.is_some() && local == after_local { "SAME" } else { "FAIL" },
            if after_enforce.as_deref() == Some("1") { "YES" } else { "FAIL" },
        );
        let status_str = if result == 3 {
            "BLOCKED"
        } else if result != 0 {
            "FAIL"
        } else {
            "COMPLETE"
        };
        println!("PROBE_RESULT={status_str} exit={result}");
        let code = if unchanged { result } else { 4 };
        ExitCode::from(code as u8)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mount_option_and_propagation_parsing() {
        assert!(option("rw,hidepid=4,gid=0", "hidepid=4"));
        assert!(!option("rw,hidepid=40", "hidepid=4"));
        assert!(private_line("1 0 0:1 / / rw - rootfs rootfs rw\n"));
        assert!(!private_line("1 0 0:1 / / rw shared:1 - rootfs rootfs rw\n"));
        assert!(!private_line("1 0 0:1 / / rw master:1 - rootfs rootfs rw\n"));
        assert!(!private_line(
            "1 0 0:1 / / rw propagate_from:1 - rootfs rootfs rw\n"
        ));
        assert!(!private_line("malformed"));
    }
}
