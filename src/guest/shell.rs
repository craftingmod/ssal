//! Shell execution has no dependency on Binder, Zygote or SystemServer.
use crate::guest::{environment, prepare};
use ssal::namespace_mounts::{mount, Mounts};
use std::fs::{self, File};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::Path;
use std::process::Command;
use std::sync::{
    atomic::{AtomicI32, Ordering},
    OnceLock,
};

struct Options {
    words: Vec<String>,
    stdout: File,
}
static OPTIONS: OnceLock<Options> = OnceLock::new();
static EXIT: AtomicI32 = AtomicI32::new(0);

fn exit_code(status: std::process::ExitStatus) -> i32 {
    status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(1))
}

pub(crate) fn session(name: &str, words: &[String]) -> io::Result<i32> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(io::Error::other("root required"));
    }
    let root = Path::new(ssal::unix::ROOT);
    let name = if name.is_empty() {
        let names = fs::read_dir(root.join("guests"))?
            .filter_map(Result::ok)
            .filter(|entry| entry.path().join("profile.json").is_file())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        if names.len() != 1 {
            return Err(io::Error::other(
                "specify PROFILE_NAME when there is not exactly one Guest profile",
            ));
        }
        names[0].clone()
    } else {
        name.to_owned()
    };
    if !ssal::unix::valid_image_name(&name) {
        return Err(io::Error::other("invalid profile name"));
    }
    let profile_dir = root.join("guests").join(&name);
    let admission = environment::admission(&profile_dir)?;
    let saved = unsafe { libc::fcntl(1, libc::F_DUPFD_CLOEXEC, 3) };
    if saved < 0 {
        return Err(io::Error::last_os_error());
    }
    let stdout = unsafe { File::from_raw_fd(saved) };
    OPTIONS
        .set(Options {
            words: words.to_vec(),
            stdout,
        })
        .map_err(|_| io::Error::other("Shell session already configured"))?;
    if let Some(attached) = environment::attach(&profile_dir)? {
        attached.enter()?;
        use crate::guest::concurrent::graphics;
        if attached.root.join("dev").join(graphics::KGSL).exists() != graphics::requested() {
            return Err(io::Error::other(
                "graphics mode must match the active Guest shell session",
            ));
        }
        drop(admission);
        return isolated(&attached.root);
    }
    let log_path = root
        .join("logs")
        .join(format!("shell-{}.log", std::process::id()));
    let log = File::create(&log_path)?;
    eprintln!(
        "ssal: preparing Guest environment; details: {}",
        log_path.display()
    );
    if unsafe { libc::dup2(log.as_raw_fd(), 1) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let profile = prepare::check(root, &name)?;
    if unsafe { libc::unshare(libc::CLONE_NEWNET) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let base = root
        .join("mnt")
        .join(format!("shell-{}", std::process::id()));
    fs::create_dir(&base)?;
    let result = (|| {
        fs::create_dir(base.join("system"))?;
        fs::create_dir(base.join("data"))?;
        prepare::worker_admitted(
            &profile.system,
            &profile.userdata,
            &base,
            "--shell-worker",
            false,
            Some(admission),
        )
    })();
    // Never recursively remove a session path unless all namespace mounts are gone.
    let info = fs::read_to_string("/proc/self/mountinfo")?;
    if info
        .lines()
        .filter_map(|line| line.split_whitespace().nth(4))
        .any(|path| Path::new(path).starts_with(&base))
    {
        return Err(io::Error::other(format!(
            "Shell session has residual mounts: {}; previous result: {result:?}",
            base.display()
        )));
    }
    fs::remove_dir_all(&base)?;
    result?;
    Ok(EXIT.load(Ordering::SeqCst))
}

pub(crate) fn standalone(
    mounts: &mut Mounts,
    root: &Path,
    profile: &Path,
    host_namespace: &Path,
    admission: &mut Option<File>,
) -> io::Result<()> {
    crate::guest::runtime::linkerconfig::linkerconfig(root)?;
    let bin = std::env::current_exe()?
        .parent()
        .ok_or_else(|| io::Error::other("binary directory missing"))?
        .to_owned();
    let mut properties = environment::start_property_service(mounts, root, &bin, host_namespace, false)?;
    crate::guest::mount::seal_system(root)?;
    let published = environment::Published::new(profile, root, admission.take())?;
    let result = isolated(root);
    *admission = Some(published.finish()?);
    properties.stop()?;
    fs::remove_file(root.join("dev/socket/property_service"))?;
    fs::remove_file(root.join("dev/socket/property_service_for_system"))?;
    EXIT.store(result?, Ordering::SeqCst);
    Ok(())
}

fn isolated(root: &Path) -> io::Result<i32> {
    let options = OPTIONS
        .get()
        .ok_or_else(|| io::Error::other("Shell options missing"))?;
    let mut command = Command::new(std::env::current_exe()?);
    command.arg0("ssal-shell");
    command
        .arg("--shell-fork")
        .arg(root)
        .arg("--")
        .args(&options.words)
        .stdout(options.stdout.try_clone()?);
    ssal::shell_transport::kill_with_parent(&mut command)?;
    unsafe {
        command.pre_exec(|| {
            // shortcut: kernels without CONFIG_PID_NS use SELinux and proc DAC; use PID isolation when supported.
            let pid_namespace = if Path::new("/proc/self/ns/pid").exists() {
                libc::CLONE_NEWPID
            } else {
                0
            };
            let network = if fs::read_link("/proc/self/ns/net")? == fs::read_link("/proc/1/ns/net")?
            {
                libc::CLONE_NEWNET
            } else {
                0
            };
            if libc::unshare(pid_namespace | libc::CLONE_NEWNS | network) != 0 {
                return Err(io::Error::last_os_error());
            }
            mount(
                Path::new("none"),
                Path::new("/"),
                None,
                libc::MS_REC | libc::MS_PRIVATE,
                "",
            )
        });
    }
    Ok(exit_code(command.status()?))
}

pub(crate) fn enter(root: &Path, words: &[String]) -> io::Result<i32> {
    if unsafe { libc::geteuid() } != 0
        || (Path::new("/proc/self/ns/pid").exists() && std::process::id() != 1)
    {
        return Err(io::Error::other(
            "Shell entry requires its own root PID supervisor",
        ));
    }
    if fs::read_link("/proc/self/ns/mnt")? == fs::read_link("/proc/1/ns/mnt")? {
        return Err(io::Error::other(
            "Shell entry requires a private mount namespace",
        ));
    }
    crate::guest::process::supervision::enable_subreaper()?;
    let plan = ssal::guest_policy::runtime::load(root)?
        .ok_or_else(|| io::Error::other("Guest SELinux mapping required"))?;
    let context = plan.context("shell", true)?;
    crate::diagnostics::selinux::require_guest_domain_mode(&plan, &context)?;
    crate::guest::mount::directory(root, "data/local", 0o755)?;
    let home = crate::guest::mount::directory(root, "data/local/ssal-shell", 0o700)?;
    ssal::guest_policy::runtime::set_label(&home, &plan.context("shell_data_file", false)?)?;
    let home_c = crate::guest::mount::cpath(&home)?;
    if unsafe { libc::chown(home_c.as_ptr(), 2000, 2000) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut mounts = Mounts::new();
    mounts.attach(
        Path::new("proc"),
        &root.join("proc"),
        Some("proc"),
        libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
        "hidepid=2",
    )?;
    // The pivot scratch belongs to this session, so concurrent shells never share it.
    let scratch = format!(".ssal-old-root-{}", fs::read_link("/proc/self")?.display());
    let mut command =
        crate::guest::process::command::root_command_at(root, "/system/bin/sh", true, &scratch)?;
    if words.is_empty() {
        command.arg("-i");
    } else {
        // Enter through shell_exec, then preserve argv without evaluating command text.
        command.args(["-c", "exec \"$@\"", "ssal-exec"]).args(words);
    }
    command
        .env("HOME", "/data/local/ssal-shell")
        .env("TMPDIR", "/data/local/ssal-shell")
        .env("USER", "shell")
        .env("LOGNAME", "shell")
        .env("TERM", "xterm-256color")
        .env("ANDROID_ROOT", "/system")
        .env("ANDROID_DATA", "/data")
        .env("ANDROID_RUNTIME_ROOT", "/apex/com.android.runtime");
    let interactive = words.is_empty();
    unsafe {
        command.pre_exec(move || {
            fs::write("/proc/thread-self/attr/exec", context.as_bytes())?;
            if interactive && libc::ioctl(0, libc::TIOCSCTTY, 0) < 0 {
                return Err(io::Error::last_os_error());
            }
            // The mapped shell SID and Android shell credentials apply to every command.
            for capability in 0..64 {
                if libc::prctl(libc::PR_CAPBSET_DROP, capability, 0, 0, 0) != 0 {
                    if io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL) {
                        break;
                    }
                    return Err(io::Error::last_os_error());
                }
            }
            if libc::setgroups(0, std::ptr::null()) != 0
                || libc::setresgid(2000, 2000, 2000) != 0
                || libc::setresuid(2000, 2000, 2000) != 0
            {
                return Err(io::Error::last_os_error());
            }
            #[repr(C)]
            struct Header {
                version: u32,
                pid: i32,
            }
            let header = Header {
                version: 0x20080522,
                pid: 0,
            };
            let data = [0u32; 6];
            if libc::syscall(libc::SYS_capset, &header as *const Header, data.as_ptr()) != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    // setresuid clears PDEATHSIG, so arm it after the credential transition.
    ssal::shell_transport::kill_with_parent(&mut command)?;
    let result = if interactive {
        ssal::shell_transport::guest_terminal(&mut command, root, &plan)
    } else {
        Ok(exit_code(command.status()?))
    };
    crate::guest::process::supervision::cleanup_descendants(false)?;
    result
}

pub(crate) fn fork(root: &Path, words: &[String]) -> io::Result<i32> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(io::Error::other("root required"));
    }
    // unshare(CLONE_NEWPID) affects the next fork, not the process calling unshare.
    let mut command = Command::new(std::env::current_exe()?);
    command.arg0("ssal-shell");
    command.arg("--shell-enter").arg(root).arg("--").args(words);
    ssal::shell_transport::kill_with_parent(&mut command)?;
    Ok(exit_code(command.status()?))
}
