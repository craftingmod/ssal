//! Disposable Guest service launcher; shared PID namespace is intentional.
use ssal::namespace_mounts::Mounts;
use std::fs::{self, File};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

pub(crate) fn command(
    root: &Path,
    executable: &str,
    uid: u32,
    guest_domain: bool,
) -> io::Result<Command> {
    let mut command = crate::guest_probe::root_command(root, executable, false)?;
    command.env("LD_LIBRARY_PATH", "/run/ssal");
    if executable == "/system/bin/bootstrap/linker64" {
        command.env("LD_LIBRARY_PATH", "/system/lib64/bootstrap:/system/lib64");
    }
    command
        .env("ANDROID_ROOT", "/system")
        .env("ANDROID_DATA", "/data")
        .env("ANDROID_RUNTIME_ROOT", "/apex/com.android.runtime")
        .env("ANDROID_ART_ROOT", "/apex/com.android.art")
        .env("ASEC_MOUNTPOINT", "/mnt/asec")
        .env("ANDROID_STORAGE", "/storage")
        .env("ANDROID_I18N_ROOT", "/apex/com.android.i18n")
        .env("ANDROID_TZDATA_ROOT", "/apex/com.android.tzdata")
        .stdin(Stdio::null());
    if executable == "/apex/com.android.art/bin/artd" {
        command.env("LD_LIBRARY_PATH", "/run/ssal:/apex/com.android.art/lib64:/system/lib64:/apex/com.android.os.statsd/lib64:/apex/com.android.i18n/lib64");
    }
    unsafe {
        command.pre_exec(move || {
            // The root transition already ran; only this child joins Guest cgroups.
            for (_, target) in crate::guest_mounts::GUEST_CGROUPS {
                fs::write(
                    format!("/{target}/cgroup.procs"),
                    std::process::id().to_string(),
                )?;
            }
            if guest_domain {
                fs::write("/proc/thread-self/attr/exec", b"u:r:ssal_guest_probe:s0\0")?;
            }
            if libc::setgroups(0, std::ptr::null()) != 0
                || libc::setresgid(uid, uid, uid) != 0
                || libc::setresuid(uid, uid, uid) != 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    Ok(command)
}

fn run(root: &Path, exe: &str, args: &[&str], uid: u32) -> io::Result<String> {
    let output = crate::guest_probe::run_with_timeout(
        command(root, exe, uid, true)?.args(args),
        exe,
        Duration::from_secs(20),
    )?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    println!(
        "Guest call executable={exe} args={args:?} return={}\n{stdout}{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "Guest call {exe} {args:?}: {}",
            output.status
        )));
    }
    Ok(stdout.into_owned())
}

struct Service {
    child: Child,
    log: std::path::PathBuf,
    stopped: bool,
}
impl Service {
    fn start(root: &Path, exe: &str, args: &[&str], name: &str, uid: u32) -> io::Result<Self> {
        let log = root.join(format!("run/ssal/{name}.log"));
        let output = File::create(&log)?;
        let child = command(root, exe, uid, true)?
            .env("LD_PRELOAD", "/run/ssal/ssal-phase2-log.so")
            .args(args)
            .stdout(output.try_clone()?)
            .stderr(output)
            .spawn()?;
        println!("Guest service={name} pid={} executable={exe}", child.id());
        Ok(Self {
            child,
            log,
            stopped: false,
        })
    }
    fn wait_text(&mut self, text: &str) -> io::Result<()> {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let log = fs::read_to_string(&self.log)?;
            if let Some(status) = self.child.try_wait()? {
                return Err(io::Error::other(format!(
                    "Guest service exited {status}: {log}"
                )));
            }
            if log.contains(text) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(io::Error::other(format!(
                    "Guest service readiness timeout ({text}): {log}"
                )));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    fn stop(&mut self) -> io::Result<()> {
        if self.stopped {
            return Ok(());
        }
        if self.child.try_wait()?.is_none() {
            // This process group was created by root_command in the owned child.
            if unsafe { libc::kill(-(self.child.id() as i32), libc::SIGKILL) } != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        let status = self.child.wait()?;
        self.stopped = true;
        println!(
            "Guest owned service pid={} stopped={status}\n{}",
            self.child.id(),
            fs::read_to_string(&self.log)?
        );
        Ok(())
    }
}
impl Drop for Service {
    fn drop(&mut self) {
        if let Err(e) = self.stop() {
            eprintln!("Guest service cleanup: {e}");
        }
    }
}

fn isolated(root: &Path, userdata: &Path) -> io::Result<()> {
    let identity = |path: &Path| -> io::Result<_> {
        let m = fs::metadata(path)?;
        Ok((m.dev(), m.ino()))
    };
    if identity(&root.join("data"))? != identity(userdata)?
        || identity(userdata)? == identity(Path::new("/data"))?
    {
        return Err(io::Error::other("Guest userdata identity mismatch"));
    }
    for path in [
        "dev/socket/property_service",
        "dev/socket/property_service_for_system",
        "dev/socket/init",
        "dev/socket/ctl.start",
        "dev/hwbinder",
        "dev/vndbinder",
    ] {
        if fs::symlink_metadata(root.join(path)).is_ok() {
            return Err(io::Error::other(format!(
                "unexpected Guest endpoint {path}"
            )));
        }
    }
    if fs::read_dir(root.join("dev/socket"))?.next().is_some() {
        return Err(io::Error::other(
            "Guest control socket directory is not empty",
        ));
    }
    Ok(())
}

pub(crate) fn verify(
    mounts: &mut Mounts,
    root: &Path,
    userdata: &Path,
    phase6a: bool,
) -> io::Result<()> {
    if fs::read_to_string("/sys/fs/selinux/enforce")?.trim() != "1" {
        return Err(io::Error::other("Host global Enforcing required"));
    }
    isolated(root, userdata)?;
    let runtime = crate::guest_mounts::directory(root, "run/ssal", 0o755)?;
    let bin = std::env::current_exe()?.parent().unwrap().to_owned();
    for name in ["guest_probe", "phase3-ipc", "ssal-phase2-log.so"] {
        let target = runtime.join(name);
        File::create(&target)?;
        mounts.bind(&bin.join(name), &target, true, false)?;
    }
    let mut binder = crate::binder_probe::Session::new();
    let result = (|| {
        // Reuse the established servicemanager view: libselinux rejects an RO root.
        // All control endpoints stay RO; only existing AV/context query files are RW.
        mounts.bind(
            Path::new("/sys/fs/selinux"),
            &root.join("sys/fs/selinux"),
            false,
            false,
        )?;
        for entry in fs::read_dir("/sys/fs/selinux")? {
            let entry = entry?;
            if ["access", "context", "create", "relabel", "member", "user"]
                .contains(&entry.file_name().to_str().unwrap_or(""))
            {
                continue;
            }
            mounts.bind(
                &entry.path(),
                &root.join("sys/fs/selinux").join(entry.file_name()),
                true,
                entry.file_type()?.is_dir(),
            )?;
        }
        let (major, minor, _) = binder.provision(root)?;
        let device = binder.private_device()?;
        if unsafe { libc::fchmod(device.as_raw_fd(), 0o666) } != 0 {
            return Err(io::Error::last_os_error());
        }
        crate::guest_mounts::directory(root, "dev/__properties__", 0o755)?;
        run(
            root,
            "/system/bin/bootstrap/linker64",
            &[
                "/run/ssal/guest_probe",
                "--initialize-private-properties",
                "/dev/guest-properties",
            ],
            0,
        )?;
        fs::remove_dir(root.join("dev/__properties__"))?;
        fs::rename(
            root.join("dev/guest-properties"),
            root.join("dev/__properties__"),
        )?;
        let area = fs::metadata(root.join("dev/__properties__"))?;
        let host = fs::metadata("/dev/__properties__")?;
        if (area.dev(), area.ino()) == (host.dev(), host.ino()) {
            return Err(io::Error::other("Host property area selected"));
        }
        // Linkerconfig must see Guest properties and only the private Binder alias.
        run(
            root,
            crate::guest_mounts::linkerconfig_binary(root)?,
            &["--target", "/linkerconfig"],
            0,
        )?;
        let sentinel = File::open("/data")?;
        if unsafe { libc::fcntl(sentinel.as_raw_fd(), libc::F_SETFD, 0) } != 0 {
            return Err(io::Error::last_os_error());
        }
        println!("Guest FD pre-exec: injected Host /data fd={}; root command closes inherited identities and marks later FDs CLOEXEC", sentinel.as_raw_fd());
        let shell = run(
            root,
            "/system/bin/sh",
            &[
                "-c",
                r#"set -eu
test "$(getprop ro.build.version.sdk)" = 36
test -z "$(getprop ro.boot.serialno)"
for p in /dev/socket/property_service /dev/socket/property_service_for_system /dev/socket/init; do test ! -e "$p"; done
for fd in /proc/$$/fd/*; do
    target=$(readlink "$fd") || continue
    echo "Guest post-exec fd=$fd target=$target"
    case "$target" in /dev/null|pipe:*|/system/bin/sh|/system/bin/mksh) ;; *) exit 31;; esac
done
test "$(cat /proc/$$/attr/current)" = u:r:ssal_guest_probe:s0
umask 077
marker=/data/local/tmp/ssal-launcher-$$
set -C
printf guest > "$marker"
test "$(cat "$marker")" = guest
rm "$marker"
set +e
setprop ctl.start ssal_must_not_reach_host_init
rc=$?
set -e
echo "Guest ctl.start return=$rc"
test "$rc" != 0
echo SSAL_GUEST_SHELL_PROPERTY_FD=PASS
"#,
            ],
            1000,
        )?;
        if !shell.contains("SSAL_GUEST_SHELL_PROPERTY_FD=PASS") {
            return Err(io::Error::other("shell evidence missing"));
        }
        drop(sentinel);
        let mut manager = Service::start(
            root,
            "/system/bin/servicemanager",
            &[],
            "servicemanager",
            1000,
        )?;
        manager.wait_text("servicemanager")?;
        let mut server = Service::start(
            root,
            "/system/bin/bootstrap/linker64",
            &["/run/ssal/phase3-ipc", "server"],
            "aidl-server",
            1000,
        )?;
        server.wait_text("\"event\":\"registered\"")?;
        let ipc = run(
            root,
            "/system/bin/bootstrap/linker64",
            &["/run/ssal/phase3-ipc", "client"],
            1000,
        )?;
        if !ipc.contains("\"event\":\"ipc_passed\"") {
            return Err(io::Error::other("AIDL IPC success evidence missing"));
        }
        println!("PHASE5B=PASS shell=PASS private_aidl=PASS properties=PASS host_control_socket=ABSENT private_binder={major}:{minor}");
        if phase6a {
            println!("PHASE6A=START installd/artd through common launcher");
            for path in ["data/misc/user", "data/misc/installd"] {
                crate::guest_mounts::directory(root, path, 0o755)?;
            }
            for (exe, name) in [
                ("/system/bin/installd", "installd"),
                ("/apex/com.android.art/bin/artd", "artd"),
            ] {
                let mut service = Service::start(root, exe, &[], name, 0)?;
                std::thread::sleep(Duration::from_millis(500));
                if let Some(status) = service.child.try_wait()? {
                    return Err(io::Error::other(format!(
                        "Phase6A {exe} exit={status}: {}",
                        fs::read_to_string(&service.log)?
                    )));
                }
                println!(
                    "PHASE6A service={name} pid={} alive_after_500ms=true",
                    service.child.id()
                );
                run(
                    root,
                    "/system/bin/bootstrap/linker64",
                    &["/run/ssal/phase3-ipc", "inspect-data-service", name],
                    1000,
                )?;
                service.stop()?;
            }
        }
        server.stop()?;
        manager.stop()?;
        isolated(root, userdata)?;
        Ok(())
    })();
    let cleanup = binder.cleanup();
    if fs::read_to_string("/sys/fs/selinux/enforce")?.trim() != "1" {
        return Err(io::Error::other("Host global Enforcing changed"));
    }
    match (result, cleanup) {
        (Err(e), Err(c)) => Err(io::Error::other(format!("{e}; Binder cleanup: {c}"))),
        (Err(e), _) | (_, Err(e)) => Err(e),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn owned_service_is_reaped_and_stop_is_idempotent() -> io::Result<()> {
        let log = std::env::temp_dir().join(format!("ssal-launcher-test-{}", std::process::id()));
        let output = File::create(&log)?;
        let mut cmd = Command::new("/bin/sh");
        cmd.args(["-c", "sleep 30 & wait"])
            .stdout(output.try_clone()?)
            .stderr(output);
        unsafe {
            cmd.pre_exec(|| {
                if libc::setsid() < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = cmd.spawn()?;
        let pid = child.id();
        let mut service = Service {
            child,
            log: log.clone(),
            stopped: false,
        };
        service.stop()?;
        service.stop()?;
        assert!(service.stopped);
        assert_eq!(unsafe { libc::kill(pid as i32, 0) }, -1);
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::ESRCH));
        fs::remove_file(log)?;
        Ok(())
    }
}
