use std::fs;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;
pub(in crate::guest) fn system_server_requested(
    phase7a: bool,
    mapped: bool,
) -> io::Result<bool> {
    if crate::guest::disabled("SYSTEM_SERVER") {
        return Ok(false);
    }
    Ok(phase7a && mapped)
}

pub(in crate::guest) fn zygote_args(
    controlled_fork: bool,
    system_server: bool,
) -> Vec<&'static str> {
    let mut args = vec!["-Xzygote"];
    if controlled_fork {
        args.push("-XX:ForceJavaZygoteForkLoop=true");
    }
    args.extend(["/system/bin", "--zygote"]);
    if system_server {
        args.push("--start-system-server");
    }
    args.push("--socket-name=zygote");
    args
}

pub(in crate::guest) fn zygote_sockets(
    command: &mut Command,
    directory: &Path,
    contexts: Option<(String, String)>,
) -> io::Result<Vec<UnixListener>> {
    let mut sockets = Vec::new();
    for name in ["zygote", "usap_pool_primary"] {
        let raw = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let socket = unsafe { UnixListener::from_raw_fd(raw) };
        let fd = socket.as_raw_fd();
        let path = directory.join(name);
        let contexts = contexts.clone();
        command.env(format!("ANDROID_SOCKET_{name}"), fd.to_string());
        unsafe {
            command.pre_exec(move || {
                if let Some((socket, file)) = &contexts {
                    fs::write("/proc/thread-self/attr/sockcreate", format!("{socket}\0"))?;
                    fs::write("/proc/thread-self/attr/fscreate", format!("{file}\0"))?;
                }
                let bound = UnixListener::bind(&path)?;
                if contexts.is_some() {
                    fs::write("/proc/thread-self/attr/sockcreate", b"\0")?;
                    fs::write("/proc/thread-self/attr/fscreate", b"\0")?;
                }
                if name == "zygote" {
                    let cpath = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())?;
                    if libc::chown(cpath.as_ptr(), !0, 1000) != 0 {
                        return Err(io::Error::last_os_error());
                    }
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o660))?;
                }
                if libc::dup2(bound.as_raw_fd(), fd) < 0 {
                    return Err(io::Error::last_os_error());
                }
                if libc::fcntl(fd, libc::F_SETFD, 0) != 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        sockets.push(socket);
    }
    Ok(sockets)
}
