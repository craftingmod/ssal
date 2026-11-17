//! Local terminal transport; Guest setup runs in a separate privileged process.
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};

pub fn run(profile: Option<&str>, words: &[String]) -> io::Result<i32> {
    let executable = std::env::current_exe()?.with_file_name("ssald");
    let mut command = Command::new(executable);
    command.arg0("ssal-shell");
    command.arg("--shell-session").arg(profile.unwrap_or(""));
    command.arg("--").args(words);
    kill_with_parent(&mut command)?;
    if words.is_empty() {
        if unsafe { libc::isatty(0) } != 1 || unsafe { libc::isatty(1) } != 1 {
            return Err(io::Error::other(
                "ssal shell requires a terminal; use ssal exec -- COMMAND for pipes",
            ));
        }
        terminal(&mut command)
    } else {
        pipes(&mut command)
    }
}

fn pipes(command: &mut Command) -> io::Result<i32> {
    use std::sync::atomic::{AtomicBool, Ordering};
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn()?;
    let mut input = child.stdin.take().unwrap();
    let mut output = child.stdout.take().unwrap();
    let mut errors = child.stderr.take().unwrap();
    let flags = unsafe { libc::fcntl(input.as_raw_fd(), libc::F_GETFL) };
    if flags < 0
        || unsafe { libc::fcntl(input.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
    {
        let _ = child.kill();
        let _ = child.wait();
        return Err(io::Error::last_os_error());
    }
    let done = AtomicBool::new(false);
    std::thread::scope(|scope| {
        let writer = scope.spawn(|| -> io::Result<()> {
            let mut buffer = [0; 8192];
            while !done.load(Ordering::Acquire) {
                let mut fd = libc::pollfd {
                    fd: 0,
                    events: libc::POLLIN,
                    revents: 0,
                };
                if unsafe { libc::poll(&mut fd, 1, 100) } <= 0 {
                    continue;
                }
                let n = io::stdin().read(&mut buffer)?;
                if n == 0 {
                    break;
                }
                let mut offset = 0;
                while offset < n && !done.load(Ordering::Acquire) {
                    let mut fd = libc::pollfd {
                        fd: input.as_raw_fd(),
                        events: libc::POLLOUT,
                        revents: 0,
                    };
                    if unsafe { libc::poll(&mut fd, 1, 100) } <= 0 {
                        continue;
                    }
                    match input.write(&buffer[offset..n]) {
                        Ok(0) => return Ok(()),
                        Ok(count) => offset += count,
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => (),
                        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => return Ok(()),
                        Err(error) => return Err(error),
                    }
                }
            }
            drop(input);
            Ok(())
        });
        let stdout = scope.spawn(|| relay(&mut output, &mut io::stdout()));
        let stderr = scope.spawn(|| relay(&mut errors, &mut io::stderr()));
        let result = child.wait();
        done.store(true, Ordering::Release);
        writer
            .join()
            .map_err(|_| io::Error::other("stdin relay panicked"))??;
        stdout
            .join()
            .map_err(|_| io::Error::other("stdout relay panicked"))??;
        stderr
            .join()
            .map_err(|_| io::Error::other("stderr relay panicked"))??;
        Ok(code(result?))
    })
}

fn relay(reader: &mut impl Read, writer: &mut impl Write) -> io::Result<()> {
    let mut buffer = [0; 8192];
    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            return Ok(());
        }
        writer.write_all(&buffer[..n])?;
        writer.flush()?;
    }
}

/// Keep cancellation from leaving a privileged supervisor or Shell behind.
pub fn kill_with_parent(command: &mut Command) -> io::Result<()> {
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, std::process::id(), 0) } as i32;
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let parent = unsafe { File::from_raw_fd(fd) };
    unsafe {
        command.pre_exec(move || {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                return Err(io::Error::last_os_error());
            }
            let mut fd = libc::pollfd {
                fd: parent.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            if libc::poll(&mut fd, 1, 0) != 0 {
                return Err(io::Error::other("Shell supervisor parent disappeared"));
            }
            Ok(())
        });
    }
    Ok(())
}

fn code(status: std::process::ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(1))
}

struct Terminal(libc::termios);
impl Drop for Terminal {
    fn drop(&mut self) {
        unsafe {
            libc::tcsetattr(0, libc::TCSANOW, &self.0);
        }
    }
}

fn size(fd: i32) -> io::Result<libc::winsize> {
    let mut size = unsafe { std::mem::zeroed() };
    if unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &mut size) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(size)
}

fn terminal(command: &mut Command) -> io::Result<i32> {
    terminal_pair(command, None)
}

pub fn guest_terminal(
    command: &mut Command,
    root: &std::path::Path,
    plan: &crate::guest_policy::Plan,
) -> io::Result<i32> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
    let tty = root.join("dev/tty");
    let tty_name = std::ffi::CString::new(tty.as_os_str().as_bytes()).map_err(io::Error::other)?;
    if unsafe {
        libc::mknod(
            tty_name.as_ptr(),
            libc::S_IFCHR | 0o666,
            libc::makedev(5, 0),
        )
    } != 0
        && io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST)
    {
        return Err(io::Error::last_os_error());
    }
    let metadata = std::fs::symlink_metadata(&tty)?;
    if !metadata.file_type().is_char_device() || metadata.rdev() != libc::makedev(5, 0) {
        return Err(io::Error::other("unsafe Guest /dev/tty"));
    }
    std::fs::set_permissions(&tty, std::fs::Permissions::from_mode(0o666))?;
    crate::guest_policy::runtime::set_label(&tty, &plan.context("tty_device", false)?)?;
    let pts = root.join("dev/pts");
    std::fs::create_dir_all(&pts)?;
    let context = plan.context("shell_devpts", false)?;
    crate::namespace_mounts::mount(
        std::path::Path::new("devpts"),
        &pts,
        Some("devpts"),
        libc::MS_NOSUID | libc::MS_NOEXEC,
        &format!("newinstance,gid=2000,mode=620,ptmxmode=666,context={context}"),
    )?;
    let master = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOCTTY)
        .open(pts.join("ptmx"))?;
    let mut unlock = 0;
    let mut index: libc::c_uint = 0;
    // Linux UAPI values; libc does not export these names on Android.
    if unsafe { libc::ioctl(master.as_raw_fd(), 0x40045431u32 as _, &mut unlock) } < 0
        || unsafe { libc::ioctl(master.as_raw_fd(), 0x80045430u32 as _, &mut index) } < 0
    {
        return Err(io::Error::last_os_error());
    }
    let slave = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOCTTY)
        .open(pts.join(index.to_string()))?;
    if unsafe { libc::fchown(slave.as_raw_fd(), 2000, 2000) } != 0 {
        return Err(io::Error::last_os_error());
    }
    terminal_pair(command, Some((master, slave)))
}

fn terminal_pair(command: &mut Command, pair: Option<(File, File)>) -> io::Result<i32> {
    let mut original = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(0, &mut original) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut dimensions = size(0)?;
    let (mut master, slave) = if let Some(pair) = pair {
        pair
    } else {
        let (mut master, mut slave) = (-1, -1);
        if unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                &original,
                &dimensions,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        (unsafe { File::from_raw_fd(master) }, unsafe {
            File::from_raw_fd(slave)
        })
    };
    if unsafe { libc::tcsetattr(slave.as_raw_fd(), libc::TCSANOW, &original) } != 0
        || unsafe { libc::ioctl(master.as_raw_fd(), libc::TIOCSWINSZ, &dimensions) } < 0
    {
        return Err(io::Error::last_os_error());
    }
    command
        .stdin(Stdio::from(slave.try_clone()?))
        .stdout(Stdio::from(slave.try_clone()?))
        .stderr(Stdio::from(slave));
    let mut child = command.spawn()?;
    let mut raw = original;
    unsafe {
        libc::cfmakeraw(&mut raw);
    }
    if unsafe { libc::tcsetattr(0, libc::TCSANOW, &raw) } != 0 {
        let _ = child.kill();
        let _ = child.wait();
        return Err(io::Error::last_os_error());
    }
    let _restore = Terminal(original);
    let result = (|| {
        let mut buffer = [0; 8192];
        loop {
            let next = size(0)?;
            if next.ws_row != dimensions.ws_row || next.ws_col != dimensions.ws_col {
                if unsafe { libc::ioctl(master.as_raw_fd(), libc::TIOCSWINSZ, &next) } < 0 {
                    return Err(io::Error::last_os_error());
                }
                dimensions = next;
            }
            let mut fds = [
                libc::pollfd {
                    fd: 0,
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: master.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            if unsafe { libc::poll(fds.as_mut_ptr(), 2, 100) } < 0 {
                if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(io::Error::last_os_error());
            }
            if fds[1].revents != 0 {
                match master.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(n) => {
                        io::stdout().write_all(&buffer[..n])?;
                        io::stdout().flush()?;
                    }
                    Err(error) if error.raw_os_error() == Some(libc::EIO) => break,
                    Err(error) => return Err(error),
                }
            }
            if fds[0].revents != 0 {
                let n = io::stdin().read(&mut buffer)?;
                if n == 0 {
                    break;
                }
                master.write_all(&buffer[..n])?;
            }
            if let Some(status) = child.try_wait()? {
                // Drain pending PTY output before reporting the child's status.
                loop {
                    let mut fd = libc::pollfd {
                        fd: master.as_raw_fd(),
                        events: libc::POLLIN,
                        revents: 0,
                    };
                    if unsafe { libc::poll(&mut fd, 1, 0) } <= 0 {
                        break;
                    }
                    match master.read(&mut buffer) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            io::stdout().write_all(&buffer[..n])?;
                            io::stdout().flush()?;
                        }
                    }
                }
                return Ok(code(status));
            }
        }
        // EOF also closes the controlling terminal and signals the foreground job.
        drop(master);
        Ok(code(child.wait()?))
    })();
    if result.is_err() {
        // Closing the master sends HUP to the controlling terminal's foreground job.
        let _ = child.wait();
    }
    result
}
