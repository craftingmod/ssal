use super::{policy, Properties, SOCKET, SYSTEM_SOCKET};
use std::fs;
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::time::{Duration, Instant};

struct RequestReader<'a> {
    stream: &'a mut UnixStream,
    deadline: Instant,
}

impl Read for RequestReader<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "property request deadline",
            ));
        }
        self.stream.set_read_timeout(Some(remaining))?;
        self.stream.read(bytes)
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct PeerCredentials {
    pub pid: i32,
    pub uid: u32,
    pub gid: u32,
}

pub(super) fn peer(stream: &UnixStream) -> io::Result<(PeerCredentials, String)> {
    let mut credential: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of_val(&credential) as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credential as *mut libc::ucred).cast(),
            &mut len,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    if len as usize != std::mem::size_of_val(&credential)
        || credential.pid <= 0
        || credential.uid == u32::MAX
        || credential.gid == u32::MAX
    {
        return Err(io::Error::other("invalid property peer credentials"));
    }
    let mut context = [0u8; 512];
    len = context.len() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERSEC,
            context.as_mut_ptr().cast(),
            &mut len,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    let context = &context[..len as usize];
    let context = std::str::from_utf8(context.strip_suffix(&[0]).unwrap_or(context))
        .map_err(io::Error::other)?;
    if context.is_empty() {
        return Err(io::Error::other("empty property peer context"));
    }
    Ok((
        PeerCredentials {
            pid: credential.pid,
            uid: credential.uid,
            gid: credential.gid,
        },
        context.into(),
    ))
}

fn read_u32(stream: &mut impl Read) -> io::Result<u32> {
    let mut bytes = [0; 4];
    stream.read_exact(&mut bytes)?;
    Ok(u32::from_le_bytes(bytes))
}

fn string(stream: &mut impl Read, limit: usize) -> io::Result<String> {
    let len = read_u32(stream)? as usize;
    if len > limit {
        return Err(io::Error::other("property wire field too large"));
    }
    let mut bytes = vec![0; len];
    stream.read_exact(&mut bytes)?;
    String::from_utf8(bytes).map_err(io::Error::other)
}

fn request(stream: &mut impl Read, command: u32) -> Result<(String, String), i32> {
    use rsproperties::wire::*;
    match command {
        PROP_MSG_SETPROP2 => Ok((
            string(stream, MAX_WIRE_NAME_LEN).map_err(|_| PROP_ERROR_READ_DATA)?,
            string(stream, MAX_WIRE_VALUE_LEN).map_err(|_| PROP_ERROR_READ_DATA)?,
        )),
        PROP_MSG_SETPROP => {
            let mut name = [0; PROP_NAME_MAX];
            let mut value = [0; PROP_VALUE_MAX];
            stream
                .read_exact(&mut name)
                .map_err(|_| PROP_ERROR_READ_DATA)?;
            stream
                .read_exact(&mut value)
                .map_err(|_| PROP_ERROR_READ_DATA)?;
            let field = |bytes: &[u8]| -> Result<String, i32> {
                let end = bytes
                    .iter()
                    .position(|b| *b == 0)
                    .ok_or(PROP_ERROR_READ_DATA)?;
                String::from_utf8(bytes[..end].to_vec()).map_err(|_| PROP_ERROR_READ_DATA)
            };
            Ok((field(&name)?, field(&value)?))
        }
        _ => Err(PROP_ERROR_INVALID_CMD),
    }
}

fn response(stream: &mut UnixStream, command: u32, status: i32) {
    if command != rsproperties::wire::PROP_MSG_SETPROP {
        let _ = stream.write_all(&(status as u32).to_le_bytes());
    }
}

fn rejection_code(name: &str, error: &io::Error) -> i32 {
    use rsproperties::wire::*;
    if name.starts_with("ctl.") && validate_property_name(name).is_ok() {
        return PROP_ERROR_HANDLE_CONTROL_MESSAGE;
    }
    match error.kind() {
        io::ErrorKind::InvalidInput if validate_property_name(name).is_err() => {
            PROP_ERROR_INVALID_NAME
        }
        io::ErrorKind::InvalidInput => PROP_ERROR_INVALID_VALUE,
        io::ErrorKind::AlreadyExists => PROP_ERROR_READ_ONLY_PROPERTY,
        io::ErrorKind::PermissionDenied => PROP_ERROR_PERMISSION_DENIED,
        _ => PROP_ERROR_SET_FAILED,
    }
}

// Invalid peers/requests are local rejections; committed-state failures stop the server.
pub(super) fn handle(
    stream: &mut UnixStream,
    properties: &mut Properties,
    mut authorize: impl FnMut(&UnixStream, &str, bool) -> io::Result<PeerCredentials>,
    control_handler: impl FnOnce(&str, &str, PeerCredentials, &mut Properties) -> io::Result<bool>,
    powerctl_handler: impl FnOnce(&str, PeerCredentials) -> bool,
) -> io::Result<()> {
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    let mut reader = RequestReader {
        stream,
        deadline: Instant::now() + Duration::from_secs(2),
    };
    let command = match read_u32(&mut reader) {
        Ok(command) => command,
        Err(_) => {
            response(
                stream,
                rsproperties::wire::PROP_MSG_SETPROP2,
                rsproperties::wire::PROP_ERROR_READ_CMD,
            );
            return Ok(());
        }
    };
    let (name, value) = match request(&mut reader, command) {
        Ok(pair) => pair,
        Err(status) => {
            response(stream, command, status);
            return Ok(());
        }
    };
    let credentials = match properties.check_write(&name, &value, |target| {
        authorize(stream, target, name.starts_with("ctl."))
    }) {
        Ok(credentials) => credentials,
        Err(error) => {
            response(stream, command, rejection_code(&name, &error));
            return Ok(());
        }
    };
    if let Some(action) = name.strip_prefix("ctl.") {
        let result = control_handler(action, &value, credentials, properties);
        let status = if matches!(result, Ok(true)) {
            rsproperties::wire::PROP_SUCCESS
        } else {
            rsproperties::wire::PROP_ERROR_HANDLE_CONTROL_MESSAGE
        };
        response(stream, command, status);
        return result.map(|_| ());
    }
    if name == "sys.powerctl" {
        if !super::control::valid_powerctl(&value) {
            response(
                stream,
                command,
                rsproperties::wire::PROP_ERROR_INVALID_VALUE,
            );
            return Ok(());
        }
        // A parent teardown delivers SIGKILL to this supervised child, so acknowledge first.
        response(stream, command, rsproperties::wire::PROP_SUCCESS);
        if !powerctl_handler(&value, credentials) {
            eprintln!(
                "Guest sys.powerctl request accepted but session teardown failed: pid={}",
                credentials.pid
            );
        }
        return Ok(());
    }
    let result = properties.set(&name, &value);
    response(
        stream,
        command,
        if result.is_ok() {
            rsproperties::wire::PROP_SUCCESS
        } else {
            rsproperties::wire::PROP_ERROR_SET_FAILED
        },
    );
    result
}

fn ensure_socket_label(
    context: &[u8],
    mut read: impl FnMut() -> io::Result<Vec<u8>>,
    write: impl FnOnce() -> io::Result<()>,
) -> io::Result<()> {
    let matches = |actual: &[u8]| actual.strip_suffix(&[0]).unwrap_or(actual) == context;
    if matches(&read()?) {
        return Ok(());
    }
    write()?;
    if !matches(&read()?) {
        return Err(io::Error::other("Guest socket label mismatch"));
    }
    Ok(())
}

fn label_socket(path: &Path, context: &str) -> io::Result<()> {
    let name = std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(io::Error::other)?;
    let target = std::ffi::CString::new(context).map_err(io::Error::other)?;
    let error = |syscall: &str| {
        let error = io::Error::last_os_error();
        io::Error::new(
            error.kind(),
            format!("{syscall} {} as {context}: {error}", path.display()),
        )
    };
    ensure_socket_label(
        target.as_bytes(),
        || {
            let mut actual = vec![0u8; 512];
            let size = unsafe {
                libc::lgetxattr(
                    name.as_ptr(),
                    c"security.selinux".as_ptr(),
                    actual.as_mut_ptr().cast(),
                    actual.len(),
                )
            };
            if size < 0 {
                return Err(error("lgetxattr"));
            }
            actual.truncate(size as usize);
            eprintln!(
                "property_socket_label path={} actual_sid={} target_sid={} lsetxattr={}",
                path.display(),
                String::from_utf8_lossy(actual.strip_suffix(&[0]).unwrap_or(&actual)),
                context,
                if actual.strip_suffix(&[0]).unwrap_or(&actual) == target.as_bytes() {
                    "unnecessary"
                } else {
                    "required"
                }
            );
            Ok(actual)
        },
        || {
            if unsafe {
                libc::lsetxattr(
                    name.as_ptr(),
                    c"security.selinux".as_ptr(),
                    target.as_ptr().cast(),
                    target.as_bytes_with_nul().len(),
                    0,
                )
            } != 0
            {
                return Err(error("lsetxattr"));
            }
            Ok(())
        },
    )
}

pub(super) fn serve(
    properties: &mut Properties,
    session_owner_pid: i32,
    services: &mut super::services::Registry,
) -> io::Result<()> {
    let guest_sources = services.guest_sources();
    let path = Path::new(SOCKET);
    let system_path = Path::new(SYSTEM_SOCKET);
    // Fresh /dev/socket belongs to this session. Never replace a running/stale server's socket.
    for socket in [path, system_path] {
        match fs::symlink_metadata(socket) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            _ => {
                return Err(io::Error::other(format!(
                    "Guest property socket already exists or cannot be checked: {}",
                    socket.display()
                )))
            }
        }
    }
    unsafe {
        libc::umask(0o077);
    }
    let listener = bind_socket(path, &properties.socket_context, 0o666, 0)?;
    let system_listener = match bind_socket(system_path, &properties.socket_context, 0o660, 1000) {
        Ok(listener) => listener,
        Err(error) => {
            drop(listener);
            let _ = fs::remove_file(path);
            return Err(error);
        }
    };
    let result: io::Result<()> = (|| {
        println!("{{\"event\":\"guest_property_service_ready\",\"persistent_file\":\"/data/property/persistent_properties\",\"sockets\":[\"property_service\",\"property_service_for_system\"]}}");
        loop {
            services.tick(properties)?;
            let mut ready = [
                libc::pollfd {
                    fd: listener.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: system_listener.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            let polled = unsafe { libc::poll(ready.as_mut_ptr(), ready.len() as _, 100) };
            if polled < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            if polled == 0 {
                continue;
            }
            let system_ready = ready[1].revents & libc::POLLIN != 0;
            if ready
                .iter()
                .any(|fd| fd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0)
            {
                return Err(io::Error::other("Guest property socket listener failed"));
            }
            let listener = if system_ready {
                &system_listener
            } else {
                &listener
            };
            let (mut stream, _) = match listener.accept() {
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                result => result?,
            };
            handle(
                &mut stream,
                properties,
                |stream, target, control| {
                    let (credentials, source) = peer(stream).map_err(|_| {
                        io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "property peer identity unavailable",
                        )
                    })?;
                    if control && !guest_sources.contains(&source) {
                        return Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "control caller is not in this Guest policy",
                        ));
                    }
                    policy::check_access(&source, target).map_err(|e| {
                        eprintln!(
                            "Guest property denied: pid={} uid={} gid={} source={} target={}: {}",
                            credentials.pid, credentials.uid, credentials.gid, source, target, e
                        );
                        io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "property authorization failed",
                        )
                    })?;
                    Ok(credentials)
                },
                |action, target, peer, properties| {
                    services.dispatch(action, target, peer, properties)
                },
                |command, peer| super::control::powerctl(command, peer, session_owner_pid),
            )?;
        }
    })();
    drop(listener);
    drop(system_listener);
    let cleanup = remove_socket(path);
    let system_cleanup = remove_socket(system_path);
    result.and(cleanup.and(system_cleanup))
}

fn bind_socket(path: &Path, context: &str, mode: u32, gid: u32) -> io::Result<UnixListener> {
    let listener = UnixListener::bind(path)?;
    let setup = label_socket(path, context).and_then(|()| {
        let path_c =
            std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(io::Error::other)?;
        if unsafe { libc::chown(path_c.as_ptr(), 0, gid) } != 0 {
            return Err(io::Error::last_os_error());
        }
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
    });
    if let Err(error) = setup {
        drop(listener);
        let _ = fs::remove_file(path);
        return Err(error);
    }
    Ok(listener)
}

fn remove_socket(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn socket_label_skips_only_an_exact_match() {
        for actual in [b"target".to_vec(), b"target\0".to_vec()] {
            ensure_socket_label(
                b"target",
                || Ok(actual.clone()),
                || panic!("already labeled"),
            )
            .unwrap();
        }
        let mut labels = [b"old".to_vec(), b"target\0".to_vec()].into_iter();
        let mut writes = 0;
        ensure_socket_label(
            b"target",
            || Ok(labels.next().unwrap()),
            || {
                writes += 1;
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(writes, 1);
        assert!(labels.next().is_none(), "must verify after setting");

        let denied = || io::Error::from_raw_os_error(libc::EACCES);
        let error =
            ensure_socket_label(b"target", || Err(denied()), || panic!("read failed")).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EACCES));
        let error =
            ensure_socket_label(b"target", || Ok(b"old".to_vec()), || Err(denied())).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EACCES));
        assert!(
            ensure_socket_label(b"target", || Ok(b"target-prefix".to_vec()), || Ok(())).is_err()
        );
        let mut reads = 0;
        assert!(ensure_socket_label(
            b"target",
            || {
                reads += 1;
                if reads == 1 {
                    Ok(b"old".to_vec())
                } else {
                    Err(denied())
                }
            },
            || Ok(()),
        )
        .is_err());
    }

    #[test]
    fn v1_v2_bounds_and_truncation() {
        let mut bytes = Vec::new();
        bytes.extend(9u32.to_le_bytes());
        bytes.extend(b"persist.x");
        bytes.extend(2u32.to_le_bytes());
        bytes.extend(b"ok");
        assert_eq!(
            request(&mut Cursor::new(&bytes), 0x20001).unwrap(),
            ("persist.x".into(), "ok".into())
        );
        bytes.pop();
        assert_eq!(
            request(&mut Cursor::new(bytes), 0x20001),
            Err(rsproperties::wire::PROP_ERROR_READ_DATA)
        );
        assert_eq!(
            request(&mut Cursor::new(u32::MAX.to_le_bytes()), 0x20001),
            Err(rsproperties::wire::PROP_ERROR_READ_DATA)
        );
        assert_eq!(
            request(&mut Cursor::new([1; 124]), 1),
            Err(rsproperties::wire::PROP_ERROR_READ_DATA)
        );
        assert_eq!(
            request(&mut Cursor::new([]), 7),
            Err(rsproperties::wire::PROP_ERROR_INVALID_CMD)
        );

        let mut v1 =
            vec![0u8; rsproperties::wire::PROP_NAME_MAX + rsproperties::wire::PROP_VALUE_MAX];
        v1[..9].copy_from_slice(b"persist.x");
        v1[rsproperties::wire::PROP_NAME_MAX..rsproperties::wire::PROP_NAME_MAX + 2]
            .copy_from_slice(b"ok");
        assert_eq!(
            request(&mut Cursor::new(v1), rsproperties::wire::PROP_MSG_SETPROP).unwrap(),
            ("persist.x".into(), "ok".into())
        );
        let (mut client, mut stream) = UnixStream::pair().unwrap();
        response(
            &mut stream,
            rsproperties::wire::PROP_MSG_SETPROP,
            rsproperties::wire::PROP_SUCCESS,
        );
        drop(stream);
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).unwrap();
        assert!(reply.is_empty(), "V1 clients receive no status word");
    }

    fn exchange(
        properties: &mut Properties,
        name: &str,
        value: &str,
        allowed: bool,
    ) -> (io::Result<()>, u32) {
        let (mut client, mut stream) = UnixStream::pair().unwrap();
        for part in [
            0x20001u32.to_le_bytes().to_vec(),
            (name.len() as u32).to_le_bytes().to_vec(),
            name.as_bytes().to_vec(),
            (value.len() as u32).to_le_bytes().to_vec(),
            value.as_bytes().to_vec(),
        ] {
            client.write_all(&part).unwrap();
        }
        let result = handle(
            &mut stream,
            properties,
            |_, _, _| {
                if allowed {
                    Ok(PeerCredentials {
                        pid: 1,
                        uid: 0,
                        gid: 0,
                    })
                } else {
                    Err(io::Error::new(io::ErrorKind::PermissionDenied, "denied"))
                }
            },
            |_, _, _, _| Ok(false),
            |_, _| true,
        );
        (result, read_u32(&mut client).unwrap())
    }

    #[test]
    fn protocol_ack_denials_and_disk_failure() {
        let root = super::super::tests::temp_dir("wire");
        let mut properties = super::super::tests::fixture(&root);
        let (result, status) = exchange(&mut properties, "persist.number", "7", true);
        assert!(result.is_ok());
        assert_eq!(status, 0);
        assert_eq!(properties.area.get("persist.number").unwrap(), "7");
        assert_eq!(properties.store.values["persist.number"], "7");
        for (name, value, allowed, expected) in [
            (
                "persist.number",
                "bad",
                true,
                rsproperties::wire::PROP_ERROR_INVALID_VALUE,
            ),
            (
                "persist.number",
                "8",
                false,
                rsproperties::wire::PROP_ERROR_PERMISSION_DENIED,
            ),
            (
                "ro.denied",
                "x",
                false,
                rsproperties::wire::PROP_ERROR_PERMISSION_DENIED,
            ),
            (
                "ctl.start",
                "x",
                true,
                rsproperties::wire::PROP_ERROR_HANDLE_CONTROL_MESSAGE,
            ),
            (
                "sys.powerctl",
                "reboot",
                true,
                rsproperties::wire::PROP_SUCCESS,
            ),
            (
                "sys.powerctl",
                "reboot,userspace",
                true,
                rsproperties::wire::PROP_ERROR_INVALID_VALUE,
            ),
            (
                "sys.powerctl",
                "reboot,",
                true,
                rsproperties::wire::PROP_ERROR_INVALID_VALUE,
            ),
            ("ro.late", "x", true, rsproperties::wire::PROP_SUCCESS),
            (
                "ro.late",
                "y",
                true,
                rsproperties::wire::PROP_ERROR_READ_ONLY_PROPERTY,
            ),
            (
                "bad..name",
                "x",
                true,
                rsproperties::wire::PROP_ERROR_INVALID_NAME,
            ),
        ] {
            let (result, status) = exchange(&mut properties, name, value, allowed);
            assert!(result.is_ok(), "rejection must keep server alive");
            assert_eq!(status, expected as u32, "{name}={value}");
        }
        assert!(properties.area.find("ctl.start").unwrap().is_none());
        assert!(properties.area.find("sys.powerctl").unwrap().is_none());
        assert_eq!(properties.area.get("ro.late").unwrap(), "x");
        fs::create_dir(root.join("property/persistent_properties.tmp")).unwrap();
        let (result, status) = exchange(&mut properties, "persist.number", "9", true);
        assert!(result.is_err(), "storage failure must stop server");
        assert_eq!(status, rsproperties::wire::PROP_ERROR_SET_FAILED as u32);
        assert_eq!(properties.area.get("persist.number").unwrap(), "7");
        assert_eq!(properties.store.values["persist.number"], "7");
        drop(properties);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn v1_setprop_is_handled_without_an_acknowledgment() {
        let root = super::super::tests::temp_dir("v1-wire");
        let mut properties = super::super::tests::fixture(&root);
        let (mut client, mut stream) = UnixStream::pair().unwrap();
        client
            .write_all(&rsproperties::wire::PROP_MSG_SETPROP.to_le_bytes())
            .unwrap();
        let mut name = [0; rsproperties::wire::PROP_NAME_MAX];
        name[..9].copy_from_slice(b"debug.v1x");
        let mut value = [0; rsproperties::wire::PROP_VALUE_MAX];
        value[..5].copy_from_slice(b"value");
        client.write_all(&name).unwrap();
        client.write_all(&value).unwrap();
        handle(
            &mut stream,
            &mut properties,
            |_, _, _| {
                Ok(PeerCredentials {
                    pid: 1,
                    uid: 0,
                    gid: 0,
                })
            },
            |_, _, _, _| Ok(false),
            |_, _| false,
        )
        .unwrap();
        drop(stream);
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).unwrap();
        assert!(reply.is_empty());
        assert_eq!(properties.area.get("debug.v1x").unwrap(), "value");
        drop(properties);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn control_requests_use_guest_handlers_without_writing_properties() {
        let root = super::super::tests::temp_dir("control-wire");
        let mut properties = super::super::tests::fixture(&root);
        let peer = PeerCredentials {
            pid: 42,
            uid: 1000,
            gid: 1000,
        };
        for (name, value) in [
            ("ctl.start", "zygote"),
            ("sys.powerctl", "shutdown,userrequested"),
        ] {
            let (mut client, mut stream) = UnixStream::pair().unwrap();
            for part in [
                rsproperties::wire::PROP_MSG_SETPROP2.to_le_bytes().to_vec(),
                (name.len() as u32).to_le_bytes().to_vec(),
                name.as_bytes().to_vec(),
                (value.len() as u32).to_le_bytes().to_vec(),
                value.as_bytes().to_vec(),
            ] {
                client.write_all(&part).unwrap();
            }
            let mut service_called = false;
            let mut powerctl_called = false;
            handle(
                &mut stream,
                &mut properties,
                |_, _, _| Ok(peer),
                |action, target, actual_peer, _| {
                    assert_eq!(actual_peer.pid, peer.pid);
                    assert_eq!((action, target), ("start", "zygote"));
                    service_called = true;
                    Ok(true)
                },
                |command, actual_peer| {
                    assert_eq!(actual_peer.pid, peer.pid);
                    assert_eq!(command, "shutdown,userrequested");
                    powerctl_called = true;
                    true
                },
            )
            .unwrap();
            assert_eq!(
                read_u32(&mut client).unwrap(),
                rsproperties::wire::PROP_SUCCESS as u32
            );
            assert_eq!(service_called, name == "ctl.start");
            assert_eq!(powerctl_called, name == "sys.powerctl");
            assert!(properties.area.find(name).unwrap().is_none());
        }
        drop(properties);
        fs::remove_dir_all(root).unwrap();
    }
}
