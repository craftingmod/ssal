use super::{policy, Properties, SOCKET};
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

pub(super) fn peer(stream: &UnixStream) -> io::Result<(libc::ucred, String)> {
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
    Ok((credential, context.into()))
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

fn request(stream: &mut impl Read, command: u32) -> io::Result<(String, String)> {
    use rsproperties::wire::*;
    match command {
        PROP_MSG_SETPROP2 => Ok((
            string(stream, MAX_WIRE_NAME_LEN)?,
            string(stream, MAX_WIRE_VALUE_LEN)?,
        )),
        PROP_MSG_SETPROP => {
            let mut name = [0; PROP_NAME_MAX];
            let mut value = [0; PROP_VALUE_MAX];
            stream.read_exact(&mut name)?;
            stream.read_exact(&mut value)?;
            let field = |bytes: &[u8]| -> io::Result<String> {
                let end = bytes
                    .iter()
                    .position(|b| *b == 0)
                    .ok_or_else(|| io::Error::other("unterminated V1 field"))?;
                Ok(std::str::from_utf8(&bytes[..end])
                    .map_err(io::Error::other)?
                    .into())
            };
            Ok((field(&name)?, field(&value)?))
        }
        _ => Err(io::Error::other("unknown property protocol command")),
    }
}

fn response(stream: &mut UnixStream, command: u32, success: bool) {
    if command == rsproperties::wire::PROP_MSG_SETPROP2 {
        let status: u32 = if success { 0 } else { 0x0020 };
        let _ = stream.write_all(&status.to_le_bytes());
    }
}

// Invalid peers/requests are local rejections; committed-state failures stop the server.
pub(super) fn handle(
    stream: &mut UnixStream,
    properties: &mut Properties,
    authorize: impl FnOnce(&UnixStream, &str) -> io::Result<()>,
) -> io::Result<()> {
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    let mut reader = RequestReader {
        stream,
        deadline: Instant::now() + Duration::from_secs(2),
    };
    let Ok(command) = read_u32(&mut reader) else {
        return Ok(());
    };
    let (name, value) = match request(&mut reader, command) {
        Ok(pair) => pair,
        Err(_) => {
            response(stream, command, false);
            return Ok(());
        }
    };
    if properties
        .check_write(&name, &value, |target| authorize(stream, target))
        .is_err()
    {
        response(stream, command, false);
        return Ok(());
    }
    let result = properties.set(&name, &value);
    response(stream, command, result.is_ok());
    result
}

pub(super) fn serve(properties: &mut Properties) -> io::Result<()> {
    let path = Path::new(SOCKET);
    // Fresh /dev/socket belongs to this session. Never replace a running/stale server's socket.
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        _ => {
            return Err(io::Error::other(
                "Guest property socket already exists or cannot be checked",
            ))
        }
    }
    unsafe {
        libc::umask(0o077);
    }
    let listener = UnixListener::bind(path)?;
    let result: io::Result<()> = (|| {
        let name = std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(io::Error::other)?;
        let context =
            std::ffi::CString::new(properties.socket_context.as_str()).map_err(io::Error::other)?;
        if unsafe {
            libc::lsetxattr(
                name.as_ptr(),
                c"security.selinux".as_ptr(),
                context.as_ptr().cast(),
                context.as_bytes_with_nul().len(),
                0,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        let mut actual = [0u8; 512];
        let size = unsafe {
            libc::lgetxattr(
                name.as_ptr(),
                c"security.selinux".as_ptr(),
                actual.as_mut_ptr().cast(),
                actual.len(),
            )
        };
        if size < 0 {
            return Err(io::Error::last_os_error());
        }
        let actual = &actual[..size as usize];
        if actual.strip_suffix(&[0]).unwrap_or(actual) != context.as_bytes() {
            return Err(io::Error::other("Guest socket label mismatch"));
        }
        // Bionic clients of all UIDs connect; authorization is per property via SO_PEERSEC.
        fs::set_permissions(path, fs::Permissions::from_mode(0o666))?;
        println!("{{\"event\":\"guest_property_service_ready\",\"persistent_file\":\"/data/property/persistent_properties\"}}");
        loop {
            let (mut stream, _) = match listener.accept() {
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                result => result?,
            };
            handle(&mut stream, properties, |stream, target| {
                let (credentials, source) = peer(stream).map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "property peer identity unavailable",
                    )
                })?;
                policy::check_access(&source, target).map_err(|e| {
                    eprintln!(
                        "Guest property denied: pid={} uid={} gid={} source={} target={}: {}",
                        credentials.pid, credentials.uid, credentials.gid, source, target, e
                    );
                    io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "property authorization failed",
                    )
                })
            })?;
        }
    })();
    drop(listener);
    let cleanup = fs::remove_file(path);
    result.and(cleanup)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
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
        assert!(request(&mut Cursor::new(bytes), 0x20001).is_err());
        assert!(request(&mut Cursor::new(u32::MAX.to_le_bytes()), 0x20001).is_err());
        assert!(request(&mut Cursor::new([1; 124]), 1).is_err());
        assert!(request(&mut Cursor::new([]), 7).is_err());
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
        let result = handle(&mut stream, properties, |_, _| {
            if allowed {
                Ok(())
            } else {
                Err(io::Error::new(io::ErrorKind::PermissionDenied, "denied"))
            }
        });
        (result, read_u32(&mut client).unwrap())
    }

    #[test]
    fn protocol_ack_denials_and_disk_failure() {
        let root = super::super::tests::temp_dir("wire");
        let mut properties = super::super::tests::fixture(&root);
        let (result, status) = exchange(&mut properties, "persist.number", "7", true);
        assert!(result.is_ok());
        assert_eq!(status, 0);
        assert_eq!(
            properties.area.get_with_result("persist.number").unwrap(),
            "7"
        );
        assert_eq!(properties.store.values["persist.number"], "7");
        for (name, value, allowed) in [
            ("persist.number", "bad", true),
            ("persist.number", "8", false),
            ("ctl.start", "x", true),
            ("sys.powerctl", "reboot", true),
            ("ro.late", "x", true),
            ("bad..name", "x", true),
        ] {
            let (result, status) = exchange(&mut properties, name, value, allowed);
            assert!(result.is_ok(), "rejection must keep server alive");
            assert_ne!(status, 0);
        }
        fs::create_dir(root.join("property/persistent_properties.tmp")).unwrap();
        let (result, status) = exchange(&mut properties, "persist.number", "9", true);
        assert!(result.is_err(), "storage failure must stop server");
        assert_ne!(status, 0);
        assert_eq!(
            properties.area.get_with_result("persist.number").unwrap(),
            "7"
        );
        assert_eq!(properties.store.values["persist.number"], "7");
        drop(properties);
        fs::remove_dir_all(root).unwrap();
    }
}
