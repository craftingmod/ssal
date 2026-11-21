use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const PRESENTER_ALLOW_FILE: &str = "state/presenter-allow.json";
const MAX_SCM_FDS: usize = 32;
const MAX_PAYLOAD_BYTES: usize = 4096;
const TOUCH_MAGIC_LE: [u8; 4] = 0x53544348u32.to_le_bytes();
const KEY_MAGIC_LE: [u8; 4] = 0x534B4559u32.to_le_bytes();
const INPUT_HEADER_BYTES: usize = 32;
const MAX_TOUCH_PACKET_BYTES: usize = 512;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub(crate) struct AllowedApp {
    pub package_name: String,
    pub uid: u32,
    pub socket_path: String,
}

#[derive(Clone)]
pub(crate) struct RelayHandle {
    allowlist: Arc<Mutex<Vec<AllowedApp>>>,
    composer_fd: Arc<Mutex<Option<Arc<OwnedFd>>>>,
    input_fd: Arc<Mutex<Option<Arc<OwnedFd>>>>,
    app_fd: Arc<Mutex<Option<Arc<OwnedFd>>>>,
}

pub(crate) fn valid_package_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name.contains('.')
        && !name.starts_with('.')
        && !name.ends_with('.')
        && !name.contains("..")
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.' || b == b'-')
}

pub(crate) fn parse_packages_list(contents: &str, package_name: &str) -> Option<AllowedApp> {
    for line in contents.lines() {
        let mut fields = line.split_whitespace();
        let Some(pkg) = fields.next() else {
            continue;
        };
        if pkg != package_name {
            continue;
        }
        let Some(uid_str) = fields.next() else {
            continue;
        };
        let Ok(uid) = uid_str.parse::<u32>() else {
            continue;
        };
        let _debuggable = fields.next();
        let data_dir = fields
            .next()
            .filter(|dir| dir.starts_with('/'))
            .map(str::to_owned)
            .unwrap_or_else(|| format!("/data/user/0/{package_name}"));
        let socket_path = format!("{}/cache/ssal-presenter.sock", data_dir.trim_end_matches('/'));
        return Some(AllowedApp {
            package_name: package_name.to_owned(),
            uid,
            socket_path,
        });
    }
    None
}

fn load_allowlist(root: &Path) -> Vec<AllowedApp> {
    let path = root.join(PRESENTER_ALLOW_FILE);
    let Ok(bytes) = fs::read(path) else {
        return Vec::new();
    };
    serde_json::from_slice(&bytes).unwrap_or_default()
}

pub(crate) fn allow_package(
    root: &Path,
    package_name: &str,
    relay: &RelayHandle,
) -> io::Result<String> {
    if !valid_package_name(package_name) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid package name '{package_name}'"),
        ));
    }
    let packages_list = fs::read_to_string("/data/system/packages.list").map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("failed to read /data/system/packages.list: {e}"),
        )
    })?;
    let app = parse_packages_list(&packages_list, package_name).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("package '{package_name}' not found in /data/system/packages.list"),
        )
    })?;

    let mut list = relay.allowlist.lock().unwrap();
    if let Some(existing) = list.iter_mut().find(|a| a.package_name == package_name) {
        *existing = app.clone();
    } else {
        list.push(app.clone());
    }
    let json = serde_json::to_vec_pretty(&*list).map_err(io::Error::other)?;
    super::atomic(&root.join(PRESENTER_ALLOW_FILE), &json)?;

    Ok(format!(
        "allowed {} uid={} socket={}",
        app.package_name, app.uid, app.socket_path
    ))
}

pub(crate) fn set_composer_fd(relay: &RelayHandle, fd: OwnedFd) {
    let arc_fd = Arc::new(fd);
    *relay.composer_fd.lock().unwrap() = Some(Arc::clone(&arc_fd));
    if relay.app_fd.lock().unwrap().is_some() {
        send_resync(&arc_fd);
    }
}

pub(crate) fn set_input_fd(relay: &RelayHandle, fd: OwnedFd) {
    *relay.input_fd.lock().unwrap() = Some(Arc::new(fd));
}

pub(crate) fn start(root: &Path) -> RelayHandle {
    let initial = load_allowlist(root);
    let handle = RelayHandle {
        allowlist: Arc::new(Mutex::new(initial)),
        composer_fd: Arc::new(Mutex::new(None)),
        input_fd: Arc::new(Mutex::new(None)),
        app_fd: Arc::new(Mutex::new(None)),
    };
    let connector_handle = handle.clone();
    std::thread::Builder::new()
        .name("ssal-presenter-app".into())
        .spawn(move || app_connector_loop(connector_handle))
        .expect("spawn presenter app connector thread");
    let pump_handle = handle.clone();
    std::thread::Builder::new()
        .name("ssal-presenter-pump".into())
        .spawn(move || composer_pump_loop(pump_handle))
        .expect("spawn presenter composer pump thread");
    let input_handle = handle.clone();
    std::thread::Builder::new()
        .name("ssal-input-pump".into())
        .spawn(move || input_pump_loop(input_handle))
        .expect("spawn presenter input pump thread");
    handle
}

fn connect_seqpacket_path(path: &str) -> io::Result<OwnedFd> {
    let c_path = std::ffi::CString::new(path)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid socket path"))?;
    let bytes = c_path.as_bytes_with_nul();
    let mut sun: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    sun.sun_family = libc::AF_UNIX as _;
    if bytes.len() > sun.sun_path.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "socket path too long",
        ));
    }
    unsafe {
        std::ptr::copy_nonoverlapping(
            bytes.as_ptr(),
            sun.sun_path.as_mut_ptr().cast::<u8>(),
            bytes.len(),
        );
    }
    let addr_len = std::mem::size_of::<libc::sa_family_t>() + bytes.len();
    connect_seqpacket(&sun, addr_len)
}

fn connect_seqpacket(sun: &libc::sockaddr_un, addr_len: usize) -> io::Result<OwnedFd> {
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    let rc = unsafe {
        libc::connect(
            owned.as_raw_fd(),
            (sun as *const libc::sockaddr_un).cast(),
            addr_len as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(owned)
}

fn peer_uid(fd: &OwnedFd) -> io::Result<u32> {
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of_val(&cred) as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(cred.uid as u32)
}

fn peer_closed(fd: &OwnedFd) -> bool {
    let mut pfd = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLHUP | libc::POLLERR,
        revents: 0,
    };
    let rc = unsafe { libc::poll(&mut pfd, 1, 0) };
    rc > 0 && (pfd.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL)) != 0
}

fn send_resync(vc_fd: &OwnedFd) {
    let byte: [u8; 1] = [b'R'];
    let _ = unsafe {
        libc::send(
            vc_fd.as_raw_fd(),
            byte.as_ptr().cast(),
            byte.len(),
            libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
        )
    };
}

fn app_connector_loop(relay: RelayHandle) {
    loop {
        {
            let mut guard = relay.app_fd.lock().unwrap();
            if let Some(ref fd) = *guard {
                if !peer_closed(fd) {
                    drop(guard);
                    std::thread::sleep(Duration::from_millis(250));
                    continue;
                }
                *guard = None;
            }
        }

        let snapshot = relay.allowlist.lock().unwrap().clone();
        if snapshot.is_empty() {
            std::thread::sleep(Duration::from_millis(500));
            continue;
        }

        let mut connected = false;
        for app in snapshot {
            let Ok(new_app_fd) = connect_seqpacket_path(&app.socket_path) else {
                continue;
            };
            let Ok(uid) = peer_uid(&new_app_fd) else {
                continue;
            };
            if uid != app.uid {
                eprintln!(
                    "ssald_presenter_relay_uid_mismatch pkg={} expected={} actual={}",
                    app.package_name, app.uid, uid
                );
                continue;
            }
            *relay.app_fd.lock().unwrap() = Some(Arc::new(new_app_fd));
            if let Some(ref vc_fd) = *relay.composer_fd.lock().unwrap() {
                send_resync(vc_fd);
            }
            eprintln!(
                "ssald_presenter_relay_app_connected pkg={} uid={}",
                app.package_name, app.uid
            );
            connected = true;
            break;
        }

        if !connected {
            std::thread::sleep(Duration::from_millis(500));
        }
    }
}

fn send_packet(sock_fd: RawFd, data: &[u8], fds: &[RawFd]) -> bool {
    let mut iov = libc::iovec {
        iov_base: data.as_ptr() as *mut libc::c_void,
        iov_len: data.len(),
    };
    let cmsg_space = if fds.is_empty() {
        0
    } else {
        unsafe { libc::CMSG_SPACE(std::mem::size_of_val(fds) as u32) as usize }
    };
    let mut cmsg_buf = vec![0u8; cmsg_space];

    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    if !fds.is_empty() {
        msg.msg_control = cmsg_buf.as_mut_ptr().cast();
        msg.msg_controllen = cmsg_space as _;
        unsafe {
            let cmsg = libc::CMSG_FIRSTHDR(&msg);
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of_val(fds) as u32) as _;
            std::ptr::copy_nonoverlapping(
                fds.as_ptr().cast::<u8>(),
                libc::CMSG_DATA(cmsg),
                std::mem::size_of_val(fds),
            );
        }
    }

    let sent = unsafe { libc::sendmsg(sock_fd, &msg, libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT) };
    if sent < 0 {
        let err = io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO);
        err == libc::EAGAIN || err == libc::EWOULDBLOCK
    } else {
        true
    }
}

fn composer_pump_loop(relay: RelayHandle) {
    let mut payload = vec![0u8; MAX_PAYLOAD_BYTES];
    let cmsg_cap =
        unsafe { libc::CMSG_SPACE((MAX_SCM_FDS * std::mem::size_of::<RawFd>()) as u32) as usize };
    let mut cmsg_buf = vec![0u8; cmsg_cap];

    loop {
        let Some(vc_fd) = relay.composer_fd.lock().unwrap().clone() else {
            std::thread::sleep(Duration::from_millis(100));
            continue;
        };

        loop {
            let mut pfd = libc::pollfd {
                fd: vc_fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let prc = unsafe { libc::poll(&mut pfd, 1, 200) };
            if prc < 0 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                break;
            }
            if prc == 0 {
                let replaced = relay
                    .composer_fd
                    .lock()
                    .unwrap()
                    .as_ref()
                    .is_none_or(|cur| !Arc::ptr_eq(cur, &vc_fd));
                if replaced {
                    break;
                }
                continue;
            }
            if (pfd.revents & libc::POLLIN) == 0 {
                if (pfd.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL)) != 0 {
                    let mut guard = relay.composer_fd.lock().unwrap();
                    if guard.as_ref().is_some_and(|cur| Arc::ptr_eq(cur, &vc_fd)) {
                        *guard = None;
                    }
                    eprintln!("ssald_presenter_relay_composer_disconnected");
                    break;
                }
                continue;
            }

            let mut iov = libc::iovec {
                iov_base: payload.as_mut_ptr().cast(),
                iov_len: payload.len(),
            };
            let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = cmsg_buf.as_mut_ptr().cast();
            msg.msg_controllen = cmsg_buf.len() as _;

            let n = unsafe { libc::recvmsg(vc_fd.as_raw_fd(), &mut msg, libc::MSG_CMSG_CLOEXEC) };
            if n <= 0 {
                let mut guard = relay.composer_fd.lock().unwrap();
                if guard.as_ref().is_some_and(|cur| Arc::ptr_eq(cur, &vc_fd)) {
                    *guard = None;
                }
                eprintln!("ssald_presenter_relay_composer_disconnected");
                break;
            }

            let mut received_fds: Vec<OwnedFd> = Vec::new();
            unsafe {
                let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
                while !cmsg.is_null() {
                    if (*cmsg).cmsg_level == libc::SOL_SOCKET
                        && (*cmsg).cmsg_type == libc::SCM_RIGHTS
                    {
                        let data_len = (*cmsg).cmsg_len as usize - libc::CMSG_LEN(0) as usize;
                        let count = data_len / std::mem::size_of::<RawFd>();
                        let ptr = libc::CMSG_DATA(cmsg).cast::<RawFd>();
                        for i in 0..count {
                            let fd = std::ptr::read_unaligned(ptr.add(i));
                            if fd >= 0 {
                                received_fds.push(OwnedFd::from_raw_fd(fd));
                            }
                        }
                    }
                    cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
                }
            }

            if (msg.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC)) != 0 {
                continue;
            }

            let raw_fds: Vec<RawFd> = received_fds.iter().map(AsRawFd::as_raw_fd).collect();
            let app_fd = relay.app_fd.lock().unwrap().clone();
            if let Some(ref app_fd) = app_fd {
                let send_ok = send_packet(app_fd.as_raw_fd(), &payload[..n as usize], &raw_fds);
                if !send_ok {
                    let mut guard = relay.app_fd.lock().unwrap();
                    if guard.as_ref().is_some_and(|cur| Arc::ptr_eq(cur, app_fd)) {
                        *guard = None;
                    }
                    eprintln!("ssald_presenter_relay_app_disconnected");
                }
            }
            drop(received_fds);
        }
    }
}

fn valid_input_packet(packet: &[u8]) -> bool {
    packet.len() >= INPUT_HEADER_BYTES
        && (packet[..4] == TOUCH_MAGIC_LE
            || (packet.len() == INPUT_HEADER_BYTES && packet[..4] == KEY_MAGIC_LE))
}

fn input_pump_loop(relay: RelayHandle) {
    let mut buf = [0u8; MAX_TOUCH_PACKET_BYTES];

    loop {
        let Some(app_fd) = relay.app_fd.lock().unwrap().clone() else {
            std::thread::sleep(Duration::from_millis(100));
            continue;
        };

        loop {
            let mut pfd = libc::pollfd {
                fd: app_fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let prc = unsafe { libc::poll(&mut pfd, 1, 200) };
            if prc < 0 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                break;
            }
            if prc == 0 {
                let replaced = relay
                    .app_fd
                    .lock()
                    .unwrap()
                    .as_ref()
                    .is_none_or(|cur| !Arc::ptr_eq(cur, &app_fd));
                if replaced {
                    break;
                }
                continue;
            }
            if (pfd.revents & libc::POLLIN) == 0 {
                if (pfd.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL)) != 0 {
                    let mut guard = relay.app_fd.lock().unwrap();
                    if guard.as_ref().is_some_and(|cur| Arc::ptr_eq(cur, &app_fd)) {
                        *guard = None;
                    }
                    eprintln!("ssald_presenter_relay_app_disconnected");
                    break;
                }
                continue;
            }

            let n = unsafe {
                libc::recv(
                    app_fd.as_raw_fd(),
                    buf.as_mut_ptr().cast(),
                    buf.len(),
                    libc::MSG_DONTWAIT,
                )
            };
            if n < 0 {
                let err = io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO);
                if err == libc::EAGAIN || err == libc::EWOULDBLOCK || err == libc::EINTR {
                    continue;
                }
                let mut guard = relay.app_fd.lock().unwrap();
                if guard.as_ref().is_some_and(|cur| Arc::ptr_eq(cur, &app_fd)) {
                    *guard = None;
                }
                eprintln!("ssald_presenter_relay_app_disconnected");
                break;
            }
            if n == 0 {
                let mut guard = relay.app_fd.lock().unwrap();
                if guard.as_ref().is_some_and(|cur| Arc::ptr_eq(cur, &app_fd)) {
                    *guard = None;
                }
                eprintln!("ssald_presenter_relay_app_disconnected");
                break;
            }

            let len = n as usize;
            if !valid_input_packet(&buf[..len]) {
                continue;
            }

            let input_fd = relay.input_fd.lock().unwrap().clone();
            if let Some(ref in_fd) = input_fd {
                let sent = unsafe {
                    libc::send(
                        in_fd.as_raw_fd(),
                        buf.as_ptr().cast(),
                        len,
                        libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
                    )
                };
                if sent < 0 {
                    let err = io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO);
                    if err != libc::EAGAIN && err != libc::EWOULDBLOCK {
                        let mut guard = relay.input_fd.lock().unwrap();
                        if guard.as_ref().is_some_and(|cur| Arc::ptr_eq(cur, in_fd)) {
                            *guard = None;
                        }
                        eprintln!("ssald_presenter_relay_input_disconnected");
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_key_and_touch_packets() {
        let mut packet = [0u8; INPUT_HEADER_BYTES + 16];
        packet[..4].copy_from_slice(&KEY_MAGIC_LE);
        assert!(valid_input_packet(&packet[..INPUT_HEADER_BYTES]));
        assert!(!valid_input_packet(&packet[..INPUT_HEADER_BYTES - 1]));
        assert!(!valid_input_packet(&packet));
        packet[..4].copy_from_slice(&TOUCH_MAGIC_LE);
        assert!(valid_input_packet(&packet));
        packet[..4].fill(0);
        assert!(!valid_input_packet(&packet[..INPUT_HEADER_BYTES]));
    }

    #[test]
    fn validates_package_names() {
        assert!(valid_package_name("alyac.android.ssalsurface"));
        assert!(valid_package_name("com.example.app_1"));
        assert!(!valid_package_name("singleword"));
        assert!(!valid_package_name(".leading.dot"));
        assert!(!valid_package_name("trailing.dot."));
        assert!(!valid_package_name("a..b"));
        assert!(!valid_package_name("a/b.c"));
    }

    #[test]
    fn parses_packages_list_entry() {
        let sample = "\
com.android.shell 2000 0 /data/user/0/com.android.shell platform:privapp 0 0 1
alyac.android.ssalsurface 10059 1 /data/user/0/alyac.android.ssalsurface default:targetSdkVersion=37 0 0 1
";
        let app = parse_packages_list(sample, "alyac.android.ssalsurface").unwrap();
        assert_eq!(app.uid, 10059);
        assert_eq!(
            app.socket_path,
            "/data/user/0/alyac.android.ssalsurface/cache/ssal-presenter.sock"
        );
        assert!(parse_packages_list(sample, "com.missing.app").is_none());
    }
}
