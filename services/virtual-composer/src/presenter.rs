use std::collections::BTreeMap;
use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex,
};

const PACKET_MAGIC: u32 = 0x5353_414C; // 'SSAL'
const PACKET_VERSION: u32 = 1;
const DEFAULT_SOCKET: &str = "@ssal-virtual-composer-presenter";
const MAX_SCM_FDS: usize = 32;

#[repr(C)]
#[derive(Clone, Copy)]
struct PresenterPacketHeader {
    magic: u32,
    version: u32,
    slot: i32,
    width: u32,
    height: u32,
    format: u32,
    dataspace: i32,
    num_fds: u32,
    num_ints: u32,
    has_fence: u32,
}

struct CachedHandle {
    fds: Vec<OwnedFd>,
    ints: Vec<i32>,
    sent_generation: u64,
}

struct PeerState {
    fd: Option<OwnedFd>,
    generation: u64,
}

#[derive(Clone, Copy)]
struct LastFrame {
    slot: i32,
    width: u32,
    height: u32,
    format: u32,
    dataspace: i32,
}

pub struct PresenterBridge {
    peer: Arc<Mutex<PeerState>>,
    generation: Arc<AtomicU64>,
    slots: Arc<Mutex<BTreeMap<i32, CachedHandle>>>,
    last_frame: Arc<Mutex<Option<LastFrame>>>,
}

pub fn dup_fd(raw: RawFd) -> Option<OwnedFd> {
    if raw < 0 {
        return None;
    }
    let fd = unsafe { libc::fcntl(raw, libc::F_DUPFD_CLOEXEC, 0) };
    if fd < 0 {
        None
    } else {
        Some(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

impl PresenterBridge {
    pub fn start_from_env() -> Self {
        let peer = Arc::new(Mutex::new(PeerState {
            fd: None,
            generation: 0,
        }));
        let generation = Arc::new(AtomicU64::new(0));
        let slots = Arc::new(Mutex::new(BTreeMap::new()));
        let last_frame = Arc::new(Mutex::new(None));

        if let Ok(fd_str) = std::env::var("SSAL_PRESENTER_FD") {
            if let Ok(raw_fd) = fd_str.trim().parse::<RawFd>() {
                if let Some(owned) = dup_fd(raw_fd) {
                    if raw_fd == 0 {
                        let dev_null = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY) };
                        if dev_null >= 0 {
                            unsafe {
                                libc::dup2(dev_null, 0);
                                if dev_null > 2 {
                                    libc::close(dev_null);
                                }
                            }
                        }
                    }
                    let rx_fd = dup_fd(owned.as_raw_fd());
                    let init_gen = generation.fetch_add(1, Ordering::AcqRel) + 1;
                    {
                        let mut guard = peer.lock().unwrap();
                        guard.fd = Some(owned);
                        guard.generation = init_gen;
                    }
                    println!("virtual_composer_presenter_fd_ready fd={raw_fd} gen={init_gen}");
                    if let Some(rx_fd) = rx_fd {
                        let peer_clone = Arc::clone(&peer);
                        let gen_clone = Arc::clone(&generation);
                        let slots_clone = Arc::clone(&slots);
                        let last_clone = Arc::clone(&last_frame);
                        std::thread::spawn(move || {
                            resync_loop(rx_fd, peer_clone, gen_clone, slots_clone, last_clone)
                        });
                    }
                    return Self {
                        peer,
                        generation,
                        slots,
                        last_frame,
                    };
                }
            }
        }

        let addr = std::env::var("SSAL_PRESENTER_SOCKET").unwrap_or_else(|_| DEFAULT_SOCKET.into());
        if !addr.is_empty() && addr != "none" {
            let peer_clone = Arc::clone(&peer);
            let gen_clone = Arc::clone(&generation);
            std::thread::spawn(move || accept_loop(&addr, peer_clone, gen_clone));
        }

        Self {
            peer,
            generation,
            slots,
            last_frame,
        }
    }

    pub fn has_peer(&self) -> bool {
        self.peer.lock().unwrap().fd.is_some()
    }

    pub fn cache_handle(&self, slot: i32, fds: Vec<OwnedFd>, ints: Vec<i32>) {
        self.slots.lock().unwrap().insert(
            slot,
            CachedHandle {
                fds,
                ints,
                sent_generation: 0,
            },
        );
    }

    pub fn present_slot(
        &self,
        slot: i32,
        width: u32,
        height: u32,
        format: u32,
        dataspace: i32,
        acquire_fence: Option<OwnedFd>,
    ) -> bool {
        *self.last_frame.lock().unwrap() = Some(LastFrame {
            slot,
            width,
            height,
            format,
            dataspace,
        });
        present_slot_inner(
            &self.peer,
            &self.slots,
            slot,
            width,
            height,
            format,
            dataspace,
            acquire_fence,
        )
    }
}

fn present_slot_inner(
    peer: &Mutex<PeerState>,
    slots: &Mutex<BTreeMap<i32, CachedHandle>>,
    slot: i32,
    width: u32,
    height: u32,
    format: u32,
    dataspace: i32,
    acquire_fence: Option<OwnedFd>,
) -> bool {
    let mut peer_guard = peer.lock().unwrap();
    let Some(peer_fd) = peer_guard.fd.as_ref() else {
        return false;
    };
    let peer_gen = peer_guard.generation;

    let mut slots = slots.lock().unwrap();
    let Some(cached) = slots.get_mut(&slot) else {
        eprintln!("virtual_composer_presenter_missing_slot slot={slot}");
        return false;
    };

    let send_handle = cached.sent_generation != peer_gen;
    let num_fds = if send_handle { cached.fds.len() } else { 0 };
    let num_ints = if send_handle { cached.ints.len() } else { 0 };
    let has_fence = if acquire_fence.is_some() { 1 } else { 0 };

    if num_fds + has_fence > MAX_SCM_FDS {
        eprintln!(
            "virtual_composer_presenter_drop slot={slot} too_many_fds={}",
            num_fds + has_fence
        );
        return false;
    }

    let header = PresenterPacketHeader {
        magic: PACKET_MAGIC,
        version: PACKET_VERSION,
        slot,
        width,
        height,
        format,
        dataspace,
        num_fds: num_fds as u32,
        num_ints: num_ints as u32,
        has_fence: has_fence as u32,
    };

    let mut fds_to_send: Vec<RawFd> = Vec::with_capacity(num_fds + has_fence);
    if send_handle {
        for fd in &cached.fds {
            fds_to_send.push(fd.as_raw_fd());
        }
    }
    if let Some(ref fence) = acquire_fence {
        fds_to_send.push(fence.as_raw_fd());
    }

    let ints_slice: &[i32] = if send_handle { &cached.ints } else { &[] };
    match send_packet(peer_fd.as_raw_fd(), &header, ints_slice, &fds_to_send) {
        Ok(()) => {
            if send_handle {
                cached.sent_generation = peer_gen;
            }
            true
        }
        Err(err) => {
            if err == libc::EPIPE || err == libc::ECONNRESET || err == libc::ENOTCONN {
                eprintln!("virtual_composer_presenter_disconnected errno={err}");
                peer_guard.fd = None;
            } else if err != libc::EAGAIN && err != libc::EWOULDBLOCK {
                eprintln!("virtual_composer_presenter_send_err errno={err}");
            }
            false
        }
    }
}

fn send_packet(
    sock_fd: RawFd,
    header: &PresenterPacketHeader,
    ints: &[i32],
    fds: &[RawFd],
) -> Result<(), i32> {
    let mut iov = [
        libc::iovec {
            iov_base: (header as *const PresenterPacketHeader) as *mut libc::c_void,
            iov_len: std::mem::size_of::<PresenterPacketHeader>(),
        },
        libc::iovec {
            iov_base: ints.as_ptr() as *mut libc::c_void,
            iov_len: std::mem::size_of_val(ints),
        },
    ];
    let iovlen = if ints.is_empty() { 1 } else { 2 };

    let cmsg_space = if fds.is_empty() {
        0
    } else {
        unsafe { libc::CMSG_SPACE(std::mem::size_of_val(fds) as u32) as usize }
    };
    let mut cmsg_buf = vec![0u8; cmsg_space];

    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = iov.as_mut_ptr();
    msg.msg_iovlen = iovlen;
    if !fds.is_empty() {
        msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = cmsg_space as _;
        unsafe {
            let cmsg = libc::CMSG_FIRSTHDR(&msg);
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of_val(fds) as u32) as _;
            std::ptr::copy_nonoverlapping(
                fds.as_ptr() as *const u8,
                libc::CMSG_DATA(cmsg),
                std::mem::size_of_val(fds),
            );
        }
    }

    let sent = unsafe { libc::sendmsg(sock_fd, &msg, libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT) };
    if sent < 0 {
        Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO))
    } else {
        Ok(())
    }
}

fn bind_unix_seqpacket(addr: &str) -> Option<OwnedFd> {
    let sock_fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0) };
    if sock_fd < 0 {
        eprintln!(
            "virtual_composer_presenter_socket_err={}",
            std::io::Error::last_os_error()
        );
        return None;
    }
    let listener = unsafe { OwnedFd::from_raw_fd(sock_fd) };

    let mut sun: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    sun.sun_family = libc::AF_UNIX as _;
    let max_len = sun.sun_path.len();

    let addr_len = if let Some(abstract_name) = addr.strip_prefix('@') {
        let bytes = abstract_name.as_bytes();
        if bytes.len() + 1 > max_len {
            eprintln!("virtual_composer_presenter_addr_too_long={addr}");
            return None;
        }
        sun.sun_path[0] = 0;
        unsafe {
            std::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                sun.sun_path.as_mut_ptr().add(1) as *mut u8,
                bytes.len(),
            );
        }
        std::mem::size_of::<libc::sa_family_t>() + 1 + bytes.len()
    } else {
        let Ok(c_path) = CString::new(addr) else {
            return None;
        };
        let bytes = c_path.as_bytes_with_nul();
        if bytes.len() > max_len {
            eprintln!("virtual_composer_presenter_addr_too_long={addr}");
            return None;
        }
        unsafe {
            let _ = libc::unlink(c_path.as_ptr());
            std::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                sun.sun_path.as_mut_ptr() as *mut u8,
                bytes.len(),
            );
        }
        std::mem::size_of::<libc::sa_family_t>() + bytes.len()
    };

    let rc = unsafe {
        libc::bind(
            listener.as_raw_fd(),
            (&sun as *const libc::sockaddr_un) as *const libc::sockaddr,
            addr_len as libc::socklen_t,
        )
    };
    if rc < 0 {
        eprintln!(
            "virtual_composer_presenter_bind_err addr={addr} err={}",
            std::io::Error::last_os_error()
        );
        return None;
    }

    if !addr.starts_with('@') {
        if let Ok(c_path) = CString::new(addr) {
            unsafe {
                libc::chmod(c_path.as_ptr(), 0o666);
            }
        }
    }

    if unsafe { libc::listen(listener.as_raw_fd(), 4) } < 0 {
        eprintln!(
            "virtual_composer_presenter_listen_err err={}",
            std::io::Error::last_os_error()
        );
        return None;
    }

    println!("virtual_composer_presenter_listening={addr}");
    Some(listener)
}

fn accept_loop(addr: &str, peer: Arc<Mutex<PeerState>>, generation: Arc<AtomicU64>) {
    let Some(listener) = bind_unix_seqpacket(addr) else {
        return;
    };
    loop {
        let client_fd = unsafe {
            libc::accept4(
                listener.as_raw_fd(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                libc::SOCK_CLOEXEC,
            )
        };
        if client_fd < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
            continue;
        }
        let owned = unsafe { OwnedFd::from_raw_fd(client_fd) };
        let new_gen = generation.fetch_add(1, Ordering::AcqRel) + 1;
        let mut guard = peer.lock().unwrap();
        guard.fd = Some(owned);
        guard.generation = new_gen;
        println!("virtual_composer_presenter_connected gen={new_gen}");
    }
}

fn resync_loop(
    rx_fd: OwnedFd,
    peer: Arc<Mutex<PeerState>>,
    generation: Arc<AtomicU64>,
    slots: Arc<Mutex<BTreeMap<i32, CachedHandle>>>,
    last_frame: Arc<Mutex<Option<LastFrame>>>,
) {
    let mut buf = [0u8; 64];
    loop {
        let n = unsafe {
            libc::recv(
                rx_fd.as_raw_fd(),
                buf.as_mut_ptr().cast::<libc::c_void>(),
                buf.len(),
                0,
            )
        };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            break;
        }
        if n == 0 {
            break;
        }
        let new_gen = generation.fetch_add(1, Ordering::AcqRel) + 1;
        {
            let mut guard = peer.lock().unwrap();
            guard.generation = new_gen;
        }
        let last = *last_frame.lock().unwrap();
        let resent = if let Some(f) = last {
            present_slot_inner(&peer, &slots, f.slot, f.width, f.height, f.format, f.dataspace, None)
        } else {
            false
        };
        println!("virtual_composer_presenter_resync gen={new_gen} resent={resent}");
    }
}
