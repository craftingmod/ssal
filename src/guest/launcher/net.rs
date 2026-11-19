use std::ffi::CString;
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, RawFd};

const IFLA_IFNAME: u16 = 3;
const IFLA_LINKINFO: u16 = 18;
const IFLA_NET_NS_FD: u16 = 28;
const IFLA_INFO_KIND: u16 = 1;
const IFLA_INFO_DATA: u16 = 2;
const VETH_INFO_PEER: u16 = 1;

fn align4(len: usize) -> usize {
    (len + 3) & !3
}

struct NlMsg {
    buf: Vec<u8>,
}

impl NlMsg {
    fn new(nlmsg_type: u16, nlmsg_flags: u16) -> Self {
        let mut buf = vec![0u8; 16 + 16]; // nlmsghdr (16) + ifinfomsg (16)
        buf[4..6].copy_from_slice(&nlmsg_type.to_ne_bytes());
        buf[6..8].copy_from_slice(&nlmsg_flags.to_ne_bytes());
        buf[8..12].copy_from_slice(&1u32.to_ne_bytes()); // seq = 1
        Self { buf }
    }

    fn put_attr(&mut self, attr_type: u16, payload: &[u8]) {
        let start = self.buf.len();
        let len = (4 + payload.len()) as u16;
        self.buf.extend_from_slice(&len.to_ne_bytes());
        self.buf.extend_from_slice(&attr_type.to_ne_bytes());
        self.buf.extend_from_slice(payload);
        self.buf.resize(start + align4(len as usize), 0);
    }

    fn start_nested(&mut self, attr_type: u16) -> usize {
        let start = self.buf.len();
        self.buf.extend_from_slice(&0u16.to_ne_bytes());
        self.buf.extend_from_slice(&attr_type.to_ne_bytes());
        start
    }

    fn end_nested(&mut self, start: usize) {
        let len = (self.buf.len() - start) as u16;
        self.buf[start..start + 2].copy_from_slice(&len.to_ne_bytes());
    }

    fn finish(mut self) -> Vec<u8> {
        let len = self.buf.len() as u32;
        self.buf[0..4].copy_from_slice(&len.to_ne_bytes());
        self.buf
    }
}

fn create_veth_pair(guest_if: &str, peer_if: &str, guest_netns_fd: RawFd) -> io::Result<()> {
    let sock = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        )
    };
    if sock < 0 {
        return Err(io::Error::last_os_error());
    }

    let res = (|| {
        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as _;
        if unsafe {
            libc::bind(
                sock,
                &addr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }

        let mut msg = NlMsg::new(
            libc::RTM_NEWLINK,
            (libc::NLM_F_REQUEST | libc::NLM_F_CREATE | libc::NLM_F_EXCL | libc::NLM_F_ACK) as u16,
        );
        let guest_c = CString::new(guest_if).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let peer_c = CString::new(peer_if).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        msg.put_attr(IFLA_IFNAME, guest_c.as_bytes_with_nul());
        msg.put_attr(IFLA_NET_NS_FD, &(guest_netns_fd as i32).to_ne_bytes());

        let linkinfo = msg.start_nested(IFLA_LINKINFO);
        msg.put_attr(IFLA_INFO_KIND, b"veth\0");
        let infodata = msg.start_nested(IFLA_INFO_DATA);
        let peer = msg.start_nested(VETH_INFO_PEER);
        msg.buf.extend_from_slice(&[0u8; 16]); // struct ifinfomsg for peer
        msg.put_attr(IFLA_IFNAME, peer_c.as_bytes_with_nul());
        msg.end_nested(peer);
        msg.end_nested(infodata);
        msg.end_nested(linkinfo);

        let bytes = msg.finish();
        let sent = unsafe { libc::send(sock, bytes.as_ptr().cast(), bytes.len(), 0) };
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }

        let mut ack = [0u8; 256];
        let n = unsafe { libc::recv(sock, ack.as_mut_ptr().cast(), ack.len(), 0) };
        if n < 20 {
            return Err(io::Error::last_os_error());
        }
        let nlmsg_type = u16::from_ne_bytes([ack[4], ack[5]]);
        if nlmsg_type == libc::NLMSG_ERROR as u16 {
            let err = i32::from_ne_bytes([ack[16], ack[17], ack[18], ack[19]]);
            if err != 0 {
                return Err(io::Error::from_raw_os_error(-err));
            }
        }
        Ok(())
    })();

    unsafe { libc::close(sock) };
    res
}

fn bring_up_interface(name: &str) -> io::Result<()> {
    let c_name = CString::new(name).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if sock < 0 {
        return Err(io::Error::last_os_error());
    }

    let res = (|| {
        let mut req: libc::ifreq = unsafe { std::mem::zeroed() };
        let bytes = c_name.as_bytes_with_nul();
        let copy_len = bytes.len().min(req.ifr_name.len());
        for (dst, &src) in req.ifr_name[..copy_len].iter_mut().zip(&bytes[..copy_len]) {
            *dst = src as libc::c_char;
        }
        if unsafe { libc::ioctl(sock, libc::SIOCGIFFLAGS as _, &mut req) } != 0 {
            return Err(io::Error::last_os_error());
        }
        unsafe {
            req.ifr_ifru.ifru_flags |= libc::IFF_UP as i16;
        }
        if unsafe { libc::ioctl(sock, libc::SIOCSIFFLAGS as _, &mut req) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    })();

    unsafe { libc::close(sock) };
    res
}

pub(crate) fn setup_guest_veth() -> io::Result<File> {
    let guest_ns = File::open("/proc/self/ns/net")?;
    let guest_ns_fd = guest_ns.as_raw_fd();
    let peer_ns = std::thread::spawn(move || -> io::Result<File> {
        if unsafe { libc::unshare(libc::CLONE_NEWNET) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let peer_ns = File::open("/proc/self/ns/net")?;
        create_veth_pair("eth0", "veth-ssal", guest_ns_fd)?;
        bring_up_interface("veth-ssal")?;
        Ok(peer_ns)
    })
    .join()
    .map_err(|_| io::Error::other("veth peer thread panicked"))??;

    bring_up_interface("lo")?;
    bring_up_interface("eth0")?;
    Ok(peer_ns)
}
