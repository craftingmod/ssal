use std::ffi::CString;
use std::fs::{self, File};
use std::io;
use std::net::{Ipv4Addr, Shutdown, SocketAddrV4, TcpListener, TcpStream, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::path::Path;
use std::process::Command;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;

const BASE_HOST_ADB_PORT: u16 = 15554;
pub(crate) const GUEST_ADB_PORT: u16 = 5555;

const HOST_VETH_IF: &str = "veth-ssal";
const GUEST_ETH_IF: &str = "eth0";
const HOST_VETH_IP: [u8; 4] = [10, 242, 0, 1];
const GUEST_ETH_IP: [u8; 4] = [10, 242, 0, 2];
const GUEST_SUBNET_CIDR: &str = "10.242.0.0/24";
const GUEST_PREFIX_LEN: u8 = 24;
const DNS_PRIMARY: [u8; 4] = [8, 8, 8, 8];
const DNS_SECONDARY: [u8; 4] = [1, 1, 1, 1];

const IFLA_IFNAME: u16 = 3;
const IFLA_LINKINFO: u16 = 18;
const IFLA_NET_NS_FD: u16 = 28;
const IFLA_INFO_KIND: u16 = 1;
const IFLA_INFO_DATA: u16 = 2;
const VETH_INFO_PEER: u16 = 1;

const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const IFA_BROADCAST: u16 = 4;

const RTA_OIF: u16 = 4;
const RTA_GATEWAY: u16 = 5;

fn align4(len: usize) -> usize {
    (len + 3) & !3
}

struct NlMsg {
    buf: Vec<u8>,
}

impl NlMsg {
    fn new_with_header(nlmsg_type: u16, nlmsg_flags: u16, header_len: usize) -> Self {
        let mut buf = vec![0u8; 16 + header_len];
        buf[4..6].copy_from_slice(&nlmsg_type.to_ne_bytes());
        buf[6..8].copy_from_slice(&nlmsg_flags.to_ne_bytes());
        buf[8..12].copy_from_slice(&1u32.to_ne_bytes()); // seq = 1
        Self { buf }
    }

    fn new(nlmsg_type: u16, nlmsg_flags: u16) -> Self {
        Self::new_with_header(nlmsg_type, nlmsg_flags, 16) // nlmsghdr (16) + ifinfomsg (16)
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

fn netlink_route_exchange(bytes: &[u8]) -> io::Result<()> {
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

fn if_index(name: &str) -> io::Result<u32> {
    let c_name = CString::new(name).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let idx = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
    if idx == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(idx)
}

fn delete_link_if_exists(name: &str) {
    let Ok(c_name) = CString::new(name) else {
        return;
    };
    let mut msg = NlMsg::new(
        libc::RTM_DELLINK,
        (libc::NLM_F_REQUEST | libc::NLM_F_ACK) as u16,
    );
    msg.put_attr(IFLA_IFNAME, c_name.as_bytes_with_nul());
    let _ = netlink_route_exchange(&msg.finish());
}

fn create_veth_pair(guest_if: &str, peer_if: &str, guest_netns_fd: RawFd) -> io::Result<()> {
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

    netlink_route_exchange(&msg.finish())
}

fn add_ipv4_addr(if_name: &str, ip: [u8; 4], prefix_len: u8) -> io::Result<()> {
    let idx = if_index(if_name)?;
    // struct ifaddrmsg: family(1), prefixlen(1), flags(1), scope(1), index(4) = 8 bytes
    let mut msg = NlMsg::new_with_header(
        libc::RTM_NEWADDR,
        (libc::NLM_F_REQUEST | libc::NLM_F_CREATE | libc::NLM_F_REPLACE | libc::NLM_F_ACK) as u16,
        8,
    );
    msg.buf[16] = libc::AF_INET as u8;
    msg.buf[17] = prefix_len;
    msg.buf[18] = 0; // ifa_flags
    msg.buf[19] = 0; // RT_SCOPE_UNIVERSE
    msg.buf[20..24].copy_from_slice(&idx.to_ne_bytes());

    let bcast = [ip[0], ip[1], ip[2], 255];
    msg.put_attr(IFA_LOCAL, &ip);
    msg.put_attr(IFA_ADDRESS, &ip);
    msg.put_attr(IFA_BROADCAST, &bcast);

    netlink_route_exchange(&msg.finish())
}

fn add_default_route(if_name: &str, gateway: [u8; 4]) -> io::Result<()> {
    let idx = if_index(if_name)?;
    // struct rtmsg = 12 bytes
    let mut msg = NlMsg::new_with_header(
        libc::RTM_NEWROUTE,
        (libc::NLM_F_REQUEST | libc::NLM_F_CREATE | libc::NLM_F_REPLACE | libc::NLM_F_ACK) as u16,
        12,
    );
    msg.buf[16] = libc::AF_INET as u8; // rtm_family
    msg.buf[17] = 0; // rtm_dst_len = 0 (default)
    msg.buf[18] = 0; // rtm_src_len
    msg.buf[19] = 0; // rtm_tos
    msg.buf[20] = 254; // RT_TABLE_MAIN
    msg.buf[21] = 3; // RTPROT_BOOT
    msg.buf[22] = 0; // RT_SCOPE_UNIVERSE
    msg.buf[23] = 1; // RTN_UNICAST

    msg.put_attr(RTA_GATEWAY, &gateway);
    msg.put_attr(RTA_OIF, &idx.to_ne_bytes());

    netlink_route_exchange(&msg.finish())
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

fn run_tool(bin: &str, args: &[&str]) -> io::Result<std::process::Output> {
    let path = if Path::new(bin).is_file() {
        bin
    } else {
        Path::new(bin)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(bin)
    };
    Command::new(path).args(args).output()
}

fn ensure_iptables_rule(table: Option<&str>, chain: &str, insert_pos: Option<&str>, rule: &[&str]) {
    let mut check_args = Vec::new();
    if let Some(t) = table {
        check_args.extend(["-t", t]);
    }
    check_args.extend(["-C", chain]);
    check_args.extend(rule.iter().copied());
    if let Ok(out) = run_tool("/system/bin/iptables", &check_args) {
        if out.status.success() {
            return;
        }
    }

    let mut add_args = Vec::new();
    if let Some(t) = table {
        add_args.extend(["-t", t]);
    }
    if let Some(pos) = insert_pos {
        add_args.extend(["-I", chain, pos]);
    } else {
        add_args.extend(["-A", chain]);
    }
    add_args.extend(rule.iter().copied());
    let _ = run_tool("/system/bin/iptables", &add_args);
}

fn delete_iptables_rule(table: Option<&str>, chain: &str, rule: &[&str]) {
    let mut del_args = Vec::new();
    if let Some(t) = table {
        del_args.extend(["-t", t]);
    }
    del_args.extend(["-D", chain]);
    del_args.extend(rule.iter().copied());
    let _ = run_tool("/system/bin/iptables", &del_args);
}

fn detect_host_upstream_table() -> String {
    if let Ok(out) = run_tool("/system/bin/ip", &["route", "get", "8.8.8.8"]) {
        if out.status.success() {
            let text = String::from_utf8_lossy(&out.stdout);
            let mut tokens = text.split_whitespace();
            while let Some(tok) = tokens.next() {
                if tok == "table" {
                    if let Some(tbl) = tokens.next() {
                        return tbl.to_owned();
                    }
                }
            }
        }
    }
    "main".to_owned()
}

fn apply_host_policy_route(table: &str) {
    let _ = run_tool("/system/bin/ip", &["rule", "del", "to", GUEST_SUBNET_CIDR]);
    let _ = run_tool(
        "/system/bin/ip",
        &[
            "rule",
            "add",
            "to",
            GUEST_SUBNET_CIDR,
            "lookup",
            "main",
            "pref",
            "11000",
        ],
    );
    let _ = run_tool("/system/bin/ip", &["rule", "del", "iif", HOST_VETH_IF]);
    let _ = run_tool(
        "/system/bin/ip",
        &[
            "rule",
            "add",
            "iif",
            HOST_VETH_IF,
            "lookup",
            table,
            "pref",
            "11500",
        ],
    );
}

fn configure_host_nat_and_routing() -> String {
    let _ = fs::write("/proc/sys/net/ipv4/ip_forward", b"1");
    let _ = fs::write(
        format!("/proc/sys/net/ipv4/conf/{HOST_VETH_IF}/rp_filter"),
        b"0",
    );

    ensure_iptables_rule(
        Some("nat"),
        "POSTROUTING",
        None,
        &["-s", GUEST_SUBNET_CIDR, "!", "-d", GUEST_SUBNET_CIDR, "-j", "MASQUERADE"],
    );
    ensure_iptables_rule(None, "FORWARD", Some("1"), &["-i", HOST_VETH_IF, "-j", "ACCEPT"]);
    ensure_iptables_rule(None, "FORWARD", Some("1"), &["-o", HOST_VETH_IF, "-j", "ACCEPT"]);

    let table = detect_host_upstream_table();
    apply_host_policy_route(&table);
    table
}

fn cleanup_host_nat_and_routing() {
    let _ = run_tool("/system/bin/ip", &["rule", "del", "to", GUEST_SUBNET_CIDR]);
    let _ = run_tool("/system/bin/ip", &["rule", "del", "iif", HOST_VETH_IF]);
    delete_iptables_rule(
        Some("nat"),
        "POSTROUTING",
        &["-s", GUEST_SUBNET_CIDR, "!", "-d", GUEST_SUBNET_CIDR, "-j", "MASQUERADE"],
    );
    delete_iptables_rule(None, "FORWARD", &["-i", HOST_VETH_IF, "-j", "ACCEPT"]);
    delete_iptables_rule(None, "FORWARD", &["-o", HOST_VETH_IF, "-j", "ACCEPT"]);
    delete_link_if_exists(HOST_VETH_IF);
}

fn bind_dhcp_socket_on_veth() -> io::Result<UdpSocket> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let sock = unsafe { UdpSocket::from_raw_fd(fd) };

    let enable: libc::c_int = 1;
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            (&raw const enable).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_BROADCAST,
            (&raw const enable).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }

    let if_c = CString::new(HOST_VETH_IF).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    if unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            if_c.as_ptr().cast(),
            if_c.as_bytes_with_nul().len() as libc::socklen_t,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }

    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    addr.sin_family = libc::AF_INET as _;
    addr.sin_port = 67u16.to_be();
    addr.sin_addr = libc::in_addr { s_addr: 0 };
    if unsafe {
        libc::bind(
            fd,
            (&raw const addr).cast(),
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }

    let _ = sock.set_read_timeout(Some(Duration::from_millis(500)));
    Ok(sock)
}

fn parse_dhcp_message_type(pkt: &[u8]) -> Option<u8> {
    // BOOTP header is 236 bytes + 4-byte magic cookie [99, 130, 83, 99]
    if pkt.len() < 240 || pkt[0] != 1 || pkt[236..240] != [0x63, 0x82, 0x53, 0x63] {
        return None;
    }
    let mut i = 240;
    while i < pkt.len() {
        let opt = pkt[i];
        if opt == 255 {
            break;
        }
        if opt == 0 {
            i += 1;
            continue;
        }
        if i + 1 >= pkt.len() {
            break;
        }
        let len = pkt[i + 1] as usize;
        if i + 2 + len > pkt.len() {
            break;
        }
        if opt == 53 && len == 1 {
            return Some(pkt[i + 2]);
        }
        i += 2 + len;
    }
    None
}

fn build_dhcp_reply(req: &[u8], msg_type: u8) -> Vec<u8> {
    let mut resp = vec![0u8; 300];
    resp[0] = 2; // BOOTREPLY
    resp[1] = req[1]; // htype
    resp[2] = req[2]; // hlen
    resp[3] = 0; // hops
    resp[4..8].copy_from_slice(&req[4..8]); // xid
    resp[10..12].copy_from_slice(&req[10..12]); // flags
    resp[16..20].copy_from_slice(&GUEST_ETH_IP); // yiaddr
    resp[20..24].copy_from_slice(&HOST_VETH_IP); // siaddr
    resp[28..44].copy_from_slice(&req[28..44]); // chaddr
    resp[236..240].copy_from_slice(&[0x63, 0x82, 0x53, 0x63]); // DHCP magic cookie

    let mut pos = 240;
    let mut push_opt = |code: u8, data: &[u8]| {
        resp[pos] = code;
        resp[pos + 1] = data.len() as u8;
        resp[pos + 2..pos + 2 + data.len()].copy_from_slice(data);
        pos += 2 + data.len();
    };
    push_opt(53, &[msg_type]); // DHCP Message Type
    push_opt(54, &HOST_VETH_IP); // Server Identifier
    push_opt(51, &86400u32.to_be_bytes()); // IP Address Lease Time
    push_opt(1, &[255, 255, 255, 0]); // Subnet Mask
    push_opt(3, &HOST_VETH_IP); // Router
    let mut dns = [0u8; 8];
    dns[..4].copy_from_slice(&DNS_PRIMARY);
    dns[4..].copy_from_slice(&DNS_SECONDARY);
    push_opt(6, &dns); // Domain Name Server
    resp[pos] = 255; // End
    resp.truncate(pos + 1);
    resp
}

pub(crate) struct HostNetGuard {
    host_ns: File,
    stop: Arc<AtomicBool>,
}

impl Drop for HostNetGuard {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let host_fd = self.host_ns.as_raw_fd();
        let _ = std::thread::spawn(move || {
            if unsafe { libc::setns(host_fd, libc::CLONE_NEWNET) } == 0 {
                cleanup_host_nat_and_routing();
            }
        })
        .join();
    }
}

pub(crate) fn setup_guest_veth() -> io::Result<HostNetGuard> {
    let guest_ns = File::open("/proc/self/ns/net")?;
    let guest_ns_fd = guest_ns.as_raw_fd();
    let host_ns = File::open("/proc/1/ns/net")?;
    let host_ns_fd = host_ns.as_raw_fd();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_worker = Arc::clone(&stop);

    let initial_table = std::thread::spawn(move || -> io::Result<String> {
        if unsafe { libc::setns(host_ns_fd, libc::CLONE_NEWNET) } != 0 {
            return Err(io::Error::last_os_error());
        }
        delete_link_if_exists(HOST_VETH_IF);
        create_veth_pair(GUEST_ETH_IF, HOST_VETH_IF, guest_ns_fd)?;
        add_ipv4_addr(HOST_VETH_IF, HOST_VETH_IP, GUEST_PREFIX_LEN)?;
        bring_up_interface(HOST_VETH_IF)?;
        let table = configure_host_nat_and_routing();

        if let Ok(dhcp_sock) = bind_dhcp_socket_on_veth() {
            let stop_dhcp = Arc::clone(&stop_worker);
            std::thread::spawn(move || {
                let mut buf = [0u8; 1500];
                let bcast = SocketAddrV4::new(Ipv4Addr::BROADCAST, 68);
                while !stop_dhcp.load(Ordering::Relaxed) {
                    if let Ok((n, _)) = dhcp_sock.recv_from(&mut buf) {
                        if let Some(msg_type) = parse_dhcp_message_type(&buf[..n]) {
                            let reply_type = match msg_type {
                                1 => Some(2), // DISCOVER -> OFFER
                                3 => Some(5), // REQUEST -> ACK
                                _ => None,
                            };
                            if let Some(rt) = reply_type {
                                let reply = build_dhcp_reply(&buf[..n], rt);
                                let _ = dhcp_sock.send_to(&reply, bcast);
                            }
                        }
                    }
                }
            });
        }

        Ok(table)
    })
    .join()
    .map_err(|_| io::Error::other("veth host setup thread panicked"))??;

    // Keep Host policy route synced if Host switches Wi-Fi / LTE / VPN
    let monitor_host_fd = host_ns.try_clone()?;
    let stop_monitor = Arc::clone(&stop);
    std::thread::spawn(move || {
        if unsafe { libc::setns(monitor_host_fd.as_raw_fd(), libc::CLONE_NEWNET) } != 0 {
            return;
        }
        let mut current_table = initial_table;
        while !stop_monitor.load(Ordering::Relaxed) {
            std::thread::sleep(Duration::from_secs(5));
            if stop_monitor.load(Ordering::Relaxed) {
                break;
            }
            let next_table = detect_host_upstream_table();
            if next_table != current_table {
                apply_host_policy_route(&next_table);
                current_table = next_table;
            }
        }
    });

    let _ = fs::write("/proc/sys/net/ipv4/ip_unprivileged_port_start", b"0");
    bring_up_interface("lo")?;
    bring_up_interface(GUEST_ETH_IF)?;
    add_ipv4_addr(GUEST_ETH_IF, GUEST_ETH_IP, GUEST_PREFIX_LEN)?;
    add_default_route(GUEST_ETH_IF, HOST_VETH_IP)?;
    Ok(HostNetGuard { host_ns, stop })
}

fn parse_profile_adb_port(profile_json: &str) -> Option<u16> {
    let value: serde_json::Value = serde_json::from_str(profile_json).ok()?;
    let id = value.get("selinux_id")?.as_str()?;
    let index: u16 = id.strip_prefix('p')?.parse().ok()?;
    if index == 0 {
        return None;
    }
    BASE_HOST_ADB_PORT.checked_add(index)
}

pub(crate) fn profile_adb_port(profile_dir: &Path) -> u16 {
    fs::read_to_string(profile_dir.join("profile.json"))
        .ok()
        .and_then(|json| parse_profile_adb_port(&json))
        .unwrap_or(BASE_HOST_ADB_PORT + 1)
}

/// Bind a loopback TCP listener in the Host network namespace before `unshare(CLONE_NEWNET)`.
pub(crate) fn bind_adb_host_listener(profile_dir: &Path) -> io::Result<(TcpListener, u16)> {
    let requested = std::env::var("SSAL_GUEST_ADB_PORT")
        .ok()
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or_else(|| profile_adb_port(profile_dir));
    let listener = match TcpListener::bind(("127.0.0.1", requested)) {
        Ok(listener) => listener,
        Err(err) if err.kind() == io::ErrorKind::AddrInUse && requested != 0 => {
            TcpListener::bind(("127.0.0.1", 0))?
        }
        Err(err) => return Err(err),
    };
    let port = listener.local_addr()?.port();
    Ok((listener, port))
}

fn relay_pair(mut client: TcpStream, mut guest: TcpStream) {
    let Ok(mut client_w) = client.try_clone() else {
        return;
    };
    let Ok(mut guest_r) = guest.try_clone() else {
        return;
    };
    let uplink = std::thread::spawn(move || {
        let _ = io::copy(&mut client, &mut guest);
        let _ = guest.shutdown(Shutdown::Write);
    });
    let _ = io::copy(&mut guest_r, &mut client_w);
    let _ = client_w.shutdown(Shutdown::Write);
    let _ = uplink.join();
}

/// Forward Host loopback connections from `listener` into Guest `127.0.0.1:5555`.
/// Must be called after the launcher has entered the Guest network namespace with `lo` UP.
pub(crate) fn spawn_adb_relay(listener: TcpListener, host_port: u16) {
    println!(
        "Guest adbd TCP relay listening on Host 127.0.0.1:{host_port} -> Guest 127.0.0.1:{GUEST_ADB_PORT}"
    );
    std::thread::spawn(move || {
        for incoming in listener.incoming() {
            let Ok(client) = incoming else {
                break;
            };
            std::thread::spawn(move || {
                if let Ok(guest) = TcpStream::connect(("127.0.0.1", GUEST_ADB_PORT)) {
                    relay_pair(client, guest);
                }
            });
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_adb_port_shifts_by_selinux_index() {
        assert_eq!(parse_profile_adb_port(r#"{"selinux_id":"p0001"}"#), Some(15555));
        assert_eq!(parse_profile_adb_port(r#"{"selinux_id":"p0002"}"#), Some(15556));
        assert_eq!(parse_profile_adb_port(r#"{"selinux_id":"p0010"}"#), Some(15564));
        assert_eq!(parse_profile_adb_port(r#"{"selinux_id":"p0000"}"#), None);
        assert_eq!(parse_profile_adb_port(r#"{}"#), None);
    }
}
