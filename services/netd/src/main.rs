use rsbinder::{
    declare_binder_interface, Binder, Interface, Parcel, Result as BinderResult, SIBinder,
    Status, TransactionCode,
};
use std::ffi::{CStr, CString};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::os::fd::FromRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const NETD_INTERFACE_HASH: &str = "c1bb4eac63bf70e3b1fc43f626693deafb43c5b0";
const NETD_INTERFACE_VERSION: i32 = 15;

pub trait INetd: Interface + Send {
    fn descriptor() -> &'static str
    where
        Self: Sized,
    {
        "android.net.INetd"
    }

    fn handle_transact(
        &self,
        _code: TransactionCode,
        _data: &mut Parcel,
        _reply: &mut Parcel,
    ) -> BinderResult<()> {
        Ok(())
    }
}

declare_binder_interface! {
    INetd["android.net.INetd"] {
        native: {
            BnNetd(on_transact),
        },
        proxy: BpNetd,
        local_transport: enabled,
    }
}

impl INetd for BpNetd {}
impl INetd for Binder<BnNetd> {}

fn on_transact(
    service: &dyn INetd,
    code: TransactionCode,
    data: &mut Parcel,
    reply: &mut Parcel,
) -> BinderResult<()> {
    service.handle_transact(code, data, reply)
}

pub trait IDnsResolver: Interface + Send {
    fn descriptor() -> &'static str
    where
        Self: Sized,
    {
        "android.net.IDnsResolver"
    }

    fn handle_transact(
        &self,
        _code: TransactionCode,
        _data: &mut Parcel,
        _reply: &mut Parcel,
    ) -> BinderResult<()> {
        Ok(())
    }
}

declare_binder_interface! {
    IDnsResolver["android.net.IDnsResolver"] {
        native: {
            BnDnsResolver(on_dns_transact),
        },
        proxy: BpDnsResolver,
        local_transport: enabled,
    }
}

impl IDnsResolver for BpDnsResolver {}
impl IDnsResolver for Binder<BnDnsResolver> {}

fn on_dns_transact(
    service: &dyn IDnsResolver,
    code: TransactionCode,
    data: &mut Parcel,
    reply: &mut Parcel,
) -> BinderResult<()> {
    service.handle_transact(code, data, reply)
}

pub trait IDnsResolverUnstable: Interface + Send {
    fn descriptor() -> &'static str
    where
        Self: Sized,
    {
        "android.net.resolv.unstable.IDnsResolverUnstable"
    }

    fn handle_transact(
        &self,
        _code: TransactionCode,
        _data: &mut Parcel,
        _reply: &mut Parcel,
    ) -> BinderResult<()> {
        Ok(())
    }
}

declare_binder_interface! {
    IDnsResolverUnstable["android.net.resolv.unstable.IDnsResolverUnstable"] {
        native: {
            BnDnsResolverUnstable(on_dns_unstable_transact),
        },
        proxy: BpDnsResolverUnstable,
        local_transport: enabled,
    }
}

impl IDnsResolverUnstable for BpDnsResolverUnstable {}
impl IDnsResolverUnstable for Binder<BnDnsResolverUnstable> {}

fn on_dns_unstable_transact(
    service: &dyn IDnsResolverUnstable,
    code: TransactionCode,
    data: &mut Parcel,
    reply: &mut Parcel,
) -> BinderResult<()> {
    service.handle_transact(code, data, reply)
}

struct InterfaceCfg {
    if_name: String,
    hw_addr: String,
    ipv4_addr: String,
    prefix_len: i32,
    flags: Vec<String>,
}

fn list_netns_interfaces() -> Vec<String> {
    let mut names = Vec::new();
    unsafe {
        let list = libc::if_nameindex();
        if list.is_null() {
            return names;
        }
        let mut cur = list;
        while (*cur).if_index != 0 && !(*cur).if_name.is_null() {
            if let Ok(name) = CStr::from_ptr((*cur).if_name).to_str() {
                names.push(name.to_owned());
            }
            cur = cur.add(1);
        }
        libc::if_freenameindex(list);
    }
    names
}

fn read_interface_cfg(if_name: &str) -> InterfaceCfg {
    let mut hw_addr = "00:00:00:00:00:00".to_owned();
    let mut ipv4_addr = "0.0.0.0".to_owned();
    let mut prefix_len = 0i32;
    let mut flags = Vec::new();

    let Ok(c_name) = CString::new(if_name) else {
        return InterfaceCfg {
            if_name: if_name.to_owned(),
            hw_addr,
            ipv4_addr,
            prefix_len,
            flags,
        };
    };

    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if sock < 0 {
        return InterfaceCfg {
            if_name: if_name.to_owned(),
            hw_addr,
            ipv4_addr,
            prefix_len,
            flags,
        };
    }

    let make_ifreq = || -> libc::ifreq {
        let mut req: libc::ifreq = unsafe { std::mem::zeroed() };
        let bytes = c_name.as_bytes_with_nul();
        let copy_len = bytes.len().min(req.ifr_name.len());
        for (dst, &src) in req.ifr_name[..copy_len].iter_mut().zip(&bytes[..copy_len]) {
            *dst = src as libc::c_char;
        }
        req
    };

    let mut req = make_ifreq();
    if unsafe { libc::ioctl(sock, libc::SIOCGIFFLAGS as _, &mut req) } == 0 {
        let f = unsafe { req.ifr_ifru.ifru_flags as i32 };
        flags.push(if (f & libc::IFF_UP) != 0 { "up" } else { "down" }.to_owned());
        if (f & libc::IFF_RUNNING) != 0 {
            flags.push("running".to_owned());
        }
        if (f & libc::IFF_LOOPBACK) != 0 {
            flags.push("loopback".to_owned());
        }
        if (f & libc::IFF_BROADCAST) != 0 {
            flags.push("broadcast".to_owned());
        }
        if (f & libc::IFF_MULTICAST) != 0 {
            flags.push("multicast".to_owned());
        }
        if (f & libc::IFF_POINTOPOINT) != 0 {
            flags.push("point-to-point".to_owned());
        }
    }

    let mut req = make_ifreq();
    if unsafe { libc::ioctl(sock, libc::SIOCGIFHWADDR as _, &mut req) } == 0 {
        let sa = unsafe { &req.ifr_ifru.ifru_hwaddr };
        hw_addr = format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            sa.sa_data[0] as u8,
            sa.sa_data[1] as u8,
            sa.sa_data[2] as u8,
            sa.sa_data[3] as u8,
            sa.sa_data[4] as u8,
            sa.sa_data[5] as u8
        );
    }

    let mut req = make_ifreq();
    if unsafe { libc::ioctl(sock, libc::SIOCGIFADDR as _, &mut req) } == 0 {
        let sa = unsafe { &*(&req.ifr_ifru.ifru_addr as *const libc::sockaddr as *const libc::sockaddr_in) };
        let ip = Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr));
        ipv4_addr = ip.to_string();
    }

    let mut req = make_ifreq();
    if unsafe { libc::ioctl(sock, libc::SIOCGIFNETMASK as _, &mut req) } == 0 {
        let sa = unsafe { &*(&req.ifr_ifru.ifru_netmask as *const libc::sockaddr as *const libc::sockaddr_in) };
        prefix_len = u32::from_be(sa.sin_addr.s_addr).leading_ones() as i32;
    }

    unsafe { libc::close(sock) };
    InterfaceCfg {
        if_name: if_name.to_owned(),
        hw_addr,
        ipv4_addr,
        prefix_len,
        flags,
    }
}

fn write_sized_parcelable(
    reply: &mut Parcel,
    write_fields: impl FnOnce(&mut Parcel) -> BinderResult<()>,
) -> BinderResult<()> {
    reply.write(&1i32)?;
    let start_pos = reply.data_position();
    reply.write(&0i32)?;
    write_fields(reply)?;
    let end_pos = reply.data_position();
    reply.set_data_position(start_pos);
    reply.write(&((end_pos - start_pos) as i32))?;
    reply.set_data_position(end_pos);
    Ok(())
}

struct GuestNetd {
    listeners: Mutex<Vec<SIBinder>>,
    default_net_id: Mutex<i32>,
}

impl Interface for GuestNetd {}

impl GuestNetd {
    fn new() -> Self {
        Self {
            listeners: Mutex::new(Vec::new()),
            default_net_id: Mutex::new(0),
        }
    }
}

fn set_interface_up_down(if_name: &str, up: bool) {
    let Ok(c_name) = CString::new(if_name) else {
        return;
    };
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if sock < 0 {
        return;
    }
    let mut req: libc::ifreq = unsafe { std::mem::zeroed() };
    let bytes = c_name.as_bytes_with_nul();
    let copy_len = bytes.len().min(req.ifr_name.len());
    for (dst, &src) in req.ifr_name[..copy_len].iter_mut().zip(&bytes[..copy_len]) {
        *dst = src as libc::c_char;
    }
    if unsafe { libc::ioctl(sock, libc::SIOCGIFFLAGS as _, &mut req) } == 0 {
        unsafe {
            if up {
                req.ifr_ifru.ifru_flags |= libc::IFF_UP as i16;
            } else {
                req.ifr_ifru.ifru_flags &= !(libc::IFF_UP as i16);
            }
        }
        let _ = unsafe { libc::ioctl(sock, libc::SIOCSIFFLAGS as _, &mut req) };
    }
    unsafe { libc::close(sock) };
}

fn set_interface_mtu(if_name: &str, mtu: i32) {
    let Ok(c_name) = CString::new(if_name) else {
        return;
    };
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if sock < 0 {
        return;
    }
    let mut req: libc::ifreq = unsafe { std::mem::zeroed() };
    let bytes = c_name.as_bytes_with_nul();
    let copy_len = bytes.len().min(req.ifr_name.len());
    for (dst, &src) in req.ifr_name[..copy_len].iter_mut().zip(&bytes[..copy_len]) {
        *dst = src as libc::c_char;
    }
    req.ifr_ifru.ifru_mtu = mtu;
    let _ = unsafe { libc::ioctl(sock, libc::SIOCSIFMTU as _, &mut req) };
    unsafe { libc::close(sock) };
}

fn set_interface_ipv4(if_name: &str, addr_str: &str, prefix_len: i32) {
    let Ok(ip) = addr_str.parse::<Ipv4Addr>() else {
        return;
    };
    let Ok(c_name) = CString::new(if_name) else {
        return;
    };
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if sock < 0 {
        return;
    }
    let make_ifreq = || -> libc::ifreq {
        let mut req: libc::ifreq = unsafe { std::mem::zeroed() };
        let bytes = c_name.as_bytes_with_nul();
        let copy_len = bytes.len().min(req.ifr_name.len());
        for (dst, &src) in req.ifr_name[..copy_len].iter_mut().zip(&bytes[..copy_len]) {
            *dst = src as libc::c_char;
        }
        req
    };

    let mut req = make_ifreq();
    let sa = unsafe { &mut *(&mut req.ifr_ifru.ifru_addr as *mut libc::sockaddr as *mut libc::sockaddr_in) };
    sa.sin_family = libc::AF_INET as _;
    sa.sin_addr.s_addr = u32::from(ip).to_be();
    if unsafe { libc::ioctl(sock, libc::SIOCSIFADDR as _, &mut req) } == 0 && (0..=32).contains(&prefix_len) {
        let mask = if prefix_len == 0 {
            0u32
        } else {
            !0u32 << (32 - prefix_len as u32)
        };
        let mut mask_req = make_ifreq();
        let msa = unsafe {
            &mut *(&mut mask_req.ifr_ifru.ifru_netmask as *mut libc::sockaddr as *mut libc::sockaddr_in)
        };
        msa.sin_family = libc::AF_INET as _;
        msa.sin_addr.s_addr = mask.to_be();
        let _ = unsafe { libc::ioctl(sock, libc::SIOCSIFNETMASK as _, &mut mask_req) };
    }
    unsafe { libc::close(sock) };
}

impl INetd for GuestNetd {
    fn handle_transact(
        &self,
        code: TransactionCode,
        data: &mut Parcel,
        reply: &mut Parcel,
    ) -> BinderResult<()> {
        let pid = rsbinder::get_calling_pid();
        let uid = rsbinder::get_calling_uid();
        match code {
            1 => {
                // isAlive() -> boolean
                eprintln!("guest_netd_call=isAlive pid={pid} uid={uid}");
                reply.write(&Status::ok())?;
                reply.write(&true)?;
            }
            2 | 3 | 13 => {
                // firewallReplaceUidChain / bandwidthEnableDataSaver / tetherApplyDnsInterfaces -> boolean
                reply.write(&Status::ok())?;
                reply.write(&true)?;
            }
            4 | 5 | 6 | 7 | 8 => {
                // networkCreatePhysical / networkCreateVpn / networkDestroy / networkAddInterface / networkRemoveInterface
                let net_id = data.read::<i32>().unwrap_or(0);
                eprintln!("guest_netd_call=tx_{code} netId={net_id} pid={pid} uid={uid}");
                reply.write(&Status::ok())?;
            }
            14 => {
                // tetherGetStats() -> TetherStatsParcel[]
                reply.write(&Status::ok())?;
                reply.write(&0i32)?;
            }
            15 => {
                // interfaceAddAddress(String ifName, String addrString, int prefixLength)
                let if_name = data.read::<String>().unwrap_or_default();
                let addr = data.read::<String>().unwrap_or_default();
                let prefix_len = data.read::<i32>().unwrap_or(24);
                eprintln!(
                    "guest_netd_call=interfaceAddAddress if={if_name} addr={addr}/{prefix_len} pid={pid} uid={uid}"
                );
                set_interface_ipv4(&if_name, &addr, prefix_len);
                reply.write(&Status::ok())?;
            }
            16 => {
                // interfaceDelAddress(String ifName, String addrString, int prefixLength)
                let if_name = data.read::<String>().unwrap_or_default();
                let addr = data.read::<String>().unwrap_or_default();
                let prefix_len = data.read::<i32>().unwrap_or(24);
                eprintln!(
                    "guest_netd_call=interfaceDelAddress if={if_name} addr={addr}/{prefix_len} pid={pid} uid={uid}"
                );
                reply.write(&Status::ok())?;
            }
            17 => {
                // getProcSysNet(int ipversion, int which, String ifname, String parameter) -> String
                reply.write(&Status::ok())?;
                reply.write(&"")?;
            }
            39 => {
                // ipfwdEnabled() -> boolean
                reply.write(&Status::ok())?;
                reply.write(&false)?;
            }
            40 | 59 | 61 => {
                // ipfwdGetRequesterList / tetherInterfaceList / tetherDnsList -> String[]
                reply.write(&Status::ok())?;
                reply.write(&Vec::<String>::new())?;
            }
            56 => {
                // tetherIsEnabled() -> boolean
                reply.write(&Status::ok())?;
                reply.write(&false)?;
            }
            66 => {
                // networkGetDefault() -> int
                let net_id = *self.default_net_id.lock().unwrap();
                reply.write(&Status::ok())?;
                reply.write(&net_id)?;
            }
            67 => {
                // networkSetDefault(int netId)
                let net_id = data.read::<i32>().unwrap_or(0);
                *self.default_net_id.lock().unwrap() = net_id;
                eprintln!("guest_netd_call=networkSetDefault netId={net_id} pid={pid} uid={uid}");
                reply.write(&Status::ok())?;
            }
            68 => {
                // networkClearDefault()
                *self.default_net_id.lock().unwrap() = 0;
                reply.write(&Status::ok())?;
            }
            75 => {
                // networkCanProtect(int uid) -> boolean
                reply.write(&Status::ok())?;
                reply.write(&true)?;
            }
            80 => {
                // interfaceGetList() -> String[]
                let ifaces = list_netns_interfaces();
                eprintln!("guest_netd_call=interfaceGetList ifaces={ifaces:?} pid={pid} uid={uid}");
                reply.write(&Status::ok())?;
                reply.write(&ifaces)?;
            }
            81 => {
                // interfaceGetCfg(String ifName) -> InterfaceConfigurationParcel
                let if_name = data.read::<String>().unwrap_or_default();
                let cfg = read_interface_cfg(&if_name);
                eprintln!(
                    "guest_netd_call=interfaceGetCfg if={if_name} hw={} ip={}/{} flags={:?} pid={pid} uid={uid}",
                    cfg.hw_addr, cfg.ipv4_addr, cfg.prefix_len, cfg.flags
                );
                reply.write(&Status::ok())?;
                write_sized_parcelable(reply, |p| {
                    p.write(&cfg.if_name)?;
                    p.write(&cfg.hw_addr)?;
                    p.write(&cfg.ipv4_addr)?;
                    p.write(&cfg.prefix_len)?;
                    p.write(&cfg.flags)?;
                    Ok(())
                })?;
            }
            82 => {
                // interfaceSetCfg(InterfaceConfigurationParcel cfg)
                let present = data.read::<i32>().unwrap_or(0);
                if present != 0 {
                    let _parcel_size = data.read::<i32>().unwrap_or(0);
                    let if_name = data.read::<String>().unwrap_or_default();
                    let _hw_addr = data.read::<String>().unwrap_or_default();
                    let ipv4_addr = data.read::<String>().unwrap_or_default();
                    let prefix_len = data.read::<i32>().unwrap_or(0);
                    let flags = data.read::<Vec<String>>().unwrap_or_default();
                    eprintln!(
                        "guest_netd_call=interfaceSetCfg if={if_name} ip={ipv4_addr}/{prefix_len} flags={flags:?} pid={pid} uid={uid}"
                    );
                    if !ipv4_addr.is_empty() && ipv4_addr != "0.0.0.0" {
                        set_interface_ipv4(&if_name, &ipv4_addr, prefix_len);
                    }
                    if flags.iter().any(|f| f == "up") {
                        set_interface_up_down(&if_name, true);
                    } else if flags.iter().any(|f| f == "down") {
                        set_interface_up_down(&if_name, false);
                    }
                }
                reply.write(&Status::ok())?;
            }
            86 => {
                // interfaceSetMtu(String ifName, int mtu)
                let if_name = data.read::<String>().unwrap_or_default();
                let mtu = data.read::<i32>().unwrap_or(1500);
                set_interface_mtu(&if_name, mtu);
                reply.write(&Status::ok())?;
            }
            90 => {
                // registerUnsolicitedEventListener(INetdUnsolicitedEventListener listener)
                let listener = data.read::<Option<SIBinder>>().ok().flatten();
                eprintln!(
                    "guest_netd_call=registerUnsolicitedEventListener has_listener={} pid={pid} uid={uid}",
                    listener.is_some()
                );
                if let Some(l) = listener {
                    self.listeners.lock().unwrap().push(l);
                }
                reply.write(&Status::ok())?;
            }
            94 => {
                // getOemNetd() -> IBinder
                eprintln!("guest_netd_call=getOemNetd pid={pid} uid={uid}");
                reply.write(&Status::ok())?;
                reply.write(&None::<SIBinder>)?;
            }
            96 => {
                // getFwmarkForNetwork(int netId) -> MarkMaskParcel
                reply.write(&Status::ok())?;
                write_sized_parcelable(reply, |p| {
                    p.write(&0i32)?;
                    p.write(&0i32)?;
                    Ok(())
                })?;
            }
            16777214 => {
                // getInterfaceHash() -> String
                reply.write(&Status::ok())?;
                reply.write(&NETD_INTERFACE_HASH)?;
            }
            16777215 => {
                // getInterfaceVersion() -> int
                reply.write(&Status::ok())?;
                reply.write(&NETD_INTERFACE_VERSION)?;
            }
            _ => {
                eprintln!("guest_netd_call=tx_{code} pid={pid} uid={uid}");
                reply.write(&Status::ok())?;
            }
        }
        Ok(())
    }
}

struct GuestDnsResolverUnstable;

impl Interface for GuestDnsResolverUnstable {}

impl IDnsResolverUnstable for GuestDnsResolverUnstable {
    fn handle_transact(
        &self,
        code: TransactionCode,
        _data: &mut Parcel,
        reply: &mut Parcel,
    ) -> BinderResult<()> {
        let pid = rsbinder::get_calling_pid();
        let uid = rsbinder::get_calling_uid();
        eprintln!("guest_dnsresolver_unstable_call=tx_{code} pid={pid} uid={uid}");
        reply.write(&Status::ok())?;
        Ok(())
    }
}

struct GuestDnsResolver {
    listeners: Mutex<Vec<SIBinder>>,
    unstable: SIBinder,
    nameservers: Arc<Mutex<Vec<Ipv4Addr>>>,
}

impl Interface for GuestDnsResolver {}

impl GuestDnsResolver {
    fn new(nameservers: Arc<Mutex<Vec<Ipv4Addr>>>) -> Self {
        Self {
            listeners: Mutex::new(Vec::new()),
            unstable: BnDnsResolverUnstable::new_binder(GuestDnsResolverUnstable).as_binder(),
            nameservers,
        }
    }
}

impl IDnsResolver for GuestDnsResolver {
    fn handle_transact(
        &self,
        code: TransactionCode,
        data: &mut Parcel,
        reply: &mut Parcel,
    ) -> BinderResult<()> {
        let pid = rsbinder::get_calling_pid();
        let uid = rsbinder::get_calling_uid();
        match code {
            3 => {
                // setResolverConfiguration(ResolverParamsParcel resolverParams)
                if data.read::<i32>().unwrap_or(0) != 0 {
                    let _size = data.read::<i32>().unwrap_or(0);
                    let _net_id = data.read::<i32>().unwrap_or(0);
                    let _sample_validity = data.read::<i32>().unwrap_or(0);
                    let _success_threshold = data.read::<i32>().unwrap_or(0);
                    let _min_samples = data.read::<i32>().unwrap_or(0);
                    let _max_samples = data.read::<i32>().unwrap_or(0);
                    let _base_timeout = data.read::<i32>().unwrap_or(0);
                    let _retry_count = data.read::<i32>().unwrap_or(0);
                    if let Ok(servers) = data.read::<Vec<String>>() {
                        let parsed: Vec<Ipv4Addr> =
                            servers.iter().filter_map(|s| s.parse().ok()).collect();
                        if !parsed.is_empty() {
                            eprintln!(
                                "guest_dnsresolver_call=setResolverConfiguration servers={parsed:?}"
                            );
                            *self.nameservers.lock().unwrap() = parsed;
                        }
                    }
                }
                reply.write(&Status::ok())?;
            }
            13 => {
                // registerUnsolicitedEventListener
                let listener = data.read::<Option<SIBinder>>().ok().flatten();
                eprintln!(
                    "guest_dnsresolver_call=registerUnsolicitedEventListener has_listener={} pid={pid} uid={uid}",
                    listener.is_some()
                );
                if let Some(l) = listener {
                    self.listeners.lock().unwrap().push(l);
                }
                reply.write(&Status::ok())?;
            }
            17 => {
                // getUnstableInterface() -> IBinder
                eprintln!("guest_dnsresolver_call=getUnstableInterface pid={pid} uid={uid}");
                reply.write(&Status::ok())?;
                reply.write(&Some(self.unstable.clone()))?;
            }
            16777214 => {
                reply.write(&Status::ok())?;
                reply.write(&"")?;
            }
            16777215 => {
                reply.write(&Status::ok())?;
                reply.write(&12i32)?;
            }
            _ => {
                eprintln!("guest_dnsresolver_call=tx_{code} pid={pid} uid={uid}");
                reply.write(&Status::ok())?;
            }
        }
        Ok(())
    }
}

fn encode_dns_query(tx_id: u16, host: &str) -> Option<Vec<u8>> {
    let mut pkt = Vec::with_capacity(64);
    pkt.extend_from_slice(&tx_id.to_be_bytes());
    pkt.extend_from_slice(&0x0100u16.to_be_bytes()); // standard query, recursion desired
    pkt.extend_from_slice(&1u16.to_be_bytes()); // qdcount = 1
    pkt.extend_from_slice(&[0u8; 6]); // ancount, nscount, arcount = 0
    for label in host.trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        pkt.push(label.len() as u8);
        pkt.extend_from_slice(label.as_bytes());
    }
    pkt.push(0);
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QTYPE = A
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN
    Some(pkt)
}

fn skip_dns_name(pkt: &[u8], mut offset: usize) -> Option<usize> {
    let mut jumps = 0;
    loop {
        if offset >= pkt.len() || jumps > 16 {
            return None;
        }
        let len = pkt[offset];
        if len == 0 {
            return Some(offset + 1);
        }
        if (len & 0xC0) == 0xC0 {
            if offset + 1 >= pkt.len() {
                return None;
            }
            return Some(offset + 2);
        }
        offset += 1 + len as usize;
        jumps += 1;
    }
}

fn parse_dns_a_records(pkt: &[u8], expected_tx_id: u16) -> Vec<Ipv4Addr> {
    let mut addrs = Vec::new();
    if pkt.len() < 12 {
        return addrs;
    }
    let tx_id = u16::from_be_bytes([pkt[0], pkt[1]]);
    if tx_id != expected_tx_id {
        return addrs;
    }
    let qdcount = u16::from_be_bytes([pkt[4], pkt[5]]);
    let ancount = u16::from_be_bytes([pkt[6], pkt[7]]);
    let mut off = 12;
    for _ in 0..qdcount {
        let Some(next) = skip_dns_name(pkt, off) else {
            return addrs;
        };
        off = next + 4;
        if off > pkt.len() {
            return addrs;
        }
    }
    for _ in 0..ancount {
        let Some(next) = skip_dns_name(pkt, off) else {
            break;
        };
        off = next;
        if off + 10 > pkt.len() {
            break;
        }
        let rtype = u16::from_be_bytes([pkt[off], pkt[off + 1]]);
        let rclass = u16::from_be_bytes([pkt[off + 2], pkt[off + 3]]);
        let rdlen = u16::from_be_bytes([pkt[off + 8], pkt[off + 9]]) as usize;
        off += 10;
        if off + rdlen > pkt.len() {
            break;
        }
        if rtype == 1 && rclass == 1 && rdlen == 4 {
            addrs.push(Ipv4Addr::new(pkt[off], pkt[off + 1], pkt[off + 2], pkt[off + 3]));
        }
        off += rdlen;
    }
    addrs
}

fn resolve_ipv4(host: &str, nameservers: &[Ipv4Addr]) -> Vec<Ipv4Addr> {
    if host.eq_ignore_ascii_case("localhost") {
        return vec![Ipv4Addr::LOCALHOST];
    }
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        return vec![ip];
    }
    let Some(query) = encode_dns_query(0x55AA, host) else {
        return Vec::new();
    };
    let Ok(sock) = UdpSocket::bind("0.0.0.0:0") else {
        return Vec::new();
    };
    let _ = sock.set_read_timeout(Some(Duration::from_millis(1500)));
    let mut buf = [0u8; 1500];
    for &ns in nameservers {
        if sock.send_to(&query, SocketAddrV4::new(ns, 53)).is_ok() {
            if let Ok((n, _)) = sock.recv_from(&mut buf) {
                let addrs = parse_dns_a_records(&buf[..n], 0x55AA);
                if !addrs.is_empty() {
                    return addrs;
                }
            }
        }
    }
    Vec::new()
}

fn write_dnsproxy_error(stream: &mut UnixStream, eai_err: i32) {
    let _ = stream.write_all(&eai_err.to_be_bytes());
}

fn handle_dnsproxy_client(mut stream: UnixStream, nameservers: Arc<Mutex<Vec<Ipv4Addr>>>) {
    let mut req = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    while req.len() < 1024 {
        match stream.read(&mut byte) {
            Ok(0) | Err(_) => return,
            Ok(_) => {
                if byte[0] == 0 {
                    break;
                }
                req.push(byte[0]);
            }
        }
    }
    let Ok(cmd) = std::str::from_utf8(&req) else {
        write_dnsproxy_error(&mut stream, 7); // EAI_NODATA
        return;
    };
    let parts: Vec<&str> = cmd.split_whitespace().collect();
    if parts.first().copied() != Some("getaddrinfo") || parts.len() < 7 {
        write_dnsproxy_error(&mut stream, 7);
        return;
    }
    let host = parts[1];
    let serv = parts[2];
    let flags: i32 = parts[3].parse().unwrap_or(0);
    let family: i32 = parts[4].parse().unwrap_or(0);
    let socktype: i32 = parts[5].parse().unwrap_or(0);
    let protocol: i32 = parts[6].parse().unwrap_or(0);

    if host == "^" || (family != 0 && family != libc::AF_INET) {
        if host == "^" && (family == 0 || family == libc::AF_INET) {
            // Passive / localhost bind
        } else if family == libc::AF_INET6 {
            write_dnsproxy_error(&mut stream, 7);
            return;
        }
    }

    let port: u16 = if serv == "^" {
        0
    } else {
        serv.parse::<u16>().unwrap_or(0)
    };
    let ips = if host == "^" {
        vec![Ipv4Addr::UNSPECIFIED]
    } else {
        let servers = nameservers.lock().unwrap().clone();
        resolve_ipv4(host, &servers)
    };

    if ips.is_empty() {
        write_dnsproxy_error(&mut stream, 7);
        return;
    }

    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&0i32.to_be_bytes()); // rv = 0
    let effective_socktype = if socktype == 0 { libc::SOCK_STREAM } else { socktype };
    let effective_proto = if protocol == 0 {
        if effective_socktype == libc::SOCK_DGRAM {
            libc::IPPROTO_UDP
        } else {
            libc::IPPROTO_TCP
        }
    } else {
        protocol
    };

    for ip in ips {
        out.extend_from_slice(&1i32.to_be_bytes()); // have_more = 1
        out.extend_from_slice(&flags.to_be_bytes());
        out.extend_from_slice(&(libc::AF_INET).to_be_bytes());
        out.extend_from_slice(&effective_socktype.to_be_bytes());
        out.extend_from_slice(&effective_proto.to_be_bytes());
        out.extend_from_slice(&16u32.to_be_bytes()); // sizeof(sockaddr_in)

        let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        sa.sin_family = libc::AF_INET as _;
        sa.sin_port = port.to_be();
        sa.sin_addr.s_addr = u32::from(ip).to_be();
        let sa_bytes = unsafe {
            std::slice::from_raw_parts((&raw const sa).cast::<u8>(), 16)
        };
        out.extend_from_slice(sa_bytes);
        out.extend_from_slice(&0u32.to_be_bytes()); // canonname_len = 0
    }
    out.extend_from_slice(&0i32.to_be_bytes()); // have_more = 0
    let _ = stream.write_all(&out);
}

fn spawn_dnsproxyd(nameservers: Arc<Mutex<Vec<Ipv4Addr>>>) {
    let Ok(fd_str) = std::env::var("ANDROID_SOCKET_dnsproxyd") else {
        return;
    };
    let Ok(fd) = fd_str.parse::<i32>() else {
        return;
    };
    if unsafe { libc::listen(fd, 16) } != 0 {
        eprintln!("ssal-netd: dnsproxyd listen failed: {}", std::io::Error::last_os_error());
        return;
    }
    let listener = unsafe { UnixListener::from_raw_fd(fd) };
    eprintln!("guest_dnsproxyd_ready=1");
    std::thread::spawn(move || {
        for incoming in listener.incoming() {
            if let Ok(stream) = incoming {
                let ns = Arc::clone(&nameservers);
                std::thread::spawn(move || handle_dnsproxy_client(stream, ns));
            }
        }
    });
}

fn serve(device: u64, hwbinder: Option<u64>, context: &str) -> ssal_binder_service::Result<()> {
    ssal_binder_service::init_with_hwbinder(device, hwbinder, context)?;
    let nameservers = Arc::new(Mutex::new(vec![
        Ipv4Addr::new(8, 8, 8, 8),
        Ipv4Addr::new(1, 1, 1, 1),
    ]));
    spawn_dnsproxyd(Arc::clone(&nameservers));
    let dns_binder = BnDnsResolver::new_binder(GuestDnsResolver::new(nameservers));
    ssal_binder_service::register("dnsresolver", dns_binder)?;
    let binder = BnNetd::new_binder(GuestNetd::new());
    ssal_binder_service::register("netd", binder)?;
    ssal_binder_service::join()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let result = match args.get(1).map(String::as_str) {
        Some("serve") if args.len() == 4 || args.len() == 5 => {
            let hw = args
                .get(4)
                .map(|v| v.parse::<u64>())
                .transpose()
                .map_err(|e| -> Box<dyn std::error::Error> { Box::new(e) });
            hw.and_then(|hw| {
                args[2]
                    .parse::<u64>()
                    .map_err(|e| -> Box<dyn std::error::Error> { Box::new(e) })
                    .and_then(|dev| serve(dev, hw, &args[3]))
            })
        }
        _ => Err("usage: ssal-netd serve <binder-rdev> <context> [hwbinder-rdev]".into()),
    };
    if let Err(err) = result {
        eprintln!("ssal-netd: {err}");
        std::process::exit(1);
    }
}
