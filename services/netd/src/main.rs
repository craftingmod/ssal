use rsbinder::{
    declare_binder_interface, Binder, Interface, Parcel, Result as BinderResult, SIBinder,
    Status, TransactionCode,
};
use std::ffi::{CStr, CString};
use std::net::Ipv4Addr;
use std::sync::Mutex;

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
}

impl Interface for GuestNetd {}

impl GuestNetd {
    fn new() -> Self {
        Self {
            listeners: Mutex::new(Vec::new()),
        }
    }
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
            14 => {
                // tetherGetStats() -> TetherStatsParcel[]
                reply.write(&Status::ok())?;
                reply.write(&0i32)?;
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
                reply.write(&Status::ok())?;
                reply.write(&0i32)?;
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
}

impl Interface for GuestDnsResolver {}

impl GuestDnsResolver {
    fn new() -> Self {
        Self {
            listeners: Mutex::new(Vec::new()),
            unstable: BnDnsResolverUnstable::new_binder(GuestDnsResolverUnstable).as_binder(),
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

fn serve(device: u64, hwbinder: Option<u64>, context: &str) -> ssal_binder_service::Result<()> {
    ssal_binder_service::init_with_hwbinder(device, hwbinder, context)?;
    let dns_binder = BnDnsResolver::new_binder(GuestDnsResolver::new());
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
