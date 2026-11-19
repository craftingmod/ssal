use rsbinder::{
    declare_binder_interface, Binder, Interface, Parcel, Result as BinderResult, SIBinder,
    Status, TransactionCode, FLAG_ONEWAY,
};
use std::sync::Mutex;

pub trait IVold: Interface + Send {
    fn descriptor() -> &'static str
    where
        Self: Sized,
    {
        "android.os.IVold"
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
    IVold["android.os.IVold"] {
        native: {
            BnVold(on_transact),
        },
        proxy: BpVold,
        local_transport: enabled,
    }
}

impl IVold for BpVold {}
impl IVold for Binder<BnVold> {}

fn on_transact(
    service: &dyn IVold,
    code: TransactionCode,
    data: &mut Parcel,
    reply: &mut Parcel,
) -> BinderResult<()> {
    service.handle_transact(code, data, reply)
}

struct GuestVold {
    listener: Mutex<Option<SIBinder>>,
}

impl Interface for GuestVold {}

impl GuestVold {
    fn new() -> Self {
        Self {
            listener: Mutex::new(None),
        }
    }
}

impl IVold for GuestVold {
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
                // setListener(IVoldListener listener)
                let listener = data.read::<Option<SIBinder>>().ok().flatten();
                eprintln!(
                    "guest_vold_call=setListener has_listener={} pid={pid} uid={uid}",
                    listener.is_some()
                );
                *self.listener.lock().unwrap() = listener;
                reply.write(&Status::ok())?;
            }
            2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 29 | 30 | 37 | 38 | 42 | 43 | 44
            | 47 | 48 | 49 | 66 => {
                let name = match code {
                    2 => "abortFuse",
                    3 => "monitor",
                    4 => "reset",
                    5 => "shutdown",
                    6 => "onUserAdded",
                    7 => "onUserRemoved",
                    8 => "onUserStarted",
                    9 => "onUserStopped",
                    10 => "addAppIds",
                    11 => "addSandboxIds",
                    12 => "onSecureKeyguardStateChanged",
                    29 => "runIdleMaint",
                    30 => "abortIdleMaint",
                    37 => "fbeEnable",
                    38 => "initUser0",
                    42 => "createUserStorageKeys",
                    43 => "destroyUserStorageKeys",
                    44 => "setCeStorageProtection",
                    47 => "lockCeStorage",
                    48 => "prepareUserStorage",
                    49 => "destroyUserStorage",
                    66 => "earlyBootEnded",
                    _ => "unknown",
                };
                if code != 3 {
                    eprintln!("guest_vold_call={name} pid={pid} uid={uid}");
                }
                reply.write(&Status::ok())?;
            }
            28 => {
                // fstrim(int fstrimFlags, IVoldTaskCallback callback)
                let flags = data.read::<i32>().unwrap_or(0);
                let callback = data.read::<Option<SIBinder>>().ok().flatten();
                eprintln!(
                    "guest_vold_call=fstrim flags={flags} has_callback={} pid={pid} uid={uid}",
                    callback.is_some()
                );
                if let Some(cb) = callback {
                    if let Some(tr) = cb.__transport() {
                        if let Ok(mut cb_data) = tr.prepare_request("android.os.IVoldTaskCallback") {
                            let _ = cb_data.write(&0i32); // status = 0
                            let _ = cb_data.write(&0i32); // null PersistableBundle
                            let _ = tr.submit_transact(2, cb_data, FLAG_ONEWAY);
                        }
                    }
                }
                reply.write(&Status::ok())?;
            }
            45 => {
                // getUnlockedUsers() -> int[]
                eprintln!("guest_vold_call=getUnlockedUsers pid={pid} uid={uid}");
                reply.write(&Status::ok())?;
                reply.write(&vec![0i32])?;
            }
            53 | 54 | 55 | 62 | 63 | 64 | 70 => {
                let name = match code {
                    53 => "needsCheckpoint",
                    54 => "needsRollback",
                    55 => "isCheckpointing",
                    62 => "supportsCheckpoint",
                    63 => "supportsBlockCheckpoint",
                    64 => "supportsFileCheckpoint",
                    70 => "incFsEnabled",
                    _ => "bool_query",
                };
                eprintln!("guest_vold_call={name} result=false pid={pid} uid={uid}");
                reply.write(&Status::ok())?;
                reply.write(&false)?;
            }
            _ => {
                eprintln!("guest_vold_unhandled_tx code={code} pid={pid} uid={uid}");
                reply.write(&Status::ok())?;
            }
        }
        Ok(())
    }
}

fn serve(device: u64, hwbinder: Option<u64>, context: &str) -> ssal_binder_service::Result<()> {
    ssal_binder_service::init_with_hwbinder(device, hwbinder, context)?;
    let binder = BnVold::new_binder(GuestVold::new());
    ssal_binder_service::register("vold", binder)?;
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
        _ => Err("usage: ssal-vold serve <binder-rdev> <context> [hwbinder-rdev]".into()),
    };
    if let Err(err) = result {
        eprintln!("ssal-vold: {err}");
        std::process::exit(1);
    }
}
