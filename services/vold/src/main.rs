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

const VOLUME_TYPE_EMULATED: i32 = 2;
const VOLUME_STATE_UNMOUNTED: i32 = 0;
const VOLUME_STATE_MOUNTED: i32 = 2;

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

    fn emit_listener<F>(&self, tx_code: TransactionCode, build: F)
    where
        F: FnOnce(&mut Parcel),
    {
        let listener = self.listener.lock().unwrap().clone();
        if let Some(listener) = listener {
            if let Some(tr) = listener.__transport() {
                if let Ok(mut req) = tr.prepare_request("android.os.IVoldListener") {
                    build(&mut req);
                    let _ = tr.submit_transact(tx_code, req, FLAG_ONEWAY);
                }
            }
        }
    }

    fn emit_emulated_created(&self, user_id: i32) {
        let vol_id = format!("emulated;{user_id}");
        self.emit_listener(5, |req| {
            let _ = req.write(&vol_id);
            let _ = req.write(&VOLUME_TYPE_EMULATED);
            let _ = req.write(&"");
            let _ = req.write(&"");
            let _ = req.write(&user_id);
        });
        eprintln!("guest_vold_emit=onVolumeCreated volId={vol_id} userId={user_id}");
    }

    fn emit_emulated_mounted(&self, vol_id: &str, user_id: i32) {
        self.emit_listener(8, |req| {
            let _ = req.write(&vol_id);
            let _ = req.write(&"/storage/emulated");
        });
        self.emit_listener(9, |req| {
            let _ = req.write(&vol_id);
            let _ = req.write(&"/data/media");
        });
        self.emit_listener(6, |req| {
            let _ = req.write(&vol_id);
            let _ = req.write(&VOLUME_STATE_MOUNTED);
            let _ = req.write(&user_id);
        });
        eprintln!("guest_vold_emit=onVolumeStateChanged volId={vol_id} state=MOUNTED userId={user_id}");
    }

    fn emit_emulated_unmounted(&self, vol_id: &str, user_id: i32) {
        self.emit_listener(6, |req| {
            let _ = req.write(&vol_id);
            let _ = req.write(&VOLUME_STATE_UNMOUNTED);
            let _ = req.write(&user_id);
        });
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
            6 => {
                // onUserAdded(int userId, int userSerial)
                let user_id = data.read::<i32>().unwrap_or(0);
                eprintln!("guest_vold_call=onUserAdded userId={user_id} pid={pid} uid={uid}");
                reply.write(&Status::ok())?;
            }
            8 => {
                // onUserStarted(int userId)
                let user_id = data.read::<i32>().unwrap_or(0);
                eprintln!("guest_vold_call=onUserStarted userId={user_id} pid={pid} uid={uid}");
                reply.write(&Status::ok())?;
                let vol_id = format!("emulated;{user_id}");
                self.emit_emulated_created(user_id);
                self.emit_emulated_mounted(&vol_id, user_id);
            }
            15 => {
                // mount(String volId, int mountFlags, int mountUserId, IVoldMountCallback callback)
                let vol_id = data
                    .read::<String>()
                    .unwrap_or_else(|_| "emulated;0".to_string());
                let _mount_flags = data.read::<i32>().unwrap_or(0);
                let mount_user_id = data.read::<i32>().unwrap_or(0);
                eprintln!(
                    "guest_vold_call=mount volId={vol_id} userId={mount_user_id} pid={pid} uid={uid}"
                );
                reply.write(&Status::ok())?;
                self.emit_emulated_mounted(&vol_id, mount_user_id);
            }
            16 => {
                // unmount(String volId)
                let vol_id = data
                    .read::<String>()
                    .unwrap_or_else(|_| "emulated;0".to_string());
                eprintln!("guest_vold_call=unmount volId={vol_id} pid={pid} uid={uid}");
                reply.write(&Status::ok())?;
                self.emit_emulated_unmounted(&vol_id, 0);
            }
            2 | 3 | 4 | 5 | 7 | 9 | 10 | 11 | 12 | 29 | 30 | 37 | 38 | 42 | 43 | 44
            | 47 | 48 | 49 | 66 => {
                let name = match code {
                    2 => "abortFuse",
                    3 => "monitor",
                    4 => "reset",
                    5 => "shutdown",
                    7 => "onUserRemoved",
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
