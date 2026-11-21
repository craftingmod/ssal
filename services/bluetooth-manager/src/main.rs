use rsbinder::{
    declare_binder_interface, Binder, Interface, Parcel, Result as BinderResult, SIBinder, Status,
    TransactionCode,
};

pub trait IBluetoothManager: Interface + Send {
    fn descriptor() -> &'static str
    where
        Self: Sized,
    {
        "android.bluetooth.IBluetoothManager"
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
    IBluetoothManager["android.bluetooth.IBluetoothManager"] {
        native: {
            BnBluetoothManager(on_transact),
        },
        proxy: BpBluetoothManager,
        local_transport: enabled,
    }
}

impl IBluetoothManager for BpBluetoothManager {}
impl IBluetoothManager for Binder<BnBluetoothManager> {}

fn on_transact(
    service: &dyn IBluetoothManager,
    code: TransactionCode,
    data: &mut Parcel,
    reply: &mut Parcel,
) -> BinderResult<()> {
    service.handle_transact(code, data, reply)
}

struct GuestBluetoothManager;

impl Interface for GuestBluetoothManager {}

impl IBluetoothManager for GuestBluetoothManager {
    fn handle_transact(
        &self,
        code: TransactionCode,
        _data: &mut Parcel,
        reply: &mut Parcel,
    ) -> BinderResult<()> {
        match code {
            // registerAdapter -> null IBluetooth (BluetoothAdapter.STATE_OFF)
            1 => {
                reply.write(&Status::ok())?;
                reply.write::<Option<SIBinder>>(&None)?;
            }
            // unregisterAdapter, setAutoOnEnabled -> void
            2 | 18 => {
                reply.write(&Status::ok())?;
            }
            // getState -> BluetoothAdapter.STATE_OFF (10)
            3 => {
                reply.write(&Status::ok())?;
                reply.write(&10i32)?;
            }
            // getAddress -> null
            4 => {
                reply.write(&Status::ok())?;
                reply.write::<Option<String>>(&None)?;
            }
            // getName -> ""
            5 => {
                reply.write(&Status::ok())?;
                reply.write(&Some(""))?;
            }
            // isHearingAidProfileSupported, isBleScanAvailable, enable*, disable*, factoryReset, isAutoOn* -> false
            6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 16 | 17 => {
                reply.write(&Status::ok())?;
                reply.write(&false)?;
            }
            // setBtHciSnoopLogMode, getBtHciSnoopLogMode -> 0
            14 | 15 => {
                reply.write(&Status::ok())?;
                reply.write(&0i32)?;
            }
            // getServiceMessenger -> null nullable Parcelable
            19 => {
                reply.write(&Status::ok())?;
                reply.write(&0i32)?;
            }
            _ => {
                reply.write(&Status::ok())?;
            }
        }
        Ok(())
    }
}

fn serve(device: u64, context: &str) -> ssal_binder_service::Result<()> {
    ssal_binder_service::init(device, context)?;
    let binder = BnBluetoothManager::new_binder(GuestBluetoothManager);
    ssal_binder_service::register("bluetooth_manager", binder)?;
    ssal_binder_service::join()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let result = match args.get(1).map(String::as_str) {
        Some("serve") if args.len() == 4 => args[2]
            .parse::<u64>()
            .map_err(|e| -> Box<dyn std::error::Error> { Box::new(e) })
            .and_then(|dev| serve(dev, &args[3])),
        _ => Err("usage: ssal-bluetooth-manager serve <binder-rdev> <context>".into()),
    };
    if let Err(err) = result {
        eprintln!("ssal-bluetooth-manager: {err}");
        std::process::exit(1);
    }
}
