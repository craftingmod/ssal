rsbinder::include_aidl!("thermal");

use android::hardware::thermal::{
    CoolingDevice::CoolingDevice,
    CoolingType::CoolingType,
    ICoolingDeviceChangedCallback::ICoolingDeviceChangedCallback,
    IThermal::{BnThermal, IThermal},
    IThermalChangedCallback::IThermalChangedCallback,
    Temperature::Temperature,
    TemperatureThreshold::TemperatureThreshold,
    TemperatureType::TemperatureType,
    ThrottlingSeverity::ThrottlingSeverity,
};
use rsbinder::{BinderResult, DeathRecipient, ExceptionCode, Interface, Status, Strong, WIBinder};
use ssal_binder_service::Result;
use std::{
    io::{self, BufRead},
    sync::{Arc, Mutex},
};

mod source;
use source::ThermalSnapshot;

const HAL: &str = "android.hardware.thermal.IThermal/default";

type TempCallbackEntry = (Option<TemperatureType>, Strong<dyn IThermalChangedCallback>);
type CoolingCallbackEntry = (Option<CoolingType>, Strong<dyn ICoolingDeviceChangedCallback>);

#[derive(Default)]
struct Callbacks {
    temp: Mutex<Vec<TempCallbackEntry>>,
    cooling: Mutex<Vec<CoolingCallbackEntry>>,
}

impl DeathRecipient for Callbacks {
    fn binder_died(&self, who: &WIBinder) {
        self.temp
            .lock()
            .unwrap()
            .retain(|(_, cb)| *who != cb.as_binder());
        self.cooling
            .lock()
            .unwrap()
            .retain(|(_, cb)| *who != cb.as_binder());
    }
}

#[derive(Clone)]
struct Thermal {
    snapshot: Arc<Mutex<ThermalSnapshot>>,
    callbacks: Arc<Callbacks>,
}

impl Thermal {
    fn temperatures(&self, filter: Option<TemperatureType>) -> Vec<Temperature> {
        let snap = self.snapshot.lock().unwrap();
        snap.temperatures
            .iter()
            .filter(|t| filter.is_none_or(|f| t.r#type == f.0))
            .map(|t| Temperature {
                r#type: TemperatureType(t.r#type),
                name: t.name.clone(),
                value: t.value,
                throttlingStatus: ThrottlingSeverity(t.throttling_status),
            })
            .collect()
    }

    fn cooling_devices(&self, filter: Option<CoolingType>) -> Vec<CoolingDevice> {
        let snap = self.snapshot.lock().unwrap();
        snap.cooling_devices
            .iter()
            .filter(|c| filter.is_none_or(|f| c.r#type == f.0))
            .map(|c| CoolingDevice {
                r#type: CoolingType(c.r#type),
                name: c.name.clone(),
                value: c.value,
                powerLimitMw: -1,
                powerMw: -1,
                timeWindowMs: -1,
            })
            .collect()
    }

    fn notify_if_changed(&self, prev: &ThermalSnapshot, next: &ThermalSnapshot) {
        let changed_temps: Vec<Temperature> = next
            .temperatures
            .iter()
            .filter(|n| {
                prev.temperatures
                    .iter()
                    .find(|p| p.name == n.name)
                    .is_none_or(|p| p.throttling_status != n.throttling_status)
            })
            .map(|t| Temperature {
                r#type: TemperatureType(t.r#type),
                name: t.name.clone(),
                value: t.value,
                throttlingStatus: ThrottlingSeverity(t.throttling_status),
            })
            .collect();

        if !changed_temps.is_empty() {
            let cbs = self.callbacks.temp.lock().unwrap().clone();
            for temp in &changed_temps {
                for (filter, cb) in &cbs {
                    if filter.is_none_or(|f| f == temp.r#type) {
                        let _ = cb.notifyThrottling(temp);
                    }
                }
            }
        }

        let changed_cooling: Vec<CoolingDevice> = next
            .cooling_devices
            .iter()
            .filter(|n| {
                prev.cooling_devices
                    .iter()
                    .find(|p| p.name == n.name)
                    .is_none_or(|p| p.value != n.value)
            })
            .map(|c| CoolingDevice {
                r#type: CoolingType(c.r#type),
                name: c.name.clone(),
                value: c.value,
                powerLimitMw: -1,
                powerMw: -1,
                timeWindowMs: -1,
            })
            .collect();

        if !changed_cooling.is_empty() {
            let cbs = self.callbacks.cooling.lock().unwrap().clone();
            for dev in &changed_cooling {
                for (filter, cb) in &cbs {
                    if filter.is_none_or(|f| f == dev.r#type) {
                        let _ = cb.notifyCoolingDeviceChanged(dev);
                    }
                }
            }
        }
    }
}

impl Interface for Thermal {}

impl IThermal for Thermal {
    fn r#getCoolingDevices(&self) -> BinderResult<Vec<CoolingDevice>> {
        Ok(self.cooling_devices(None))
    }

    fn r#getCoolingDevicesWithType(&self, r#type: CoolingType) -> BinderResult<Vec<CoolingDevice>> {
        Ok(self.cooling_devices(Some(r#type)))
    }

    fn r#getTemperatures(&self) -> BinderResult<Vec<Temperature>> {
        Ok(self.temperatures(None))
    }

    fn r#getTemperaturesWithType(&self, r#type: TemperatureType) -> BinderResult<Vec<Temperature>> {
        Ok(self.temperatures(Some(r#type)))
    }

    fn r#getTemperatureThresholds(&self) -> BinderResult<Vec<TemperatureThreshold>> {
        Ok(Vec::new())
    }

    fn r#getTemperatureThresholdsWithType(
        &self,
        _type: TemperatureType,
    ) -> BinderResult<Vec<TemperatureThreshold>> {
        Ok(Vec::new())
    }

    fn r#registerThermalChangedCallback(
        &self,
        callback: &Strong<dyn IThermalChangedCallback>,
    ) -> BinderResult<()> {
        let mut cbs = self.callbacks.temp.lock().unwrap();
        if !cbs.iter().any(|(_, existing)| existing == callback) {
            callback.link_to_death_arc(&self.callbacks)?;
            cbs.push((None, callback.clone()));
        }
        Ok(())
    }

    fn r#registerThermalChangedCallbackWithType(
        &self,
        callback: &Strong<dyn IThermalChangedCallback>,
        r#type: TemperatureType,
    ) -> BinderResult<()> {
        let mut cbs = self.callbacks.temp.lock().unwrap();
        if !cbs.iter().any(|(_, existing)| existing == callback) {
            callback.link_to_death_arc(&self.callbacks)?;
            cbs.push((Some(r#type), callback.clone()));
        }
        Ok(())
    }

    fn r#unregisterThermalChangedCallback(
        &self,
        callback: &Strong<dyn IThermalChangedCallback>,
    ) -> BinderResult<()> {
        let _ = callback.unlink_to_death_arc(&self.callbacks);
        self.callbacks
            .temp
            .lock()
            .unwrap()
            .retain(|(_, existing)| existing != callback);
        Ok(())
    }

    fn r#registerCoolingDeviceChangedCallbackWithType(
        &self,
        callback: &Strong<dyn ICoolingDeviceChangedCallback>,
        r#type: CoolingType,
    ) -> BinderResult<()> {
        let mut cbs = self.callbacks.cooling.lock().unwrap();
        if !cbs.iter().any(|(_, existing)| existing == callback) {
            callback.link_to_death_arc(&self.callbacks)?;
            cbs.push((Some(r#type), callback.clone()));
        }
        Ok(())
    }

    fn r#unregisterCoolingDeviceChangedCallback(
        &self,
        callback: &Strong<dyn ICoolingDeviceChangedCallback>,
    ) -> BinderResult<()> {
        let _ = callback.unlink_to_death_arc(&self.callbacks);
        self.callbacks
            .cooling
            .lock()
            .unwrap()
            .retain(|(_, existing)| existing != callback);
        Ok(())
    }

    fn r#forecastSkinTemperature(&self, _forecast_seconds: i32) -> BinderResult<f32> {
        Err(Status::from(ExceptionCode::UnsupportedOperation))
    }
}

fn read_snapshot_line<R: BufRead>(reader: &mut R) -> io::Result<Option<ThermalSnapshot>> {
    let mut line = String::new();
    let n = reader.read_line(&mut line)?;
    if n == 0 {
        return Ok(None);
    }
    let snapshot = serde_json::from_str(&line)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    Ok(Some(snapshot))
}

fn serve(device: u64, context: &str, source_mode: &str) -> Result<()> {
    ssal_binder_service::init(device, context)?;
    let initial = if source_mode == "host" {
        let mut stdin = io::stdin().lock();
        read_snapshot_line(&mut stdin)?
            .ok_or_else(|| io::Error::other("Host thermal provider exited before first sample"))?
    } else {
        ThermalSnapshot::default()
    };
    let thermal = Thermal {
        snapshot: Arc::new(Mutex::new(initial)),
        callbacks: Arc::new(Callbacks::default()),
    };
    if source_mode == "host" {
        let worker = thermal.clone();
        std::thread::spawn(move || {
            let mut stdin = io::stdin().lock();
            while let Ok(Some(next)) = read_snapshot_line(&mut stdin) {
                let prev = {
                    let mut guard = worker.snapshot.lock().unwrap();
                    let prev = guard.clone();
                    *guard = next.clone();
                    prev
                };
                worker.notify_if_changed(&prev, &next);
            }
        });
    }
    ssal_binder_service::register(HAL, BnThermal::new_binder(thermal))?;
    ssal_binder_service::join()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let result = match args.get(1).map(String::as_str) {
        Some("serve") if args.len() == 5 => args[2]
            .parse()
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
            .and_then(|device| serve(device, &args[3], &args[4])),
        Some("host-provider") if args.len() == 3 => args[2]
            .parse()
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
            .and_then(source::host_provider),
        _ => Err("usage: ssal-thermal <serve <device> <context> <source>|host-provider <device>>".into()),
    };
    if let Err(error) = result {
        eprintln!("ssal-thermal: {error}");
        std::process::exit(1);
    }
}
