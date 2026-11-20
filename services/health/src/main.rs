use rsbinder::{BinderResult, DeathRecipient, ExceptionCode, Interface, Status, Strong, WIBinder};
use ssal_binder_service::Result;
use std::{
    io::{self, BufRead},
    sync::{Arc, Mutex},
};

mod source;
use source::Sample;

mod aidl {
    include!(concat!(env!("OUT_DIR"), "/health.rs"));
}

use aidl::android::hardware::health::{
    BatteryCapacityLevel::BatteryCapacityLevel,
    BatteryChargingPolicy::BatteryChargingPolicy,
    BatteryHealth::BatteryHealth,
    BatteryHealthData::BatteryHealthData,
    BatteryStatus::BatteryStatus,
    DiskStats::DiskStats,
    HealthInfo::HealthInfo,
    HingeInfo::HingeInfo,
    IHealth::{BnHealth, IHealth, STATUS_CALLBACK_DIED},
    IHealthInfoCallback::IHealthInfoCallback,
    StorageInfo::StorageInfo,
};

const HAL: &str = "android.hardware.health.IHealth/default";
type Callback = Strong<dyn IHealthInfoCallback>;

#[derive(Default)]
struct Callbacks(Mutex<Vec<Callback>>);

impl DeathRecipient for Callbacks {
    fn binder_died(&self, who: &WIBinder) {
        self.0
            .lock()
            .unwrap()
            .retain(|callback| *who != callback.as_binder());
    }
}

#[derive(Clone)]
struct Health {
    sample: Arc<Mutex<Sample>>,
    callbacks: Arc<Callbacks>,
}

impl Health {
    fn info(&self) -> HealthInfo {
        let sample = self.sample.lock().unwrap();
        HealthInfo {
            chargerAcOnline: sample.ac,
            chargerUsbOnline: sample.usb,
            chargerWirelessOnline: sample.wireless,
            chargerDockOnline: sample.dock,
            maxChargingCurrentMicroamps: sample.max_current,
            maxChargingVoltageMicrovolts: sample.max_voltage,
            batteryPresent: sample.present,
            batteryStatus: BatteryStatus(sample.status),
            batteryHealth: BatteryHealth(sample.health),
            batteryLevel: sample.level,
            batteryVoltageMillivolts: sample.voltage,
            batteryTemperatureTenthsCelsius: sample.temperature,
            batteryCurrentMicroamps: sample.current.unwrap_or(0),
            batteryCurrentAverageMicroamps: sample.average_current.unwrap_or(0),
            batteryCycleCount: sample.cycle_count,
            batteryFullChargeUah: sample.full_charge,
            batteryFullChargeDesignCapacityUah: sample.design_charge,
            batteryChargeCounterUah: sample.charge_counter,
            batteryTechnology: sample.technology.clone(),
            batteryCapacityLevel: BatteryCapacityLevel::UNSUPPORTED,
            batteryChargeTimeToFullNowSeconds: -1,
            ..HealthInfo::default()
        }
    }
}

fn unsupported() -> Status {
    Status::from(ExceptionCode::UnsupportedOperation)
}

impl Interface for Health {}

impl IHealth for Health {
    fn registerCallback(&self, callback: &Callback) -> BinderResult<()> {
        {
            let mut callbacks = self.callbacks.0.lock().unwrap();
            if !callbacks.contains(callback) {
                callback.link_to_death_arc(&self.callbacks)?;
                callbacks.push(callback.clone());
            }
        }
        if callback.healthInfoChanged(&self.info()).is_err() {
            let _ = self.unregisterCallback(callback);
            return Err(Status::new_service_specific_error(
                STATUS_CALLBACK_DIED,
                None,
            ));
        }
        println!("guest_health_initial_callback=PASS");
        Ok(())
    }

    fn unregisterCallback(&self, callback: &Callback) -> BinderResult<()> {
        let mut callbacks = self.callbacks.0.lock().unwrap();
        if let Some(index) = callbacks.iter().position(|entry| entry == callback) {
            callbacks.swap_remove(index);
            let _ = callback.unlink_to_death_arc(&self.callbacks);
        }
        Ok(())
    }

    fn update(&self) -> BinderResult<()> {
        let callbacks = self.callbacks.0.lock().unwrap().clone();
        let info = self.info();
        for callback in callbacks {
            if callback.healthInfoChanged(&info).is_err() {
                let _ = self.unregisterCallback(&callback);
            }
        }
        Ok(())
    }

    fn getHealthInfo(&self) -> BinderResult<HealthInfo> {
        Ok(self.info())
    }

    fn getChargeCounterUah(&self) -> BinderResult<i32> {
        Ok(self.sample.lock().unwrap().charge_counter)
    }

    fn getCurrentNowMicroamps(&self) -> BinderResult<i32> {
        self.sample.lock().unwrap().current.ok_or_else(unsupported)
    }

    fn getCurrentAverageMicroamps(&self) -> BinderResult<i32> {
        self.sample
            .lock()
            .unwrap()
            .average_current
            .ok_or_else(unsupported)
    }

    fn getCapacity(&self) -> BinderResult<i32> {
        Ok(self.sample.lock().unwrap().level)
    }

    fn getEnergyCounterNwh(&self) -> BinderResult<i64> {
        Err(unsupported())
    }

    fn getChargeStatus(&self) -> BinderResult<BatteryStatus> {
        Ok(BatteryStatus(self.sample.lock().unwrap().status))
    }

    fn getStorageInfo(&self) -> BinderResult<Vec<StorageInfo>> {
        Err(unsupported())
    }

    fn getDiskStats(&self) -> BinderResult<Vec<DiskStats>> {
        Err(unsupported())
    }

    fn setChargingPolicy(&self, _: BatteryChargingPolicy) -> BinderResult<()> {
        Err(unsupported())
    }

    fn getChargingPolicy(&self) -> BinderResult<BatteryChargingPolicy> {
        Err(unsupported())
    }

    fn getBatteryHealthData(&self) -> BinderResult<BatteryHealthData> {
        Err(unsupported())
    }

    fn getHingeInfo(&self) -> BinderResult<Vec<HingeInfo>> {
        Ok(Vec::new())
    }
}

fn run() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    let (device, context, host_source) = match args.as_slice() {
        [_, mode, device] if mode == "host-provider" => return source::host_provider(device.parse()?),
        [_, mode, device, context, source] if mode == "serve" => (device, context, match source.as_str() {
            "host" => true,
            "diagnostic" => false,
            _ => return Err("invalid Guest Health source".into()),
        }),
        _ => return Err("expected serve GUEST_BINDER_RDEV GUEST_CONTEXT SOURCE or host-provider HOST_BINDER_RDEV".into()),
    };
    ssal_binder_service::init(device.parse()?, context)
        .map_err(|error| format!("Guest Health Binder init: {error:?}"))?;
    let manager = rsbinder::hub::default()
        .map_err(|error| format!("Guest Health ServiceManager lookup: {error:?}"))?;
    if !manager
        .try_is_declared(HAL)
        .map_err(|error| format!("Guest Health VINTF lookup: {error:?}"))?
    {
        return Err(format!("Guest VINTF declaration missing: {HAL}").into());
    }
    let input = io::stdin();
    let mut samples = input.lock().lines();
    let sample = if host_source {
        serde_json::from_str(
            &samples
                .next()
                .ok_or("Host battery provider closed before initial sample")??,
        )?
    } else {
        Sample::diagnostic()
    };
    println!(
        "guest_health_source={} level={} status={}",
        if host_source {
            "host_readonly"
        } else {
            "diagnostic_synthetic"
        },
        sample.level,
        sample.status
    );
    let health = Health {
        sample: Arc::new(Mutex::new(sample)),
        callbacks: Arc::default(),
    };
    ssal_binder_service::register(HAL, BnHealth::new_binder(health.clone()))
        .map_err(|error| format!("Guest Health registration: {error:?}"))?;
    if !host_source {
        return ssal_binder_service::join();
    }
    for line in samples {
        let sample: Sample = serde_json::from_str(&line?)?;
        let mut current = health.sample.lock().unwrap();
        if *current != sample {
            *current = sample;
            drop(current);
            health.update()?;
        }
    }
    Err("Host battery provider closed".into())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("ssal-health: {error:?}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostic_sample_is_consistent_and_marked() {
        let health = Health {
            sample: Arc::new(Mutex::new(Sample::diagnostic())),
            callbacks: Arc::default(),
        };
        let info = health.getHealthInfo().unwrap();
        assert!(info.batteryTechnology.contains("synthetic"));
        assert_eq!(health.getCapacity().unwrap(), info.batteryLevel);
        assert_eq!(
            health.getChargeCounterUah().unwrap(),
            info.batteryFullChargeUah * info.batteryLevel / 100
        );
        assert!(health
            .setChargingPolicy(BatteryChargingPolicy::DEFAULT)
            .is_err());
    }
}
