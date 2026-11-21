use crate::{CoolingType, Result, TemperatureType, ThrottlingSeverity};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{self, Write},
    os::unix::fs::{FileTypeExt, MetadataExt},
    path::Path,
    thread,
    time::Duration,
};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TempEntry {
    pub r#type: i32,
    pub name: String,
    pub value: f32,
    pub throttling_status: i32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoolingEntry {
    pub r#type: i32,
    pub name: String,
    pub value: i64,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ThermalSnapshot {
    pub temperatures: Vec<TempEntry>,
    pub cooling_devices: Vec<CoolingEntry>,
}

fn classify_temperature_type(zone_type: &str) -> i32 {
    let lower = zone_type.to_ascii_lowercase();
    if lower.contains("cpu")
        || lower.contains("tsens")
        || lower.contains("apc")
        || lower.contains("silver")
        || lower.contains("gold")
        || lower.contains("prime")
    {
        TemperatureType::CPU.0
    } else if lower.contains("gpu") || lower.contains("gpuss") {
        TemperatureType::GPU.0
    } else if lower.contains("battery") || lower.contains("batt") {
        TemperatureType::BATTERY.0
    } else if lower.contains("skin") || lower.contains("quiet") || lower.contains("xo-therm") {
        TemperatureType::SKIN.0
    } else if lower.contains("usb") || lower.contains("conn") {
        TemperatureType::USB_PORT.0
    } else if lower.contains("npu") || lower.contains("nsp") {
        TemperatureType::NPU.0
    } else if lower.contains("modem") {
        TemperatureType::MODEM.0
    } else if lower.contains("soc") {
        TemperatureType::SOC.0
    } else if lower.contains("wifi") || lower.contains("wlan") {
        TemperatureType::WIFI.0
    } else if lower.contains("pa") {
        TemperatureType::POWER_AMPLIFIER.0
    } else {
        TemperatureType::UNKNOWN.0
    }
}

fn classify_cooling_type(device_type: &str) -> i32 {
    let lower = device_type.to_ascii_lowercase();
    if lower.contains("fan") {
        CoolingType::FAN.0
    } else if lower.contains("cpu") || lower.contains("cpufreq") {
        CoolingType::CPU.0
    } else if lower.contains("gpu") || lower.contains("kgsl") {
        CoolingType::GPU.0
    } else if lower.contains("battery") || lower.contains("batt") || lower.contains("chg") {
        CoolingType::BATTERY.0
    } else if lower.contains("modem") {
        CoolingType::MODEM.0
    } else if lower.contains("npu") || lower.contains("nsp") {
        CoolingType::NPU.0
    } else if lower.contains("display") || lower.contains("lcd") || lower.contains("panel") {
        CoolingType::DISPLAY.0
    } else if lower.contains("pa") {
        CoolingType::POWER_AMPLIFIER.0
    } else {
        CoolingType::COMPONENT.0
    }
}

fn severity_for_celsius(temp_c: f32) -> i32 {
    if temp_c >= 90.0 {
        ThrottlingSeverity::SHUTDOWN.0
    } else if temp_c >= 80.0 {
        ThrottlingSeverity::EMERGENCY.0
    } else if temp_c >= 70.0 {
        ThrottlingSeverity::CRITICAL.0
    } else if temp_c >= 60.0 {
        ThrottlingSeverity::SEVERE.0
    } else if temp_c >= 50.0 {
        ThrottlingSeverity::MODERATE.0
    } else if temp_c >= 42.0 {
        ThrottlingSeverity::LIGHT.0
    } else {
        ThrottlingSeverity::NONE.0
    }
}

fn read_trimmed(path: &Path) -> Option<String> {
    fs::read_to_string(path).ok().map(|s| s.trim().to_string())
}

pub fn read_host_sysfs() -> ThermalSnapshot {
    let mut snapshot = ThermalSnapshot::default();
    let Ok(entries) = fs::read_dir("/sys/class/thermal") else {
        return snapshot;
    };
    let mut paths: Vec<_> = entries.filter_map(|e| e.ok()).map(|e| e.path()).collect();
    paths.sort();

    for path in paths {
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if name.starts_with("thermal_zone") {
            let Some(zone_type) = read_trimmed(&path.join("type")) else {
                continue;
            };
            let Some(temp_raw) = read_trimmed(&path.join("temp"))
                .and_then(|s| s.parse::<i64>().ok())
            else {
                continue;
            };
            let value = (temp_raw as f32) / 1000.0;
            if !value.is_finite() || value < -50.0 || value > 200.0 {
                continue;
            }
            snapshot.temperatures.push(TempEntry {
                r#type: classify_temperature_type(&zone_type),
                name: zone_type,
                value,
                throttling_status: severity_for_celsius(value),
            });
        } else if name.starts_with("cooling_device") {
            let Some(dev_type) = read_trimmed(&path.join("type")) else {
                continue;
            };
            let cur_state = read_trimmed(&path.join("cur_state"))
                .and_then(|s| s.parse::<i64>().ok())
                .unwrap_or(0);
            snapshot.cooling_devices.push(CoolingEntry {
                r#type: classify_cooling_type(&dev_type),
                name: dev_type,
                value: cur_state,
            });
        }
    }
    snapshot
}

pub fn host_provider(expected_device: u64) -> Result<()> {
    let binder = fs::metadata("/dev/binder")?;
    let init = fs::metadata("/proc/1/root/dev/binder")?;
    if !binder.file_type().is_char_device()
        || binder.rdev() != expected_device
        || (binder.dev(), binder.ino(), binder.rdev()) != (init.dev(), init.ino(), init.rdev())
    {
        return Err("Host thermal provider Binder identity mismatch".into());
    }
    let mut stdout = io::stdout().lock();
    loop {
        let snapshot = read_host_sysfs();
        serde_json::to_writer(&mut stdout, &snapshot)?;
        stdout.write_all(b"\n")?;
        stdout.flush()?;
        thread::sleep(Duration::from_secs(2));
    }
}
