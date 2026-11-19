use crate::{BatteryHealth, BatteryStatus, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    io::{self, Write},
    process::Command,
    thread,
    time::Duration,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sample {
    pub status: i32,
    pub health: i32,
    pub present: bool,
    pub level: i32,
    pub voltage: i32,
    pub temperature: i32,
    pub current: Option<i32>,
    pub average_current: Option<i32>,
    pub charge_counter: i32,
    pub full_charge: i32,
    pub design_charge: i32,
    pub cycle_count: i32,
    pub ac: bool,
    pub usb: bool,
    pub wireless: bool,
    pub dock: bool,
    pub max_current: i32,
    pub max_voltage: i32,
    pub technology: String,
}

impl Sample {
    pub fn diagnostic() -> Self {
        Self {
            status: BatteryStatus::DISCHARGING.0,
            health: BatteryHealth::GOOD.0,
            present: true,
            level: 75,
            voltage: 3800,
            temperature: 250,
            current: Some(-100_000),
            average_current: Some(-100_000),
            charge_counter: 3_000_000,
            full_charge: 4_000_000,
            design_charge: 4_000_000,
            cycle_count: 0,
            ac: false,
            usb: false,
            wireless: false,
            dock: false,
            max_current: 0,
            max_voltage: 0,
            technology: "SSAL diagnostic (synthetic)".into(),
        }
    }

    fn from_host_dump(dump: &str) -> Result<Self> {
        let fields: BTreeMap<_, _> = dump
            .lines()
            .filter_map(|line| line.trim().split_once(": "))
            .collect();
        let get = |key| {
            fields.get(key).copied().ok_or_else(|| {
                io::Error::other(format!("Host BatteryService field missing: {key}"))
            })
        };
        let number = |key| -> Result<i32> { Ok(get(key)?.parse()?) };
        let flag = |key| -> Result<bool> { Ok(get(key)?.parse()?) };
        let level = number("level")?;
        if number("scale")? != 100
            || !(0..=100).contains(&level)
            || dump.contains("UPDATES STOPPED")
        {
            return Err("invalid or overridden Host BatteryService state".into());
        }
        Ok(Self {
            status: number("status")?,
            health: number("health")?,
            present: flag("present")?,
            level,
            voltage: number("voltage")?,
            temperature: number("temperature")?,
            current: None,
            average_current: None,
            charge_counter: number("Charge counter")?,
            full_charge: 0,
            design_charge: 0,
            cycle_count: 0,
            ac: flag("AC powered")?,
            usb: flag("USB powered")?,
            wireless: flag("Wireless powered")?,
            dock: fields
                .get("Dock powered")
                .map(|value| value.parse())
                .transpose()?
                .unwrap_or(false),
            max_current: number("Max charging current")?,
            max_voltage: number("Max charging voltage")?,
            technology: get("technology")?.into(),
        })
    }
}

fn battery_sysfs(name: &str) -> Option<i32> {
    fs::read_to_string(format!("/sys/class/power_supply/battery/{name}"))
        .ok()?
        .trim()
        .parse()
        .ok()
}

pub fn host_provider(expected_device: u64) -> Result<()> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let binder = fs::metadata("/dev/binder")?;
    let init = fs::metadata("/proc/1/root/dev/binder")?;
    if !binder.file_type().is_char_device()
        || binder.rdev() != expected_device
        || (binder.dev(), binder.ino(), binder.rdev()) != (init.dev(), init.ino(), init.rdev())
    {
        return Err("Host battery provider Binder identity mismatch".into());
    }
    let mut stdout = io::stdout().lock();
    loop {
        let output = Command::new("/system/bin/dumpsys")
            .args(["-t", "2", "battery"])
            .output()?;
        if !output.status.success() {
            return Err("Host BatteryService dump failed".into());
        }
        let mut sample = Sample::from_host_dump(std::str::from_utf8(&output.stdout)?)?;
        sample.current = battery_sysfs("current_now");
        sample.average_current = battery_sysfs("current_avg");
        sample.full_charge = battery_sysfs("charge_full").unwrap_or(0);
        sample.design_charge = battery_sysfs("charge_full_design").unwrap_or(0);
        sample.cycle_count = battery_sysfs("cycle_count").unwrap_or(0);
        serde_json::to_writer(&mut stdout, &sample)?;
        stdout.write_all(b"\n")?;
        stdout.flush()?;
        thread::sleep(Duration::from_secs(5));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_dump_preserves_units_and_refuses_overrides() {
        let dump = "AC powered: true\nUSB powered: false\nWireless powered: false\nMax charging current: 3000000\nMax charging voltage: 5000000\nCharge counter: 4750060\nstatus: 5\nhealth: 2\npresent: true\nlevel: 98\nscale: 100\nvoltage: 4368\ntemperature: 340\ntechnology: Li-ion\n";
        let sample = Sample::from_host_dump(dump).unwrap();
        assert!(sample.ac);
        assert_eq!(
            (sample.level, sample.voltage, sample.temperature),
            (98, 4368, 340)
        );
        assert_eq!(sample.charge_counter, 4_750_060);
        assert!(sample.current.is_none());
        assert!(Sample::from_host_dump(&format!("UPDATES STOPPED\n{dump}")).is_err());
        assert!(Sample::from_host_dump(&dump.replace("scale: 100", "scale: 50")).is_err());
    }
}
