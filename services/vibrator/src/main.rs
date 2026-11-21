rsbinder::include_aidl!("vibrator");

use android::hardware::vibrator::{
    Braking::Braking,
    CompositeEffect::CompositeEffect,
    CompositePrimitive::CompositePrimitive,
    Effect::Effect,
    EffectStrength::EffectStrength,
    IVibrator::{BnVibrator, IVibrator, CAP_ON_CALLBACK, CAP_PERFORM_CALLBACK},
    IVibratorCallback::IVibratorCallback,
    PrimitivePwle::PrimitivePwle,
};
use rsbinder::{BinderResult, ExceptionCode, Interface, Status, Strong};
use serde::{Deserialize, Serialize};
use ssal_binder_service::Result;
use std::{
    fs::File,
    io::{self, BufRead, BufReader, Write},
    os::fd::FromRawFd,
    process::Command,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

const HAL: &str = "android.hardware.vibrator.IVibrator/default";

#[derive(Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
enum HostCommand {
    On { ms: i32 },
    Off,
}

fn unsupported() -> Status {
    Status::from(ExceptionCode::UnsupportedOperation)
}

#[derive(Clone)]
struct Vibrator {
    host_tx: Arc<Mutex<Option<File>>>,
    generation: Arc<AtomicU64>,
}

impl Vibrator {
    fn send(&self, cmd: &HostCommand) {
        if let Some(tx) = self.host_tx.lock().unwrap().as_mut() {
            if serde_json::to_writer(&mut *tx, cmd).is_ok() {
                let _ = tx.write_all(b"\n");
                let _ = tx.flush();
            }
        }
    }

    fn trigger(&self, ms: i32, callback: Option<Strong<dyn IVibratorCallback>>) {
        let gen = self.generation.fetch_add(1, Ordering::SeqCst) + 1;
        self.send(&HostCommand::On { ms });
        if let Some(cb) = callback {
            let generation = Arc::clone(&self.generation);
            let delay = Duration::from_millis(ms.max(0) as u64);
            std::thread::spawn(move || {
                std::thread::sleep(delay);
                if generation.load(Ordering::SeqCst) == gen {
                    let _ = cb.onComplete();
                }
            });
        }
    }
}

impl Interface for Vibrator {}

impl IVibrator for Vibrator {
    fn r#getCapabilities(&self) -> BinderResult<i32> {
        Ok(CAP_ON_CALLBACK | CAP_PERFORM_CALLBACK)
    }

    fn r#off(&self) -> BinderResult<()> {
        self.generation.fetch_add(1, Ordering::SeqCst);
        self.send(&HostCommand::Off);
        Ok(())
    }

    fn r#on(
        &self,
        timeout_ms: i32,
        callback: &Strong<dyn IVibratorCallback>,
    ) -> BinderResult<()> {
        self.trigger(timeout_ms.max(1), Some(callback.clone()));
        Ok(())
    }

    fn r#perform(
        &self,
        effect: Effect,
        _strength: EffectStrength,
        callback: &Strong<dyn IVibratorCallback>,
    ) -> BinderResult<i32> {
        let ms = match effect {
            Effect::TICK => 10,
            Effect::POP => 15,
            Effect::CLICK => 20,
            Effect::THUD => 25,
            Effect::DOUBLE_CLICK => 30,
            Effect::HEAVY_CLICK => 35,
            _ => return Err(unsupported()),
        };
        self.trigger(ms, Some(callback.clone()));
        Ok(ms)
    }

    fn r#getSupportedEffects(&self) -> BinderResult<Vec<Effect>> {
        Ok(vec![
            Effect::CLICK,
            Effect::DOUBLE_CLICK,
            Effect::TICK,
            Effect::THUD,
            Effect::POP,
            Effect::HEAVY_CLICK,
        ])
    }

    fn r#setAmplitude(&self, _amplitude: f32) -> BinderResult<()> {
        Err(unsupported())
    }

    fn r#setExternalControl(&self, _enabled: bool) -> BinderResult<()> {
        Err(unsupported())
    }

    fn r#getCompositionDelayMax(&self) -> BinderResult<i32> {
        Err(unsupported())
    }

    fn r#getCompositionSizeMax(&self) -> BinderResult<i32> {
        Err(unsupported())
    }

    fn r#getSupportedPrimitives(&self) -> BinderResult<Vec<CompositePrimitive>> {
        Ok(Vec::new())
    }

    fn r#getPrimitiveDuration(&self, _primitive: CompositePrimitive) -> BinderResult<i32> {
        Err(unsupported())
    }

    fn r#compose(
        &self,
        _composite: &[CompositeEffect],
        _callback: &Strong<dyn IVibratorCallback>,
    ) -> BinderResult<()> {
        Err(unsupported())
    }

    fn r#getSupportedAlwaysOnEffects(&self) -> BinderResult<Vec<Effect>> {
        Ok(Vec::new())
    }

    fn r#alwaysOnEnable(&self, _id: i32, _effect: Effect, _strength: EffectStrength) -> BinderResult<()> {
        Err(unsupported())
    }

    fn r#alwaysOnDisable(&self, _id: i32) -> BinderResult<()> {
        Err(unsupported())
    }

    fn r#getResonantFrequency(&self) -> BinderResult<f32> {
        Err(unsupported())
    }

    fn r#getQFactor(&self) -> BinderResult<f32> {
        Err(unsupported())
    }

    fn r#getFrequencyResolution(&self) -> BinderResult<f32> {
        Err(unsupported())
    }

    fn r#getFrequencyMinimum(&self) -> BinderResult<f32> {
        Err(unsupported())
    }

    fn r#getBandwidthAmplitudeMap(&self) -> BinderResult<Vec<f32>> {
        Err(unsupported())
    }

    fn r#getPwlePrimitiveDurationMax(&self) -> BinderResult<i32> {
        Err(unsupported())
    }

    fn r#getPwleCompositionSizeMax(&self) -> BinderResult<i32> {
        Err(unsupported())
    }

    fn r#getSupportedBraking(&self) -> BinderResult<Vec<Braking>> {
        Err(unsupported())
    }

    fn r#composePwle(
        &self,
        _composite: &[PrimitivePwle],
        _callback: &Strong<dyn IVibratorCallback>,
    ) -> BinderResult<()> {
        Err(unsupported())
    }
}

fn host_provider(expected_device: u64) -> Result<()> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let binder = std::fs::metadata("/dev/binder")?;
    let init = std::fs::metadata("/proc/1/root/dev/binder")?;
    if !binder.file_type().is_char_device()
        || binder.rdev() != expected_device
        || (binder.dev(), binder.ino(), binder.rdev()) != (init.dev(), init.ino(), init.rdev())
    {
        return Err("Host vibrator provider Binder identity mismatch".into());
    }
    let reader = BufReader::new(io::stdin().lock());
    for line in reader.lines() {
        let line = line?;
        let Ok(cmd) = serde_json::from_str::<HostCommand>(&line) else {
            continue;
        };
        match cmd {
            HostCommand::On { ms } => {
                let _ = Command::new("/system/bin/cmd")
                    .args(["vibrator", "vibrate", &ms.max(1).to_string()])
                    .status();
            }
            HostCommand::Off => {
                let _ = Command::new("/system/bin/cmd")
                    .args(["vibrator", "cancel"])
                    .status();
            }
        }
    }
    Ok(())
}

fn serve(device: u64, context: &str, source_mode: &str) -> Result<()> {
    ssal_binder_service::init(device, context)?;
    let host_tx = if source_mode == "host" {
        let dup = unsafe { libc::fcntl(libc::STDIN_FILENO, libc::F_DUPFD_CLOEXEC, 0) };
        if dup < 0 {
            return Err(io::Error::last_os_error().into());
        }
        Some(unsafe { File::from_raw_fd(dup) })
    } else {
        None
    };
    let vibrator = Vibrator {
        host_tx: Arc::new(Mutex::new(host_tx)),
        generation: Arc::new(AtomicU64::new(0)),
    };
    ssal_binder_service::register(HAL, BnVibrator::new_binder(vibrator))?;
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
            .and_then(host_provider),
        _ => Err("usage: ssal-vibrator <serve <device> <context> <source>|host-provider <device>>".into()),
    };
    if let Err(error) = result {
        eprintln!("ssal-vibrator: {error}");
        std::process::exit(1);
    }
}
