rsbinder::include_aidl!("suspend");

use android::system::suspend::{
    internal::{
        ISuspendControlServiceInternal::*, SuspendInfo::SuspendInfo, WakeLockInfo::WakeLockInfo,
        WakeupInfo::WakeupInfo,
    },
    ISuspendCallback::ISuspendCallback,
    ISuspendControlService::*,
    ISystemSuspend::*,
    IWakeLock::*,
    IWakelockCallback::IWakelockCallback,
    WakeLockType::WakeLockType,
};
use rsbinder::{BinderResult, ExceptionCode, Interface, SIBinder, Status, Strong};
use ssal_binder_service::Result;
use std::{
    fs,
    io::{self, Read, Write},
    net::Shutdown,
    os::unix::{
        fs::{FileTypeExt, MetadataExt},
        io::FromRawFd,
        net::UnixStream,
    },
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

const HAL: &str = "android.system.suspend.ISystemSuspend/default";
const HOST_LOCK: &str = "SSAL:VirtualWakeLock";
const MAX_HOLD: Duration = Duration::from_secs(300);
const READY: u8 = 0;
const ACQUIRE: u8 = 1;
const RELEASE: u8 = 2;
const ACK: u8 = 3;

fn exchange(stream: &mut UnixStream, request: u8) -> io::Result<()> {
    let mut reply = [0];
    let result = stream
        .write_all(&[request])
        .inspect_err(|error| {
            eprintln!(
                "power_broker_write request={request} errno={:?}: {error}",
                error.raw_os_error()
            );
        })
        .and_then(|()| {
            stream.read_exact(&mut reply).inspect_err(|error| {
                eprintln!(
                    "power_broker_read_ack request={request} errno={:?}: {error}",
                    error.raw_os_error()
                );
            })?;
            if reply != [ACK] {
                return Err(io::Error::other("invalid power broker acknowledgement"));
            }
            Ok(())
        });
    if result.is_err() {
        let _ = stream.shutdown(Shutdown::Both);
    }
    result
}

struct VirtualWakeLocks {
    broker: UnixStream,
    count: usize,
    deadline: Option<Instant>,
}

struct Suspend(Arc<Mutex<VirtualWakeLocks>>);
impl Interface for Suspend {}

struct WakeLock {
    locks: Arc<Mutex<VirtualWakeLocks>>,
    released: AtomicBool,
}
impl Interface for WakeLock {}

impl ISystemSuspend for Suspend {
    fn acquireWakeLock(
        &self,
        kind: WakeLockType,
        _name: &str,
    ) -> BinderResult<Strong<dyn IWakeLock>> {
        if kind != WakeLockType::PARTIAL {
            return Err(Status::from(ExceptionCode::UnsupportedOperation));
        }
        let mut locks = self.0.lock().unwrap();
        let unavailable = || Status::from(ExceptionCode::IllegalState);
        if locks.count == 0 {
            let deadline = Instant::now() + MAX_HOLD;
            exchange(&mut locks.broker, ACQUIRE).map_err(|error| {
                eprintln!("Guest wakelock acquire failed: {error}");
                unavailable()
            })?;
            locks.deadline = Some(deadline);
        } else if locks.deadline.is_some_and(|end| Instant::now() >= end) {
            return Err(unavailable());
        }
        locks.count = locks.count.checked_add(1).ok_or_else(unavailable)?;
        Ok(BnWakeLock::new_binder(WakeLock {
            locks: self.0.clone(),
            released: AtomicBool::new(false),
        }))
    }
}

impl IWakeLock for WakeLock {
    fn release(&self) -> BinderResult<()> {
        if !self.released.swap(true, Ordering::AcqRel) {
            let mut locks = self.locks.lock().unwrap();
            locks.count -= 1;
            if locks.count == 0 {
                locks.deadline = None;
                exchange(&mut locks.broker, RELEASE).map_err(|error| {
                    eprintln!("Guest wakelock release failed: {error}");
                    Status::from(ExceptionCode::IllegalState)
                })?;
            }
        }
        Ok(())
    }
}

impl Drop for WakeLock {
    fn drop(&mut self) {
        let _ = self.release();
    }
}

struct Control;
impl Interface for Control {}

impl ISuspendControlService for Control {
    fn registerCallback(&self, _: &Strong<dyn ISuspendCallback>) -> BinderResult<bool> {
        Ok(false)
    }
    fn registerWakelockCallback(
        &self,
        _: &Strong<dyn IWakelockCallback>,
        _: &str,
    ) -> BinderResult<bool> {
        Ok(false)
    }
}

impl ISuspendControlServiceInternal for Control {
    fn enableAutosuspend(&self, _: &SIBinder) -> BinderResult<bool> {
        Ok(false)
    }
    fn forceSuspend(&self) -> BinderResult<bool> {
        Ok(false)
    }
    fn getWakeLockStats(&self) -> BinderResult<Vec<WakeLockInfo>> {
        Ok(vec![])
    }
    fn getWakeLockStatsFiltered(&self, _: i32) -> BinderResult<Vec<WakeLockInfo>> {
        Ok(vec![])
    }
    fn getWakeupStats(&self) -> BinderResult<Vec<WakeupInfo>> {
        Ok(vec![])
    }
    fn getSuspendStats(&self) -> BinderResult<SuspendInfo> {
        Ok(SuspendInfo::default())
    }
}

fn broker(mut stream: UnixStream, expected_device: u64) -> Result<()> {
    let device = fs::metadata("/dev/binder")?;
    if !device.file_type().is_char_device() || device.rdev() != expected_device {
        return Err("Host Binder device mismatch".into());
    }
    rsbinder::ProcessState::init("/dev/binder", 1)
        .map_err(|error| io::Error::other(format!("Host Binder init: {error}")))?;
    let suspend: Strong<dyn ISystemSuspend> = rsbinder::hub::check_interface(HAL)
        .map_err(|error| io::Error::other(format!("Host SystemSuspend lookup: {error}")))?;
    let mut held: Option<Strong<dyn IWakeLock>> = None;
    let result: Result<()> = (|| {
        let mut request = [0];
        stream.read_exact(&mut request)?;
        if request != [READY] {
            return Err("invalid power broker handshake".into());
        }
        stream.set_read_timeout(None)?;
        stream.write_all(&[ACK])?;
        loop {
            match stream.read(&mut request)? {
                0 => return Ok(()),
                1 => (),
                _ => unreachable!("single byte request"),
            }
            match (request[0], held.is_some()) {
                (ACQUIRE, false) => {
                    held = Some(suspend.acquireWakeLock(WakeLockType::PARTIAL, HOST_LOCK)?);
                    stream.set_read_timeout(Some(MAX_HOLD))?;
                }
                (RELEASE, true) => {
                    held.take().unwrap().release()?;
                    stream.set_read_timeout(None)?;
                }
                _ => return Err("invalid power broker request".into()),
            }
            stream.write_all(&[ACK])?;
        }
    })();
    if let Some(wake_lock) = held {
        let _ = wake_lock.release();
    }
    result
}

fn run() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    match args.as_slice() {
        [_, mode, device] if mode == "broker" => {
            let device = device.parse()?;
            broker(unsafe { UnixStream::from_raw_fd(0) }, device)
        }
        [_, mode, device, context] if mode == "serve" => {
            ssal_binder_service::init(device.parse()?, context).inspect_err(|error| {
                eprintln!("Guest SystemSuspend Binder init: {error:?}");
            })?;
            if !rsbinder::hub::default()?.try_is_declared(HAL)? {
                return Err(format!("Guest VINTF declaration missing: {HAL}").into());
            }
            println!("guest_vintf_declared=PASS name={HAL}");
            let mut broker = unsafe { UnixStream::from_raw_fd(0) };
            exchange(&mut broker, READY)?;
            println!("guest_power_broker_ready_ack=PASS");
            ssal_binder_service::register(
                "suspend_control",
                BnSuspendControlService::new_binder(Control),
            )?;
            ssal_binder_service::register(
                "suspend_control_internal",
                BnSuspendControlServiceInternal::new_binder(Control),
            )?;
            let state = VirtualWakeLocks {
                broker,
                count: 0,
                deadline: None,
            };
            ssal_binder_service::register(
                HAL,
                BnSystemSuspend::new_binder(Suspend(Arc::new(Mutex::new(state)))),
            )?;
            ssal_binder_service::join()
        }
        _ => {
            Err("expected serve GUEST_BINDER_RDEV GUEST_CONTEXT or broker HOST_BINDER_RDEV".into())
        }
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("ssal-system-suspend: {error}");
        std::process::exit(1);
    }
}
