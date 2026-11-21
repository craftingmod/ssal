rsbinder::include_aidl!("sensors");

use android::hardware::common::fmq::{
    MQDescriptor::MQDescriptor, SynchronizedReadWrite::SynchronizedReadWrite,
};
use android::hardware::sensors::{
    Event::Event,
    ISensors::{
        BnSensors, ISensors, OperationMode::OperationMode, RateLevel::RateLevel,
        SharedMemInfo::SharedMemInfo, ERROR_BAD_VALUE, EVENT_QUEUE_FLAG_BITS_READ_AND_PROCESS,
    },
    ISensorsCallback::ISensorsCallback,
    SensorInfo::SensorInfo,
    SensorType::SensorType,
};
use rsbinder::{BinderResult, ExceptionCode, Interface, Status, Strong};
use rsbinder_fmq::{
    AttachPolicy, Descriptor as FmqDescriptor, Element, EventFlag, Flavor, Grantor, MessageQueue,
};
use serde::Deserialize;
use ssal_binder_service::Result;
use std::{
    fs::File,
    io::{self, BufRead, BufReader, Read, Write},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    sync::{Arc, Mutex},
};

const HAL: &str = "android.hardware.sensors.ISensors/default";

#[repr(C)]
#[derive(Clone, Copy)]
struct HostEventPacket {
    timestamp: i64,
    sensor_handle: i32,
    sensor_type: i32,
    status: i32,
    pad: i32,
    data: [f32; 16],
    step_count: i64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct FmqEvent {
    timestamp: i64,
    sensor_handle: i32,
    sensor_type: i32,
    payload_tag: i32,
    payload_pad: i32,
    payload_value: [u8; 64],
}

const _: () = assert!(std::mem::size_of::<FmqEvent>() == 88);
const _: () = assert!(std::mem::align_of::<FmqEvent>() == 8);

unsafe impl Element for FmqEvent {}

impl FmqEvent {
    fn from_host_packet(pkt: &HostEventPacket) -> Self {
        let mut ev = Self {
            timestamp: pkt.timestamp,
            sensor_handle: pkt.sensor_handle,
            sensor_type: pkt.sensor_type,
            payload_tag: 10, // data
            payload_pad: 0,
            payload_value: [0u8; 64],
        };
        let tag = match pkt.sensor_type {
            1 | 2 | 3 | 4 | 9 | 10 => {
                // vec3: 3 floats + i8 status
                let mut buf = [0u8; 16];
                buf[0..4].copy_from_slice(&pkt.data[0].to_ne_bytes());
                buf[4..8].copy_from_slice(&pkt.data[1].to_ne_bytes());
                buf[8..12].copy_from_slice(&pkt.data[2].to_ne_bytes());
                buf[12] = pkt.status as i8 as u8;
                ev.payload_value[..16].copy_from_slice(&buf);
                0
            }
            11 | 15 | 20 => {
                // vec4: 4 floats
                for i in 0..4 {
                    ev.payload_value[i * 4..(i + 1) * 4]
                        .copy_from_slice(&pkt.data[i].to_ne_bytes());
                }
                1
            }
            14 | 16 | 35 => {
                // uncal: 6 floats
                for i in 0..6 {
                    ev.payload_value[i * 4..(i + 1) * 4]
                        .copy_from_slice(&pkt.data[i].to_ne_bytes());
                }
                2
            }
            19 => {
                // stepCount: i64
                ev.payload_value[..8].copy_from_slice(&pkt.step_count.to_ne_bytes());
                5
            }
            21 => {
                // heartRate: bpm (f32) + status (i8)
                ev.payload_value[0..4].copy_from_slice(&pkt.data[0].to_ne_bytes());
                ev.payload_value[4] = pkt.status as i8 as u8;
                6
            }
            5 | 6 | 7 | 8 | 12 | 13 | 17 | 18 | 22 | 23 | 24 | 25 | 29 | 30 | 31 | 34 | 36 => {
                // scalar: f32
                ev.payload_value[0..4].copy_from_slice(&pkt.data[0].to_ne_bytes());
                4
            }
            _ => {
                // data: 16 floats
                for i in 0..16 {
                    ev.payload_value[i * 4..(i + 1) * 4]
                        .copy_from_slice(&pkt.data[i].to_ne_bytes());
                }
                10
            }
        };
        ev.payload_tag = tag;
        ev
    }

    fn flush_complete(sensor_handle: i32) -> Self {
        let mut ev = Self {
            timestamp: 0,
            sensor_handle,
            sensor_type: 0, // META_DATA
            payload_tag: 3, // meta
            payload_pad: 0,
            payload_value: [0u8; 64],
        };
        // MetaDataEventType::META_DATA_FLUSH_COMPLETE == 1
        ev.payload_value[0..4].copy_from_slice(&1i32.to_ne_bytes());
        ev
    }
}

#[derive(Deserialize)]
struct HostSensorList {
    sensors: Vec<HostSensorInfo>,
}

#[derive(Clone, Deserialize)]
struct HostSensorInfo {
    handle: i32,
    name: String,
    vendor: String,
    r#type: i32,
    type_str: String,
    resolution: f32,
    min_delay: i32,
    fifo_reserved: i32,
    fifo_max: i32,
    reporting_mode: i32,
    wake_up: bool,
}

impl From<&HostSensorInfo> for SensorInfo {
    fn from(s: &HostSensorInfo) -> Self {
        let mut flags = (s.reporting_mode & 0x7) << 1;
        if s.wake_up {
            flags |= 1;
        }
        SensorInfo {
            sensorHandle: s.handle,
            name: s.name.clone(),
            vendor: s.vendor.clone(),
            version: 1,
            r#type: SensorType(s.r#type),
            typeAsString: s.type_str.clone(),
            maxRange: 100.0,
            resolution: if s.resolution > 0.0 { s.resolution } else { 0.01 },
            power: 0.5,
            minDelayUs: s.min_delay,
            fifoReservedEventCount: s.fifo_reserved.max(0),
            fifoMaxEventCount: s.fifo_max.max(0),
            requiredPermission: String::new(),
            maxDelayUs: 1_000_000,
            flags,
        }
    }
}

struct QueueState {
    queue: MessageQueue<FmqEvent>,
    flag: Option<EventFlag>,
}

struct Sensors {
    sensors: Vec<HostSensorInfo>,
    host_tx: Mutex<Option<File>>,
    queue: Arc<Mutex<Option<QueueState>>>,
    _callback: Mutex<Option<Strong<dyn ISensorsCallback>>>,
}

impl Sensors {
    fn send_cmd(&self, cmd: &str) {
        if let Some(tx) = self.host_tx.lock().unwrap().as_mut() {
            let _ = tx.write_all(cmd.as_bytes());
            let _ = tx.flush();
        }
    }

    fn push_event(&self, ev: FmqEvent) {
        let mut guard = self.queue.lock().unwrap();
        if let Some(state) = guard.as_mut() {
            if state.queue.write(&[ev]).is_ok() {
                if let Some(flag) = &state.flag {
                    let _ = flag.wake(EVENT_QUEUE_FLAG_BITS_READ_AND_PROCESS as u32);
                }
            }
        }
    }
}

fn dup_fd(raw: i32) -> io::Result<OwnedFd> {
    let dup = unsafe { libc::fcntl(raw, libc::F_DUPFD_CLOEXEC, 0) };
    if dup < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(dup) })
    }
}

fn to_fmq_descriptor<T, F>(desc: &MQDescriptor<T, F>) -> io::Result<FmqDescriptor> {
    let mut fds = Vec::with_capacity(desc.handle.fds.len());
    for pfd in &desc.handle.fds {
        fds.push(dup_fd(pfd.as_raw_fd())?);
    }
    let grantors = desc
        .grantors
        .iter()
        .map(|g| Grantor {
            fd_index: g.fdIndex as u32,
            offset: g.offset as u32,
            extent: g.extent as u64,
        })
        .collect();
    Ok(FmqDescriptor {
        fds,
        ints: desc.handle.ints.clone(),
        grantors,
        quantum: desc.quantum as u32,
        flavor: Flavor::SynchronizedReadWrite,
    })
}

impl Interface for Sensors {}

impl ISensors for Sensors {
    fn r#activate(&self, sensor_handle: i32, enabled: bool) -> BinderResult<()> {
        if !self.sensors.iter().any(|s| s.handle == sensor_handle) {
            return Err(Status::new_service_specific_error(ERROR_BAD_VALUE, None));
        }
        self.send_cmd(&format!(
            "{{\"cmd\":\"activate\",\"handle\":{sensor_handle},\"enabled\":{enabled}}}\n"
        ));
        Ok(())
    }

    fn r#batch(
        &self,
        sensor_handle: i32,
        sampling_period_ns: i64,
        max_report_latency_ns: i64,
    ) -> BinderResult<()> {
        if !self.sensors.iter().any(|s| s.handle == sensor_handle) {
            return Err(Status::new_service_specific_error(ERROR_BAD_VALUE, None));
        }
        self.send_cmd(&format!(
            "{{\"cmd\":\"batch\",\"handle\":{sensor_handle},\"period_ns\":{sampling_period_ns},\"latency_ns\":{max_report_latency_ns}}}\n"
        ));
        Ok(())
    }

    fn r#configDirectReport(
        &self,
        _sensor_handle: i32,
        _channel_handle: i32,
        _rate: RateLevel,
    ) -> BinderResult<i32> {
        Err(Status::from(ExceptionCode::UnsupportedOperation))
    }

    fn r#flush(&self, sensor_handle: i32) -> BinderResult<()> {
        if !self.sensors.iter().any(|s| s.handle == sensor_handle) {
            return Err(Status::new_service_specific_error(ERROR_BAD_VALUE, None));
        }
        self.push_event(FmqEvent::flush_complete(sensor_handle));
        Ok(())
    }

    fn r#getSensorsList(&self) -> BinderResult<Vec<SensorInfo>> {
        Ok(self.sensors.iter().map(Into::into).collect())
    }

    fn r#initialize(
        &self,
        event_queue_descriptor: &MQDescriptor<Event, SynchronizedReadWrite>,
        _wake_lock_descriptor: &MQDescriptor<i32, SynchronizedReadWrite>,
        sensors_callback: &Strong<dyn ISensorsCallback>,
    ) -> BinderResult<()> {
        let fmq_desc = to_fmq_descriptor(event_queue_descriptor)
            .map_err(|_| Status::new_service_specific_error(ERROR_BAD_VALUE, None))?;
        let queue = MessageQueue::<FmqEvent>::attach(&fmq_desc, &AttachPolicy::new(1024 * 1024))
            .map_err(|_| Status::new_service_specific_error(ERROR_BAD_VALUE, None))?;
        let flag = queue.event_flag();
        *self.queue.lock().unwrap() = Some(QueueState { queue, flag });
        *self._callback.lock().unwrap() = Some(sensors_callback.clone());
        Ok(())
    }

    fn r#injectSensorData(&self, _event: &Event) -> BinderResult<()> {
        Err(Status::from(ExceptionCode::UnsupportedOperation))
    }

    fn r#registerDirectChannel(&self, _mem: &SharedMemInfo) -> BinderResult<i32> {
        Err(Status::from(ExceptionCode::UnsupportedOperation))
    }

    fn r#setOperationMode(&self, mode: OperationMode) -> BinderResult<()> {
        if mode == OperationMode::NORMAL {
            Ok(())
        } else {
            Err(Status::from(ExceptionCode::UnsupportedOperation))
        }
    }

    fn r#unregisterDirectChannel(&self, _channel_handle: i32) -> BinderResult<()> {
        Err(Status::from(ExceptionCode::UnsupportedOperation))
    }
}

fn serve(device: u64, context: &str) -> Result<()> {
    ssal_binder_service::init(device, context)?;
    let sock_rx = unsafe { File::from_raw_fd(dup_fd(libc::STDIN_FILENO)?.into_raw_fd()) };
    let sock_tx = unsafe { File::from_raw_fd(dup_fd(libc::STDIN_FILENO)?.into_raw_fd()) };
    use std::os::fd::IntoRawFd;

    let mut reader = BufReader::new(sock_rx);
    let mut header = String::new();
    reader.read_line(&mut header)?;
    let list: HostSensorList = serde_json::from_str(&header)?;
    let sensors_list: Vec<HostSensorInfo> = list.sensors;

    let service = Arc::new(Sensors {
        sensors: sensors_list,
        host_tx: Mutex::new(Some(sock_tx)),
        queue: Arc::new(Mutex::new(None)),
        _callback: Mutex::new(None),
    });

    let worker = Arc::clone(&service);
    std::thread::spawn(move || {
        let mut buf = [0u8; std::mem::size_of::<HostEventPacket>()];
        while reader.read_exact(&mut buf).is_ok() {
            let pkt: HostEventPacket = unsafe { std::ptr::read_unaligned(buf.as_ptr().cast()) };
            worker.push_event(FmqEvent::from_host_packet(&pkt));
        }
    });

    let binder = BnSensors::new_binder(SensorsWrapper(service));
    ssal_binder_service::register(HAL, binder)?;
    ssal_binder_service::join()
}

struct SensorsWrapper(Arc<Sensors>);

impl Interface for SensorsWrapper {}

impl ISensors for SensorsWrapper {
    fn r#activate(&self, sensor_handle: i32, enabled: bool) -> BinderResult<()> {
        self.0.r#activate(sensor_handle, enabled)
    }
    fn r#batch(&self, sensor_handle: i32, sampling_period_ns: i64, max_report_latency_ns: i64) -> BinderResult<()> {
        self.0.r#batch(sensor_handle, sampling_period_ns, max_report_latency_ns)
    }
    fn r#configDirectReport(&self, sensor_handle: i32, channel_handle: i32, rate: RateLevel) -> BinderResult<i32> {
        self.0.r#configDirectReport(sensor_handle, channel_handle, rate)
    }
    fn r#flush(&self, sensor_handle: i32) -> BinderResult<()> {
        self.0.r#flush(sensor_handle)
    }
    fn r#getSensorsList(&self) -> BinderResult<Vec<SensorInfo>> {
        self.0.r#getSensorsList()
    }
    fn r#initialize(
        &self,
        event_queue_descriptor: &MQDescriptor<Event, SynchronizedReadWrite>,
        wake_lock_descriptor: &MQDescriptor<i32, SynchronizedReadWrite>,
        sensors_callback: &Strong<dyn ISensorsCallback>,
    ) -> BinderResult<()> {
        self.0.r#initialize(event_queue_descriptor, wake_lock_descriptor, sensors_callback)
    }
    fn r#injectSensorData(&self, event: &Event) -> BinderResult<()> {
        self.0.r#injectSensorData(event)
    }
    fn r#registerDirectChannel(&self, mem: &SharedMemInfo) -> BinderResult<i32> {
        self.0.r#registerDirectChannel(mem)
    }
    fn r#setOperationMode(&self, mode: OperationMode) -> BinderResult<()> {
        self.0.r#setOperationMode(mode)
    }
    fn r#unregisterDirectChannel(&self, channel_handle: i32) -> BinderResult<()> {
        self.0.r#unregisterDirectChannel(channel_handle)
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let result = match args.get(1).map(String::as_str) {
        Some("serve") if args.len() == 4 => args[2]
            .parse()
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
            .and_then(|device| serve(device, &args[3])),
        _ => Err("usage: ssal-sensors serve <device> <context>".into()),
    };
    if let Err(error) = result {
        eprintln!("ssal-sensors: {error}");
        std::process::exit(1);
    }
}
