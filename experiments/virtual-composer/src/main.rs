#![allow(non_snake_case, dead_code, unused_imports)]
rsbinder::include_aidl!("composer3");

use android::hardware::common::NativeHandle::NativeHandle;
use android::hardware::graphics::common::{
    Dataspace::Dataspace, DisplayDecorationSupport::DisplayDecorationSupport, Hdr::Hdr,
    HdrConversionCapability::HdrConversionCapability,
    HdrConversionStrategy::HdrConversionStrategy, PixelFormat::PixelFormat, Transform::Transform,
};
use android::hardware::graphics::composer3::{
    Capability::Capability,
    ChangedCompositionLayer::ChangedCompositionLayer,
    ChangedCompositionTypes::ChangedCompositionTypes,
    ColorMode::ColorMode,
    CommandError::CommandError,
    CommandResultPayload::CommandResultPayload,
    Composition::Composition,
    ContentType::ContentType,
    DisplayAttribute::DisplayAttribute,
    DisplayCapability::DisplayCapability,
    DisplayCommand::DisplayCommand,
    DisplayConnectionType::DisplayConnectionType,
    DisplayContentSample::DisplayContentSample,
    DisplayContentSamplingAttributes::DisplayContentSamplingAttributes,
    DisplayIdentification::DisplayIdentification,
    FormatColorComponent::FormatColorComponent,
    HdrCapabilities::HdrCapabilities,
    IComposer::{BnComposer, IComposer},
    IComposerCallback::IComposerCallback,
    IComposerClient::{
        BnComposerClient, IComposerClient, EX_BAD_CONFIG, EX_BAD_DISPLAY, EX_BAD_LAYER,
        EX_NO_RESOURCES, EX_UNSUPPORTED,
    },
    OverlayProperties::OverlayProperties,
    PerFrameMetadataKey::PerFrameMetadataKey,
    PowerMode::PowerMode,
    PresentFence::PresentFence,
    PresentOrValidate::{PresentOrValidate, Result::Result as PresentOrValidateResult},
    ReadbackBufferAttributes::ReadbackBufferAttributes,
    ReleaseFences::ReleaseFences,
    RenderIntent::RenderIntent,
    VirtualDisplay::VirtualDisplay,
    VsyncPeriodChangeConstraints::VsyncPeriodChangeConstraints,
    VsyncPeriodChangeTimeline::VsyncPeriodChangeTimeline,
};
use rsbinder::{BinderResult, Interface, ParcelFileDescriptor, Status, Strong};
use ssal_binder_service::Result;
use std::collections::BTreeMap;
use std::os::fd::AsRawFd;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc, Condvar, Mutex,
};
use std::time::Duration;

const HAL_SERVICE: &str = "android.hardware.graphics.composer3.IComposer/default";
const DISPLAY_ID: i64 = 0;
const CONFIG_ID: i32 = 0;
const WIDTH: i32 = 1080;
const HEIGHT: i32 = 1920;
const VSYNC_PERIOD_NS: i32 = 16_666_667; // 60 Hz
const DPI_MILLIS: i32 = 320_000; // 320 dpi * 1000

fn monotonic_ns() -> i64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe {
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
    }
    ts.tv_sec
        .saturating_mul(1_000_000_000)
        .saturating_add(ts.tv_nsec)
}

fn wait_sync_fence(fence: &Option<ParcelFileDescriptor>) {
    let Some(pfd) = fence else {
        return;
    };
    let fd = pfd.as_raw_fd();
    if fd < 0 {
        return;
    }
    let mut pfd_poll = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    unsafe {
        libc::poll(&mut pfd_poll, 1, 1000);
    }
}

fn service_error(code: i32) -> Status {
    Status::new_service_specific_error(code, None)
}

struct VsyncState {
    enabled: bool,
    stopped: bool,
    callback: Option<Strong<dyn IComposerCallback>>,
}

struct DisplayState {
    next_layer_id: i64,
    layers: BTreeMap<i64, Composition>,
    power_mode: PowerMode,
    color_mode: ColorMode,
    client_target_slot_count: i32,
    present_count: u64,
}

impl Default for DisplayState {
    fn default() -> Self {
        Self {
            next_layer_id: 1,
            layers: BTreeMap::new(),
            power_mode: PowerMode::ON,
            color_mode: ColorMode::NATIVE,
            client_target_slot_count: 3,
            present_count: 0,
        }
    }
}

struct VirtualComposerClient {
    state: Mutex<DisplayState>,
    vsync: Arc<(Mutex<VsyncState>, Condvar)>,
    vsync_thread_started: AtomicBool,
}

impl VirtualComposerClient {
    fn new() -> Self {
        Self {
            state: Mutex::new(DisplayState::default()),
            vsync: Arc::new((
                Mutex::new(VsyncState {
                    enabled: false,
                    stopped: false,
                    callback: None,
                }),
                Condvar::new(),
            )),
            vsync_thread_started: AtomicBool::new(false),
        }
    }

    fn check_display(&self, display: i64) -> BinderResult<()> {
        if display != DISPLAY_ID {
            return Err(service_error(EX_BAD_DISPLAY));
        }
        Ok(())
    }

    fn start_vsync_thread(&self) {
        if self.vsync_thread_started.swap(true, Ordering::AcqRel) {
            return;
        }
        let vsync = Arc::clone(&self.vsync);
        std::thread::spawn(move || {
            let period = Duration::from_nanos(VSYNC_PERIOD_NS as u64);
            loop {
                let cb = {
                    let (lock, cvar) = &*vsync;
                    let mut guard = lock.lock().unwrap();
                    while !guard.stopped && (!guard.enabled || guard.callback.is_none()) {
                        guard = cvar.wait(guard).unwrap();
                    }
                    if guard.stopped {
                        return;
                    }
                    guard.callback.clone()
                };
                std::thread::sleep(period);
                if let Some(cb) = cb {
                    let still_enabled = vsync.0.lock().unwrap().enabled;
                    if still_enabled {
                        let _ = cb.r#onVsync(DISPLAY_ID, monotonic_ns(), VSYNC_PERIOD_NS);
                    }
                }
            }
        });
    }
}

impl Drop for VirtualComposerClient {
    fn drop(&mut self) {
        let (lock, cvar) = &*self.vsync;
        let mut guard = lock.lock().unwrap();
        guard.stopped = true;
        guard.enabled = false;
        guard.callback = None;
        cvar.notify_all();
    }
}

impl Interface for VirtualComposerClient {}

impl IComposerClient for VirtualComposerClient {
    fn r#createLayer(&self, display: i64, _buffer_slot_count: i32) -> BinderResult<i64> {
        self.check_display(display)?;
        let mut state = self.state.lock().unwrap();
        let id = state.next_layer_id;
        state.next_layer_id += 1;
        state.layers.insert(id, Composition::INVALID);
        Ok(id)
    }

    fn r#createVirtualDisplay(
        &self,
        _width: i32,
        _height: i32,
        _format_hint: PixelFormat,
        _output_buffer_slot_count: i32,
    ) -> BinderResult<VirtualDisplay> {
        Err(service_error(EX_NO_RESOURCES))
    }

    fn r#destroyLayer(&self, display: i64, layer: i64) -> BinderResult<()> {
        self.check_display(display)?;
        let mut state = self.state.lock().unwrap();
        if state.layers.remove(&layer).is_none() {
            return Err(service_error(EX_BAD_LAYER));
        }
        Ok(())
    }

    fn r#destroyVirtualDisplay(&self, _display: i64) -> BinderResult<()> {
        Err(service_error(EX_BAD_DISPLAY))
    }

    fn r#executeCommands(
        &self,
        commands: &[DisplayCommand],
    ) -> BinderResult<Vec<CommandResultPayload>> {
        let mut results = Vec::new();
        let mut state = self.state.lock().unwrap();

        for (index, cmd) in commands.iter().enumerate() {
            if cmd.r#display != DISPLAY_ID {
                results.push(CommandResultPayload::r#Error(CommandError {
                    r#commandIndex: index as i32,
                    r#errorCode: EX_BAD_DISPLAY,
                }));
                continue;
            }

            for layer_cmd in &cmd.r#layers {
                if let Some(comp) = &layer_cmd.r#composition {
                    if let Some(entry) = state.layers.get_mut(&layer_cmd.r#layer) {
                        *entry = comp.r#composition;
                    }
                }
            }

            if let Some(client_target) = &cmd.r#clientTarget {
                wait_sync_fence(&client_target.r#buffer.r#fence);
            }

            if cmd.r#validateDisplay || cmd.r#presentOrValidateDisplay {
                let mut changed = Vec::new();
                for (&layer_id, &comp) in &state.layers {
                    if comp != Composition::CLIENT {
                        changed.push(ChangedCompositionLayer {
                            r#layer: layer_id,
                            r#composition: Composition::CLIENT,
                        });
                    }
                }
                if !changed.is_empty() {
                    results.push(CommandResultPayload::r#ChangedCompositionTypes(
                        ChangedCompositionTypes {
                            r#display: DISPLAY_ID,
                            r#layers: changed,
                        },
                    ));
                }
                if cmd.r#presentOrValidateDisplay {
                    results.push(CommandResultPayload::r#PresentOrValidateResult(
                        PresentOrValidate {
                            r#display: DISPLAY_ID,
                            r#result: PresentOrValidateResult::Validated,
                        },
                    ));
                }
            }

            if cmd.r#acceptDisplayChanges {
                for comp in state.layers.values_mut() {
                    *comp = Composition::CLIENT;
                }
            }

            if cmd.r#presentDisplay {
                state.present_count += 1;
                let count = state.present_count;
                if count <= 5 || count % 60 == 0 {
                    println!(
                        "virtual_composer_present display={} frame={} layers={}",
                        DISPLAY_ID,
                        count,
                        state.layers.len()
                    );
                }
                results.push(CommandResultPayload::r#PresentFence(PresentFence {
                    r#display: DISPLAY_ID,
                    r#fence: None,
                }));
                results.push(CommandResultPayload::r#ReleaseFences(ReleaseFences {
                    r#display: DISPLAY_ID,
                    r#layers: Vec::new(),
                }));
            }
        }

        Ok(results)
    }

    fn r#getActiveConfig(&self, display: i64) -> BinderResult<i32> {
        self.check_display(display)?;
        Ok(CONFIG_ID)
    }

    fn r#getColorModes(&self, display: i64) -> BinderResult<Vec<ColorMode>> {
        self.check_display(display)?;
        Ok(vec![ColorMode::NATIVE])
    }

    fn r#getDataspaceSaturationMatrix(&self, _dataspace: Dataspace) -> BinderResult<Vec<f32>> {
        Ok(vec![
            1.0, 0.0, 0.0, 0.0, //
            0.0, 1.0, 0.0, 0.0, //
            0.0, 0.0, 1.0, 0.0, //
            0.0, 0.0, 0.0, 1.0,
        ])
    }

    fn r#getDisplayAttribute(
        &self,
        display: i64,
        config: i32,
        attribute: DisplayAttribute,
    ) -> BinderResult<i32> {
        self.check_display(display)?;
        if config != CONFIG_ID {
            return Err(service_error(EX_BAD_CONFIG));
        }
        match attribute {
            DisplayAttribute::WIDTH => Ok(WIDTH),
            DisplayAttribute::HEIGHT => Ok(HEIGHT),
            DisplayAttribute::VSYNC_PERIOD => Ok(VSYNC_PERIOD_NS),
            DisplayAttribute::DPI_X => Ok(DPI_MILLIS),
            DisplayAttribute::DPI_Y => Ok(DPI_MILLIS),
            DisplayAttribute::CONFIG_GROUP => Ok(0),
            _ => Err(service_error(EX_UNSUPPORTED)),
        }
    }

    fn r#getDisplayCapabilities(&self, display: i64) -> BinderResult<Vec<DisplayCapability>> {
        self.check_display(display)?;
        Ok(Vec::new())
    }

    fn r#getDisplayConfigs(&self, display: i64) -> BinderResult<Vec<i32>> {
        self.check_display(display)?;
        Ok(vec![CONFIG_ID])
    }

    fn r#getDisplayConnectionType(&self, display: i64) -> BinderResult<DisplayConnectionType> {
        self.check_display(display)?;
        Ok(DisplayConnectionType::INTERNAL)
    }

    fn r#getDisplayIdentificationData(&self, display: i64) -> BinderResult<DisplayIdentification> {
        self.check_display(display)?;
        Err(service_error(EX_UNSUPPORTED))
    }

    fn r#getDisplayName(&self, display: i64) -> BinderResult<String> {
        self.check_display(display)?;
        Ok("SSAL Virtual Primary".into())
    }

    fn r#getDisplayVsyncPeriod(&self, display: i64) -> BinderResult<i32> {
        self.check_display(display)?;
        Ok(VSYNC_PERIOD_NS)
    }

    fn r#getDisplayedContentSample(
        &self,
        display: i64,
        _max_frames: i64,
        _timestamp: i64,
    ) -> BinderResult<DisplayContentSample> {
        self.check_display(display)?;
        Err(service_error(EX_UNSUPPORTED))
    }

    fn r#getDisplayedContentSamplingAttributes(
        &self,
        display: i64,
    ) -> BinderResult<DisplayContentSamplingAttributes> {
        self.check_display(display)?;
        Err(service_error(EX_UNSUPPORTED))
    }

    fn r#getDisplayPhysicalOrientation(&self, display: i64) -> BinderResult<Transform> {
        self.check_display(display)?;
        Ok(Transform::NONE)
    }

    fn r#getHdrCapabilities(&self, display: i64) -> BinderResult<HdrCapabilities> {
        self.check_display(display)?;
        Ok(HdrCapabilities::default())
    }

    fn r#getMaxVirtualDisplayCount(&self) -> BinderResult<i32> {
        Ok(0)
    }

    fn r#getPerFrameMetadataKeys(&self, display: i64) -> BinderResult<Vec<PerFrameMetadataKey>> {
        self.check_display(display)?;
        Ok(Vec::new())
    }

    fn r#getReadbackBufferAttributes(
        &self,
        display: i64,
    ) -> BinderResult<ReadbackBufferAttributes> {
        self.check_display(display)?;
        Err(service_error(EX_UNSUPPORTED))
    }

    fn r#getReadbackBufferFence(
        &self,
        display: i64,
    ) -> BinderResult<Option<ParcelFileDescriptor>> {
        self.check_display(display)?;
        Err(service_error(EX_UNSUPPORTED))
    }

    fn r#getRenderIntents(&self, display: i64, mode: ColorMode) -> BinderResult<Vec<RenderIntent>> {
        self.check_display(display)?;
        if mode != ColorMode::NATIVE {
            return Err(service_error(EX_UNSUPPORTED));
        }
        Ok(vec![RenderIntent::COLORIMETRIC])
    }

    fn r#getSupportedContentTypes(&self, display: i64) -> BinderResult<Vec<ContentType>> {
        self.check_display(display)?;
        Ok(Vec::new())
    }

    fn r#getDisplayDecorationSupport(
        &self,
        display: i64,
    ) -> BinderResult<Option<DisplayDecorationSupport>> {
        self.check_display(display)?;
        Ok(None)
    }

    fn r#registerCallback(&self, callback: &Strong<dyn IComposerCallback>) -> BinderResult<()> {
        {
            let (lock, cvar) = &*self.vsync;
            let mut guard = lock.lock().unwrap();
            guard.callback = Some(callback.clone());
            cvar.notify_all();
        }
        self.start_vsync_thread();
        println!("virtual_composer_hotplug display={} connected=true", DISPLAY_ID);
        callback.r#onHotplug(DISPLAY_ID, true)?;
        Ok(())
    }

    fn r#setActiveConfig(&self, display: i64, config: i32) -> BinderResult<()> {
        self.check_display(display)?;
        if config != CONFIG_ID {
            return Err(service_error(EX_BAD_CONFIG));
        }
        Ok(())
    }

    fn r#setActiveConfigWithConstraints(
        &self,
        display: i64,
        config: i32,
        _constraints: &VsyncPeriodChangeConstraints,
    ) -> BinderResult<VsyncPeriodChangeTimeline> {
        self.check_display(display)?;
        if config != CONFIG_ID {
            return Err(service_error(EX_BAD_CONFIG));
        }
        Ok(VsyncPeriodChangeTimeline {
            r#newVsyncAppliedTimeNanos: monotonic_ns(),
            r#refreshRequired: false,
            r#refreshTimeNanos: 0,
        })
    }

    fn r#setBootDisplayConfig(&self, display: i64, config: i32) -> BinderResult<()> {
        self.check_display(display)?;
        if config != CONFIG_ID {
            return Err(service_error(EX_BAD_CONFIG));
        }
        Ok(())
    }

    fn r#clearBootDisplayConfig(&self, display: i64) -> BinderResult<()> {
        self.check_display(display)?;
        Ok(())
    }

    fn r#getPreferredBootDisplayConfig(&self, display: i64) -> BinderResult<i32> {
        self.check_display(display)?;
        Ok(CONFIG_ID)
    }

    fn r#setAutoLowLatencyMode(&self, display: i64, _on: bool) -> BinderResult<()> {
        self.check_display(display)?;
        Err(service_error(EX_UNSUPPORTED))
    }

    fn r#setClientTargetSlotCount(&self, display: i64, count: i32) -> BinderResult<()> {
        self.check_display(display)?;
        self.state.lock().unwrap().client_target_slot_count = count;
        Ok(())
    }

    fn r#setColorMode(
        &self,
        display: i64,
        mode: ColorMode,
        _intent: RenderIntent,
    ) -> BinderResult<()> {
        self.check_display(display)?;
        if mode != ColorMode::NATIVE {
            return Err(service_error(EX_UNSUPPORTED));
        }
        self.state.lock().unwrap().color_mode = mode;
        Ok(())
    }

    fn r#setContentType(&self, display: i64, content_type: ContentType) -> BinderResult<()> {
        self.check_display(display)?;
        if content_type == ContentType::NONE {
            Ok(())
        } else {
            Err(service_error(EX_UNSUPPORTED))
        }
    }

    fn r#setDisplayedContentSamplingEnabled(
        &self,
        display: i64,
        _enable: bool,
        _component_mask: FormatColorComponent,
        _max_frames: i64,
    ) -> BinderResult<()> {
        self.check_display(display)?;
        Err(service_error(EX_UNSUPPORTED))
    }

    fn r#setPowerMode(&self, display: i64, mode: PowerMode) -> BinderResult<()> {
        self.check_display(display)?;
        self.state.lock().unwrap().power_mode = mode;
        println!("virtual_composer_power display={} mode={:?}", display, mode);
        Ok(())
    }

    fn r#setReadbackBuffer(
        &self,
        display: i64,
        _buffer: &NativeHandle,
        _release_fence: Option<&ParcelFileDescriptor>,
    ) -> BinderResult<()> {
        self.check_display(display)?;
        Err(service_error(EX_UNSUPPORTED))
    }

    fn r#setVsyncEnabled(&self, display: i64, enabled: bool) -> BinderResult<()> {
        self.check_display(display)?;
        let (lock, cvar) = &*self.vsync;
        let mut guard = lock.lock().unwrap();
        guard.enabled = enabled;
        cvar.notify_all();
        Ok(())
    }

    fn r#setIdleTimerEnabled(&self, display: i64, _timeout_ms: i32) -> BinderResult<()> {
        self.check_display(display)?;
        Err(service_error(EX_UNSUPPORTED))
    }

    fn r#getOverlaySupport(&self) -> BinderResult<OverlayProperties> {
        Ok(OverlayProperties::default())
    }

    fn r#getHdrConversionCapabilities(&self) -> BinderResult<Vec<HdrConversionCapability>> {
        Ok(Vec::new())
    }

    fn r#setHdrConversionStrategy(&self, _strategy: &HdrConversionStrategy) -> BinderResult<Hdr> {
        Ok(Hdr::INVALID)
    }

    fn r#setRefreshRateChangedCallbackDebugEnabled(
        &self,
        display: i64,
        _enabled: bool,
    ) -> BinderResult<()> {
        self.check_display(display)?;
        Ok(())
    }
}

struct VirtualComposer {
    clients_created: AtomicU64,
}

impl Interface for VirtualComposer {}

impl IComposer for VirtualComposer {
    fn r#createClient(&self) -> BinderResult<Strong<dyn IComposerClient>> {
        let count = self.clients_created.fetch_add(1, Ordering::AcqRel) + 1;
        println!("virtual_composer_create_client count={count}");
        Ok(BnComposerClient::new_binder(VirtualComposerClient::new()))
    }

    fn r#getCapabilities(&self) -> BinderResult<Vec<Capability>> {
        Ok(Vec::new())
    }
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    match args.as_slice() {
        [_, mode, device, context] if mode == "serve" => {
            ssal_binder_service::init(device.parse()?, context)?;
        }
        [_, mode, device, hwbinder, context] if mode == "serve" => {
            let hw = if hwbinder == "none" {
                None
            } else {
                Some(hwbinder.parse()?)
            };
            ssal_binder_service::init_with_hwbinder(device.parse()?, hw, context)?;
        }
        _ => {
            return Err("usage: ssal-virtual-composer serve <binder_rdev> [hwbinder_rdev|none] <context>".into());
        }
    }
    let service = BnComposer::new_binder(VirtualComposer {
        clients_created: AtomicU64::new(0),
    });
    ssal_binder_service::register(HAL_SERVICE, service)?;
    ssal_binder_service::join()
}
