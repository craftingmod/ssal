use crate::{Args, ProbeKind};
use rsbinder::hub::android_16::IServiceManager;
use rsbinder::{hub, ProcessState, INTERFACE_TRANSACTION};
use serde_json::{json, Value};
use std::ffi::{c_char, CStr};
use std::fs::{self, Metadata, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::Path;
use std::process::Command;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

const BINDER_VERSION_IOCTL: libc::c_int = 0xc004_6209u32 as libc::c_int;
const EXPECTED_BINDER_PROTOCOL: i32 = 8;
const BIONIC_PROP_VALUE_MAX: usize = 92;

extern "C" {
    fn __system_property_get(name: *const c_char, value: *mut c_char) -> libc::c_int;
}

#[repr(C)]
struct BinderVersion {
    protocol_version: libc::c_int,
}

const _: () = assert!(std::mem::size_of::<BinderVersion>() == 4);

struct Failure {
    stage: &'static str,
    code: String,
    detail: String,
}

pub(super) fn initialize_private_properties(path: &Path) -> std::io::Result<String> {
    // Test B sets umask 0000; rsproperties rejects group- or world-writable area files.
    unsafe { libc::umask(0o022) };
    let build = fs::read_to_string("/system/build.prop")?;
    let sdk = build
        .lines()
        .find_map(|line| {
            line.strip_prefix("ro.build.version.sdk=")
                .or_else(|| line.strip_prefix("ro.system.build.version.sdk="))
        })
        .ok_or_else(|| std::io::Error::other("Guest /system/build.prop has no SDK value"))?;
    if sdk != "36" {
        return Err(std::io::Error::other(format!(
            "Guest /system/build.prop SDK is {sdk}, expected 36"
        )));
    }

    fs::create_dir(path)?;
    set_label(path, "u:object_r:properties_device:s0")?;
    let seeds = [
        ("ro.build.version.sdk", sdk),
        ("servicemanager.ready", "true"),
        ("ro.product.cpu.abilist64", "arm64-v8a"),
        ("ro.build.version.codename", "REL"),
        ("dalvik.vm.dex2oat64.enabled", "true"),
        ("ro.zygote.disable_gl_preload", "1"),
    ];
    let entries = seeds
        .iter()
        .map(|(name, _)| {
            rsproperties::PropertyInfoEntry::new(
                (*name).to_owned(),
                "u:object_r:build_prop:s0".to_owned(),
                "string",
                true,
            )
            .map_err(std::io::Error::other)
        })
        .collect::<std::io::Result<Vec<_>>>()?;
    let property_info = path.join("property_info");
    fs::write(
        &property_info,
        rsproperties::build_trie(&entries, "u:object_r:default_prop:s0", "string")
            .map_err(std::io::Error::other)?,
    )?;
    set_label(&property_info, "u:object_r:property_info:s0")?;

    let mut properties =
        rsproperties::SystemProperties::new_area(path).map_err(std::io::Error::other)?;
    for (name, value) in seeds {
        properties.add(name, value).map_err(std::io::Error::other)?;
    }
    drop(properties);
    rsproperties::try_init(rsproperties::PropertyConfig::with_properties_dir(
        path.to_path_buf(),
    ))
    .map_err(std::io::Error::other)?;
    let observed =
        rsproperties::get::<String>("ro.build.version.sdk").map_err(std::io::Error::other)?;
    if observed != sdk {
        return Err(std::io::Error::other(format!(
            "rsproperties read {observed}, Guest build.prop says {sdk}"
        )));
    }
    Ok(json!({
        "event":"private_property_area_initialized",
        "sdk_source":"Guest /system/build.prop",
        "guest_sdk":sdk,
        "rsproperties_sdk":observed,
        "property_area":path.display().to_string(),
        "property_info_context":"u:object_r:property_info:s0",
        "property_value_context":"u:object_r:build_prop:s0",
    })
    .to_string())
}

fn set_label(path: &Path, label: &str) -> std::io::Result<()> {
    let path =
        std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(std::io::Error::other)?;
    let label = std::ffi::CString::new(label).map_err(std::io::Error::other)?;
    if unsafe {
        libc::setxattr(
            path.as_ptr(),
            c"security.selinux".as_ptr(),
            label.as_ptr().cast(),
            label.as_bytes().len(),
            0,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

impl Failure {
    fn io(stage: &'static str, error: std::io::Error) -> Self {
        Self {
            stage,
            code: format!("errno={:?}", error.raw_os_error()),
            detail: error.to_string(),
        }
    }

    fn status(stage: &'static str, code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            stage,
            code: code.into(),
            detail: detail.into(),
        }
    }

    fn binder(stage: &'static str, error: impl std::fmt::Debug + std::fmt::Display) -> Self {
        Self {
            stage,
            code: format!("{error:?}"),
            detail: error.to_string(),
        }
    }
}

pub(super) fn run(kind: ProbeKind, args: Args) {
    let start = Instant::now();
    let timestamp_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or_default();
    let pid = unsafe { libc::getpid() };
    let mut record = json!({
        "event": "rsbinder_probe_result",
        "probe_kind": kind.name(),
        "run_id": format!("{timestamp_unix_ms}-{pid}"),
        "timestamp_unix_ms": timestamp_unix_ms,
        "device_model": property("ro.product.model"),
        "android_release": property("ro.build.version.release"),
        "build_fingerprint_redacted": property("ro.build.fingerprint").map(redact_fingerprint),
        "probe_version": env!("CARGO_PKG_VERSION"),
        "rsbinder_version": "0.12.0",
        "abi": std::env::consts::ARCH,
        "pid": pid,
        "uid": unsafe { libc::getuid() },
        "gid": unsafe { libc::getgid() },
        "selinux_context": read_trimmed("/proc/self/attr/current"),
        "mount_ns": fs::read_link("/proc/self/ns/mnt").ok().map(|path| path.display().to_string()),
        "requested_binder_path": args.device,
        "observed_device_identity": Value::Null,
        "process_state_fd": Value::Null,
        "binder_protocol": Value::Null,
        "service_name": args.service,
        "expected_descriptor": args.expected_descriptor,
        "lookup_result": "not_run",
        "descriptor_result": "not_run",
        "descriptor": Value::Null,
        "property_diagnostics": {
            "getprop_sdk": Value::Null,
            "bionic_system_property_get": Value::Null,
            "rsproperties_sdk": Value::Null,
            "rsbinder_get_android_sdk_version": Value::Null,
            "process_state_context_object_result": Value::Null,
        },
        "stage_results": {
            "binder_device_initialization": "not_run",
            "handle0_acquisition": "not_run",
            "sdk_detection": "not_run",
            "servicemanager_proxy_construction": "not_run",
            "service_lookup": "not_run",
            "interface_descriptor_transaction": "not_run",
            "binder_device_identity_check": "not_run",
        },
        "error_stage": Value::Null,
        "error_code": Value::Null,
        "error_detail": Value::Null,
        "errno_or_status": Value::Null,
        "avc_excerpt": Value::Null,
        "host_state_before": Value::Null,
        "host_state_after": Value::Null,
    });

    let result = probe(kind, &args, &mut record);
    record["elapsed_ms"] = json!(start.elapsed().as_millis());
    record["ok"] = json!(result.is_ok());
    if let Err(failure) = result {
        record["error_stage"] = json!(failure.stage);
        record["error_code"] = json!(failure.code);
        record["error_detail"] = json!(failure.detail);
        record["errno_or_status"] = json!(failure.code);
    }
    println!("{record}");
    if record["ok"] != true {
        std::process::exit(1);
    }
}

fn probe(kind: ProbeKind, args: &Args, record: &mut Value) -> Result<(), Failure> {
    let link_metadata =
        fs::symlink_metadata(&args.device).map_err(|error| Failure::io("device_open", error))?;
    let target_metadata =
        fs::metadata(&args.device).map_err(|error| Failure::io("device_open", error))?;
    if !target_metadata.file_type().is_char_device() {
        return Err(Failure::status(
            "device_open",
            "not_character_device",
            "requested path does not resolve to a character device",
        ));
    }
    let before = device_identity(&target_metadata);
    record["observed_device_identity"] = json!({
        "link": if link_metadata.file_type().is_symlink() {
            fs::read_link(&args.device).ok().map(|path| path.display().to_string())
        } else {
            None
        },
        "target": before,
    });
    if kind == ProbeKind::Host {
        record["host_state_before"] = json!({"binder_device": before});
    }

    let device = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&args.device)
        .map_err(|error| Failure::io("device_open", error))?;
    let mut version = BinderVersion {
        protocol_version: 0,
    };
    // Linux binder UAPI: _IOWR('b', 9, struct binder_version).
    if unsafe {
        libc::ioctl(
            device.as_raw_fd(),
            BINDER_VERSION_IOCTL,
            &mut version as *mut BinderVersion,
        )
    } < 0
    {
        return Err(Failure::io(
            "binder_version",
            std::io::Error::last_os_error(),
        ));
    }
    record["binder_protocol"] = json!(version.protocol_version);
    drop(device);
    if version.protocol_version != EXPECTED_BINDER_PROTOCOL {
        return Err(Failure::status(
            "binder_version",
            "protocol_mismatch",
            format!(
                "observed {}, rsbinder 0.12.0 expects {}",
                version.protocol_version, EXPECTED_BINDER_PROTOCOL
            ),
        ));
    }

    ProcessState::init(&args.device, 0)
        .map_err(|error| Failure::binder("binder_device_initialization", error))?;
    let driver = ProcessState::as_self().driver();
    let driver_metadata = driver
        .metadata()
        .map_err(|error| Failure::io("binder_device_initialization", error))?;
    let fd = driver.as_raw_fd();
    let fd_identity = device_identity(&driver_metadata);
    if !same_device(&target_metadata, &driver_metadata) {
        return Err(Failure::status(
            "binder_device_initialization",
            "device_identity_mismatch",
            "rsbinder driver FD identity differs from the explicitly requested path",
        ));
    }
    record["process_state_fd"] = json!({
        "fd": fd,
        "link": fs::read_link(format!("/proc/self/fd/{fd}"))
            .ok()
            .map(|path| path.display().to_string()),
        "identity": fd_identity,
    });
    record["stage_results"]["binder_device_initialization"] = json!("passed");

    let context = ProcessState::as_self().context_object();
    record["stage_results"]["handle0_acquisition"] =
        json!(if context.is_ok() { "passed" } else { "failed" });
    record["property_diagnostics"]["process_state_context_object_result"] = match &context {
        Ok(_) => json!({"status":"passed"}),
        Err(error) => {
            json!({"status":"failed","error_code":format!("{error:?}"),"error_detail":error.to_string()})
        }
    };

    let getprop_sdk = property("ro.build.version.sdk");
    let bionic_sdk = bionic_property(c"ro.build.version.sdk");
    let rsproperties_sdk = rsproperties::get::<String>("ro.build.version.sdk");
    let rsbinder_sdk = rsbinder::get_android_sdk_version();
    let bionic_value = bionic_sdk["value"].as_str().map(str::to_owned);
    let rsproperties_value = rsproperties_sdk.as_ref().ok().cloned();
    record["property_diagnostics"]["getprop_sdk"] = json!(getprop_sdk.clone());
    record["property_diagnostics"]["bionic_system_property_get"] = bionic_sdk;
    record["property_diagnostics"]["rsproperties_sdk"] = match &rsproperties_sdk {
        Ok(value) => json!({"status":"ok","value":value}),
        Err(error) => json!({"status":"error","error":error.to_string()}),
    };
    record["property_diagnostics"]["rsbinder_get_android_sdk_version"] = json!(rsbinder_sdk);

    // Keep handle 0 alive so hub::default reuses this cached proxy.
    let _context = context.map_err(|error| Failure::binder("handle0_acquisition", error))?;
    let sdk_text = rsbinder_sdk.to_string();
    let sdk_matches = rsbinder_sdk > 0
        && getprop_sdk.as_deref() == Some(sdk_text.as_str())
        && bionic_value.as_deref() == Some(sdk_text.as_str())
        && rsproperties_value.as_deref() == Some(sdk_text.as_str())
        && (kind != ProbeKind::Guest || rsbinder_sdk == 36);
    if !sdk_matches {
        record["stage_results"]["sdk_detection"] = json!("failed");
        return Err(Failure::status(
            "sdk_detection",
            "sdk_mismatch",
            format!(
                "getprop={getprop_sdk:?}, Bionic={bionic_value:?}, rsproperties={rsproperties_value:?}, rsbinder={rsbinder_sdk}; Guest requires SDK 36"
            ),
        ));
    }
    record["stage_results"]["sdk_detection"] = json!("passed");

    let manager = match hub::default() {
        Ok(manager) => manager,
        Err(error) => {
            record["stage_results"]["servicemanager_proxy_construction"] = json!("failed");
            return Err(Failure::binder("servicemanager_proxy_construction", error));
        }
    };
    if !matches!(&*manager, hub::ServiceManager::Android16(_)) {
        record["stage_results"]["servicemanager_proxy_construction"] = json!("failed");
        return Err(Failure::status(
            "servicemanager_proxy_construction",
            "unexpected_variant",
            "runtime ServiceManager variant was not Android 16",
        ));
    }
    record["stage_results"]["servicemanager_proxy_construction"] = json!("passed");

    let hub::ServiceManager::Android16(service_manager) = &*manager;
    let service = match service_manager.checkService2(&args.service) {
        Ok(service) => service,
        Err(error) => {
            record["stage_results"]["service_lookup"] = json!("failed");
            return Err(Failure::binder("service_lookup", error));
        }
    };
    let binder = match service {
        hub::android_16::android::os::Service::Service::ServiceWithMetadata(service) => {
            match service.service {
                Some(binder) => binder,
                None => {
                    record["lookup_result"] = json!("not_found");
                    record["stage_results"]["service_lookup"] = json!("failed");
                    return Err(Failure::status(
                        "service_lookup",
                        "not_found",
                        "checkService2 returned a ServiceWithMetadata without a Binder",
                    ));
                }
            }
        }
        hub::android_16::android::os::Service::Service::Accessor(_) => {
            record["stage_results"]["service_lookup"] = json!("failed");
            return Err(Failure::status(
                "service_lookup",
                "unexpected_accessor",
                "checkService2 returned an Accessor instead of the registered test Binder",
            ));
        }
    };
    record["lookup_result"] = json!("found");
    record["stage_results"]["service_lookup"] = json!("passed");

    let remote = match binder.as_remote() {
        Some(remote) => remote,
        None => {
            record["stage_results"]["interface_descriptor_transaction"] = json!("failed");
            return Err(Failure::status(
                "interface_descriptor",
                "not_remote_proxy",
                "ServiceManager returned a Binder that is not an rsbinder remote proxy",
            ));
        }
    };
    let request = match remote.prepare_transact(false) {
        Ok(request) => request,
        Err(error) => {
            record["stage_results"]["interface_descriptor_transaction"] = json!("failed");
            return Err(Failure::binder("interface_descriptor", error));
        }
    };
    let mut reply = match remote.submit_transact(INTERFACE_TRANSACTION, &request, 0) {
        Ok(Some(reply)) => reply,
        Ok(None) => {
            record["stage_results"]["interface_descriptor_transaction"] = json!("failed");
            return Err(Failure::status(
                "interface_descriptor",
                "missing_reply",
                "INTERFACE_TRANSACTION returned no reply Parcel",
            ));
        }
        Err(error) => {
            record["stage_results"]["interface_descriptor_transaction"] = json!("failed");
            return Err(Failure::binder("interface_descriptor", error));
        }
    };
    let descriptor = match reply.read::<String>() {
        Ok(descriptor) => descriptor,
        Err(error) => {
            record["interface_descriptor_transaction_result"] = json!("failed");
            return Err(Failure::binder("interface_descriptor", error));
        }
    };
    record["descriptor"] = json!(descriptor);
    if descriptor != args.expected_descriptor {
        record["descriptor_result"] = json!("mismatch");
        record["stage_results"]["interface_descriptor_transaction"] = json!("failed");
        return Err(Failure::status(
            "interface_descriptor",
            "descriptor_mismatch",
            format!(
                "expected {:?}, observed {:?}",
                args.expected_descriptor, descriptor
            ),
        ));
    }
    record["descriptor_result"] = json!("matched");
    record["stage_results"]["interface_descriptor_transaction"] = json!("passed");

    let after = fs::metadata(&args.device)
        .map_err(|error| Failure::io("binder_device_identity_check", error))?;
    if !same_device(&target_metadata, &after) || !same_device(&after, &driver_metadata) {
        return Err(Failure::status(
            "binder_device_identity_check",
            "identity_changed",
            "requested path or rsbinder FD identity changed during the probe",
        ));
    }
    record["stage_results"]["binder_device_identity_check"] = json!("passed");
    if kind == ProbeKind::Host {
        record["host_state_after"] = json!({"binder_device": device_identity(&after)});
    }
    Ok(())
}

fn bionic_property(name: &CStr) -> Value {
    let mut value = [0 as c_char; BIONIC_PROP_VALUE_MAX];
    let length = unsafe { __system_property_get(name.as_ptr(), value.as_mut_ptr()) };
    let value = (length > 0).then(|| unsafe { CStr::from_ptr(value.as_ptr()) }.to_string_lossy());
    json!({"length":length,"value":value.map(|value|value.into_owned())})
}

fn same_device(left: &Metadata, right: &Metadata) -> bool {
    left.dev() == right.dev() && left.ino() == right.ino() && left.rdev() == right.rdev()
}

fn device_identity(metadata: &Metadata) -> Value {
    json!({
        "type": if metadata.file_type().is_char_device() { "character_device" } else { "other" },
        "dev": metadata.dev(),
        "inode": metadata.ino(),
        "rdev_major": libc::major(metadata.rdev()),
        "rdev_minor": libc::minor(metadata.rdev()),
        "mode_octal": format!("{:o}", metadata.mode() & 0o7777),
    })
}

fn property(name: &str) -> Option<String> {
    let output = Command::new("/system/bin/getprop")
        .arg(name)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8(output.stdout).ok()?.trim().to_owned();
    (!value.is_empty()).then_some(value)
}

fn redact_fingerprint(value: String) -> String {
    let Some((product, rest)) = value.split_once(':') else {
        return "[redacted]".to_owned();
    };
    let release = rest.split('/').next().unwrap_or_default();
    format!("{product}:{release}/[redacted]")
}

fn read_trimmed(path: &str) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|value| value.trim().to_owned())
}
