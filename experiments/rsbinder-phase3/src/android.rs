use rsbinder::{
    hub, DeathRecipient, Interface, Parcel, ProcessState, StatusCode, Strong, WIBinder,
    INTERFACE_TRANSACTION,
};
use serde_json::json;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::sync::{mpsc, Arc};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

rsbinder::include_aidl!("phase3");
use org::ssal::phase3::{IPhase3Callback::*, IPhase3Service::*};

const SERVICE: &str = "aidl_lazy_test_1";
const DESCRIPTOR: &str = "org.ssal.phase3.IPhase3Service";

struct TestService;

impl Interface for TestService {}

impl IPhase3Service for TestService {
    fn r#add(&self, a: i32, b: i32) -> rsbinder::BinderResult<i32> {
        Ok(a + b)
    }

    fn r#echo(&self, message: &str) -> rsbinder::BinderResult<String> {
        Ok(message.to_owned())
    }

    fn r#callCallback(
        &self,
        callback: &Strong<dyn IPhase3Callback>,
        message: &str,
    ) -> rsbinder::BinderResult<String> {
        callback.r#onMessage(message)
    }
}

struct TestCallback;

impl Interface for TestCallback {}

impl IPhase3Callback for TestCallback {
    fn r#onMessage(&self, message: &str) -> rsbinder::BinderResult<String> {
        Ok(format!("callback:{message}"))
    }
}

struct Died(mpsc::Sender<()>);

impl DeathRecipient for Died {
    fn binder_died(&self, _who: &WIBinder) {
        let _ = self.0.send(());
    }
}

pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("server") => serve(),
        Some("client") => client(),
        Some("death-client") => death_client(),
        Some("check-absent") => check_absent(),
        _ => Err("usage: phase3-ipc server|client|death-client|check-absent".into()),
    }
}

fn init() -> Result<(), Box<dyn std::error::Error>> {
    ProcessState::init_default()?;
    ProcessState::start_thread_pool();
    Ok(())
}

fn identity() -> serde_json::Value {
    let binder_fds: Vec<_> = std::fs::read_dir("/proc/self/fd")
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| {
            let target = std::fs::read_link(entry.path()).ok()?;
            let metadata = std::fs::metadata(entry.path()).ok()?;
            metadata.file_type().is_char_device().then(|| {
                json!({
                    "fd":entry.file_name().to_string_lossy(),
                    "path":target.display().to_string(),
                    "major":libc::major(metadata.rdev()),
                    "minor":libc::minor(metadata.rdev()),
                    "rdev":metadata.rdev(),
                })
            })
        })
        .collect();
    json!({
        "pid":unsafe { libc::getpid() },
        "uid":unsafe { libc::getuid() },
        "selinux":std::fs::read_to_string("/proc/self/attr/current").ok().map(|s| s.trim().to_owned()),
        "mount_namespace":std::fs::read_link("/proc/self/ns/mnt").ok().map(|p| p.display().to_string()),
        "binder_fds":binder_fds,
        "sdk":rsbinder::get_android_sdk_version(),
    })
}

fn serve() -> Result<(), Box<dyn std::error::Error>> {
    init()?;
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let binder = BnPhase3Service::new_binder(TestService);
    hub::add_service(SERVICE, binder)?;
    println!(
        "{}",
        json!({
            "event":"registered",
            "service":SERVICE,
            "descriptor":DESCRIPTOR,
            "identity":identity(),
        })
    );
    std::io::Write::flush(&mut std::io::stdout())?;
    ProcessState::join_thread_pool()?;
    Ok(())
}

fn service() -> Result<Strong<dyn IPhase3Service>, Box<dyn std::error::Error>> {
    let service = hub::default()?
        .check_interface::<dyn IPhase3Service>(SERVICE)
        .map_err(|error| {
            std::io::Error::other(format!("ServiceManager interface lookup: {error}"))
        })?;
    let binder = service.as_binder();
    let remote = binder
        .as_remote()
        .ok_or("service is not a remote Binder proxy")?;
    let mut reply = remote
        .submit_transact(INTERFACE_TRANSACTION, &Parcel::new(), 0)
        .map_err(|error| std::io::Error::other(format!("INTERFACE_TRANSACTION: {error}")))?
        .ok_or("INTERFACE_TRANSACTION returned no reply")?;
    let descriptor: String = reply.read().map_err(|error| {
        std::io::Error::other(format!("INTERFACE_TRANSACTION reply decode: {error}"))
    })?;
    if descriptor != DESCRIPTOR {
        return Err(format!("descriptor mismatch: {descriptor}").into());
    }
    Ok(service)
}

fn client() -> Result<(), Box<dyn std::error::Error>> {
    init()?;
    let manager = hub::default()?;
    let missing = format!(
        "ssal.phase3.missing.{}.{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
    );
    if manager.check_service(&missing).is_some() {
        return Err("unique unavailable service unexpectedly exists".into());
    }
    match manager.check_interface::<dyn IPhase3Service>(&missing) {
        Err(StatusCode::NameNotFound) => {}
        Err(error) => return Err(format!("unexpected unavailable-service error: {error}").into()),
        Ok(_) => return Err("lookup of unavailable service unexpectedly succeeded".into()),
    }
    let service = service()?;
    let add = service
        .r#add(17, 25)
        .map_err(|error| std::io::Error::other(format!("AIDL add transaction: {error}")))?;
    let echo = service
        .r#echo("ssal-phase3")
        .map_err(|error| std::io::Error::other(format!("AIDL echo transaction: {error}")))?;
    let callback = BnPhase3Callback::new_binder(TestCallback);
    let mut callback_results = Vec::new();
    for (index, message) in ["ssal-phase3", "ssal-phase3-repeat"].iter().enumerate() {
        let result = service
            .r#callCallback(&callback, message)
            .map_err(|error| {
                std::io::Error::other(format!("AIDL callback transaction #{index}: {error}"))
            })?;
        if result != format!("callback:{message}") {
            return Err(format!("unexpected callback response: {result:?}").into());
        }
        callback_results.push(json!({"message":message,"result":result}));
    }
    if add != 42 || echo != "ssal-phase3" {
        return Err(format!("unexpected IPC response: add={add}, echo={echo:?}").into());
    }
    println!(
        "{}",
        json!({
            "event":"ipc_passed",
            "service":SERVICE,
            "descriptor":DESCRIPTOR,
            "add":{"args":[17,25],"result":add},
            "echo":echo,
            "callback":{"binder_object_transferred":true,"invocations":callback_results},
            "callback_lifetime":"same Strong reference retained across two synchronous transactions",
            "unavailable_service":{"check_service_absent":true,"get_interface_failed":true},
            "identity":identity(),
        })
    );
    Ok(())
}

fn death_client() -> Result<(), Box<dyn std::error::Error>> {
    init()?;
    let manager = hub::default()?;
    let service = service()?;
    let (sender, receiver) = mpsc::channel();
    let recipient = Arc::new(Died(sender));
    let recipient_trait: Arc<dyn DeathRecipient> = recipient.clone();
    service
        .as_binder()
        .link_to_death(Arc::downgrade(&recipient_trait))?;
    println!(
        "{}",
        json!({"event":"death_linked","pid":unsafe { libc::getpid() }})
    );
    std::io::Write::flush(&mut std::io::stdout())?;
    receiver.recv_timeout(Duration::from_secs(15))?;
    let stale_reference_error = match service.r#echo("after-server-death") {
        Err(error) => error.to_string(),
        Ok(response) => {
            return Err(format!("dead Binder reference still returned {response:?}").into())
        }
    };
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    let absent_after_death = loop {
        if manager.check_service(SERVICE).is_none() {
            break true;
        }
        if std::time::Instant::now() >= deadline {
            break false;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    if !absent_after_death {
        return Err("dead service remained discoverable".into());
    }
    println!(
        "{}",
        json!({"event":"death_observed","service_absent":absent_after_death,"stale_reference":{"failed_as_expected":true,"error":stale_reference_error},"identity":identity()})
    );
    Ok(())
}

fn check_absent() -> Result<(), Box<dyn std::error::Error>> {
    init()?;
    let manager = hub::default()?;
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while manager.check_service(SERVICE).is_some() {
        if std::time::Instant::now() >= deadline {
            return Err("Guest service remained registered after server death".into());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    println!(
        "{}",
        json!({"event":"service_absent","service":SERVICE,"identity":identity()})
    );
    Ok(())
}
