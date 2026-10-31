//! Opt-in pre-framework probe. Never connects to ssald or starts Android services.
use crate::guest_lock_compat::{Config, APK_TARGET, XML, XML_TARGET};
use crate::namespace_mounts::{
    guest_path, inject_compat_file, inject_compat_file_with_hook, mount, require_private_mounts,
    Mounts,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::fs::{symlink, MetadataExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
mod diagnostics;

const FAILURES: &[&str] = &[
    "unshare",
    "private",
    "tmpfs",
    "context",
    "bind",
    "collision",
    "create",
    "after-inject",
    "abort",
    "after-ext4",
    "cleanup",
];
fn require(ok: bool, message: &str) -> io::Result<()> {
    if ok {
        Ok(())
    } else {
        Err(io::Error::other(message))
    }
}
fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn open_input(path: &Path) -> io::Result<File> {
    fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOATIME | libc::O_NOFOLLOW)
        .open(path)
}
fn ns(path: &str) -> io::Result<String> {
    Ok(fs::read_link(path)?.to_string_lossy().into_owned())
}
pub fn distinct_namespace(child: &str, host: &str) -> io::Result<()> {
    require(
        child.starts_with("mnt:[")
            && host.starts_with("mnt:[")
            && child.ends_with(']')
            && host.ends_with(']')
            && child != host,
        "mount namespace separation not proven",
    )
}
#[derive(Debug)]
struct Options {
    kind: String,
    execute: bool,
    guest: Option<PathBuf>,
    image: Option<PathBuf>,
    apk: Option<PathBuf>,
    failure: Option<String>,
    method: String,
    sysconfig_image: Option<PathBuf>,
    sysconfig_sha256: Option<String>,
}
fn options(args: &[String]) -> io::Result<Options> {
    let kind = args
        .first()
        .filter(|s| {
            matches!(
                s.as_str(),
                "lock-sysconfig"
                    | "lock-rro"
                    | "lock-mount-plain"
                    | "lock-mount-context"
                    | "lock-mount-relabel"
                    | "lock-target-plain"
                    | "lock-target-context"
            )
        })
        .ok_or_else(|| io::Error::other("expected lock-sysconfig or lock-rro"))?
        .clone();
    let mut o = Options {
        kind,
        execute: false,
        guest: None,
        image: None,
        apk: None,
        failure: None,
        method: "context-tmpfs".into(),
        sysconfig_image: None,
        sysconfig_sha256: None,
    };
    let mut ack = false;
    let mut dry = false;
    let mut seen = std::collections::BTreeSet::new();
    let mut it = args[1..].iter();
    while let Some(flag) = it.next() {
        require(seen.insert(flag.clone()), "duplicate probe option")?;
        match flag.as_str() {
            "--method" => {
                o.method = it
                    .next()
                    .ok_or_else(|| io::Error::other("missing method"))?
                    .clone();
                require(
                    ["context-tmpfs", "prelabelled-ext4"].contains(&o.method.as_str()),
                    "invalid method",
                )?;
            }
            "--sysconfig-image" => {
                o.sysconfig_image =
                    Some(PathBuf::from(it.next().ok_or_else(|| {
                        io::Error::other("missing sysconfig image")
                    })?));
            }
            "--sysconfig-sha256" => {
                o.sysconfig_sha256 = Some(
                    it.next()
                        .ok_or_else(|| io::Error::other("missing sysconfig hash"))?
                        .clone(),
                );
            }
            "--dry-run" => dry = true,
            "--execute" => o.execute = true,
            "--acknowledge-risk" => ack = true,
            "--guest-root" => {
                o.guest = Some(PathBuf::from(
                    it.next()
                        .ok_or_else(|| io::Error::other("missing guest root"))?,
                ))
            }
            "--image" => {
                o.image = Some(PathBuf::from(
                    it.next().ok_or_else(|| io::Error::other("missing image"))?,
                ))
            }
            "--apk" => {
                o.apk = Some(PathBuf::from(
                    it.next().ok_or_else(|| io::Error::other("missing APK"))?,
                ))
            }
            "--fail-at" => {
                let f = it
                    .next()
                    .ok_or_else(|| io::Error::other("missing failure stage"))?;
                require(FAILURES.contains(&f.as_str()), "unknown failure stage")?;
                o.failure = Some(f.clone());
            }
            _ => return Err(io::Error::other("unknown probe option")),
        }
    }
    require(
        !o.execute || ack && !dry,
        "execute requires --acknowledge-risk and forbids --dry-run",
    )?;
    require(!ack || o.execute, "acknowledgement requires --execute")?;
    require(
        o.guest.is_none() || o.image.is_none(),
        "choose --image or --guest-root",
    )?;
    require(
        o.method == "context-tmpfs" || o.kind == "lock-sysconfig",
        "alternative method is Sysconfig-only",
    )?;
    require(
        o.method == "prelabelled-ext4"
            || o.sysconfig_image.is_none() && o.sysconfig_sha256.is_none(),
        "alternative image flags require prelabelled-ext4",
    )?;
    Ok(o)
}
fn snapshot() -> io::Result<Value> {
    Ok(
        json!({"pid1_namespace":ns("/proc/1/ns/mnt")?, "pid1_mountinfo":fs::read_to_string("/proc/1/mountinfo")?,
        "self_namespace":ns("/proc/self/ns/mnt")?, "enforcing":fs::read_to_string("/sys/fs/selinux/enforce")?.trim(),
        "domain":fs::read_to_string("/proc/self/attr/current")?.trim_matches('\0').trim(),"loops":loop_backings()?,"host_files":[host_entry("/system/etc/sysconfig/ssal-lockscreen.xml")?,host_entry("/product/overlay/SSALWeaverOverlay.apk")?]}),
    )
}
fn host_entry(path: &str) -> io::Result<Value> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(json!({"path":path,"exists":false})),
        Err(e) => Err(e),
        Ok(m) if m.is_symlink() => Ok(json!({"path":path,"symlink":fs::read_link(path)?})),
        Ok(m) if m.is_file() => {
            let mut bytes = Vec::new();
            open_input(Path::new(path))?.read_to_end(&mut bytes)?;
            Ok(
                json!({"path":path,"sha256":digest(&bytes),"mode":m.mode(),"uid":m.uid(),"gid":m.gid()}),
            )
        }
        Ok(_) => Err(io::Error::other(
            "unexpected Host compatibility target type",
        )),
    }
}
fn loop_backings() -> io::Result<BTreeMap<String, String>> {
    let mut result = BTreeMap::new();
    for entry in fs::read_dir("/sys/block")? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.starts_with("loop") {
            continue;
        }
        match fs::read_to_string(entry.path().join("loop/backing_file")) {
            Ok(backing) => {
                result.insert(name, backing);
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => (),
            Err(e) => return Err(e),
        }
    }
    Ok(result)
}
fn namespace_references(targets: &std::collections::BTreeSet<String>) -> io::Result<Vec<String>> {
    if targets.is_empty() {
        return Ok(Vec::new());
    }
    let mut references = Vec::new();
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        if entry.file_name().to_string_lossy().parse::<u32>().is_err() {
            continue;
        }
        let mut paths = vec![entry.path().join("ns/mnt")];
        match fs::read_dir(entry.path().join("fd")) {
            Ok(fds) => {
                for fd in fds {
                    paths.push(fd?.path());
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        }
        for path in paths {
            match fs::read_link(&path) {
                Ok(link) if targets.contains(link.to_string_lossy().as_ref()) => {
                    references.push(path.to_string_lossy().into_owned())
                }
                Ok(_) => (),
                Err(e) if e.kind() == io::ErrorKind::NotFound => (),
                Err(e) => return Err(e),
            }
        }
    }
    Ok(references)
}
fn avc_since(start: f64) -> Value {
    match Command::new("/system/bin/dmesg").output() {
        Ok(output) => {
            let lines: Vec<String> = String::from_utf8_lossy(&output.stdout)
                .lines()
                .filter(|line| {
                    let timestamp = line
                        .trim_start()
                        .strip_prefix('[')
                        .and_then(|s| s.split_once(']'))
                        .and_then(|(s, _)| s.trim().parse::<f64>().ok());
                    line.contains("avc:") && timestamp.is_some_and(|t| t >= start)
                })
                .map(str::to_owned)
                .collect();
            json!({"exit_code":output.status.code(),"stderr":String::from_utf8_lossy(&output.stderr),"lines":lines,"scope":"all timestamped AVCs during probe; correlation required; dontaudit and unparseable timestamps are not covered"})
        }
        Err(e) => json!({"status":"not_run","error":e.to_string(),"errno":e.raw_os_error()}),
    }
}
fn fault(o: &Options, stage: &str) -> io::Result<()> {
    require(
        o.failure.as_deref() != Some(stage),
        &format!("injected failure: {stage}"),
    )
}
fn product_policy_gate(o: &Options) -> io::Result<()> {
    require(o.kind != "lock-rro", "RRO blocked: exact Guest PackageManager Product classification is not yet certified; CLI --policy product is insufficient")
}
// lstat each entry; never follow a symlink into the host or authentication data.
fn inventory(root: &Path) -> io::Result<BTreeMap<String, Value>> {
    fn walk(base: &Path, at: &Path, out: &mut BTreeMap<String, Value>) -> io::Result<()> {
        for item in fs::read_dir(at)? {
            let item = item?;
            let p = item.path();
            let m = fs::symlink_metadata(&p)?;
            let key = p
                .strip_prefix(base)
                .unwrap()
                .to_str()
                .ok_or_else(|| io::Error::other("non UTF8 guest name"))?
                .to_owned();
            let data = if m.is_symlink() {
                json!({"symlink":fs::read_link(&p)?})
            } else if m.is_file() {
                json!({"sha256":digest(&fs::read(&p)?),"size":m.len()})
            } else if m.is_dir() {
                json!({"directory":true})
            } else {
                return Err(io::Error::other("unexpected guest special file"));
            };
            out.insert(
                key,
                json!({"content":data,"mode":m.mode(),"uid":m.uid(),"gid":m.gid()}),
            );
            if m.is_dir() {
                walk(base, &p, out)?;
            }
        }
        Ok(())
    }
    let mut out = BTreeMap::new();
    walk(root, root, &mut out)?;
    Ok(out)
}
fn readonly(path: &Path) -> io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let p = CString::new(path.as_os_str().as_bytes())?;
    let mut st = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    if unsafe { libc::statvfs(p.as_ptr(), st.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    require(unsafe {st.assume_init()}.f_flag & libc::ST_RDONLY != 0, "guest source must already be mounted read-only; probe never mounts a host image or allocates loops")
}
fn input(o: &Options) -> io::Result<(Option<File>, Vec<u8>)> {
    if o.kind.starts_with("lock-mount-") {
        return Ok((None, XML.as_bytes().to_vec()));
    }
    let source = fs::canonicalize(
        o.image
            .as_ref()
            .or(o.guest.as_ref())
            .ok_or_else(|| io::Error::other("--image or --guest-root required"))?,
    )?;
    require(
        source.starts_with("/data/local/ssal") && source != Path::new("/data/local/ssal"),
        "guest source must be below /data/local/ssal",
    )?;
    let file = if o.image.is_some() {
        require(
            fs::metadata(&source)?.is_file(),
            "image is not a regular file",
        )?;
        let mut file = open_input(&source)?;
        let mut hasher = Sha256::new();
        let mut buffer = vec![0; 1024 * 1024];
        loop {
            let n = file.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            hasher.update(&buffer[..n]);
        }
        let hash: String = hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        require(
            hash == "7b9ba62e8b48b6e40432be949ae0858a8971175c79502550e74691222d3889ff",
            "image differs from v3 baseline",
        )?;
        file
    } else {
        readonly(&source)?;
        require(
            fs::read_to_string(guest_path(&source, "system/build.prop")?)?.contains("lineage"),
            "not a Lineage guest root",
        )?;
        require(
            fs::read_link(source.join("product"))? == Path::new("/system/product"),
            "unsupported product root symlink",
        )?;
        open_input(&source)?
    };
    let bytes = if o.kind == "lock-rro" {
        let p = fs::canonicalize(
            o.apk
                .as_ref()
                .ok_or_else(|| io::Error::other("--apk required"))?,
        )?;
        require(p.starts_with("/data/local/ssal"), "APK outside SSAL inputs")?;
        let mut b = Vec::new();
        open_input(&p)?.read_to_end(&mut b)?;
        require(
            digest(&b) == "31968b1433f6a9a53a0a89a2abdab67a026a075ea5f345956de9bbddd6599f51",
            "APK differs from v3 signed artifact",
        )?;
        b
    } else {
        XML.as_bytes().to_vec()
    };
    if o.method == "prelabelled-ext4" {
        diagnostics::ext4_input(o)?;
    }
    Ok((Some(file), bytes))
}
// LOOP_CONFIGURE atomically installs READ_ONLY|AUTOCLEAR. No partial setup
// window and no device node is created on a persistent Host filesystem.
#[repr(C)]
struct LoopInfo {
    device: u64,
    inode: u64,
    rdevice: u64,
    offset: u64,
    sizelimit: u64,
    number: u32,
    encryption: u32,
    key_size: u32,
    flags: u32,
    filename: [u8; 64],
    cryptname: [u8; 64],
    key: [u8; 32],
    init: [u64; 2],
}
impl Default for LoopInfo {
    fn default() -> Self {
        // All fields are integers or byte arrays; zero is a valid empty ABI value.
        unsafe { std::mem::zeroed() }
    }
}
#[repr(C)]
struct LoopConfig {
    fd: u32,
    block_size: u32,
    info: LoopInfo,
    reserved: [u64; 8],
}
fn image_root(mounts: &mut Mounts, file: &File, evidence: &mut Value) -> io::Result<PathBuf> {
    let root = readonly_image(mounts, file, evidence, "gsi")?;
    require(
        fs::read_link(root.join("product"))? == Path::new("/system/product"),
        "unsupported image Product symlink",
    )?;
    Ok(root)
}
fn readonly_image(
    mounts: &mut Mounts,
    file: &File,
    evidence: &mut Value,
    slot: &str,
) -> io::Result<PathBuf> {
    evidence["operation"] = json!("read_only_autoclear_loop_setup");
    use std::ffi::CString;
    use std::fs::OpenOptions;
    // GET_FREE may create a global loop object. Only reuse an existing unused
    // object; atomic LOOP_CONFIGURE still rejects a concurrent allocation.
    let mut number = None;
    for entry in fs::read_dir("/sys/block")? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(candidate) = name
            .strip_prefix("loop")
            .and_then(|n| n.parse::<u32>().ok())
        else {
            continue;
        };
        match fs::metadata(entry.path().join("loop/backing_file")) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                number = Some(candidate);
                break;
            }
            Err(e) => return Err(e),
            Ok(_) => (),
        }
    }
    let number = number.ok_or_else(|| {
        io::Error::other("no existing unused loop; global loop creation forbidden")
    })?;
    let device_number = crate::namespace_mounts::parse_device_number(&fs::read_to_string(
        format!("/sys/block/loop{number}/dev"),
    )?)?;
    evidence["loop_candidate"] = json!(number);
    evidence["loop_device_number"] = json!(format!(
        "{}:{}",
        libc::major(device_number),
        libc::minor(device_number)
    ));
    let devices = PathBuf::from(format!("/mnt/loopdev-{slot}"));
    fs::create_dir(&devices)?;
    mounts.attach(
        Path::new("tmpfs"),
        &devices,
        Some("tmpfs"),
        libc::MS_NOSUID | libc::MS_NOEXEC,
        "mode=700",
    )?;
    let node = devices.join("image");
    let node_c = CString::new(node.to_str().unwrap())?;
    if unsafe { libc::mknod(node_c.as_ptr(), libc::S_IFBLK | 0o600, device_number) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let device = OpenOptions::new().read(true).open(&node)?;
    let config = LoopConfig {
        fd: file.as_raw_fd() as u32,
        block_size: 0,
        info: LoopInfo {
            flags: 1 | 4,
            ..LoopInfo::default()
        },
        reserved: [0; 8],
    };
    if unsafe { libc::ioctl(device.as_raw_fd(), 0x4c0a, &config) } != 0 {
        return Err(io::Error::last_os_error());
    }
    evidence["loop_number"] = json!(number);
    if !evidence["loops_used"].is_array() {
        evidence["loops_used"] = json!([]);
    }
    evidence["loops_used"]
        .as_array_mut()
        .unwrap()
        .push(json!({"number":number,"slot":slot}));
    evidence["loop_cleanup"] = json!("pending");
    mounts.loops.push(device);
    let root = PathBuf::from(format!("/mnt/image-{slot}"));
    fs::create_dir(&root)?;
    mounts.attach(
        &node,
        &root,
        Some("ext4"),
        libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
        "noload",
    )?;
    Ok(root)
}
fn child(o: &Options) -> Value {
    let mut evidence = json!({"status":"failed", "runtime_resource_value_verified":"not_run", "framework_validated":"not_run", "loop_cleanup":"not_applicable", "avc":"not_collected", "failure_injection":o.failure});
    let mut mounts = Mounts::new();
    let result = (|| -> io::Result<()> {
        require(o.execute, "child requires explicit execute acknowledgement")?;
        product_policy_gate(o)?;
        require(
            fs::read_to_string("/sys/fs/selinux/enforce")?.trim() == "1",
            "SELinux must remain Enforcing",
        )?;
        let (source, bytes) = input(o)?;
        evidence["input_sha256"] = json!(digest(&bytes));
        let host = ns("/proc/1/ns/mnt")?;
        evidence["operation"] = json!("unshare");
        fault(o, "unshare")?;
        if unsafe { libc::unshare(libc::CLONE_NEWNS) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let own = ns("/proc/self/ns/mnt")?;
        distinct_namespace(&own, &host)?;
        evidence["namespace"] = json!(own);
        evidence["operation"] = json!("private");
        fault(o, "private")?;
        mount(
            Path::new("none"),
            Path::new("/"),
            None,
            libc::MS_REC | libc::MS_PRIVATE,
            "",
        )?;
        let private_mountinfo = fs::read_to_string("/proc/self/mountinfo")?;
        require_private_mounts(&private_mountinfo)?;
        evidence["mountinfo_before_scratch"] = json!(private_mountinfo);
        evidence["private_propagation"] = json!("passed");
        // /mnt already exists: all scratch directories and device nodes stay here.
        require(
            fs::symlink_metadata("/mnt")?.is_dir(),
            "scratch mountpoint is not a real directory",
        )?;
        evidence["operation"] = json!("tmpfs");
        fault(o, "tmpfs")?;
        mounts.tmpfs(Path::new("/mnt"), 0o700)?;
        if o.kind.starts_with("lock-mount-") {
            return diagnostics::scratch(o, &mut mounts, &mut evidence);
        }
        let source = source.ok_or_else(|| io::Error::other("missing source file"))?;
        let source_root = if o.image.is_some() {
            image_root(&mut mounts, &source, &mut evidence)?
        } else {
            PathBuf::from(format!("/proc/self/fd/{}", source.as_raw_fd()))
        };
        let root = Path::new("/mnt/ssal-lock-probe");
        fs::create_dir(root)?;
        fs::create_dir(root.join("system"))?;
        mounts.bind(
            &guest_path(&source_root, "system")?,
            &root.join("system"),
            true,
            false,
        )?;
        symlink("/system/product", root.join("product"))?;
        let rro = o.kind == "lock-rro";
        let config = Config {
            enabled: true,
            disable_secure_lockscreen: !rro,
            disable_weaver_on_unsecured_users: rro,
            ..Default::default()
        };
        let entry = config.plan(true, true)?.remove(0);
        let target = Path::new(entry.target);
        let dir = guest_path(root, target.parent().unwrap().to_str().unwrap())?;
        evidence["resolved_directory"] = json!(dir);
        let before = inventory(&dir)?;
        if o.kind.starts_with("lock-target-") {
            return diagnostics::target(o, &mut mounts, &dir, &mut evidence);
        }
        if rro {
            require(
                before.keys().filter(|k| k.ends_with(".apk")).count() == 494,
                "expected all 494 existing Product overlays",
            )?;
            // An unknown config can exclude the APK or make it mutable. Do not
            // accept a CLI boolean as evidence of Product/OverlayConfig policy.
            require(
                !dir.join("config").exists() && !dir.join("partition_order.xml").exists(),
                "Product overlay config requires separate analysis",
            )?;
        }
        // Faults are before their named syscall and do not alter Host policy.
        if o.method == "prelabelled-ext4" {
            diagnostics::inject_ext4(o, &mut mounts, &dir, &mut evidence)?;
        } else {
            inject_compat_file_with_hook(&mut mounts, root, &entry, &bytes, |stage| {
                evidence["operation"] = json!(stage);
                fault(o, stage)
            })?;
        }
        if o.failure.as_deref() == Some("collision") {
            let error = inject_compat_file(&mut mounts, root, &entry, &bytes).unwrap_err();
            require(
                error.to_string() == "compatibility target collision",
                "wrong duplicate injection failure",
            )?;
            return Err(error);
        }
        let destination = guest_path(root, if rro { APK_TARGET } else { XML_TARGET })?;
        let actual = fs::read(&destination)?;
        require(actual == bytes, "injected bytes mismatch")?;
        let mut after = inventory(&dir)?;
        after.remove(target.file_name().unwrap().to_str().unwrap());
        require(before == after, "original files/symlinks/DAC changed")?;
        let m = fs::metadata(&destination)?;
        require(
            m.mode() & 0o7777 == 0o644 && m.uid() == 0 && m.gid() == 0,
            "injected DAC mismatch",
        )?;
        evidence["file"] = json!({"sha256":digest(&actual),"mode":m.mode(),"uid":m.uid(),"gid":m.gid(),"context":crate::unix::image_context(&File::open(destination)?)?,"existing_entries":before.len(),"preservation":"passed","open_read":"passed"});
        evidence["mountinfo"] = json!(fs::read_to_string("/proc/self/mountinfo")?);
        fault(o, "after-inject")?;
        if o.failure.as_deref() == Some("abort") {
            unsafe { libc::_exit(86) };
        }
        Ok(())
    })();
    // Deliberately hold the scratch mount busy for the approved cleanup-error
    // test. The child must report failure; its private namespace is reclaimed
    // on exit and the parent verifies that reclamation independently.
    let cleanup_busy = if o.failure.as_deref() == Some("cleanup") {
        File::open("/mnt").ok()
    } else {
        None
    };
    mounts.loops.clear();
    let cleanup = mounts.cleanup();
    drop(cleanup_busy);
    evidence["cleanup"] = json!({"status":if cleanup.is_ok(){"passed"}else{"failed"},"error":cleanup.err().map(|e|e.to_string()),"mountinfo_after":fs::read_to_string("/proc/self/mountinfo").ok()});
    if evidence["mountinfo_before_scratch"].is_string()
        && evidence["mountinfo_before_scratch"] != evidence["cleanup"]["mountinfo_after"]
    {
        evidence["cleanup"]["status"] = json!("failed");
        evidence["cleanup"]["residual_mounts"] =
            json!("mountinfo differs from private pre-scratch baseline");
    }
    if let Some(number) = evidence["loop_number"].as_i64() {
        evidence["loop_cleanup"] = match loop_backings() {
            Ok(backings) if !backings.contains_key(&format!("loop{number}")) => json!("passed"),
            Ok(backings) => {
                json!({"status":"failed","residual":backings.get(&format!("loop{number}"))})
            }
            Err(e) => json!({"status":"failed","error":e.to_string()}),
        };
    }
    if let Some(loops) = evidence["loops_used"].as_array() {
        let released = loop_backings().map(|backings| {
            loops
                .iter()
                .all(|x| !backings.contains_key(&format!("loop{}", x["number"])))
        });
        if !matches!(released, Ok(true)) {
            evidence["loop_cleanup"] = json!("failed");
        }
    }
    match result {
        Ok(()) => evidence["status"] = json!("passed"),
        Err(e) => {
            evidence["error"] = json!(e.to_string());
            evidence["errno"] = json!(e.raw_os_error());
        }
    }
    if evidence["cleanup"]["status"] != "passed" {
        evidence["status"] = json!("failed");
    }
    if evidence["loop_number"].is_number() && evidence["loop_cleanup"] != "passed" {
        evidence["status"] = json!("failed");
    }
    evidence
}
/// Standalone CLI dispatch. The child entry is also gated and cannot invoke a daemon.
pub fn cli(args: &[String], internal_child: bool) -> io::Result<bool> {
    let o = options(args)?;
    if internal_child {
        // Drop all inherited non-stdio descriptors before acquiring probe inputs.
        let fds: Vec<i32> = fs::read_dir("/proc/self/fd")?
            .filter_map(|e| e.ok()?.file_name().to_str()?.parse().ok())
            .filter(|fd| *fd > 2)
            .collect();
        for fd in fds {
            unsafe { libc::close(fd) };
        }
        let parent = unsafe { libc::getppid() };
        if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) } != 0 {
            return Err(io::Error::last_os_error());
        }
        require(
            parent != 1 && unsafe { libc::getppid() } == parent,
            "probe parent disappeared",
        )?;
        unsafe {
            libc::alarm(120);
        }
        let report = child(&o);
        println!("{report}");
        return Ok(report["status"] == "passed");
    }
    if !o.execute {
        println!(
            "{}",
            json!({"status":"not_run","mode":"dry_run","kind":o.kind,"method":o.method,"sysconfig_image_sha256":o.sysconfig_sha256,"enabled_default":false,"framework_launch":"blocked","requirements":["explicit user device approval", "--execute --acknowledge-risk", "v3 baseline raw GSI for Guest targets; comparisons use namespace-local scratch", "Enforcing", "distinct namespace then recursive private propagation"],"rro_product_classification":"blocked","failure_stages":FAILURES})
        );
        return Ok(true);
    }
    let before = snapshot()?;
    require(before["enforcing"] == "1", "SELinux must be Enforcing")?;
    product_policy_gate(&o)?;
    // Validate inputs before even creating the child; no mount operations here.
    input(&o)?;
    let uptime = fs::read_to_string("/proc/uptime")?
        .split_whitespace()
        .next()
        .and_then(|s| s.parse::<f64>().ok())
        .ok_or_else(|| io::Error::other("missing monotonic timestamp"))?;
    let mut process = Command::new(std::env::current_exe()?)
        .arg("--lock-probe-child")
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let output = process.stdout.take().unwrap();
    let reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        output
            .take(8 * 1024 * 1024)
            .read_to_end(&mut bytes)
            .map(|_| bytes)
    });
    let started = Instant::now();
    let mut observed_namespaces = std::collections::BTreeSet::new();
    let status = loop {
        if let Ok(own) = ns(&format!("/proc/{}/ns/mnt", process.id())) {
            if own != before["self_namespace"].as_str().unwrap_or("")
                && own != before["pid1_namespace"].as_str().unwrap_or("")
            {
                observed_namespaces.insert(own);
            }
        }
        match process.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Ok(None) if started.elapsed() < Duration::from_secs(130) => {
                std::thread::sleep(Duration::from_millis(20))
            }
            other => {
                let _ = process.kill();
                let waited = process.wait();
                break match other {
                    Err(e) => Err(e),
                    _ => waited,
                };
            }
        }
    }?;
    let bytes = reader
        .join()
        .map_err(|_| io::Error::other("probe report reader panicked"))??;
    let child: Value = serde_json::from_slice(&bytes).unwrap_or_else(
        |_| json!({"status":"failed","error":"child terminated without complete evidence"}),
    );
    let after = snapshot()?;
    let unchanged = before["pid1_namespace"] == after["pid1_namespace"]
        && before["pid1_mountinfo"] == after["pid1_mountinfo"]
        && before["self_namespace"] == after["self_namespace"]
        && before["enforcing"] == after["enforcing"]
        && before["loops"] == after["loops"]
        && before["host_files"] == after["host_files"];
    if let Some(own) = child["namespace"].as_str() {
        observed_namespaces.insert(own.to_owned());
    }
    let references = namespace_references(&observed_namespaces);
    let released = references.as_ref().is_ok_and(|r| r.is_empty())
        && (!observed_namespaces.is_empty() || child["error"] == "injected failure: unshare");
    let passed = unchanged && released && status.success() && child["status"] == "passed";
    let avc = avc_since(uptime);
    println!(
        "{}",
        json!({"status":if passed{"passed"}else{"failed"},"kind":o.kind,"before":before,"after":after,"child":child,"child_exit_code":status.code(),"process_reaped":true,"host_namespace_mountinfo_enforcing_unchanged":unchanged,"loop_backings_unchanged":before["loops"]==after["loops"],"namespace_references":references.as_ref().ok(),"namespace_reference_error":references.as_ref().err().map(ToString::to_string),"namespace_released":released,"avc":avc,"host_authentication_files":"not_accessed","runtime_resource_value_verified":"not_run","framework_launch":"blocked","enabled":false})
    );
    Ok(passed)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn loop_config_abi_and_rro_policy_gate() {
        assert_eq!(std::mem::size_of::<LoopInfo>(), 232);
        assert_eq!(std::mem::size_of::<LoopConfig>(), 304);
        assert!(product_policy_gate(&options(&args(&["lock-rro"])).unwrap()).is_err());
        assert!(product_policy_gate(&options(&args(&["lock-sysconfig"])).unwrap()).is_ok());
    }
    #[test]
    fn rro_duplicate_is_rejected_before_any_mount() -> io::Result<()> {
        let root = std::env::temp_dir().join(format!("ssal-rro-duplicate-{}", std::process::id()));
        let directory = root.join("system/product/overlay");
        fs::create_dir_all(&directory)?;
        symlink("/system/product", root.join("product"))?;
        let config = Config {
            enabled: true,
            disable_secure_lockscreen: false,
            ..Default::default()
        };
        let entry = config.plan(true, true)?.remove(0);
        let path = directory.join("SSALWeaverOverlay.apk");
        fs::write(&path, b"preserve")?;
        let mut mounts = Mounts::new();
        for _ in 0..2 {
            assert_eq!(
                inject_compat_file(&mut mounts, &root, &entry, b"replace")
                    .unwrap_err()
                    .to_string(),
                "compatibility target collision"
            );
            assert_eq!(fs::read(&path)?, b"preserve");
            assert!(mounts.paths.is_empty());
        }
        mounts.cleanup()?;
        fs::remove_dir_all(root)?;
        Ok(())
    }
    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }
    #[test]
    fn namespace_must_differ() {
        assert!(distinct_namespace("mnt:[2]", "mnt:[1]").is_ok());
        for (a, b) in [("mnt:[1]", "mnt:[1]"), ("", ""), ("unknown", "mnt:[1]")] {
            assert!(distinct_namespace(a, b).is_err());
        }
    }
    #[test]
    fn explicit_execution_only() {
        assert!(!options(&args(&["lock-sysconfig"])).unwrap().execute);
        for a in [
            vec!["lock-sysconfig", "--execute"],
            vec!["lock-rro", "--execute", "--acknowledge-risk", "--dry-run"],
            vec!["lock-rro", "--acknowledge-risk"],
            vec!["lock-rro", "--fail-at", "typo"],
        ] {
            assert!(options(&args(&a)).is_err());
        }
        assert!(
            options(&args(&["lock-rro", "--execute", "--acknowledge-risk"]))
                .unwrap()
                .execute
        );
    }
    #[test]
    fn failure_stages_fail_closed() {
        for stage in FAILURES {
            let o = options(&args(&["lock-sysconfig", "--fail-at", stage])).unwrap();
            assert!(fault(&o, stage).is_err());
        }
    }
    #[test]
    fn inventory_preserves_symlinks_without_following() -> io::Result<()> {
        let root =
            std::env::temp_dir().join(format!("ssal-probe-inventory-{}", std::process::id()));
        fs::create_dir(&root)?;
        fs::write(root.join("original"), b"bytes")?;
        symlink("/data/system/locksettings.db", root.join("link"))?;
        let a = inventory(&root)?;
        assert_eq!(
            a["link"]["content"]["symlink"],
            "/data/system/locksettings.db"
        );
        assert_eq!(a, inventory(&root)?);
        fs::remove_dir_all(root)?;
        Ok(())
    }
}
