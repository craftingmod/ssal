#[cfg(unix)]
mod binder_probe;
#[cfg(unix)]
mod guest_mounts;
#[cfg(unix)]
mod guest_probe;
#[cfg(unix)]
mod prepare;
#[cfg(unix)]
mod service_contract;
#[cfg(unix)]
mod daemon {
    use sha2::{Digest, Sha256};
    use ssal::unix::{label_image, receive, reply, valid_image_name, ROOT, VERSION};
    use std::fs::{self, File, OpenOptions};
    use std::io::{self, Read, Seek, SeekFrom, Write};
    use std::os::fd::{AsRawFd, OwnedFd};
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::{Arc, Mutex};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
        let temp = path.with_extension("tmp");
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&temp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        fs::rename(&temp, path)?;
        File::open(path.parent().unwrap())?.sync_all()
    }
    fn log(root: &Path, text: &str) {
        if let Ok(mut f) = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(root.join("logs/ssald.log"))
        {
            let _ = writeln!(f, "{text}");
        }
    }
    fn now() -> u128 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
    }
    fn register(
        root: &Path,
        fd: OwnedFd,
        id: &str,
        image_name: &str,
        label: impl FnOnce(&File) -> io::Result<()>,
    ) -> io::Result<String> {
        let mut input = File::from(fd);
        let meta = input.metadata()?;
        if !meta.is_file() || meta.len() < 2048 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "source must be a raw ext4 regular file",
            ));
        }
        let cpath =
            std::ffi::CString::new(root.join("images").as_os_str().as_encoded_bytes()).unwrap();
        let mut stats: libc::statvfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::statvfs(cpath.as_ptr(), &mut stats) } != 0 {
            return Err(io::Error::last_os_error());
        }
        if (stats.f_bavail as u128) * (stats.f_frsize as u128)
            < meta.len() as u128 + 16 * 1024 * 1024
        {
            return Err(io::Error::other("insufficient free space"));
        }
        input.seek(SeekFrom::Start(1080))?;
        let mut magic = [0; 2];
        input.read_exact(&mut magic)?;
        if magic != [0x53, 0xef] {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported image: expected raw ext4 (convert sparse or compressed images first)",
            ));
        }
        input.seek(SeekFrom::Start(0))?;
        let temp = root.join("images").join(format!(".tmp-{id}"));
        fs::create_dir(&temp)?;
        let result = (|| {
            let mut out = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(temp.join("system.img"))?;
            label(&out)?;
            let mut hash = Sha256::new();
            let mut buf = vec![0; 1024 * 1024];
            let mut size = 0u64;
            loop {
                let n = input.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                out.write_all(&buf[..n])?;
                hash.update(&buf[..n]);
                size += n as u64;
            }
            if size != meta.len() {
                return Err(io::Error::other("source changed during copy"));
            }
            out.sync_all()?;
            let digest = hash
                .finalize()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>();
            let manifest = serde_json::json!({"id": id, "image_name": image_name, "format": "raw-ext4", "sha256": digest, "size": size, "android_version": null, "profile": null});
            atomic(
                &temp.join("manifest.json"),
                serde_json::to_string_pretty(&manifest)?.as_bytes(),
            )?;
            File::open(&temp)?.sync_all()?;
            fs::rename(&temp, root.join("images").join(id))?;
            File::open(root.join("images"))?.sync_all()?;
            atomic(
                &root.join("state/image-refs").join(image_name),
                id.as_bytes(),
            )?;
            Ok(format!("registered image {image_name} ({id}, sha256 {digest}); ext4 magic checked, filesystem and Android compatibility not yet verified"))
        })();
        if result.is_err() {
            let _ = fs::remove_dir_all(&temp);
        }
        result
    }
    fn migrate_legacy_image(root: &Path) -> io::Result<()> {
        let legacy = root.join("state/lineage-image");
        let destination = root.join("state/image-refs/lineage");
        if !destination.exists() {
            match fs::read(legacy) {
                Ok(data) => atomic(&destination, &data)?,
                Err(e) if e.kind() == io::ErrorKind::NotFound => (),
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
    fn image_list(root: &Path) -> io::Result<String> {
        let mut images = Vec::new();
        for entry in fs::read_dir(root.join("state/image-refs"))? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if valid_image_name(&name) && entry.file_type()?.is_file() {
                images.push(format!(
                    "{name}: {}",
                    fs::read_to_string(entry.path())?.trim()
                ));
            }
        }
        images.sort();
        Ok(if images.is_empty() {
            "none".into()
        } else {
            images.join("\n")
        })
    }
    fn create_profile(
        root: &Path,
        image_name: &str,
        requested: Option<&str>,
    ) -> io::Result<String> {
        if !valid_image_name(image_name) || requested.is_some_and(|name| !valid_image_name(name)) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid image or profile name",
            ));
        }
        let id = fs::read_to_string(root.join("state/image-refs").join(image_name))?;
        let id = id.trim();
        if !valid_image_name(id) || !root.join("images").join(id).join("system.img").is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "registered image is missing or invalid",
            ));
        }
        let profiles = root.join("guests");
        let name = match requested {
            Some(name) => name.to_owned(),
            None => (1u64..)
                .map(|i| format!("profile{i}"))
                .find(|name| !profiles.join(name).exists())
                .ok_or_else(|| io::Error::other("no profile name available"))?,
        };
        let destination = profiles.join(&name);
        if destination.exists() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "profile already exists",
            ));
        }
        let temp = profiles.join(format!(".create-{name}"));
        fs::create_dir(&temp)?;
        let result = (|| {
            let data = temp.join("userdata");
            fs::create_dir(&data)?;
            fs::set_permissions(&data, fs::Permissions::from_mode(0o700))?;
            File::open(&data)?.sync_all()?;
            let property = |key: &str| -> Option<String> {
                let output = Command::new("/system/bin/getprop").arg(key).output().ok()?;
                if !output.status.success() {
                    return None;
                }
                let value = String::from_utf8(output.stdout).ok()?.trim().to_owned();
                (!value.is_empty()).then_some(value)
            };
            let manifest = serde_json::json!({"version": 2, "name": name, "image_name": image_name, "image_id": id,
                "mount_profile": super::guest_mounts::PROFILE_NAME,
                "device": {"product_device": property("ro.product.device"), "product_model": property("ro.product.model"), "build_fingerprint": property("ro.build.fingerprint"), "configuration": null},
                "userdata": {"path": "userdata", "format": "directory"}, "compatibility": "unverified"});
            atomic(
                &temp.join("profile.json"),
                serde_json::to_vec_pretty(&manifest)?.as_slice(),
            )?;
            File::open(&temp)?.sync_all()?;
            fs::rename(&temp, &destination)?;
            File::open(&profiles)?.sync_all()?;
            Ok(format!("created profile {name} for {image_name} ({id}); userdata: directory; device compatibility unverified"))
        })();
        if result.is_err() {
            let _ = fs::remove_dir_all(&temp);
        }
        result
    }

    fn profile_list(root: &Path) -> io::Result<String> {
        let mut names = Vec::new();
        for entry in fs::read_dir(root.join("guests"))? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if valid_image_name(&name)
                && entry.file_type()?.is_dir()
                && entry.path().join("profile.json").is_file()
            {
                names.push(name);
            }
        }
        names.sort();
        Ok(if names.is_empty() {
            "none".into()
        } else {
            names.join("\n")
        })
    }
    fn remove_profile(root: &Path, name: &str) -> io::Result<()> {
        if !valid_image_name(name) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid profile name",
            ));
        }
        let profiles = root.join("guests");
        let path = profiles.join(name);
        if !fs::symlink_metadata(&path)?.is_dir()
            || !fs::symlink_metadata(path.join("profile.json"))?.is_file()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "not a profile directory",
            ));
        }
        let mountinfo = fs::read_to_string("/proc/self/mountinfo")?;
        let prefix = format!("{}/", path.display());
        if mountinfo
            .lines()
            .filter_map(|line| line.split_whitespace().nth(4))
            .any(|mount| mount == path.to_string_lossy() || mount.starts_with(&prefix))
        {
            return Err(io::Error::other(
                "profile contains a mount; refusing to remove it",
            ));
        }
        fs::remove_dir_all(&path)?;
        File::open(profiles)?.sync_all()?;
        Ok(())
    }
    fn peer_root(s: &UnixStream) -> io::Result<bool> {
        let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of_val(&cred) as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                s.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut cred as *mut libc::ucred).cast(),
                &mut len,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(cred.uid == 0)
    }
    fn handle(mut stream: UnixStream, root: PathBuf, busy: Arc<Mutex<bool>>) -> io::Result<()> {
        stream.set_read_timeout(Some(std::time::Duration::from_secs(10)))?;
        if !peer_root(&stream)? {
            return reply(&mut stream, false, "root peer required");
        }
        let (req, fd) = receive(&mut stream)?;
        if req.version != VERSION {
            return reply(&mut stream, false, "unsupported protocol version");
        }
        match req.command.as_str() {
            "status" => { let job = fs::read_to_string(root.join("state/last-job.json")).unwrap_or_else(|_| "none".into()); let images = image_list(&root)?; let profiles = profile_list(&root)?; reply(&mut stream, true, format!("HOST_ACTIVE\nimages:\n{images}\nprofiles:\n{profiles}\nlast job: {job}")) }
            "doctor" if req.profile_name.is_some() => {
                match super::prepare::check(&root, req.profile_name.as_deref().unwrap()) {
                    Ok(profile) => reply(&mut stream, true, profile.report),
                    Err(e) => reply(&mut stream, false, format!("profile check failed: {e}")),
                }
            }
            "doctor" => reply(&mut stream, true, format!("daemon and root socket: OK\nmount namespace: {}\nloop control: {}\ndevice profile, Binder, property, HAL and guest services: not implemented; switching unavailable", Path::new("/proc/self/ns/mnt").exists(), Path::new("/dev/loop-control").exists())),
            "prepare" | "probe-binder" => {
                let Some(name) = req.profile_name.as_deref().filter(|name| valid_image_name(name)) else { return reply(&mut stream, false, "invalid profile name"); };
                let guard = busy.lock().unwrap();
                if *guard { return reply(&mut stream, false, "another operation is running"); }
                let result = prepare_session(&root, name, req.command == "probe-binder");
                match result { Ok(message) => { log(&root, &message); reply(&mut stream, true, message) }, Err(e) => { let message = format!("prepare failed: {e}"); log(&root, &message); reply(&mut stream, false, message) } }
            }
            "remove" => {
                let Some(name) = req.profile_name.as_deref().filter(|name| valid_image_name(name)) else { return reply(&mut stream, false, "invalid profile name"); };
                let Ok(guard) = busy.try_lock() else { return reply(&mut stream, false, "another operation is running"); };
                if *guard { return reply(&mut stream, false, "another operation is running"); }
                match remove_profile(&root, name) {
                    Ok(()) => { let message = format!("removed profile {name} and its userdata"); log(&root, &message); reply(&mut stream, true, message) },
                    Err(e) => reply(&mut stream, false, format!("profile removal failed: {e}")),
                }
            }
            "stop-for-restart" => {
                let guard = busy.lock().unwrap();
                if *guard { return reply(&mut stream, false, "an operation is running; try again later"); }
                reply(&mut stream, true, "daemon stopping")?;
                std::process::exit(0);
            }
            "logs" => reply(&mut stream, true, fs::read_to_string(root.join("logs/ssald.log")).unwrap_or_default()),
            "switch" if !req.image_name.as_deref().is_some_and(valid_image_name) => reply(&mut stream, false, "invalid image name"),
            "switch" | "return" => reply(&mut stream, false, super::service_contract::blocked_summary()?),
            "create" => {
                let Some(image_name) = req.image_name.as_deref().filter(|name| valid_image_name(name)) else { return reply(&mut stream, false, "invalid image name"); };
                if req.profile_name.as_deref().is_some_and(|name| !valid_image_name(name)) { return reply(&mut stream, false, "invalid profile name"); }
                let guard = busy.lock().unwrap();
                if *guard { return reply(&mut stream, false, "another operation is running"); }
                let result = create_profile(&root, image_name, req.profile_name.as_deref());
                match result { Ok(message) => reply(&mut stream, true, message), Err(e) => reply(&mut stream, false, format!("profile creation failed: {e}")) }
            }
            "add" => {
                let Some(image_name) = req.image_name.filter(|name| valid_image_name(name)) else { return reply(&mut stream, false, "invalid image name: use 1-64 ASCII letters, digits, underscores or hyphens"); };
                let Some(fd) = fd else { return reply(&mut stream, false, "image file descriptor required"); };
                let mut guard = busy.lock().unwrap(); if *guard { return reply(&mut stream, false, "another operation is running"); } *guard = true;
                let id = format!("{}-{}", now(), std::process::id());
                let journal = root.join("state/last-job.json");
                if let Err(e) = atomic(&journal, serde_json::json!({"id":id,"operation":"add","image_name":image_name,"status":"running"}).to_string().as_bytes()) { *guard = false; return reply(&mut stream, false, e.to_string()); }
                drop(guard);
                let job_id = id.clone();
                std::thread::spawn(move || {
                    let result = register(&root, fd, &job_id, &image_name, label_image);
                    let (status, message) = match result { Ok(s) => ("completed", s), Err(e) => ("failed", e.to_string()) };
                    let record = serde_json::json!({"id":job_id,"operation":"add","image_name":image_name,"status":status,"message":message});
                    if let Err(e) = atomic(&journal, record.to_string().as_bytes()) { log(&root, &format!("journal update failed: {e}")); }
                    log(&root, &record.to_string()); *busy.lock().unwrap() = false;
                });
                reply(&mut stream, true, format!("job {id} accepted; use ssal status"))
            }
            _ => reply(&mut stream, false, "unknown command")
        }
    }
    fn prepare_session(root: &Path, name: &str, binder_probe: bool) -> io::Result<String> {
        let profile = super::prepare::check(root, name)?;
        let base = root
            .join("mnt")
            .join(format!("prepare-{}-{}", std::process::id(), now()));
        fs::create_dir(&base)?;
        let result = (|| {
            fs::create_dir(base.join("system"))?;
            fs::create_dir(base.join("data"))?;
            let output = Command::new(std::env::current_exe()?)
                .arg(if binder_probe {
                    "--binder-probe-worker"
                } else {
                    "--prepare-worker"
                })
                .arg(&profile.system)
                .arg(&profile.userdata)
                .arg(&base)
                .output()?;
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !output.status.success() {
                return Err(io::Error::other(format!(
                    "{}\nworker exited {}\n{stdout}{stderr}",
                    profile.report, output.status
                )));
            }
            Ok(format!(
                "{}\n{stdout}prepare complete; worker exited; session-path host mounts checked absent",
                profile.report
            ))
        })();
        let mut cleanup = Vec::new();
        // Inspect this namespace explicitly before removing session scratch.
        // Worker exit alone is not proof that every namespace reference is gone.
        let host_mounts = fs::read_to_string("/proc/self/mountinfo")?;
        if host_mounts
            .lines()
            .filter_map(|line| line.split_whitespace().nth(4))
            .any(|path| Path::new(path).starts_with(&base))
        {
            return Err(io::Error::other(format!("host namespace still has a mount under {}; scratch cleanup refused; previous result: {result:?}", base.display())));
        }
        log(
            root,
            "prepare host namespace residual mount check: verified absent for session path",
        );
        for scratch in ["rootfs", "apex-cache", "loop-devices"] {
            let path = base.join(scratch);
            if let Err(e) = fs::remove_dir_all(&path) {
                if e.kind() != io::ErrorKind::NotFound {
                    cleanup.push(format!("{}: {e}", path.display()));
                }
            }
        }
        for path in [base.join("data"), base.join("system"), base.clone()] {
            if let Err(e) = fs::remove_dir(&path) {
                if e.kind() != io::ErrorKind::NotFound {
                    cleanup.push(format!("{}: {e}", path.display()));
                }
            }
        }
        if !cleanup.is_empty() {
            return Err(io::Error::other(format!(
                "temporary directory cleanup failed: {}; previous result: {:?}",
                cleanup.join(", "),
                result
            )));
        }
        result
    }
    pub fn run() -> io::Result<()> {
        if unsafe { libc::geteuid() } != 0 {
            return Err(io::Error::other("ssald must run as root"));
        }
        let root = PathBuf::from(ROOT);
        for dir in [
            "config",
            "images",
            "guests",
            "mnt",
            "state",
            "state/image-refs",
            "logs",
            "run",
        ] {
            fs::create_dir_all(root.join(dir))?;
            fs::set_permissions(root.join(dir), fs::Permissions::from_mode(0o700))?;
        }
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .mode(0o600)
            .open(root.join("run/ssald.lock"))?;
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(io::Error::other("ssald is already running"));
        }
        for entry in fs::read_dir(root.join("guests"))? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.strip_prefix(".create-").is_some_and(valid_image_name)
                && entry.file_type()?.is_dir()
            {
                fs::remove_dir_all(entry.path())?;
            }
        }
        migrate_legacy_image(&root)?;
        let journal = root.join("state/last-job.json");
        if let Ok(data) = fs::read(&journal) {
            if let Ok(mut v) = serde_json::from_slice::<serde_json::Value>(&data) {
                if v["status"] == "running" {
                    v["status"] = "interrupted".into();
                    v["message"] = "daemon restarted; registration may need to be repeated".into();
                    atomic(&journal, v.to_string().as_bytes())?;
                }
            }
        }
        let socket = root.join("run/ssald.sock");
        if socket.exists() {
            fs::remove_file(&socket)?;
        }
        let listener = UnixListener::bind(&socket)?;
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))?;
        let busy = Arc::new(Mutex::new(false));
        log(&root, "ssald started");
        for stream in listener.incoming() {
            match stream {
                Ok(s) => {
                    let r = root.clone();
                    let b = busy.clone();
                    std::thread::spawn(move || {
                        if let Err(e) = handle(s, r.clone(), b) {
                            log(&r, &format!("request error: {e}"));
                        }
                    });
                }
                Err(e) => log(&root, &format!("accept: {e}")),
            }
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn profile_creation_names_and_failure_cleanup() -> io::Result<()> {
            let root = std::env::temp_dir().join(format!(
                "ssal-profiles-test-{}-{}",
                std::process::id(),
                now()
            ));
            fs::create_dir_all(root.join("images/id-1"))?;
            fs::create_dir_all(root.join("state/image-refs"))?;
            fs::create_dir_all(root.join("guests"))?;
            fs::write(root.join("images/id-1/system.img"), b"image")?;
            fs::write(root.join("state/image-refs/lineage"), b"id-1")?;
            create_profile(&root, "lineage", None)?;
            create_profile(&root, "lineage", None)?;
            let profile: serde_json::Value =
                serde_json::from_slice(&fs::read(root.join("guests/profile1/profile.json"))?)?;
            assert_eq!(profile["image_id"], "id-1");
            assert_eq!(profile["userdata"]["format"], "directory");
            assert_eq!(
                profile["mount_profile"],
                super::super::guest_mounts::PROFILE_NAME
            );
            assert!(root.join("guests/profile1/userdata").is_dir());
            assert!(root.join("guests/profile2/profile.json").exists());
            assert!(create_profile(&root, "lineage", Some("profile1")).is_err());
            assert!(create_profile(&root, "missing", Some("other")).is_err());
            assert!(create_profile(&root, "lineage", Some("../bad")).is_err());
            fs::write(root.join("guests/profile1/userdata/example"), b"data")?;
            std::os::unix::fs::symlink(
                root.join("images/id-1"),
                root.join("guests/profile1/userdata/link"),
            )?;
            remove_profile(&root, "profile1")?;
            assert!(!root.join("guests/profile1").exists());
            assert!(root.join("guests/profile2/profile.json").exists());
            assert!(root.join("images/id-1/system.img").exists());
            assert!(remove_profile(&root, "profile1").is_err());
            assert!(remove_profile(&root, "../images").is_err());
            fs::remove_dir_all(root)?;
            Ok(())
        }

        #[test]
        fn names_registration_and_legacy_migration() -> io::Result<()> {
            for name in ["", ".", "..", "../escape", "a/b", "a.b", "space name"] {
                assert!(!valid_image_name(name));
            }
            assert!(valid_image_name("Lineage_23-test"));
            assert!(!valid_image_name(&"a".repeat(65)));

            let root =
                std::env::temp_dir().join(format!("ssal-test-{}-{}", std::process::id(), now()));
            fs::create_dir_all(root.join("images"))?;
            fs::create_dir_all(root.join("state/image-refs"))?;
            fs::write(root.join("state/lineage-image"), "old-id")?;
            migrate_legacy_image(&root)?;
            assert_eq!(
                fs::read_to_string(root.join("state/image-refs/lineage"))?,
                "old-id"
            );

            let source = root.join("source.img");
            let mut bytes = vec![0u8; 4096];
            bytes[1080..1082].copy_from_slice(&[0x53, 0xef]);
            fs::write(&source, bytes)?;
            register(&root, File::open(&source)?.into(), "first", "alpha", |_| {
                Ok(())
            })?;
            register(&root, File::open(&source)?.into(), "second", "beta", |_| {
                Ok(())
            })?;
            register(&root, File::open(&source)?.into(), "third", "alpha", |_| {
                Ok(())
            })?;
            assert!(register(
                &root,
                File::open(&source)?.into(),
                "failed",
                "alpha",
                |_| Err(io::Error::other("label failed"))
            )
            .is_err());
            assert!(!root.join("images/.tmp-failed").exists());
            assert_eq!(
                fs::read_to_string(root.join("state/image-refs/alpha"))?,
                "third"
            );
            assert_eq!(
                fs::read_to_string(root.join("state/image-refs/beta"))?,
                "second"
            );
            assert_eq!(
                fs::read_to_string(root.join("state/image-refs/lineage"))?,
                "old-id"
            );
            fs::write(root.join("state/image-refs/lineage"), "new-id")?;
            migrate_legacy_image(&root)?;
            assert_eq!(
                fs::read_to_string(root.join("state/image-refs/lineage"))?,
                "new-id"
            );
            fs::remove_dir_all(root)?;
            Ok(())
        }
    }
}
#[cfg(unix)]
fn main() {
    let args: Vec<_> = std::env::args_os().collect();
    if args
        .get(1)
        .is_some_and(|arg| arg == "--prepare-worker" || arg == "--binder-probe-worker")
    {
        if args.len() != 5 || unsafe { libc::geteuid() } != 0 {
            eprintln!("invalid prepare worker invocation");
            std::process::exit(1);
        }
        if let Err(e) = prepare::worker(
            std::path::Path::new(&args[2]),
            std::path::Path::new(&args[3]),
            std::path::Path::new(&args[4]),
            args[1] == "--binder-probe-worker",
        ) {
            eprintln!("prepare worker: {e}");
            std::process::exit(1);
        }
        return;
    }
    if let Err(e) = daemon::run() {
        eprintln!("ssald: {e}");
        std::process::exit(1);
    }
}
#[cfg(not(unix))]
fn main() {
    eprintln!("ssald requires Android/Linux");
    std::process::exit(1);
}
