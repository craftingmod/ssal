use crate::guest::init::{binder_service::BinderService, Service};
use std::{
    fs,
    io::{self, Read, Write},
    os::unix::fs::PermissionsExt,
    path::Path,
};

const HAL_KEYMINT: &str = "android.hardware.security.keymint.IKeyMintDevice/default";
const HAL_SHARED_SECRET: &str = "android.hardware.security.sharedsecret.ISharedSecret/default";
const HAL_SECURE_CLOCK: &str = "android.hardware.security.secureclock.ISecureClock/default";

pub(super) const VINTF: &str = r#"<manifest version="1.0" type="framework">
    <hal format="aidl">
        <name>android.hardware.security.keymint</name>
        <version>4</version>
        <fqname>IKeyMintDevice/default</fqname>
    </hal>
    <hal format="aidl">
        <name>android.hardware.security.sharedsecret</name>
        <version>1</version>
        <fqname>ISharedSecret/default</fqname>
    </hal>
    <hal format="aidl">
        <name>android.hardware.security.secureclock</name>
        <version>1</version>
        <fqname>ISecureClock/default</fqname>
    </hal>
</manifest>
"#;

pub(crate) const SERVICE: BinderService = BinderService {
    name: "keymint",
    executable: "/run/ssal/ssal-keymint",
    domain: "ssal_keymint",
    exec_type: "ssal_keymint_exec",
};

pub(in crate::guest) fn random_bytes<const N: usize>() -> io::Result<[u8; N]> {
    let mut buf = [0u8; N];
    let mut f = fs::File::open("/dev/urandom")?;
    f.read_exact(&mut buf)?;
    Ok(buf)
}

fn load_or_create_master_key(root: &Path) -> io::Result<[u8; 32]> {
    let path = root.join("data/vendor/ssal/keymint.master");
    if let Ok(bytes) = fs::read(&path) {
        if bytes.len() == 32 {
            let mut key = [0u8; 32];
            key.copy_from_slice(&bytes);
            return Ok(key);
        }
    }
    let key = random_bytes::<32>()?;
    if let Some(parent) = path.parent() {
        if fs::create_dir_all(parent).is_ok() {
            if let Ok(mut file) = fs::File::create(&path) {
                let _ = file.write_all(&key);
                let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
            }
        }
    }
    Ok(key)
}

pub(in crate::guest) fn start(
    root: &Path,
    guest_binder: u64,
    auth_token_key: &[u8; 32],
    services: &mut Vec<Service>,
) -> io::Result<()> {
    let plan = ssal::guest_policy::runtime::load(root)?
        .ok_or_else(|| io::Error::other("Guest KeyMint SELinux policy missing"))?;
    let context = plan.context(SERVICE.domain, true)?;
    crate::diagnostics::selinux::require_enforcing_domain(&context)?;
    let master_key = load_or_create_master_key(root)?;
    let mut keys = [0u8; 64];
    keys[..32].copy_from_slice(auth_token_key);
    keys[32..].copy_from_slice(&master_key);
    let input = super::gatekeeper::pipe_bytes(&keys)?;
    let mut service = Service::start_with_input(
        root,
        SERVICE.executable,
        &["serve", &guest_binder.to_string(), &context],
        SERVICE.name,
        1000,
        None,
        &[],
        input,
    )?;
    service.wait_text(&format!("guest_binder_registered={HAL_KEYMINT}"))?;
    service.wait_text(&format!("guest_binder_registered={HAL_SHARED_SECRET}"))?;
    service.wait_text(&format!("guest_binder_registered={HAL_SECURE_CLOCK}"))?;
    println!(
        "GUEST_KEYMINT_READY=PASS pid={} sid={context}",
        service.pid()
    );
    services.push(service);
    Ok(())
}
