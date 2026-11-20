use rsbinder::{Interface, Status};
use sha2::{Digest, Sha256};
use ssal_binder_service::Result;
use std::{
    collections::HashMap,
    io::Read,
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

mod aidl {
    #![allow(dead_code, non_snake_case, non_upper_case_globals, clippy::all)]
    include!(concat!(env!("OUT_DIR"), "/gatekeeper.rs"));
}

use aidl::android::hardware::gatekeeper::{
    GatekeeperEnrollResponse::GatekeeperEnrollResponse,
    GatekeeperVerifyResponse::GatekeeperVerifyResponse,
    IGatekeeper::{
        BnGatekeeper, IGatekeeper, ERROR_GENERAL_FAILURE, STATUS_OK,
    },
};
use aidl::android::hardware::security::keymint::{
    HardwareAuthToken::HardwareAuthToken,
    HardwareAuthenticatorType::HardwareAuthenticatorType,
};
use aidl::android::hardware::security::secureclock::Timestamp::Timestamp;

const HAL: &str = "android.hardware.gatekeeper.IGatekeeper/default";
const HANDLE_MAGIC: &[u8; 4] = b"SSGK";
const HANDLE_VERSION: u8 = 1;
const SALT_LEN: usize = 16;
const MAC_LEN: usize = 32;
// 4 (magic) + 1 (ver) + 4 (uid) + 8 (sid) + 16 (salt) + 32 (pw_hash) + 32 (mac) = 97 bytes
const HANDLE_LEN: usize = 4 + 1 + 4 + 8 + SALT_LEN + MAC_LEN + MAC_LEN;

fn getrandom(buf: &mut [u8]) -> std::io::Result<()> {
    let mut offset = 0;
    while offset < buf.len() {
        let ret = unsafe {
            libc::syscall(
                libc::SYS_getrandom,
                buf[offset..].as_mut_ptr(),
                buf.len() - offset,
                0 as libc::c_uint,
            )
        };
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        offset += ret as usize;
    }
    Ok(())
}

fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut k_pad = [0u8; 64];
    if key.len() > 64 {
        let hashed = Sha256::digest(key);
        k_pad[..32].copy_from_slice(&hashed);
    } else {
        k_pad[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k_pad[i];
        opad[i] ^= k_pad[i];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    for part in parts {
        inner.update(part);
    }
    let inner_hash = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_hash);
    outer.finalize().into()
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn monotonic_millis() -> i64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut ts) } == 0 {
        return (ts.tv_sec as i64) * 1000 + (ts.tv_nsec as i64) / 1_000_000;
    }
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn hash_password(salt: &[u8], password: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"SSAL-GK-PW-V1");
    hasher.update(salt);
    hasher.update(password);
    hasher.finalize().into()
}

struct SoftGatekeeper {
    master_key: [u8; 32],
    auth_token_key: [u8; 32],
    deleted_users: Mutex<HashMap<i32, u64>>,
}

impl SoftGatekeeper {
    fn new(auth_token_key: [u8; 32]) -> std::io::Result<Self> {
        let mut master_key = [0u8; 32];
        getrandom(&mut master_key)?;
        Ok(Self {
            master_key,
            auth_token_key,
            deleted_users: Mutex::new(HashMap::new()),
        })
    }

    fn sign_handle(&self, uid: i32, sid: i64, salt: &[u8; SALT_LEN], pw_hash: &[u8; 32]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(HANDLE_LEN);
        buf.extend_from_slice(HANDLE_MAGIC);
        buf.push(HANDLE_VERSION);
        buf.extend_from_slice(&uid.to_le_bytes());
        buf.extend_from_slice(&sid.to_le_bytes());
        buf.extend_from_slice(salt);
        buf.extend_from_slice(pw_hash);
        let mac = hmac_sha256(&self.master_key, &[&buf]);
        buf.extend_from_slice(&mac);
        buf
    }

    fn parse_and_verify_handle(&self, uid: i32, handle: &[u8], password: &[u8]) -> Option<i64> {
        if handle.len() != HANDLE_LEN || &handle[..4] != HANDLE_MAGIC || handle[4] != HANDLE_VERSION {
            return None;
        }
        let body_len = HANDLE_LEN - MAC_LEN;
        let expected_mac = hmac_sha256(&self.master_key, &[&handle[..body_len]]);
        if !ct_eq(&expected_mac, &handle[body_len..]) {
            return None;
        }
        let handle_uid = i32::from_le_bytes(handle[5..9].try_into().ok()?);
        if handle_uid != uid {
            return None;
        }
        let sid = i64::from_le_bytes(handle[9..17].try_into().ok()?);
        let salt = &handle[17..17 + SALT_LEN];
        let stored_hash = &handle[17 + SALT_LEN..body_len];
        let actual_hash = hash_password(salt, password);
        if ct_eq(stored_hash, &actual_hash) {
            Some(sid)
        } else {
            None
        }
    }

    fn make_auth_token(&self, challenge: i64, secure_user_id: i64) -> HardwareAuthToken {
        let timestamp_ms = monotonic_millis();
        let auth_type = HardwareAuthenticatorType::PASSWORD;
        let mac = hmac_sha256(
            &self.auth_token_key,
            &[
                &[0u8],
                &challenge.to_be_bytes(),
                &secure_user_id.to_be_bytes(),
                &0i64.to_be_bytes(),
                &(auth_type.0 as u32).to_be_bytes(),
                &timestamp_ms.to_be_bytes(),
            ],
        );
        HardwareAuthToken {
            challenge,
            userId: secure_user_id,
            authenticatorId: 0,
            authenticatorType: auth_type,
            timestamp: Timestamp {
                milliSeconds: timestamp_ms,
            },
            mac: mac.to_vec(),
        }
    }
}

impl Interface for SoftGatekeeper {}

impl IGatekeeper for SoftGatekeeper {
    fn deleteAllUsers(&self) -> rsbinder::BinderResult<()> {
        self.deleted_users.lock().unwrap().clear();
        Ok(())
    }

    fn deleteUser(&self, uid: i32) -> rsbinder::BinderResult<()> {
        self.deleted_users.lock().unwrap().remove(&uid);
        Ok(())
    }

    fn enroll(
        &self,
        uid: i32,
        current_password_handle: &[u8],
        current_password: &[u8],
        desired_password: &[u8],
    ) -> rsbinder::BinderResult<GatekeeperEnrollResponse> {
        if desired_password.is_empty() {
            return Err(Status::new_service_specific_error(
                ERROR_GENERAL_FAILURE,
                Some("desired password empty".into()),
            ));
        }
        let secure_user_id = if !current_password_handle.is_empty() {
            match self.parse_and_verify_handle(uid, current_password_handle, current_password) {
                Some(sid) => sid,
                None => {
                    return Err(Status::new_service_specific_error(
                        ERROR_GENERAL_FAILURE,
                        Some("current password verification failed".into()),
                    ));
                }
            }
        } else {
            let mut sid_bytes = [0u8; 8];
            getrandom(&mut sid_bytes).map_err(|_| {
                Status::new_service_specific_error(ERROR_GENERAL_FAILURE, Some("rng failed".into()))
            })?;
            let sid = i64::from_le_bytes(sid_bytes);
            if sid == 0 {
                1
            } else {
                sid
            }
        };

        let mut salt = [0u8; SALT_LEN];
        getrandom(&mut salt).map_err(|_| {
            Status::new_service_specific_error(ERROR_GENERAL_FAILURE, Some("rng failed".into()))
        })?;
        let pw_hash = hash_password(&salt, desired_password);
        let data = self.sign_handle(uid, secure_user_id, &salt, &pw_hash);

        Ok(GatekeeperEnrollResponse {
            statusCode: STATUS_OK,
            timeoutMs: 0,
            secureUserId: secure_user_id,
            data,
        })
    }

    fn verify(
        &self,
        uid: i32,
        challenge: i64,
        enrolled_password_handle: &[u8],
        provided_password: &[u8],
    ) -> rsbinder::BinderResult<GatekeeperVerifyResponse> {
        let Some(secure_user_id) =
            self.parse_and_verify_handle(uid, enrolled_password_handle, provided_password)
        else {
            return Err(Status::new_service_specific_error(
                ERROR_GENERAL_FAILURE,
                Some("password verification failed".into()),
            ));
        };
        Ok(GatekeeperVerifyResponse {
            statusCode: STATUS_OK,
            timeoutMs: 0,
            hardwareAuthToken: self.make_auth_token(challenge, secure_user_id),
        })
    }
}

fn read_auth_token_key() -> std::io::Result<[u8; 32]> {
    let mut key = [0u8; 32];
    let mut stdin = std::io::stdin().lock();
    match stdin.read_exact(&mut key) {
        Ok(()) => Ok(key),
        Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => {
            getrandom(&mut key)?;
            Ok(key)
        }
        Err(err) => Err(err),
    }
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let (device, context) = match args.as_slice() {
        [_, cmd, device, context] if cmd == "serve" => (device.parse::<u64>()?, context.as_str()),
        _ => return Err("usage: ssal-gatekeeper serve <binder-rdev> <selinux-context>".into()),
    };
    let auth_token_key = read_auth_token_key()?;
    ssal_binder_service::init(device, context)?;
    let service = BnGatekeeper::new_binder(SoftGatekeeper::new(auth_token_key)?);
    ssal_binder_service::register(HAL, service)?;
    ssal_binder_service::join()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enroll_verify_and_reenroll_roundtrip() {
        let gk = SoftGatekeeper::new([0x42; 32]).unwrap();
        let enroll = gk.enroll(0, &[], &[], b"1234").unwrap();
        assert_eq!(enroll.statusCode, STATUS_OK);
        assert_ne!(enroll.secureUserId, 0);

        let verify = gk.verify(0, 99, &enroll.data, b"1234").unwrap();
        assert_eq!(verify.statusCode, STATUS_OK);
        assert_eq!(verify.hardwareAuthToken.challenge, 99);
        assert_eq!(verify.hardwareAuthToken.userId, enroll.secureUserId);
        assert_eq!(verify.hardwareAuthToken.mac.len(), 32);

        assert!(gk.verify(0, 99, &enroll.data, b"wrong").is_err());
        assert!(gk.verify(10, 99, &enroll.data, b"1234").is_err());

        let reenroll = gk.enroll(0, &enroll.data, b"1234", b"5678").unwrap();
        assert_eq!(reenroll.secureUserId, enroll.secureUserId);
        assert!(gk.verify(0, 100, &reenroll.data, b"5678").is_ok());
    }
}
