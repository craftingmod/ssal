use rsbinder::{Interface, Status, Strong};
use serde::{Deserialize, Serialize};
use ssal_binder_service::Result;
use std::{
    io::Read,
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

mod crypto;

mod aidl {
    #![allow(dead_code, non_snake_case, non_upper_case_globals, clippy::all)]
    include!(concat!(env!("OUT_DIR"), "/keymint.rs"));
}

use aidl::android::hardware::security::keymint::{
    Algorithm::Algorithm,
    AttestationKey::AttestationKey,
    BeginResult::BeginResult,
    BlockMode::BlockMode,
    Certificate::Certificate,
    Digest::Digest,
    EcCurve::EcCurve,
    ErrorCode::ErrorCode,
    HardwareAuthToken::HardwareAuthToken,
    IKeyMintDevice::{BnKeyMintDevice, IKeyMintDevice},
    IKeyMintOperation::{BnKeyMintOperation, IKeyMintOperation},
    KeyCharacteristics::KeyCharacteristics,
    KeyCreationResult::KeyCreationResult,
    KeyFormat::KeyFormat,
    KeyMintHardwareInfo::KeyMintHardwareInfo,
    KeyOrigin::KeyOrigin,
    KeyParameter::KeyParameter,
    KeyParameterValue::KeyParameterValue,
    KeyPurpose::KeyPurpose,
    PaddingMode::PaddingMode,
    SecurityLevel::SecurityLevel,
    Tag::Tag,
};
use aidl::android::hardware::security::secureclock::{
    ISecureClock::{BnSecureClock, ISecureClock, TIME_STAMP_MAC_LABEL},
    TimeStampToken::TimeStampToken,
    Timestamp::Timestamp,
};
use aidl::android::hardware::security::sharedsecret::{
    ISharedSecret::{BnSharedSecret, ISharedSecret, KEY_AGREEMENT_LABEL, KEY_CHECK_LABEL},
    SharedSecretParameters::SharedSecretParameters,
};

const HAL_KEYMINT: &str = "android.hardware.security.keymint.IKeyMintDevice/default";
const HAL_SHARED_SECRET: &str = "android.hardware.security.sharedsecret.ISharedSecret/default";
const HAL_SECURE_CLOCK: &str = "android.hardware.security.secureclock.ISecureClock/default";

fn km_err(code: ErrorCode, msg: &str) -> Status {
    Status::new_service_specific_error(code.0, Some(msg.to_owned()))
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

#[derive(Clone, Serialize, Deserialize)]
struct StoredKey {
    algorithm: i32,
    key_material: Vec<u8>,
    purposes: Vec<i32>,
    block_modes: Vec<i32>,
    digests: Vec<i32>,
    paddings: Vec<i32>,
    key_size: i32,
    mac_length: Option<i32>,
    app_id: Option<Vec<u8>>,
    app_data: Option<Vec<u8>>,
    origin: i32,
}

impl StoredKey {
    fn to_characteristics(&self) -> Vec<KeyCharacteristics> {
        let mut auths = Vec::new();
        auths.push(KeyParameter {
            tag: Tag::ALGORITHM,
            value: KeyParameterValue::Algorithm(Algorithm(self.algorithm)),
        });
        auths.push(KeyParameter {
            tag: Tag::KEY_SIZE,
            value: KeyParameterValue::Integer(self.key_size),
        });
        auths.push(KeyParameter {
            tag: Tag::ORIGIN,
            value: KeyParameterValue::Origin(KeyOrigin(self.origin)),
        });
        for &p in &self.purposes {
            auths.push(KeyParameter {
                tag: Tag::PURPOSE,
                value: KeyParameterValue::KeyPurpose(KeyPurpose(p)),
            });
        }
        for &m in &self.block_modes {
            auths.push(KeyParameter {
                tag: Tag::BLOCK_MODE,
                value: KeyParameterValue::BlockMode(BlockMode(m)),
            });
        }
        for &d in &self.digests {
            auths.push(KeyParameter {
                tag: Tag::DIGEST,
                value: KeyParameterValue::Digest(Digest(d)),
            });
        }
        for &p in &self.paddings {
            auths.push(KeyParameter {
                tag: Tag::PADDING,
                value: KeyParameterValue::PaddingMode(PaddingMode(p)),
            });
        }
        vec![KeyCharacteristics {
            securityLevel: SecurityLevel::SOFTWARE,
            authorizations: auths,
        }]
    }
}

struct ParsedParams {
    algorithm: Option<Algorithm>,
    key_size: Option<i32>,
    ec_curve: Option<EcCurve>,
    purposes: Vec<i32>,
    block_modes: Vec<i32>,
    digests: Vec<i32>,
    paddings: Vec<i32>,
    mac_length: Option<i32>,
    nonce: Option<Vec<u8>>,
    caller_nonce: bool,
    app_id: Option<Vec<u8>>,
    app_data: Option<Vec<u8>>,
}

fn parse_params(params: &[KeyParameter]) -> ParsedParams {
    let mut parsed = ParsedParams {
        algorithm: None,
        key_size: None,
        ec_curve: None,
        purposes: Vec::new(),
        block_modes: Vec::new(),
        digests: Vec::new(),
        paddings: Vec::new(),
        mac_length: None,
        nonce: None,
        caller_nonce: false,
        app_id: None,
        app_data: None,
    };
    for p in params {
        match (p.tag, &p.value) {
            (Tag::ALGORITHM, KeyParameterValue::Algorithm(v)) => parsed.algorithm = Some(*v),
            (Tag::KEY_SIZE, KeyParameterValue::Integer(v)) => parsed.key_size = Some(*v),
            (Tag::EC_CURVE, KeyParameterValue::EcCurve(v)) => parsed.ec_curve = Some(*v),
            (Tag::PURPOSE, KeyParameterValue::KeyPurpose(v)) => parsed.purposes.push(v.0),
            (Tag::BLOCK_MODE, KeyParameterValue::BlockMode(v)) => parsed.block_modes.push(v.0),
            (Tag::DIGEST, KeyParameterValue::Digest(v)) => parsed.digests.push(v.0),
            (Tag::PADDING, KeyParameterValue::PaddingMode(v)) => parsed.paddings.push(v.0),
            (Tag::MAC_LENGTH, KeyParameterValue::Integer(v)) => parsed.mac_length = Some(*v),
            (Tag::NONCE, KeyParameterValue::Blob(v)) => parsed.nonce = Some(v.clone()),
            (Tag::CALLER_NONCE, KeyParameterValue::BoolValue(v)) => parsed.caller_nonce = *v,
            (Tag::APPLICATION_ID, KeyParameterValue::Blob(v)) => parsed.app_id = Some(v.clone()),
            (Tag::APPLICATION_DATA, KeyParameterValue::Blob(v)) => {
                parsed.app_data = Some(v.clone())
            }
            _ => {}
        }
    }
    parsed
}

struct SoftKeyMint {
    master_key: [u8; 32],
    shared_seed: [u8; 32],
    shared_nonce: [u8; 32],
}

impl SoftKeyMint {
    fn new(master_key: [u8; 32]) -> std::io::Result<Self> {
        let mut shared_seed = [0u8; 32];
        let mut shared_nonce = [0u8; 32];
        crypto::getrandom(&mut shared_seed)?;
        crypto::getrandom(&mut shared_nonce)?;
        Ok(Self {
            master_key,
            shared_seed,
            shared_nonce,
        })
    }

    fn seal_key(&self, stored: &StoredKey) -> rsbinder::BinderResult<Vec<u8>> {
        let json = serde_json::to_vec(stored)
            .map_err(|_| km_err(ErrorCode::UNKNOWN_ERROR, "serialize key failed"))?;
        crypto::seal_blob(&self.master_key, &json)
            .map_err(|e| km_err(ErrorCode::UNKNOWN_ERROR, e))
    }

    fn open_key(&self, blob: &[u8]) -> rsbinder::BinderResult<StoredKey> {
        let json = crypto::open_blob(&self.master_key, blob)
            .map_err(|_| km_err(ErrorCode::INVALID_KEY_BLOB, "invalid key blob"))?;
        serde_json::from_slice(&json)
            .map_err(|_| km_err(ErrorCode::INVALID_KEY_BLOB, "corrupt key blob"))
    }
}

impl Interface for SoftKeyMint {}

impl IKeyMintDevice for SoftKeyMint {
    fn getHardwareInfo(&self) -> rsbinder::BinderResult<KeyMintHardwareInfo> {
        Ok(KeyMintHardwareInfo {
            versionNumber: 4,
            securityLevel: SecurityLevel::SOFTWARE,
            keyMintName: "SSAL Software KeyMint".to_owned(),
            keyMintAuthorName: "SSAL".to_owned(),
            timestampTokenRequired: false,
        })
    }

    fn addRngEntropy(&self, _data: &[u8]) -> rsbinder::BinderResult<()> {
        Ok(())
    }

    fn generateKey(
        &self,
        key_params: &[KeyParameter],
        _attestation_key: Option<&AttestationKey>,
    ) -> rsbinder::BinderResult<KeyCreationResult> {
        let p = parse_params(key_params);
        let alg = p
            .algorithm
            .ok_or_else(|| km_err(ErrorCode::UNSUPPORTED_ALGORITHM, "missing algorithm"))?;

        let (key_material, key_size, cert_chain) = match alg {
            Algorithm::AES => {
                let bits = p.key_size.unwrap_or(256);
                if bits != 128 && bits != 256 {
                    return Err(km_err(ErrorCode::UNSUPPORTED_KEY_SIZE, "unsupported aes size"));
                }
                let mut raw = vec![0u8; (bits / 8) as usize];
                crypto::getrandom(&mut raw)
                    .map_err(|_| km_err(ErrorCode::UNKNOWN_ERROR, "rng failed"))?;
                (raw, bits, Vec::new())
            }
            Algorithm::HMAC => {
                let bits = p.key_size.unwrap_or(256);
                if bits < 64 || bits % 8 != 0 || bits > 512 {
                    return Err(km_err(ErrorCode::UNSUPPORTED_KEY_SIZE, "unsupported hmac size"));
                }
                let mut raw = vec![0u8; (bits / 8) as usize];
                crypto::getrandom(&mut raw)
                    .map_err(|_| km_err(ErrorCode::UNKNOWN_ERROR, "rng failed"))?;
                (raw, bits, Vec::new())
            }
            Algorithm::EC => {
                if let Some(curve) = p.ec_curve {
                    if curve != EcCurve::P_256 {
                        return Err(km_err(ErrorCode::UNSUPPORTED_EC_CURVE, "only P-256 supported"));
                    }
                }
                let (pkcs8, cert) = crypto::generate_p256_pkcs8()
                    .map_err(|e| km_err(ErrorCode::UNKNOWN_ERROR, e))?;
                (
                    pkcs8,
                    256,
                    vec![Certificate {
                        encodedCertificate: cert,
                    }],
                )
            }
            _ => return Err(km_err(ErrorCode::UNSUPPORTED_ALGORITHM, "unsupported algorithm")),
        };

        let stored = StoredKey {
            algorithm: alg.0,
            key_material,
            purposes: p.purposes,
            block_modes: p.block_modes,
            digests: p.digests,
            paddings: p.paddings,
            key_size,
            mac_length: p.mac_length,
            app_id: p.app_id,
            app_data: p.app_data,
            origin: KeyOrigin::GENERATED.0,
        };
        let key_blob = self.seal_key(&stored)?;
        let key_characteristics = stored.to_characteristics();
        Ok(KeyCreationResult {
            keyBlob: key_blob,
            keyCharacteristics: key_characteristics,
            certificateChain: cert_chain,
        })
    }

    fn importKey(
        &self,
        key_params: &[KeyParameter],
        key_format: KeyFormat,
        key_data: &[u8],
        _attestation_key: Option<&AttestationKey>,
    ) -> rsbinder::BinderResult<KeyCreationResult> {
        let p = parse_params(key_params);
        let alg = p
            .algorithm
            .ok_or_else(|| km_err(ErrorCode::UNSUPPORTED_ALGORITHM, "missing algorithm"))?;
        if key_data.is_empty() {
            return Err(km_err(ErrorCode::INVALID_ARGUMENT, "empty key data"));
        }
        let (key_size, cert_chain) = match (alg, key_format) {
            (Algorithm::AES | Algorithm::HMAC, KeyFormat::RAW) => {
                ((key_data.len() * 8) as i32, Vec::new())
            }
            (Algorithm::EC, KeyFormat::PKCS8) => {
                use p256::pkcs8::DecodePrivateKey;
                let sk = p256::ecdsa::SigningKey::from_pkcs8_der(key_data)
                    .map_err(|_| km_err(ErrorCode::INVALID_ARGUMENT, "invalid p256 pkcs8"))?;
                let cert = crypto::build_self_signed_p256_cert(&sk)
                    .map_err(|e| km_err(ErrorCode::UNKNOWN_ERROR, e))?;
                (
                    256,
                    vec![Certificate {
                        encodedCertificate: cert,
                    }],
                )
            }
            _ => {
                return Err(km_err(
                    ErrorCode::UNSUPPORTED_KEY_FORMAT,
                    "unsupported key format",
                ))
            }
        };
        let stored = StoredKey {
            algorithm: alg.0,
            key_material: key_data.to_vec(),
            purposes: p.purposes,
            block_modes: p.block_modes,
            digests: p.digests,
            paddings: p.paddings,
            key_size,
            mac_length: p.mac_length,
            app_id: p.app_id,
            app_data: p.app_data,
            origin: KeyOrigin::IMPORTED.0,
        };
        let key_blob = self.seal_key(&stored)?;
        let key_characteristics = stored.to_characteristics();
        Ok(KeyCreationResult {
            keyBlob: key_blob,
            keyCharacteristics: key_characteristics,
            certificateChain: cert_chain,
        })
    }

    fn importWrappedKey(
        &self,
        _wrapped_key_data: &[u8],
        _wrapping_key_blob: &[u8],
        _masking_key: &[u8],
        _unwrapping_params: &[KeyParameter],
        _password_sid: i64,
        _biometric_sid: i64,
    ) -> rsbinder::BinderResult<KeyCreationResult> {
        Err(km_err(ErrorCode::UNIMPLEMENTED, "importWrappedKey unimplemented"))
    }

    fn upgradeKey(
        &self,
        key_blob_to_upgrade: &[u8],
        _upgrade_params: &[KeyParameter],
    ) -> rsbinder::BinderResult<Vec<u8>> {
        let stored = self.open_key(key_blob_to_upgrade)?;
        self.seal_key(&stored)
    }

    fn deleteKey(&self, _key_blob: &[u8]) -> rsbinder::BinderResult<()> {
        Ok(())
    }

    fn deleteAllKeys(&self) -> rsbinder::BinderResult<()> {
        Ok(())
    }

    fn destroyAttestationIds(&self) -> rsbinder::BinderResult<()> {
        Ok(())
    }

    fn begin(
        &self,
        purpose: KeyPurpose,
        key_blob: &[u8],
        params: &[KeyParameter],
        _auth_token: Option<&HardwareAuthToken>,
    ) -> rsbinder::BinderResult<BeginResult> {
        let stored = self.open_key(key_blob)?;
        if !stored.purposes.is_empty() && !stored.purposes.contains(&purpose.0) {
            return Err(km_err(ErrorCode::INCOMPATIBLE_PURPOSE, "incompatible purpose"));
        }
        let op_params = parse_params(params);
        let block_mode = op_params
            .block_modes
            .first()
            .copied()
            .or_else(|| stored.block_modes.first().copied())
            .unwrap_or(BlockMode::ECB.0);
        let padding = op_params
            .paddings
            .first()
            .copied()
            .or_else(|| stored.paddings.first().copied())
            .unwrap_or(PaddingMode::NONE.0);
        let digest = op_params
            .digests
            .first()
            .copied()
            .or_else(|| stored.digests.first().copied())
            .unwrap_or(Digest::SHA_2_256.0);
        let mac_length = op_params
            .mac_length
            .or(stored.mac_length)
            .unwrap_or(if stored.algorithm == Algorithm::AES.0 { 128 } else { 256 });

        let mut ret_params = Vec::new();
        let nonce = if stored.algorithm == Algorithm::AES.0 && block_mode != BlockMode::ECB.0 {
            let needed_len = if block_mode == BlockMode::GCM.0 { 12 } else { 16 };
            match op_params.nonce {
                Some(n) => {
                    if n.len() != needed_len {
                        return Err(km_err(ErrorCode::INVALID_NONCE, "invalid nonce length"));
                    }
                    n
                }
                None => {
                    if purpose == KeyPurpose::DECRYPT {
                        return Err(km_err(ErrorCode::INVALID_NONCE, "missing decrypt nonce"));
                    }
                    let mut n = vec![0u8; needed_len];
                    crypto::getrandom(&mut n)
                        .map_err(|_| km_err(ErrorCode::UNKNOWN_ERROR, "rng failed"))?;
                    ret_params.push(KeyParameter {
                        tag: Tag::NONCE,
                        value: KeyParameterValue::Blob(n.clone()),
                    });
                    n
                }
            }
        } else {
            Vec::new()
        };

        let op = BnKeyMintOperation::new_binder(SoftOperation {
            state: Mutex::new(Some(OpState {
                stored,
                purpose,
                block_mode: BlockMode(block_mode),
                padding: PaddingMode(padding),
                digest: Digest(digest),
                mac_length,
                nonce,
                aad: Vec::new(),
                buffer: Vec::new(),
            })),
        });
        let op_strong: Strong<dyn IKeyMintOperation> = op;
        Ok(BeginResult {
            challenge: 0,
            params: ret_params,
            operation: Some(op_strong),
        })
    }

    fn deviceLocked(
        &self,
        _password_only: bool,
        _timestamp_token: Option<&TimeStampToken>,
    ) -> rsbinder::BinderResult<()> {
        Ok(())
    }

    fn earlyBootEnded(&self) -> rsbinder::BinderResult<()> {
        Ok(())
    }

    fn convertStorageKeyToEphemeral(
        &self,
        storage_key_blob: &[u8],
    ) -> rsbinder::BinderResult<Vec<u8>> {
        let stored = self.open_key(storage_key_blob)?;
        Ok(stored.key_material)
    }

    fn getKeyCharacteristics(
        &self,
        key_blob: &[u8],
        app_id: &[u8],
        app_data: &[u8],
    ) -> rsbinder::BinderResult<Vec<KeyCharacteristics>> {
        let stored = self.open_key(key_blob)?;
        if let Some(expected) = &stored.app_id {
            if !crypto::ct_eq(expected, app_id) {
                return Err(km_err(ErrorCode::INVALID_KEY_BLOB, "app_id mismatch"));
            }
        }
        if let Some(expected) = &stored.app_data {
            if !crypto::ct_eq(expected, app_data) {
                return Err(km_err(ErrorCode::INVALID_KEY_BLOB, "app_data mismatch"));
            }
        }
        Ok(stored.to_characteristics())
    }

    fn getRootOfTrustChallenge(&self) -> rsbinder::BinderResult<[u8; 16]> {
        let mut challenge = [0u8; 16];
        crypto::getrandom(&mut challenge)
            .map_err(|_| km_err(ErrorCode::UNKNOWN_ERROR, "rng failed"))?;
        Ok(challenge)
    }

    fn getRootOfTrust(&self, _challenge: &[u8; 16]) -> rsbinder::BinderResult<Vec<u8>> {
        Ok(Vec::new())
    }

    fn sendRootOfTrust(&self, _root_of_trust: &[u8]) -> rsbinder::BinderResult<()> {
        Ok(())
    }

    fn setAdditionalAttestationInfo(&self, _info: &[KeyParameter]) -> rsbinder::BinderResult<()> {
        Ok(())
    }
}

struct OpState {
    stored: StoredKey,
    purpose: KeyPurpose,
    block_mode: BlockMode,
    padding: PaddingMode,
    digest: Digest,
    mac_length: i32,
    nonce: Vec<u8>,
    aad: Vec<u8>,
    buffer: Vec<u8>,
}

struct SoftOperation {
    state: Mutex<Option<OpState>>,
}

impl Interface for SoftOperation {}

impl IKeyMintOperation for SoftOperation {
    fn updateAad(
        &self,
        input: &[u8],
        _auth_token: Option<&HardwareAuthToken>,
        _time_stamp_token: Option<&TimeStampToken>,
    ) -> rsbinder::BinderResult<()> {
        let mut guard = self.state.lock().unwrap();
        let st = guard
            .as_mut()
            .ok_or_else(|| km_err(ErrorCode::INVALID_OPERATION_HANDLE, "operation finished"))?;
        st.aad.extend_from_slice(input);
        Ok(())
    }

    fn update(
        &self,
        input: &[u8],
        _auth_token: Option<&HardwareAuthToken>,
        _time_stamp_token: Option<&TimeStampToken>,
    ) -> rsbinder::BinderResult<Vec<u8>> {
        let mut guard = self.state.lock().unwrap();
        let st = guard
            .as_mut()
            .ok_or_else(|| km_err(ErrorCode::INVALID_OPERATION_HANDLE, "operation finished"))?;
        st.buffer.extend_from_slice(input);
        Ok(Vec::new())
    }

    fn finish(
        &self,
        input: Option<&[u8]>,
        signature: Option<&[u8]>,
        _auth_token: Option<&HardwareAuthToken>,
        _timestamp_token: Option<&TimeStampToken>,
        _confirmation_token: Option<&[u8]>,
    ) -> rsbinder::BinderResult<Vec<u8>> {
        let mut guard = self.state.lock().unwrap();
        let mut st = guard
            .take()
            .ok_or_else(|| km_err(ErrorCode::INVALID_OPERATION_HANDLE, "operation finished"))?;
        if let Some(extra) = input {
            st.buffer.extend_from_slice(extra);
        }

        match Algorithm(st.stored.algorithm) {
            Algorithm::AES => finish_aes(&st),
            Algorithm::HMAC => finish_hmac(&st, signature),
            Algorithm::EC => finish_ec(&st, signature),
            _ => Err(km_err(ErrorCode::UNSUPPORTED_ALGORITHM, "unsupported algorithm")),
        }
    }

    fn abort(&self) -> rsbinder::BinderResult<()> {
        *self.state.lock().unwrap() = None;
        Ok(())
    }
}

fn finish_aes(st: &OpState) -> rsbinder::BinderResult<Vec<u8>> {
    let key = &st.stored.key_material;
    match (st.block_mode, st.purpose) {
        (BlockMode::GCM, KeyPurpose::ENCRYPT) => {
            crypto::aes_gcm_encrypt(key, &st.nonce, &st.aad, &st.buffer)
                .map_err(|e| km_err(ErrorCode::UNKNOWN_ERROR, e))
        }
        (BlockMode::GCM, KeyPurpose::DECRYPT) => {
            crypto::aes_gcm_decrypt(key, &st.nonce, &st.aad, &st.buffer)
                .map_err(|_| km_err(ErrorCode::VERIFICATION_FAILED, "gcm decrypt failed"))
        }
        (BlockMode::CBC, KeyPurpose::ENCRYPT) => {
            let data = if st.padding == PaddingMode::PKCS7 {
                crypto::pkcs7_pad(&st.buffer, 16)
            } else {
                st.buffer.clone()
            };
            crypto::aes_cbc_encrypt(key, &st.nonce, &data)
                .map_err(|e| km_err(ErrorCode::INVALID_INPUT_LENGTH, e))
        }
        (BlockMode::CBC, KeyPurpose::DECRYPT) => {
            let plain = crypto::aes_cbc_decrypt(key, &st.nonce, &st.buffer)
                .map_err(|e| km_err(ErrorCode::INVALID_INPUT_LENGTH, e))?;
            if st.padding == PaddingMode::PKCS7 {
                crypto::pkcs7_unpad(&plain, 16)
                    .map_err(|e| km_err(ErrorCode::INVALID_ARGUMENT, e))
            } else {
                Ok(plain)
            }
        }
        (BlockMode::CTR, KeyPurpose::ENCRYPT | KeyPurpose::DECRYPT) => {
            crypto::aes_ctr_crypt(key, &st.nonce, &st.buffer)
                .map_err(|e| km_err(ErrorCode::UNKNOWN_ERROR, e))
        }
        (BlockMode::ECB, KeyPurpose::ENCRYPT) => {
            let data = if st.padding == PaddingMode::PKCS7 {
                crypto::pkcs7_pad(&st.buffer, 16)
            } else {
                st.buffer.clone()
            };
            crypto::aes_ecb_encrypt(key, &data)
                .map_err(|e| km_err(ErrorCode::INVALID_INPUT_LENGTH, e))
        }
        (BlockMode::ECB, KeyPurpose::DECRYPT) => {
            let plain = crypto::aes_ecb_decrypt(key, &st.buffer)
                .map_err(|e| km_err(ErrorCode::INVALID_INPUT_LENGTH, e))?;
            if st.padding == PaddingMode::PKCS7 {
                crypto::pkcs7_unpad(&plain, 16)
                    .map_err(|e| km_err(ErrorCode::INVALID_ARGUMENT, e))
            } else {
                Ok(plain)
            }
        }
        _ => Err(km_err(ErrorCode::UNSUPPORTED_BLOCK_MODE, "unsupported block mode")),
    }
}

fn finish_hmac(st: &OpState, signature: Option<&[u8]>) -> rsbinder::BinderResult<Vec<u8>> {
    let mac_bytes = (st.mac_length / 8).max(1) as usize;
    let full = match st.digest {
        Digest::SHA_2_256 => crypto::hmac_sha256(&st.stored.key_material, &[&st.buffer]).to_vec(),
        Digest::SHA_2_512 => crypto::hmac_sha512(&st.stored.key_material, &[&st.buffer]).to_vec(),
        _ => return Err(km_err(ErrorCode::UNSUPPORTED_DIGEST, "unsupported hmac digest")),
    };
    let tag = &full[..mac_bytes.min(full.len())];
    match st.purpose {
        KeyPurpose::SIGN => Ok(tag.to_vec()),
        KeyPurpose::VERIFY => {
            let sig = signature.unwrap_or(&[]);
            if crypto::ct_eq(tag, sig) {
                Ok(Vec::new())
            } else {
                Err(km_err(ErrorCode::VERIFICATION_FAILED, "hmac verify failed"))
            }
        }
        _ => Err(km_err(ErrorCode::INCOMPATIBLE_PURPOSE, "invalid hmac purpose")),
    }
}

fn finish_ec(st: &OpState, signature: Option<&[u8]>) -> rsbinder::BinderResult<Vec<u8>> {
    match st.purpose {
        KeyPurpose::SIGN => crypto::p256_sign(&st.stored.key_material, &st.buffer)
            .map_err(|e| km_err(ErrorCode::UNKNOWN_ERROR, e)),
        KeyPurpose::VERIFY => {
            let sig = signature.unwrap_or(&[]);
            let ok = crypto::p256_verify(&st.stored.key_material, &st.buffer, sig)
                .map_err(|e| km_err(ErrorCode::INVALID_ARGUMENT, e))?;
            if ok {
                Ok(Vec::new())
            } else {
                Err(km_err(ErrorCode::VERIFICATION_FAILED, "ec verify failed"))
            }
        }
        _ => Err(km_err(ErrorCode::INCOMPATIBLE_PURPOSE, "invalid ec purpose")),
    }
}

impl Interface for SoftKeyMintSharedSecret {}
struct SoftKeyMintSharedSecret {
    auth_token_key: [u8; 32],
    seed: [u8; 32],
    nonce: [u8; 32],
}

impl ISharedSecret for SoftKeyMintSharedSecret {
    fn getSharedSecretParameters(&self) -> rsbinder::BinderResult<SharedSecretParameters> {
        Ok(SharedSecretParameters {
            seed: self.seed.to_vec(),
            nonce: self.nonce.to_vec(),
        })
    }

    fn computeSharedSecret(
        &self,
        params: &[SharedSecretParameters],
    ) -> rsbinder::BinderResult<Vec<u8>> {
        let mut parts: Vec<&[u8]> = vec![KEY_AGREEMENT_LABEL.as_bytes()];
        for p in params {
            parts.push(&p.seed);
            parts.push(&p.nonce);
        }
        let shared = crypto::hmac_sha256(&self.auth_token_key, &parts);
        Ok(crypto::hmac_sha256(&shared, &[KEY_CHECK_LABEL.as_bytes()]).to_vec())
    }
}

impl Interface for SoftSecureClock {}
struct SoftSecureClock {
    auth_token_key: [u8; 32],
}

impl ISecureClock for SoftSecureClock {
    fn generateTimeStamp(&self, challenge: i64) -> rsbinder::BinderResult<TimeStampToken> {
        let timestamp_ms = monotonic_millis();
        let mac = crypto::hmac_sha256(
            &self.auth_token_key,
            &[
                TIME_STAMP_MAC_LABEL.as_bytes(),
                &challenge.to_be_bytes(),
                &timestamp_ms.to_be_bytes(),
            ],
        );
        Ok(TimeStampToken {
            challenge,
            timestamp: Timestamp {
                milliSeconds: timestamp_ms,
            },
            mac: mac.to_vec(),
        })
    }
}

fn read_keys_from_stdin() -> std::io::Result<([u8; 32], [u8; 32])> {
    let mut buf = [0u8; 64];
    let mut stdin = std::io::stdin().lock();
    match stdin.read_exact(&mut buf) {
        Ok(()) => {
            let mut auth = [0u8; 32];
            let mut master = [0u8; 32];
            auth.copy_from_slice(&buf[..32]);
            master.copy_from_slice(&buf[32..]);
            Ok((auth, master))
        }
        Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => {
            let mut auth = [0u8; 32];
            let mut master = [0u8; 32];
            crypto::getrandom(&mut auth)?;
            crypto::getrandom(&mut master)?;
            Ok((auth, master))
        }
        Err(err) => Err(err),
    }
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let (device, context) = match args.as_slice() {
        [_, cmd, device, context] if cmd == "serve" => (device.parse::<u64>()?, context.as_str()),
        _ => return Err("usage: ssal-keymint serve <binder-rdev> <selinux-context>".into()),
    };
    let (auth_token_key, master_key) = read_keys_from_stdin()?;
    ssal_binder_service::init(device, context)?;

    let km = SoftKeyMint::new(master_key)?;
    let shared_seed = km.shared_seed;
    let shared_nonce = km.shared_nonce;

    ssal_binder_service::register(HAL_KEYMINT, BnKeyMintDevice::new_binder(km))?;
    ssal_binder_service::register(
        HAL_SHARED_SECRET,
        BnSharedSecret::new_binder(SoftKeyMintSharedSecret {
            auth_token_key,
            seed: shared_seed,
            nonce: shared_nonce,
        }),
    )?;
    ssal_binder_service::register(
        HAL_SECURE_CLOCK,
        BnSecureClock::new_binder(SoftSecureClock { auth_token_key }),
    )?;
    ssal_binder_service::join()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes_gcm_and_ec_p256_roundtrip() {
        let km = SoftKeyMint::new([0x11; 32]).unwrap();
        let aes_res = km
            .generateKey(
                &[
                    KeyParameter {
                        tag: Tag::ALGORITHM,
                        value: KeyParameterValue::Algorithm(Algorithm::AES),
                    },
                    KeyParameter {
                        tag: Tag::KEY_SIZE,
                        value: KeyParameterValue::Integer(256),
                    },
                    KeyParameter {
                        tag: Tag::PURPOSE,
                        value: KeyParameterValue::KeyPurpose(KeyPurpose::ENCRYPT),
                    },
                    KeyParameter {
                        tag: Tag::PURPOSE,
                        value: KeyParameterValue::KeyPurpose(KeyPurpose::DECRYPT),
                    },
                    KeyParameter {
                        tag: Tag::BLOCK_MODE,
                        value: KeyParameterValue::BlockMode(BlockMode::GCM),
                    },
                ],
                None,
            )
            .unwrap();
        let begin_enc = km
            .begin(KeyPurpose::ENCRYPT, &aes_res.keyBlob, &[], None)
            .unwrap();
        let nonce = begin_enc
            .params
            .iter()
            .find_map(|p| match &p.value {
                KeyParameterValue::Blob(b) if p.tag == Tag::NONCE => Some(b.clone()),
                _ => None,
            })
            .unwrap();
        let op_enc = begin_enc.operation.unwrap();
        op_enc.updateAad(b"aad", None, None).unwrap();
        let ct = op_enc.finish(Some(b"secret"), None, None, None, None).unwrap();

        let begin_dec = km
            .begin(
                KeyPurpose::DECRYPT,
                &aes_res.keyBlob,
                &[KeyParameter {
                    tag: Tag::NONCE,
                    value: KeyParameterValue::Blob(nonce),
                }],
                None,
            )
            .unwrap();
        let op_dec = begin_dec.operation.unwrap();
        op_dec.updateAad(b"aad", None, None).unwrap();
        let pt = op_dec.finish(Some(&ct), None, None, None, None).unwrap();
        assert_eq!(pt, b"secret");

        let ec_res = km
            .generateKey(
                &[
                    KeyParameter {
                        tag: Tag::ALGORITHM,
                        value: KeyParameterValue::Algorithm(Algorithm::EC),
                    },
                    KeyParameter {
                        tag: Tag::EC_CURVE,
                        value: KeyParameterValue::EcCurve(EcCurve::P_256),
                    },
                    KeyParameter {
                        tag: Tag::PURPOSE,
                        value: KeyParameterValue::KeyPurpose(KeyPurpose::SIGN),
                    },
                    KeyParameter {
                        tag: Tag::PURPOSE,
                        value: KeyParameterValue::KeyPurpose(KeyPurpose::VERIFY),
                    },
                ],
                None,
            )
            .unwrap();
        assert_eq!(ec_res.certificateChain.len(), 1);
        let sign_op = km
            .begin(KeyPurpose::SIGN, &ec_res.keyBlob, &[], None)
            .unwrap()
            .operation
            .unwrap();
        let sig = sign_op.finish(Some(b"hello"), None, None, None, None).unwrap();
        let verify_op = km
            .begin(KeyPurpose::VERIFY, &ec_res.keyBlob, &[], None)
            .unwrap()
            .operation
            .unwrap();
        verify_op
            .finish(Some(b"hello"), Some(&sig), None, None, None)
            .unwrap();
    }
}
