use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit, KeyIvInit, StreamCipher};
use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, Nonce,
};
use p256::{
    ecdsa::{
        signature::{Signer, Verifier},
        Signature, SigningKey, VerifyingKey,
    },
    pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey},
};
use sha2::{Digest, Sha256, Sha512};

pub fn getrandom(buf: &mut [u8]) -> std::io::Result<()> {
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

pub fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
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

pub fn hmac_sha512(key: &[u8], parts: &[&[u8]]) -> [u8; 64] {
    let mut k_pad = [0u8; 128];
    if key.len() > 128 {
        let hashed = Sha512::digest(key);
        k_pad[..64].copy_from_slice(&hashed);
    } else {
        k_pad[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; 128];
    let mut opad = [0x5cu8; 128];
    for i in 0..128 {
        ipad[i] ^= k_pad[i];
        opad[i] ^= k_pad[i];
    }
    let mut inner = Sha512::new();
    inner.update(ipad);
    for part in parts {
        inner.update(part);
    }
    let inner_hash = inner.finalize();

    let mut outer = Sha512::new();
    outer.update(opad);
    outer.update(inner_hash);
    outer.finalize().into()
}

pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

pub fn seal_blob(master_key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, &'static str> {
    let cipher = Aes256Gcm::new_from_slice(master_key).map_err(|_| "bad master key")?;
    let mut nonce = [0u8; 12];
    getrandom(&mut nonce).map_err(|_| "rng failed")?;
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: b"SSAL-KM-V1",
            },
        )
        .map_err(|_| "seal failed")?;
    let mut out = Vec::with_capacity(5 + 12 + ct.len());
    out.extend_from_slice(b"SSKM\x01");
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn open_blob(master_key: &[u8; 32], blob: &[u8]) -> Result<Vec<u8>, &'static str> {
    if blob.len() < 5 + 12 + 16 || &blob[..5] != b"SSKM\x01" {
        return Err("invalid blob header");
    }
    let cipher = Aes256Gcm::new_from_slice(master_key).map_err(|_| "bad master key")?;
    cipher
        .decrypt(
            Nonce::from_slice(&blob[5..17]),
            Payload {
                msg: &blob[17..],
                aad: b"SSAL-KM-V1",
            },
        )
        .map_err(|_| "invalid key blob")
}

pub fn aes_gcm_encrypt(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, &'static str> {
    if nonce.len() != 12 {
        return Err("invalid gcm nonce length");
    }
    let payload = Payload { msg: plaintext, aad };
    let n = Nonce::from_slice(nonce);
    match key.len() {
        16 => aes_gcm::Aes128Gcm::new_from_slice(key)
            .map_err(|_| "bad aes key")?
            .encrypt(n, payload)
            .map_err(|_| "encrypt failed"),
        32 => Aes256Gcm::new_from_slice(key)
            .map_err(|_| "bad aes key")?
            .encrypt(n, payload)
            .map_err(|_| "encrypt failed"),
        _ => Err("unsupported aes key size"),
    }
}

pub fn aes_gcm_decrypt(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, &'static str> {
    if nonce.len() != 12 {
        return Err("invalid gcm nonce length");
    }
    let payload = Payload { msg: ciphertext, aad };
    let n = Nonce::from_slice(nonce);
    match key.len() {
        16 => aes_gcm::Aes128Gcm::new_from_slice(key)
            .map_err(|_| "bad aes key")?
            .decrypt(n, payload)
            .map_err(|_| "decrypt failed"),
        32 => Aes256Gcm::new_from_slice(key)
            .map_err(|_| "bad aes key")?
            .decrypt(n, payload)
            .map_err(|_| "decrypt failed"),
        _ => Err("unsupported aes key size"),
    }
}

pub fn pkcs7_pad(data: &[u8], block_size: usize) -> Vec<u8> {
    let pad = block_size - (data.len() % block_size);
    let mut out = Vec::with_capacity(data.len() + pad);
    out.extend_from_slice(data);
    out.resize(data.len() + pad, pad as u8);
    out
}

pub fn pkcs7_unpad(data: &[u8], block_size: usize) -> Result<Vec<u8>, &'static str> {
    if data.is_empty() || data.len() % block_size != 0 {
        return Err("invalid padded length");
    }
    let pad = *data.last().unwrap() as usize;
    if pad == 0 || pad > block_size || data[data.len() - pad..].iter().any(|&b| b as usize != pad) {
        return Err("invalid pkcs7 padding");
    }
    Ok(data[..data.len() - pad].to_vec())
}

pub fn aes_cbc_encrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, &'static str> {
    if iv.len() != 16 || data.len() % 16 != 0 {
        return Err("invalid cbc input");
    }
    let mut buf = data.to_vec();
    match key.len() {
        16 => {
            use cbc::cipher::BlockEncryptMut;
            cbc::Encryptor::<aes::Aes128>::new_from_slices(key, iv)
                .map_err(|_| "bad key/iv")?
                .encrypt_blocks_mut(as_blocks_mut(&mut buf));
        }
        32 => {
            use cbc::cipher::BlockEncryptMut;
            cbc::Encryptor::<aes::Aes256>::new_from_slices(key, iv)
                .map_err(|_| "bad key/iv")?
                .encrypt_blocks_mut(as_blocks_mut(&mut buf));
        }
        _ => return Err("unsupported aes key size"),
    }
    Ok(buf)
}

pub fn aes_cbc_decrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, &'static str> {
    if iv.len() != 16 || data.len() % 16 != 0 {
        return Err("invalid cbc input");
    }
    let mut buf = data.to_vec();
    match key.len() {
        16 => {
            use cbc::cipher::BlockDecryptMut;
            cbc::Decryptor::<aes::Aes128>::new_from_slices(key, iv)
                .map_err(|_| "bad key/iv")?
                .decrypt_blocks_mut(as_blocks_mut(&mut buf));
        }
        32 => {
            use cbc::cipher::BlockDecryptMut;
            cbc::Decryptor::<aes::Aes256>::new_from_slices(key, iv)
                .map_err(|_| "bad key/iv")?
                .decrypt_blocks_mut(as_blocks_mut(&mut buf));
        }
        _ => return Err("unsupported aes key size"),
    }
    Ok(buf)
}

pub fn aes_ctr_crypt(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, &'static str> {
    if iv.len() != 16 {
        return Err("invalid ctr iv");
    }
    let mut buf = data.to_vec();
    match key.len() {
        16 => ctr::Ctr128BE::<aes::Aes128>::new_from_slices(key, iv)
            .map_err(|_| "bad key/iv")?
            .apply_keystream(&mut buf),
        32 => ctr::Ctr128BE::<aes::Aes256>::new_from_slices(key, iv)
            .map_err(|_| "bad key/iv")?
            .apply_keystream(&mut buf),
        _ => return Err("unsupported aes key size"),
    }
    Ok(buf)
}

pub fn aes_ecb_encrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>, &'static str> {
    if data.len() % 16 != 0 {
        return Err("invalid ecb input");
    }
    let mut buf = data.to_vec();
    match key.len() {
        16 => {
            let cipher = aes::Aes128::new_from_slice(key).map_err(|_| "bad key")?;
            for block in as_blocks_mut(&mut buf) {
                cipher.encrypt_block(block);
            }
        }
        32 => {
            let cipher = aes::Aes256::new_from_slice(key).map_err(|_| "bad key")?;
            for block in as_blocks_mut(&mut buf) {
                cipher.encrypt_block(block);
            }
        }
        _ => return Err("unsupported aes key size"),
    }
    Ok(buf)
}

pub fn aes_ecb_decrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>, &'static str> {
    if data.len() % 16 != 0 {
        return Err("invalid ecb input");
    }
    let mut buf = data.to_vec();
    match key.len() {
        16 => {
            let cipher = aes::Aes128::new_from_slice(key).map_err(|_| "bad key")?;
            for block in as_blocks_mut(&mut buf) {
                cipher.decrypt_block(block);
            }
        }
        32 => {
            let cipher = aes::Aes256::new_from_slice(key).map_err(|_| "bad key")?;
            for block in as_blocks_mut(&mut buf) {
                cipher.decrypt_block(block);
            }
        }
        _ => return Err("unsupported aes key size"),
    }
    Ok(buf)
}

fn as_blocks_mut(buf: &mut [u8]) -> &mut [aes::Block] {
    let len = buf.len() / 16;
    unsafe { std::slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut aes::Block, len) }
}

pub fn generate_p256_pkcs8() -> Result<(Vec<u8>, Vec<u8>), &'static str> {
    let mut seed = [0u8; 32];
    loop {
        getrandom(&mut seed).map_err(|_| "rng failed")?;
        if let Ok(sk) = SigningKey::from_bytes(&seed.into()) {
            let pkcs8 = sk.to_pkcs8_der().map_err(|_| "pkcs8 encode")?;
            let cert = build_self_signed_p256_cert(&sk)?;
            return Ok((pkcs8.as_bytes().to_vec(), cert));
        }
    }
}

pub fn p256_sign(pkcs8_der: &[u8], msg: &[u8]) -> Result<Vec<u8>, &'static str> {
    let sk = SigningKey::from_pkcs8_der(pkcs8_der).map_err(|_| "bad p256 key")?;
    let sig: Signature = sk.sign(msg);
    Ok(sig.to_der().as_bytes().to_vec())
}

pub fn p256_verify(pkcs8_der: &[u8], msg: &[u8], sig_der: &[u8]) -> Result<bool, &'static str> {
    let sk = SigningKey::from_pkcs8_der(pkcs8_der).map_err(|_| "bad p256 key")?;
    let vk = VerifyingKey::from(&sk);
    let sig = Signature::from_der(sig_der).map_err(|_| "bad signature")?;
    Ok(vk.verify(msg, &sig).is_ok())
}

fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    if len < 128 {
        out.push(len as u8);
    } else if len < 256 {
        out.push(0x81);
        out.push(len as u8);
    } else {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push(len as u8);
    }
    out.extend_from_slice(content);
    out
}

fn der_seq(parts: &[&[u8]]) -> Vec<u8> {
    let mut body = Vec::new();
    for p in parts {
        body.extend_from_slice(p);
    }
    der_tlv(0x30, &body)
}

/// Minimal DER X.509 v3 self-signed certificate for software EC P-256 keys.
pub fn build_self_signed_p256_cert(sk: &SigningKey) -> Result<Vec<u8>, &'static str> {
    let spki = sk
        .verifying_key()
        .to_public_key_der()
        .map_err(|_| "spki encode")?;
    // Version: [0] EXPLICIT INTEGER 2 (v3)
    let version = der_tlv(0xA0, &der_tlv(0x02, &[2]));
    // SerialNumber: INTEGER 1
    let serial = der_tlv(0x02, &[1]);
    // SignatureAlgorithm: ecdsa-with-SHA256 (1.2.840.10045.4.3.2)
    let sig_alg = der_seq(&[&der_tlv(
        0x06,
        &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02],
    )]);
    // Issuer / Subject: CN=SSAL
    let cn_oid = der_tlv(0x06, &[0x55, 0x04, 0x03]);
    let cn_val = der_tlv(0x0C, b"SSAL");
    let rdn = der_tlv(0x31, &der_seq(&[&cn_oid, &cn_val]));
    let name = der_seq(&[&rdn]);
    // Validity: 2025-01-01 to 2049-12-31
    let not_before = der_tlv(0x17, b"250101000000Z");
    let not_after = der_tlv(0x17, b"491231235959Z");
    let validity = der_seq(&[&not_before, &not_after]);

    let tbs = der_seq(&[
        &version,
        &serial,
        &sig_alg,
        &name,
        &validity,
        &name,
        spki.as_bytes(),
    ]);
    let sig: Signature = sk.sign(&tbs);
    let sig_der = sig.to_der();
    let mut bit_string = Vec::with_capacity(1 + sig_der.as_bytes().len());
    bit_string.push(0);
    bit_string.extend_from_slice(sig_der.as_bytes());
    let sig_bits = der_tlv(0x03, &bit_string);

    Ok(der_seq(&[&tbs, &sig_alg, &sig_bits]))
}
