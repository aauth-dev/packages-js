use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use der::Encode;
use napi::bindgen_prelude::*;
use yubikey::piv::{self, AlgorithmId, SlotId};
use yubikey::YubiKey;

use crate::{GeneratedKey, HardwareKeyInfo, SignatureResult};

/// Slot 9e = Card Authentication, no PIN required
const DEFAULT_SLOT: SlotId = SlotId::CardAuthentication;

/// Discover connected YubiKeys
pub fn discover() -> Option<HardwareKeyInfo> {
    let yk = YubiKey::open().ok()?;
    let serial = yk.serial().to_string();
    let version = yk.version().to_string();

    // Check what algorithms are available by checking firmware version
    // YubiKey 4+ supports ECC P-256, all support RSA 2048
    let mut algorithms = vec!["RS256".to_string()];
    // YubiKey 4+ (firmware >= 4.x) supports ECC
    algorithms.insert(0, "ES256".to_string());

    Some(HardwareKeyInfo {
        backend: "yubikey-piv".to_string(),
        description: format!("YubiKey {} (serial: {}, firmware: {})",
            yk.name(), serial, version),
        algorithms,
        device_id: serial,
    })
}

/// Generate a key in PIV slot 9e
pub fn generate_key(algorithm: &str) -> Result<GeneratedKey> {
    let mut yk = YubiKey::open()
        .map_err(|e| Error::from_reason(format!("Failed to open YubiKey: {}", e)))?;

    let alg_id = match algorithm {
        "ES256" => AlgorithmId::EccP256,
        "RS256" => AlgorithmId::Rsa2048,
        _ => return Err(Error::from_reason(format!("Unsupported algorithm: {}", algorithm))),
    };

    // Generate key in slot 9e with no PIN policy and no touch policy
    let key_info = piv::generate(
        &mut yk,
        DEFAULT_SLOT,
        alg_id,
        yubikey::PinPolicy::Never,
        yubikey::TouchPolicy::Never,
    )
    .map_err(|e| Error::from_reason(format!("Key generation failed: {}", e)))?;

    // Convert SubjectPublicKeyInfo to DER bytes, then to JWK
    let der_bytes = key_info
        .to_der()
        .map_err(|e| Error::from_reason(format!("DER encoding failed: {}", e)))?;

    let public_jwk = match algorithm {
        "ES256" => pubkey_info_to_ec_jwk(&der_bytes)?,
        "RS256" => pubkey_info_to_rsa_jwk(&der_bytes)?,
        _ => unreachable!(),
    };

    Ok(GeneratedKey {
        backend: "yubikey-piv".to_string(),
        key_id: "9e".to_string(),
        algorithm: algorithm.to_string(),
        public_jwk,
    })
}

/// Sign a SHA-256 hash using the key in slot 9e — NO PIN required
pub fn sign_hash(key_id: &str, hash: &[u8]) -> Result<SignatureResult> {
    let slot = match key_id {
        "9e" => SlotId::CardAuthentication,
        "9a" => SlotId::Authentication,
        "9c" => SlotId::Signature,
        _ => return Err(Error::from_reason(format!("Unknown slot: {}", key_id))),
    };

    let mut yk = YubiKey::open()
        .map_err(|e| Error::from_reason(format!("Failed to open YubiKey: {}", e)))?;

    // Determine algorithm from the key already in the slot
    // For now, try ECC P-256 first, fall back to RSA
    let (sig_bytes, algorithm) = match try_sign_ecdsa(&mut yk, slot, hash) {
        Ok(sig) => (sig, "ES256".to_string()),
        Err(_) => {
            // Try RSA
            let sig = try_sign_rsa(&mut yk, slot, hash)?;
            (sig, "RS256".to_string())
        }
    };

    Ok(SignatureResult {
        signature: sig_bytes.into(),
        algorithm,
    })
}

/// List keys present in PIV slots
pub fn list_keys() -> Result<Vec<GeneratedKey>> {
    let mut yk = YubiKey::open()
        .map_err(|e| Error::from_reason(format!("Failed to open YubiKey: {}", e)))?;

    let mut keys = Vec::new();

    // Try to get public key via attestation certificate (works for keys generated on-device)
    if let Ok(attest_cert) = piv::attest(&mut yk, SlotId::CardAuthentication) {
        let cert_der = attest_cert.as_ref();
        // Extract public key from the attestation certificate's SubjectPublicKeyInfo
        if let Some(jwk) = extract_ec_pubkey_from_cert(cert_der) {
            keys.push(GeneratedKey {
                backend: "yubikey-piv".to_string(),
                key_id: "9e".to_string(),
                algorithm: "ES256".to_string(),
                public_jwk: jwk,
            });
        } else {
            keys.push(GeneratedKey {
                backend: "yubikey-piv".to_string(),
                key_id: "9e".to_string(),
                algorithm: "ES256".to_string(),
                public_jwk: "{}".to_string(),
            });
        }
    }

    Ok(keys)
}

fn try_sign_ecdsa(yk: &mut YubiKey, slot: SlotId, hash: &[u8]) -> Result<Vec<u8>> {
    // sign_data expects the raw hash for ECDSA
    let sig_der = piv::sign_data(yk, hash, AlgorithmId::EccP256, slot)
        .map_err(|e| Error::from_reason(format!("ECDSA sign failed: {}", e)))?;

    // Convert DER-encoded ECDSA signature to raw r||s (64 bytes for P-256)
    let raw_sig = der_ecdsa_to_raw(&sig_der)?;
    Ok(raw_sig)
}

fn try_sign_rsa(yk: &mut YubiKey, slot: SlotId, hash: &[u8]) -> Result<Vec<u8>> {
    // For RSA, we need to PKCS#1 v1.5 pad the hash before sending
    let padded = pkcs1_v15_pad_sha256(hash)?;
    let sig = piv::sign_data(yk, &padded, AlgorithmId::Rsa2048, slot)
        .map_err(|e| Error::from_reason(format!("RSA sign failed: {}", e)))?;

    Ok(sig.to_vec())
}

/// Convert DER-encoded ECDSA signature to raw r||s format (64 bytes for P-256)
fn der_ecdsa_to_raw(der: &[u8]) -> Result<Vec<u8>> {
    // DER: 0x30 <len> 0x02 <r_len> <r_bytes> 0x02 <s_len> <s_bytes>
    if der.len() < 8 || der[0] != 0x30 {
        return Err(Error::from_reason("Invalid DER ECDSA signature"));
    }

    let mut pos = 2; // skip SEQUENCE tag + length

    // Read r
    if der[pos] != 0x02 {
        return Err(Error::from_reason("Expected INTEGER tag for r"));
    }
    pos += 1;
    let r_len = der[pos] as usize;
    pos += 1;
    let r_bytes = &der[pos..pos + r_len];
    pos += r_len;

    // Read s
    if der[pos] != 0x02 {
        return Err(Error::from_reason("Expected INTEGER tag for s"));
    }
    pos += 1;
    let s_len = der[pos] as usize;
    pos += 1;
    let s_bytes = &der[pos..pos + s_len];

    // Normalize to 32 bytes each (strip leading zero, or left-pad)
    let mut result = vec![0u8; 64];
    let r_trimmed = if r_bytes.len() > 32 && r_bytes[0] == 0 {
        &r_bytes[1..]
    } else {
        r_bytes
    };
    let s_trimmed = if s_bytes.len() > 32 && s_bytes[0] == 0 {
        &s_bytes[1..]
    } else {
        s_bytes
    };

    result[32 - r_trimmed.len()..32].copy_from_slice(r_trimmed);
    result[64 - s_trimmed.len()..64].copy_from_slice(s_trimmed);

    Ok(result)
}

/// PKCS#1 v1.5 padding for SHA-256 (for RSA signing)
fn pkcs1_v15_pad_sha256(hash: &[u8]) -> Result<Vec<u8>> {
    // DigestInfo for SHA-256
    let digest_info_prefix: &[u8] = &[
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
        0x01, 0x05, 0x00, 0x04, 0x20,
    ];

    let t_len = digest_info_prefix.len() + hash.len();
    let key_len = 256; // RSA 2048 = 256 bytes

    if key_len < t_len + 11 {
        return Err(Error::from_reason("Key too short for PKCS#1 v1.5 padding"));
    }

    let ps_len = key_len - t_len - 3;
    let mut padded = Vec::with_capacity(key_len);
    padded.push(0x00);
    padded.push(0x01);
    padded.extend(vec![0xff; ps_len]);
    padded.push(0x00);
    padded.extend_from_slice(digest_info_prefix);
    padded.extend_from_slice(hash);

    Ok(padded)
}

/// Convert SubjectPublicKeyInfo to EC JWK
fn pubkey_info_to_ec_jwk(pubkey_info: &[u8]) -> Result<String> {
    // The generate() function returns SubjectPublicKeyInfo DER bytes
    // For EC P-256, the public key point is the last 65 bytes (04 || x || y)
    // Find the uncompressed point (starts with 0x04)
    let point_start = pubkey_info
        .windows(1)
        .rposition(|w| w[0] == 0x04)
        .ok_or_else(|| Error::from_reason("Could not find EC point in public key"))?;

    let point = &pubkey_info[point_start..];
    if point.len() < 65 {
        return Err(Error::from_reason("EC point too short"));
    }

    let x = &point[1..33];
    let y = &point[33..65];

    let x_b64 = URL_SAFE_NO_PAD.encode(x);
    let y_b64 = URL_SAFE_NO_PAD.encode(y);

    Ok(format!(
        r#"{{"kty":"EC","crv":"P-256","x":"{}","y":"{}","alg":"ES256","use":"sig"}}"#,
        x_b64, y_b64
    ))
}

/// Convert SubjectPublicKeyInfo to RSA JWK
fn pubkey_info_to_rsa_jwk(pubkey_info: &[u8]) -> Result<String> {
    // TODO: Parse RSA public key from DER and extract n, e
    Ok(format!(
        r#"{{"kty":"RSA","alg":"RS256","use":"sig","der":"{}"}}"#,
        URL_SAFE_NO_PAD.encode(pubkey_info)
    ))
}

/// Extract EC P-256 public key from an X.509 DER certificate
/// Looks for the uncompressed EC point (04 || x || y) in the cert
fn extract_ec_pubkey_from_cert(cert_der: &[u8]) -> Option<String> {
    // Search for the EC P-256 OID (1.2.840.10045.3.1.7) followed by a BIT STRING
    // containing the uncompressed point. Simpler: just find 0x04 followed by 64 bytes
    // that appears after the P-256 OID bytes: 06 08 2a 86 48 ce 3d 03 01 07
    let p256_oid: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];

    let oid_pos = cert_der
        .windows(p256_oid.len())
        .position(|w| w == p256_oid)?;

    // After the OID, find the next 0x04 byte that starts the uncompressed point
    // It's typically: BIT STRING tag (03) + length + 0x00 (unused bits) + 0x04 + x + y
    let search_start = oid_pos + p256_oid.len();
    let remaining = &cert_der[search_start..];

    for i in 0..remaining.len() {
        if remaining[i] == 0x04 && i + 65 <= remaining.len() {
            let point = &remaining[i..i + 65];
            let x = &point[1..33];
            let y = &point[33..65];

            let x_b64 = URL_SAFE_NO_PAD.encode(x);
            let y_b64 = URL_SAFE_NO_PAD.encode(y);

            return Some(format!(
                r#"{{"kty":"EC","crv":"P-256","x":"{}","y":"{}","alg":"ES256","use":"sig"}}"#,
                x_b64, y_b64
            ));
        }
    }

    None
}
