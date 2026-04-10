/// macOS Secure Enclave backend for P-256/ES256 key operations
///
/// Uses Security.framework via the security-framework crate.
/// Keys are created in the Secure Enclave with no biometric/password requirement,
/// making them accessible programmatically from CLI tools.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use core_foundation::base::TCFType;
use core_foundation::boolean::CFBoolean;
use core_foundation::data::CFData;
use core_foundation::dictionary::CFDictionary;
use core_foundation::number::CFNumber;
use core_foundation::string::CFString;
use napi::bindgen_prelude::*;
use security_framework::key::{Algorithm, SecKey};
use security_framework_sys::item::{
    kSecAttrIsPermanent, kSecAttrKeySizeInBits, kSecAttrKeyType,
    kSecAttrKeyTypeECSECPrimeRandom, kSecAttrTokenID, kSecAttrTokenIDSecureEnclave, kSecClass,
    kSecClassKey, kSecPrivateKeyAttrs, kSecReturnRef,
};
use security_framework_sys::key::SecKeyCreateRandomKey;
use std::collections::HashMap;
use std::sync::Mutex;

use crate::{GeneratedKey, HardwareKeyInfo, SignatureResult};

const AAUTH_KEY_LABEL_PREFIX: &str = "com.aauth.agent.";

// kSecAttrApplicationTag is not exported by security-framework-sys,
// so we use kSecAttrApplicationLabel instead for key lookup
extern "C" {
    static kSecAttrApplicationLabel: core_foundation_sys::string::CFStringRef;
}

// In-process cache of SE key handles (since ephemeral keys can't be re-queried from keychain)
static SE_KEYS: std::sync::LazyLock<Mutex<HashMap<String, SecKey>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

/// Check if Secure Enclave is available
pub fn discover() -> Option<HardwareKeyInfo> {
    #[cfg(target_arch = "aarch64")]
    {
        Some(HardwareKeyInfo {
            backend: "secure-enclave".to_string(),
            description: "macOS Secure Enclave (Apple Silicon)".to_string(),
            algorithms: vec!["ES256".to_string()],
            device_id: "local".to_string(),
        })
    }

    #[cfg(not(target_arch = "aarch64"))]
    {
        None
    }
}

/// Generate a P-256 key in the Secure Enclave
pub fn generate_key(algorithm: &str) -> Result<GeneratedKey> {
    if algorithm != "ES256" {
        return Err(Error::from_reason(
            "Secure Enclave only supports ES256 (P-256)",
        ));
    }

    let label = format!("{}{}", AAUTH_KEY_LABEL_PREFIX, simple_date());

    let private_key = create_se_key(&label)?;

    let public_key = private_key
        .public_key()
        .ok_or_else(|| Error::from_reason("Failed to extract public key"))?;

    let public_jwk = se_pubkey_to_jwk(&public_key)?;

    // Cache the key handle for later signing
    SE_KEYS
        .lock()
        .map_err(|e| Error::from_reason(format!("Lock error: {}", e)))?
        .insert(label.clone(), private_key);

    Ok(GeneratedKey {
        backend: "secure-enclave".to_string(),
        key_id: label,
        algorithm: "ES256".to_string(),
        public_jwk,
    })
}

/// Sign a SHA-256 hash with a Secure Enclave key
pub fn sign_hash(key_id: &str, hash: &[u8]) -> Result<SignatureResult> {
    // First check in-process cache, then try keychain
    let keys = SE_KEYS
        .lock()
        .map_err(|e| Error::from_reason(format!("Lock error: {}", e)))?;
    let private_key_ref = keys.get(key_id);
    let loaded_key;
    let private_key = if let Some(k) = private_key_ref {
        k
    } else {
        drop(keys); // release lock before keychain query
        loaded_key = load_se_key(key_id)?;
        &loaded_key
    };

    // ECDSASignatureDigestX962SHA256 expects a pre-computed SHA-256 hash
    let signature_der = private_key
        .create_signature(Algorithm::ECDSASignatureDigestX962SHA256, hash)
        .map_err(|e| Error::from_reason(format!("Secure Enclave sign failed: {}", e)))?;

    let raw_sig = der_ecdsa_to_raw(&signature_der)?;

    Ok(SignatureResult {
        signature: raw_sig.into(),
        algorithm: "ES256".to_string(),
    })
}

/// List keys stored in the Secure Enclave with our label prefix
pub fn list_keys() -> Result<Vec<GeneratedKey>> {
    // TODO: query keychain for keys with our label prefix
    Ok(Vec::new())
}

/// Create a P-256 key in the Secure Enclave via Security.framework
fn create_se_key(label: &str) -> Result<SecKey> {
    let label_data = CFData::from_buffer(label.as_bytes());

    // Private key attributes
    // Note: kSecAttrIsPermanent = false for non-codesigned binaries (like node)
    // because errSecMissingEntitlement (-34018) prevents keychain persistence.
    // The key lives only for the process lifetime. For persistent SE keys,
    // the binary must be codesigned with keychain-access-groups entitlement.
    let private_key_attrs = CFDictionary::from_CFType_pairs(&[
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrIsPermanent) },
            CFBoolean::false_value().as_CFType(),
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrApplicationLabel) },
            label_data.as_CFType(),
        ),
    ]);

    // Key generation parameters
    let params = CFDictionary::from_CFType_pairs(&[
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrKeyType) },
            unsafe { CFString::wrap_under_get_rule(kSecAttrKeyTypeECSECPrimeRandom).as_CFType() },
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrKeySizeInBits) },
            CFNumber::from(256i32).as_CFType(),
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrTokenID) },
            unsafe { CFString::wrap_under_get_rule(kSecAttrTokenIDSecureEnclave).as_CFType() },
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecPrivateKeyAttrs) },
            private_key_attrs.as_CFType(),
        ),
    ]);

    let mut error: core_foundation_sys::error::CFErrorRef = std::ptr::null_mut();
    let key = unsafe { SecKeyCreateRandomKey(params.as_concrete_TypeRef(), &mut error) };

    if key.is_null() {
        let err_msg = if !error.is_null() {
            let cf_error = unsafe { core_foundation::error::CFError::wrap_under_create_rule(error) };
            format!("Secure Enclave key creation failed: {}", cf_error.description())
        } else {
            "Failed to create Secure Enclave key (unknown error)".to_string()
        };
        return Err(Error::from_reason(err_msg));
    }

    Ok(unsafe { SecKey::wrap_under_create_rule(key) })
}

/// Load an existing Secure Enclave key by label
fn load_se_key(label: &str) -> Result<SecKey> {
    let label_data = CFData::from_buffer(label.as_bytes());

    let query = CFDictionary::from_CFType_pairs(&[
        (
            unsafe { CFString::wrap_under_get_rule(kSecClass) },
            unsafe { CFString::wrap_under_get_rule(kSecClassKey).as_CFType() },
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrApplicationLabel) },
            label_data.as_CFType(),
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrKeyType) },
            unsafe {
                CFString::wrap_under_get_rule(kSecAttrKeyTypeECSECPrimeRandom).as_CFType()
            },
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecReturnRef) },
            CFBoolean::true_value().as_CFType(),
        ),
    ]);

    let mut result: core_foundation::base::CFTypeRef = std::ptr::null_mut();
    let status = unsafe {
        security_framework_sys::keychain_item::SecItemCopyMatching(
            query.as_concrete_TypeRef(),
            &mut result,
        )
    };

    if status != 0 || result.is_null() {
        return Err(Error::from_reason(format!(
            "Secure Enclave key not found for label: {} (status: {})",
            label, status
        )));
    }

    Ok(unsafe { SecKey::wrap_under_create_rule(result as *mut _) })
}

/// Convert SecKey public key to JWK
fn se_pubkey_to_jwk(public_key: &SecKey) -> Result<String> {
    let external_rep = public_key
        .external_representation()
        .ok_or_else(|| Error::from_reason("Failed to export public key"))?;

    let bytes = external_rep.to_vec();

    // External representation for EC P-256: 04 || x (32 bytes) || y (32 bytes)
    if bytes.len() != 65 || bytes[0] != 0x04 {
        return Err(Error::from_reason(format!(
            "Unexpected public key format: {} bytes",
            bytes.len()
        )));
    }

    let x = &bytes[1..33];
    let y = &bytes[33..65];

    let x_b64 = URL_SAFE_NO_PAD.encode(x);
    let y_b64 = URL_SAFE_NO_PAD.encode(y);

    Ok(format!(
        r#"{{"kty":"EC","crv":"P-256","x":"{}","y":"{}","alg":"ES256","use":"sig"}}"#,
        x_b64, y_b64
    ))
}

/// Convert DER-encoded ECDSA signature to raw r||s format (64 bytes)
fn der_ecdsa_to_raw(der: &[u8]) -> Result<Vec<u8>> {
    if der.len() < 8 || der[0] != 0x30 {
        return Err(Error::from_reason("Invalid DER ECDSA signature"));
    }

    let mut pos = 2;

    if der[pos] != 0x02 {
        return Err(Error::from_reason("Expected INTEGER tag for r"));
    }
    pos += 1;
    let r_len = der[pos] as usize;
    pos += 1;
    let r_bytes = &der[pos..pos + r_len];
    pos += r_len;

    if der[pos] != 0x02 {
        return Err(Error::from_reason("Expected INTEGER tag for s"));
    }
    pos += 1;
    let s_len = der[pos] as usize;
    pos += 1;
    let s_bytes = &der[pos..pos + s_len];

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

fn simple_date() -> String {
    use std::process::Command;
    Command::new("date")
        .arg("+%Y-%m-%d")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}
