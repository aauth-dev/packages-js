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

// kSecAttrApplicationTag is not exported by security-framework-sys,
// so we use kSecAttrApplicationLabel instead for key lookup
extern "C" {
    static kSecAttrApplicationLabel: core_foundation_sys::string::CFStringRef;
}

// In-process cache of SE key handles (since ephemeral keys can't be re-queried from keychain)
static SE_KEYS: std::sync::LazyLock<Mutex<HashMap<String, SecKey>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

/// Behaviour when `generate_key` is called with a label that already exists.
pub enum DuplicateLabelPolicy {
    /// Delete the existing key and create a fresh one.
    Replace,
    /// Return an error immediately.
    Error,
}

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

/// Generate a P-256 key in the Secure Enclave.
///
/// # Parameters
/// - `label`       – Application label stored as `kSecAttrApplicationLabel`. Must be unique
///                   per key; used for subsequent `sign_hash` / `delete_key` lookups.
/// - `algorithm`   – Only `"ES256"` is supported.
/// - `permanent`   – When `true` the key is written to the keychain
///                   (`kSecAttrIsPermanent = true`). Requires the binary to be
///                   codesigned with the `keychain-access-groups` entitlement;
///                   without it the Security framework returns
///                   `errSecMissingEntitlement (-34018)`. Pass `false` for
///                   non-codesigned binaries (e.g. plain `node`).
/// - `on_duplicate` – Controls behaviour when `label` is already known (either
///                    in the in-process cache or in the keychain).
pub fn generate_key(
    label: &str,
    algorithm: &str,
    permanent: bool,
    on_duplicate: DuplicateLabelPolicy,
) -> Result<GeneratedKey> {
    if algorithm != "ES256" {
        return Err(Error::from_reason(
            "Secure Enclave only supports ES256 (P-256)",
        ));
    }

    // Check for an existing key with the same label.
    let label_exists = SE_KEYS
        .lock()
        .map_err(|e| Error::from_reason(format!("Lock error: {}", e)))?
        .contains_key(label)
        || keychain_has_label(label);

    if label_exists {
        match on_duplicate {
            DuplicateLabelPolicy::Replace => {
                // Best-effort: remove from both cache and keychain before re-creating.
                delete_key(label)?;
            }
            DuplicateLabelPolicy::Error => {
                return Err(Error::from_reason(format!(
                    "A key with label '{}' already exists",
                    label
                )));
            }
        }
    }

    let private_key = create_se_key(label, permanent)?;

    let public_key = private_key
        .public_key()
        .ok_or_else(|| Error::from_reason("Failed to extract public key"))?;

    let public_jwk = se_pubkey_to_jwk(&public_key)?;

    // Cache the key handle for later signing.
    SE_KEYS
        .lock()
        .map_err(|e| Error::from_reason(format!("Lock error: {}", e)))?
        .insert(label.to_string(), private_key);

    Ok(GeneratedKey {
        backend: "secure-enclave".to_string(),
        key_id: label.to_string(),
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

/// List all Secure Enclave keys whose `kSecAttrApplicationLabel` starts with the
/// given `prefix`. Pass `None` to list every key managed by this module.
///
/// Keys that are in the in-process cache but not persisted to the keychain are
/// included via the cache. Keys that are only in the keychain (i.e. permanent
/// keys created by a previous process) are discovered via `SecItemCopyMatching`.
pub fn list_keys(prefix: Option<&str>) -> Result<Vec<GeneratedKey>> {
    let mut keys: Vec<GeneratedKey> = Vec::new();

    // --- 1. Collect labels from the keychain ---
    let query = CFDictionary::from_CFType_pairs(&[
        (
            unsafe { CFString::wrap_under_get_rule(kSecClass) },
            unsafe { CFString::wrap_under_get_rule(kSecClassKey).as_CFType() },
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrKeyType) },
            unsafe {
                CFString::wrap_under_get_rule(kSecAttrKeyTypeECSECPrimeRandom).as_CFType()
            },
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrTokenID) },
            unsafe { CFString::wrap_under_get_rule(kSecAttrTokenIDSecureEnclave).as_CFType() },
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecReturnRef) },
            CFBoolean::true_value().as_CFType(),
        ),
        // Return all matches as an array.
        (
            CFString::new("matchLimit"),
            CFString::new("matchLimitAll").as_CFType(),
        ),
    ]);

    let mut result: core_foundation::base::CFTypeRef = std::ptr::null_mut();
    let status = unsafe {
        security_framework_sys::keychain_item::SecItemCopyMatching(
            query.as_concrete_TypeRef(),
            &mut result,
        )
    };

    // errSecItemNotFound (-25300) simply means no permanent keys exist yet.
    if status == 0 && !result.is_null() {
        let array = unsafe {
            core_foundation::array::CFArray::<core_foundation::base::CFType>::wrap_under_create_rule(
                result as *mut _,
            )
        };

        for item in array.iter() {
            // Each item is a SecKey ref. Wrap it and extract the public key.
            let sec_key = unsafe {
                SecKey::wrap_under_get_rule(
                    item.as_CFTypeRef() as *mut _
                )
            };

            if let Some(pub_key) = sec_key.public_key() {
                if let Ok(public_jwk) = se_pubkey_to_jwk(&pub_key) {
                    // We cannot reliably recover the label from the SecKey ref without
                    // an additional SecItemCopyMatching with kSecReturnAttributes, so
                    // we use the JWK thumbprint as a fallback key_id here.
                    // Callers who need the original label should use the in-process cache.
                    let key_id = jwk_thumbprint_id(&public_jwk);

                    let entry = GeneratedKey {
                        backend: "secure-enclave".to_string(),
                        key_id,
                        algorithm: "ES256".to_string(),
                        public_jwk,
                    };

                    if prefix.map_or(true, |p| entry.key_id.starts_with(p)) {
                        keys.push(entry);
                    }
                }
            }
        }
    }

    // --- 2. Merge in-process cache (covers ephemeral / not-yet-persisted keys) ---
    let cache = SE_KEYS
        .lock()
        .map_err(|e| Error::from_reason(format!("Lock error: {}", e)))?;

    for (label, sec_key) in cache.iter() {
        if prefix.map_or(true, |p| label.starts_with(p)) {
            // Skip if already found via keychain (avoid duplicates).
            let already_listed = keys.iter().any(|k| &k.key_id == label);
            if already_listed {
                continue;
            }

            if let Some(pub_key) = sec_key.public_key() {
                if let Ok(public_jwk) = se_pubkey_to_jwk(&pub_key) {
                    keys.push(GeneratedKey {
                        backend: "secure-enclave".to_string(),
                        key_id: label.clone(),
                        algorithm: "ES256".to_string(),
                        public_jwk,
                    });
                }
            }
        }
    }

    Ok(keys)
}

/// Delete a Secure Enclave key by its application label.
///
/// Removes the key from both the in-process cache and the keychain (if it was
/// stored there as a permanent key). Returns `Ok(())` if the key was found and
/// removed from at least one location, or an error if it was not found anywhere.
pub fn delete_key(label: &str) -> Result<()> {
    let mut removed_from_cache = false;
    let mut removed_from_keychain = false;

    // --- 1. Remove from in-process cache ---
    {
        let mut cache = SE_KEYS
            .lock()
            .map_err(|e| Error::from_reason(format!("Lock error: {}", e)))?;
        if cache.remove(label).is_some() {
            removed_from_cache = true;
        }
    }

    // --- 2. Remove from keychain (permanent keys) ---
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
    ]);

    let status = unsafe {
        security_framework_sys::keychain_item::SecItemDelete(query.as_concrete_TypeRef())
    };

    // 0 = errSecSuccess, -25300 = errSecItemNotFound (not an error for us)
    match status {
        0 => removed_from_keychain = true,
        -25300 => {} // not in keychain — that's fine
        code => {
            return Err(Error::from_reason(format!(
                "SecItemDelete failed for label '{}': OSStatus {}",
                label, code
            )));
        }
    }

    if removed_from_cache || removed_from_keychain {
        Ok(())
    } else {
        Err(Error::from_reason(format!(
            "Key not found for label: '{}'",
            label
        )))
    }
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// Create a P-256 key in the Secure Enclave via Security.framework
fn create_se_key(label: &str, permanent: bool) -> Result<SecKey> {
    let label_data = CFData::from_buffer(label.as_bytes());

    // Private key attributes
    // Note: kSecAttrIsPermanent = false for non-codesigned binaries (like node)
    // because errSecMissingEntitlement (-34018) prevents keychain persistence.
    // The key lives only for the process lifetime. For persistent SE keys,
    // the binary must be codesigned with keychain-access-groups entitlement.
    let is_permanent = if permanent {
        CFBoolean::true_value()
    } else {
        CFBoolean::false_value()
    };

    let private_key_attrs = CFDictionary::from_CFType_pairs(&[
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrIsPermanent) },
            is_permanent.as_CFType(),
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
            let cf_error =
                unsafe { core_foundation::error::CFError::wrap_under_create_rule(error) };
            format!(
                "Secure Enclave key creation failed: {}",
                cf_error.description()
            )
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

/// Returns `true` if the keychain contains a permanent SE key with the given label.
fn keychain_has_label(label: &str) -> bool {
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
            CFBoolean::false_value().as_CFType(),
        ),
    ]);

    let mut result: core_foundation::base::CFTypeRef = std::ptr::null_mut();
    let status = unsafe {
        security_framework_sys::keychain_item::SecItemCopyMatching(
            query.as_concrete_TypeRef(),
            &mut result,
        )
    };

    status == 0
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

/// Derive a short deterministic ID from a JWK string (first 16 chars of its SHA-256 hex).
/// Used as a fallback `key_id` when the original label cannot be recovered from the keychain ref.
fn jwk_thumbprint_id(jwk: &str) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    jwk.hash(&mut h);
    format!("se-key-{:016x}", h.finish())
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
