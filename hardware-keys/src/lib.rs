use napi::bindgen_prelude::*;
use napi_derive::napi;

mod yubikey_piv;

#[cfg(target_os = "macos")]
mod secure_enclave;

/// Discovered hardware key backend
#[napi(object)]
pub struct HardwareKeyInfo {
    /// "yubikey-piv" or "secure-enclave"
    pub backend: String,
    /// Human-readable description
    pub description: String,
    /// Supported algorithms: "ES256", "RS256", etc.
    pub algorithms: Vec<String>,
    /// For YubiKey: serial number. For Secure Enclave: "local"
    pub device_id: String,
}

/// Result of key generation
#[napi(object)]
pub struct GeneratedKey {
    /// Backend that holds the key
    pub backend: String,
    /// Key identifier (slot for PIV, tag for Secure Enclave)
    pub key_id: String,
    /// Algorithm used
    pub algorithm: String,
    /// Public key as JWK JSON string
    pub public_jwk: String,
}

/// Result of a signing operation
#[napi(object)]
pub struct SignatureResult {
    /// Raw signature bytes (r||s for ECDSA, raw for RSA)
    pub signature: Buffer,
    /// Algorithm used
    pub algorithm: String,
}

/// Discover available hardware key backends
#[napi]
pub fn discover() -> Vec<HardwareKeyInfo> {
    let mut backends = Vec::new();

    // Check for YubiKey
    if let Some(info) = yubikey_piv::discover() {
        backends.push(info);
    }

    // Check for Secure Enclave (macOS only)
    #[cfg(target_os = "macos")]
    if let Some(info) = secure_enclave::discover() {
        backends.push(info);
    }

    backends
}

/// Generate a key on the specified backend.
///
/// # Parameters (Secure Enclave only)
/// - `label`           – Key label stored as `kSecAttrApplicationLabel`. Required for
///                       Secure Enclave; ignored for YubiKey (slot is fixed to 9e).
/// - `permanent`       – Persist to keychain (`kSecAttrIsPermanent`). Requires the
///                       binary to be codesigned with `keychain-access-groups`.
///                       Ignored for YubiKey.
/// - `replace_if_exists` – When `true` and `label` already exists, the old key is
///                       deleted before creating a new one. When `false` the call
///                       returns an error on duplicate labels. Ignored for YubiKey.
#[napi]
pub fn generate_key(
    backend: String,
    algorithm: String,
    label: Option<String>,
    permanent: Option<bool>,
    replace_if_exists: Option<bool>,
) -> Result<GeneratedKey> {
    match backend.as_str() {
        "yubikey-piv" => yubikey_piv::generate_key(&algorithm),

        #[cfg(target_os = "macos")]
        "secure-enclave" => {
            let label = label.ok_or_else(|| {
                Error::from_reason("'label' is required for the secure-enclave backend")
            })?;
            let permanent = permanent.unwrap_or(false);
            let policy = if replace_if_exists.unwrap_or(false) {
                secure_enclave::DuplicateLabelPolicy::Replace
            } else {
                secure_enclave::DuplicateLabelPolicy::Error
            };
            secure_enclave::generate_key(&label, &algorithm, permanent, policy)
        }

        _ => Err(Error::from_reason(format!("Unknown backend: {}", backend))),
    }
}

/// Sign a hash with a hardware key.
/// For JWT: pass the SHA-256 hash of the `header.payload` string.
#[napi]
pub fn sign_hash(backend: String, key_id: String, hash: Buffer) -> Result<SignatureResult> {
    match backend.as_str() {
        "yubikey-piv" => yubikey_piv::sign_hash(&key_id, &hash),
        #[cfg(target_os = "macos")]
        "secure-enclave" => secure_enclave::sign_hash(&key_id, &hash),
        _ => Err(Error::from_reason(format!("Unknown backend: {}", backend))),
    }
}

/// List existing keys on a backend.
///
/// - `prefix` – Optional label prefix filter (Secure Enclave only; ignored for YubiKey).
#[napi]
pub fn list_keys(backend: String, prefix: Option<String>) -> Result<Vec<GeneratedKey>> {
    match backend.as_str() {
        "yubikey-piv" => yubikey_piv::list_keys(),
        #[cfg(target_os = "macos")]
        "secure-enclave" => secure_enclave::list_keys(prefix.as_deref()),
        _ => Err(Error::from_reason(format!("Unknown backend: {}", backend))),
    }
}

/// Delete a key by label.
///
/// For Secure Enclave: removes from the in-process cache and keychain (if permanent).
/// For YubiKey: no-op — PIV slots cannot be deleted, only overwritten via `generate_key`.
#[napi]
pub fn delete_key(backend: String, label: String) -> Result<()> {
    match backend.as_str() {
        "yubikey-piv" => yubikey_piv::delete_key(&label),
        #[cfg(target_os = "macos")]
        "secure-enclave" => secure_enclave::delete_key(&label),
        _ => Err(Error::from_reason(format!("Unknown backend: {}", backend))),
    }
}
