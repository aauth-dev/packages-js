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

/// Generate a key on the specified backend
#[napi]
pub fn generate_key(backend: String, algorithm: String) -> Result<GeneratedKey> {
    match backend.as_str() {
        "yubikey-piv" => yubikey_piv::generate_key(&algorithm),
        #[cfg(target_os = "macos")]
        "secure-enclave" => secure_enclave::generate_key(&algorithm),
        _ => Err(Error::from_reason(format!("Unknown backend: {}", backend))),
    }
}

/// Sign a hash with a hardware key
/// For JWT: pass the SHA-256 hash of the header.payload string
#[napi]
pub fn sign_hash(backend: String, key_id: String, hash: Buffer) -> Result<SignatureResult> {
    match backend.as_str() {
        "yubikey-piv" => yubikey_piv::sign_hash(&key_id, &hash),
        #[cfg(target_os = "macos")]
        "secure-enclave" => secure_enclave::sign_hash(&key_id, &hash),
        _ => Err(Error::from_reason(format!("Unknown backend: {}", backend))),
    }
}

/// List existing keys on a backend
#[napi]
pub fn list_keys(backend: String) -> Result<Vec<GeneratedKey>> {
    match backend.as_str() {
        "yubikey-piv" => yubikey_piv::list_keys(),
        #[cfg(target_os = "macos")]
        "secure-enclave" => secure_enclave::list_keys(),
        _ => Err(Error::from_reason(format!("Unknown backend: {}", backend))),
    }
}
