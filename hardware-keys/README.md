# @mntu/hardware-keys

Native bindings for hardware key backends used by mntu: YubiKey PIV and macOS Secure Enclave. Built with [napi-rs](https://napi.rs/) and shipped as prebuilt binaries for macOS (Apple Silicon + Intel), Linux x86_64, and Windows x86_64.

Part of [mntu/packages-js](https://github.com/mntu/packages-js)

> Most users do not depend on this package directly. It is loaded as an optional dependency of [`@mntu/local-keys`](../local-keys), which provides a higher-level API with automatic key resolution and fallback to software keys.

## Install

```bash
npm install @mntu/hardware-keys
```

The right prebuilt binary for your platform is selected automatically. If no prebuilt is available, key operations on hardware backends will be unavailable but the package will still load.

## Supported Backends

| Backend | Algorithm | Platform | Notes |
|---------|-----------|----------|-------|
| `yubikey-piv` | ES256, RS256 | macOS, Linux, Windows | Uses slot 9e (no PIN required) |
| `secure-enclave` | ES256 | macOS (Apple Silicon) | Keys never leave the Secure Enclave |

## API

```ts
import { discover, generateKey, signHash, listKeys, deleteKey } from '@mntu/hardware-keys'

// Discover available hardware backends
const backends = discover()
// [{ backend: 'yubikey-piv', description: '...', algorithms: ['ES256'], deviceId: '9570775' }]

// Generate a key on a backend
//
// YubiKey: label, permanent, replaceIfExists are ignored (slot 9e is fixed)
const key = generateKey('yubikey-piv', 'ES256')

// Secure Enclave: label is required; permanent defaults to false (ephemeral, process-lifetime only);
// replaceIfExists defaults to false (throws if label already exists)
const key = generateKey('secure-enclave', 'ES256', 'com.myapp.signing-key')
const key = generateKey('secure-enclave', 'ES256', 'com.myapp.signing-key', true)              // persist to keychain
const key = generateKey('secure-enclave', 'ES256', 'com.myapp.signing-key', false, true)       // replace if exists
// { backend, keyId, algorithm, publicJwk }

// Sign a SHA-256 hash with an existing key
const result = signHash('yubikey-piv', '9e', hashBuffer)
const result = signHash('secure-enclave', 'com.myapp.signing-key', hashBuffer)
// { signature: Buffer, algorithm: 'ES256' }

// List existing keys on a backend
const keys = listKeys('yubikey-piv')

// Secure Enclave: optional label prefix filter
const keys = listKeys('secure-enclave')                      // all keys
const keys = listKeys('secure-enclave', 'com.myapp.')        // filtered by prefix
// [{ backend, keyId, algorithm, publicJwk }]

// Delete a key by label
deleteKey('secure-enclave', 'com.myapp.signing-key')
// YubiKey: no-op (PIV slots cannot be deleted, only overwritten via generateKey)
deleteKey('yubikey-piv', '9e')
```

### `generateKey` parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `backend` | `string` | ✓ | — | `"yubikey-piv"` or `"secure-enclave"` |
| `algorithm` | `string` | ✓ | — | `"ES256"` or `"RS256"` (YubiKey only) |
| `label` | `string` | SE only | — | Application label used for lookup and deletion |
| `permanent` | `boolean` | — | `false` | Persist key to keychain. Requires binary codesigned with `keychain-access-groups` entitlement |
| `replaceIfExists` | `boolean` | — | `false` | Delete existing key with the same label before creating. If `false`, throws on duplicate |

### Notes on Secure Enclave persistence

By default (`permanent: false`) a Secure Enclave key lives only for the lifetime of the current process — it is not written to the keychain. This works with any binary including unsigned `node`. Set `permanent: true` only when the binary is codesigned with the `keychain-access-groups` entitlement; otherwise the Security framework returns `errSecMissingEntitlement (-34018)`.

#### Enabling keychain persistence (macOS app / Electron)

**1. Create an entitlements file** (`entitlements.mac.plist`):

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>keychain-access-groups</key>
    <array>
        <!--
          Format: <TeamID>.<bundle-id>
          - Replace ABCDE12345 with your Team ID (developer.apple.com/account → Membership)
          - Use your app's own bundle ID as the group name — no portal registration needed.
            Only use a custom group name if sharing keys across multiple apps,
            in which case you must register it at developer.apple.com → App Groups.
        -->
        <string>ABCDE12345.com.myapp</string>
    </array>
    <key>com.apple.application-identifier</key>
    <string>ABCDE12345.com.myapp</string>
</dict>
</plist>
```

To find your Team ID:

```bash
security find-identity -v -p codesigning | head -5
# "Developer ID Application: Your Name (ABCDE12345)"
#                                        ^^^^^^^^^^^ Team ID
```

**2. Codesign the binary** (or the Electron app bundle) with the entitlements:

```bash
# Sign a standalone binary
codesign \
  --sign "Developer ID Application: Your Name (ABCDE12345)" \
  --entitlements entitlements.mac.plist \
  --force \
  /path/to/your-binary

# Sign an Electron app bundle
codesign \
  --sign "Developer ID Application: Your Name (ABCDE12345)" \
  --entitlements entitlements.mac.plist \
  --deep --force \
  /path/to/YourApp.app
```

**3. Verify the entitlement was applied:**

```bash
codesign -d --entitlements :- /path/to/your-binary | grep -A2 keychain-access-groups
```

**4. Use `permanent: true` in your code:**

```ts
const key = generateKey(
  'secure-enclave',
  'ES256',
  'com.myapp.signing-key',
  true,   // permanent — persisted to keychain across restarts
  false,  // replaceIfExists
)

// On next process start, the key is still available:
const keys = listKeys('secure-enclave', 'com.myapp.')
```

> **Electron note:** In `electron-builder`, pass the entitlements via `mac.entitlements` in `electron-builder.yml`:
> ```yaml
> mac:
>   entitlements: entitlements.mac.plist
>   entitlementsInherit: entitlements.mac.plist
>   hardenedRuntime: true
> ```

## License

MIT
