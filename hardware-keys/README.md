# @aauth/hardware-keys

Native bindings for hardware key backends used by AAuth: YubiKey PIV and macOS Secure Enclave. Built with [napi-rs](https://napi.rs/) and shipped as prebuilt binaries for macOS (Apple Silicon + Intel), Linux x86_64, and Windows x86_64.

Part of [aauth-dev/packages-js](https://github.com/aauth-dev/packages-js). Protocol spec: [dickhardt/AAuth](https://github.com/dickhardt/AAuth).

> Most users do not depend on this package directly. It is loaded as an optional dependency of [`@aauth/local-keys`](../local-keys), which provides a higher-level API with automatic key resolution and fallback to software keys.

## Install

```bash
npm install @aauth/hardware-keys
```

The right prebuilt binary for your platform is selected automatically. If no prebuilt is available, key operations on hardware backends will be unavailable but the package will still load.

## Supported Backends

| Backend | Algorithm | Platform | Notes |
|---------|-----------|----------|-------|
| `yubikey-piv` | ES256, RS256 | macOS, Linux, Windows | Uses slot 9e (no PIN required) |
| `secure-enclave` | ES256 | macOS (Apple Silicon) | Keys never leave the Secure Enclave |

## API

```ts
import { discover, generateKey, signHash, listKeys } from '@aauth/hardware-keys'

// Discover available hardware backends
const backends = discover()
// [{ backend: 'yubikey-piv', description: '...', algorithms: ['ES256'], deviceId: '9570775' }]

// Generate a key on a backend
const key = generateKey('yubikey-piv', 'ES256')
// { backend, keyId, algorithm, publicJwk }

// Sign a SHA-256 hash with an existing key
const result = signHash('yubikey-piv', '9e', hashBuffer)
// { signature: Buffer, algorithm: 'ES256' }

// List existing keys on a backend
const keys = listKeys('secure-enclave')
```

For most uses, prefer the higher-level [`@aauth/local-keys`](../local-keys) API which handles backend discovery, key resolution against published JWKS, and graceful fallback between hardware and software keys.

## License

MIT
