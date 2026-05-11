# @aauth/local-keys

Library for managing AAuth agent signing keys across hardware and software backends. Supports YubiKey PIV, macOS Secure Enclave, and OS keychain — with automatic key resolution that prefers hardware keys and tolerates devices being unavailable.

Part of [aauth-dev/packages-js](https://github.com/aauth-dev/packages-js). Protocol spec: [dickhardt/AAuth](https://github.com/dickhardt/AAuth).

> **Looking for a CLI?** This package is a library. The CLI for setting up agent keys, configuring a person server, and publishing keys is [`@aauth/bootstrap`](../bootstrap). Run `npx @aauth/bootstrap --ps <your-ps-url>` to get started.

## Install

```bash
npm install @aauth/local-keys
```

## Key Backends

| Backend | Algorithm | Platform | Storage |
|---------|-----------|----------|---------|
| `yubikey-piv` | ES256, RS256 | Cross-platform | YubiKey slot 9e (no PIN) |
| `secure-enclave` | ES256 | macOS (Apple Silicon) | Secure Enclave hardware |
| `software` | EdDSA, ES256 | All | OS keychain |

Hardware keys are always preferred over software keys. If a YubiKey is unplugged, signing automatically falls back to the next available key.

## API

### `createAgentToken(options): Promise<AgentTokenResult>`

The primary API for other packages. Signs an agent token and returns the ephemeral key material needed for HTTP Message Signatures.

```ts
import { createAgentToken } from '@aauth/local-keys'

const { signingKey, signatureKey } = await createAgentToken({
  delegate: 'claude',
  // agentUrl is optional — defaults to first configured agent
})

// signingKey: ephemeral private JWK for HTTP signatures
// signatureKey: { type: 'jwt', jwt: '...' } signed agent token
```

Key resolution is automatic: fetches the agent's published JWKS, matches against local hardware and software keys, prefers hardware, tolerates failures at every step.

### `discoverBackends(): BackendInfo[]`

List available key backends on this machine.

```ts
import { discoverBackends } from '@aauth/local-keys'

const backends = discoverBackends()
// [{ backend: 'yubikey-piv', description: '...', algorithms: ['ES256'], deviceId: '9570775' }, ...]
```

### `resolveKey(agentUrl): Promise<ResolvedKey>`

Resolve which key to use for signing. Fetches JWKS, matches thumbprints against local keys, falls back through config and keychain.

```ts
import { resolveKey } from '@aauth/local-keys'

const key = await resolveKey('https://you.github.io')
// { backend: 'yubikey-piv', keyId: '9e', kid: '2026-04-09_a3f', algorithm: 'ES256', publicJwk: {...} }
```

### Config Management

```ts
import {
  readConfig,
  getAgentConfig,
  addKeyToAgent,
  setPersonServer,
  setHosting,
} from '@aauth/local-keys'

addKeyToAgent('https://you.github.io', 'kid-123', {
  backend: 'yubikey-piv',
  algorithm: 'ES256',
  keyId: '9e',
  deviceLabel: 'yubikey-5c-0775',
})

setPersonServer('https://you.github.io', 'https://your-ps.example')

setHosting('https://you.github.io', {
  platform: 'github-pages',
  repo: 'you/you.github.io',
})
```

## Config File

`~/.aauth/config.json`:

```json
{
  "agents": {
    "https://you.github.io": {
      "personServerUrl": "https://your-ps.example",
      "hosting": {
        "platform": "github-pages",
        "repo": "you/you.github.io"
      },
      "keys": {
        "2026-04-09_a3f": {
          "backend": "yubikey-piv",
          "algorithm": "ES256",
          "keyId": "9e",
          "deviceLabel": "yubikey-5c-0775"
        },
        "2026-04-09_b71": {
          "backend": "secure-enclave",
          "algorithm": "ES256",
          "keyId": "com.aauth.agent.2026-04-09_b71",
          "deviceLabel": "macbook-pro-dick"
        }
      }
    }
  }
}
```

This file is written by [`@aauth/bootstrap`](../bootstrap) and read by every package that needs to sign as the agent.

## Key Resolution

When signing, keys are resolved automatically through this fallback chain:

1. Fetch `{agentUrl}/.well-known/aauth-agent.json` to find the JWKS
2. Match published key thumbprints against locally available hardware and software keys
3. Fall back to `~/.aauth/config.json` registered keys
4. Fall back to any available hardware key (bootstrap)
5. Fall back to OS keychain software keys (backward compatibility)

Hardware keys are always preferred. Unavailable backends (e.g. unplugged YubiKey) are gracefully skipped.

## License

MIT
