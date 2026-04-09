# @aauth/local-keys

Manage AAuth agent signing keys across hardware and software backends. Supports YubiKey PIV, macOS Secure Enclave, and OS keychain — with automatic key resolution that prefers hardware keys and tolerates devices being unavailable.

Part of the [AAuth](https://github.com/hellocoop/AAuth) project.

## Install

```bash
npm install @aauth/local-keys
```

## Quick Start

```bash
# See what key backends are available
npx @aauth/local-keys discover

# Generate keys on all available hardware (do this for each hardware backend)
npx @aauth/local-keys generate --backend yubikey-piv --agent https://you.github.io
npx @aauth/local-keys generate --backend secure-enclave --agent https://you.github.io

# Set up hosting and person server
npx @aauth/local-keys add-agent https://you.github.io \
  --person-server https://hello.coop \
  --hosting github-pages --repo you/you.github.io

# Publish your keys (see skills for platform-specific instructions)
npx @aauth/local-keys skill github-pages

# Sign an agent token
npx @aauth/local-keys sign-token --agent https://you.github.io --delegate claude
```

## Key Backends

| Backend | Algorithm | Platform | Storage |
|---------|-----------|----------|---------|
| `yubikey-piv` | ES256, RS256 | Cross-platform | YubiKey slot 9e (no PIN) |
| `secure-enclave` | ES256 | macOS (Apple Silicon) | Secure Enclave hardware |
| `software` | EdDSA, ES256 | All | OS keychain |

Generate keys on **all available hardware backends** for redundancy. Only use software keys if no hardware is available. If a YubiKey is unplugged, signing automatically falls back to the next available key.

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

### `listSkills(): SkillSummary[]` / `getSkill(name): Skill`

Discover and load agent skill instructions bundled with the package.

```ts
import { listSkills, getSkill } from '@aauth/local-keys'

const skills = listSkills()
// [{ name: 'keygen', description: '...', when: '...' }, ...]

const skill = getSkill('github.io')
// { name, description, when, requires, body: '# full markdown...' }
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

setPersonServer('https://you.github.io', 'https://hello.coop')

setHosting('https://you.github.io', {
  platform: 'github-pages',
  repo: 'you/you.github.io',
})
```

## CLI

```
npx @aauth/local-keys discover                  # list available backends (JSON)
npx @aauth/local-keys generate [options]         # generate key, output public JWK (JSON)
  --backend <name>                                #   yubikey-piv, secure-enclave, software
  --algorithm <alg>                               #   ES256 (default for hardware), EdDSA, RS256
  --agent <url>                                   #   associate with agent URL
npx @aauth/local-keys sign-token [options]       # sign agent token (JSON)
  --agent <url>                                   #   agent URL (optional if configured)
  --delegate <name>                               #   delegate name (required)
  --lifetime <seconds>                            #   token lifetime (default: 3600)
npx @aauth/local-keys add-agent <url> [options]  # register agent URL
  --person-server <url>                           #   person server URL
  --hosting <platform>                            #   github-pages, cloudflare-pages, netlify, s3, custom
  --repo <repo>                                   #   platform-specific repo/bucket identifier
npx @aauth/local-keys public-key [--agent <url>] # output public key(s) (JSON)
npx @aauth/local-keys skill                      # list available skills (JSON)
npx @aauth/local-keys skill <name>               # show full skill instructions
npx @aauth/local-keys config                     # dump ~/.aauth/config.json
npx @aauth/local-keys show                       # human-readable status
```

## Config File

`~/.aauth/config.json`:

```json
{
  "agents": {
    "https://you.github.io": {
      "personServerUrl": "https://hello.coop",
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

## Skills

Skills are agent-readable instructions bundled with the package for common tasks. Use `listSkills()` or `npx @aauth/local-keys skill` to discover them.

| Skill | Description |
|-------|-------------|
| `setup` | Generate signing keys, add keys from new devices, choose a hosting platform |

Platform skills (in `skills/platforms/`):

| Platform Skill | Description |
|----------------|-------------|
| `github-pages` | Publish to GitHub Pages |
| `gitlab-pages` | Publish to GitLab Pages |
| `cloudflare-pages` | Publish to Cloudflare Pages |
| `netlify` | Publish to Netlify |

Platform skills include discovery metadata (CLI detection, auth checks) in their front matter so the `setup` skill can dynamically detect which platforms the user has available.

**Contributing platform skills**: We welcome PRs for additional hosting platforms. Add a file to [`skills/platforms/`](./skills/platforms/) with YAML front matter including `name`, `description`, `when`, `detect_cli`, `detect_auth`, `pros`, `cons`, and `agentUrlPattern`. See the existing platform skills for the format.

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
