---
name: setup
description: Set up AAuth agent identity — generate signing keys, add keys from new devices, and publish to a hosting platform
when: User wants to create an AAuth agent identity, generate keys, add a key from a new device or hardware backend, or publish their agent metadata
---

# Skill: Set up AAuth agent identity

## When to use

- First-time setup: the user wants to create an AAuth agent identity with signing keys
- Adding a key: the user has a new device (e.g. new YubiKey, new Mac) and wants to add its key to an existing agent identity
- Publishing: the user has generated keys and needs to publish them to their hosting platform

## Prerequisites

- `@aauth/local-keys` is installed
- For YubiKey: a YubiKey is plugged in
- For Secure Enclave: macOS with Apple Silicon

## Key backend priority

Always prefer hardware keys over software keys. Generate a key on ALL available hardware backends for redundancy — if one device is unavailable (e.g. YubiKey unplugged), the agent falls back to the next available key automatically.

1. **`yubikey-piv`** — YubiKey PIV slot 9e, no PIN required, ES256. Key lives in YubiKey hardware.
2. **`secure-enclave`** — macOS Secure Enclave, ES256. Key lives in the Mac's secure hardware.
3. **`software`** — OS keychain, EdDSA or ES256. Only use if no hardware is available.

## Adding a key to an existing agent

If the user already has an agent identity set up and wants to add a key from a new device (e.g. they got a new YubiKey, or they're on a new Mac with a Secure Enclave):

1. Check existing setup: `npx @aauth/local-keys show`
2. Discover backends: `npx @aauth/local-keys discover`
3. Generate a key on the new hardware: `npx @aauth/local-keys generate --backend <backend> --agent <agent-url>`
4. Add the new public key to the existing JWKS on the hosting platform (load the appropriate platform skill)
5. The new key will be used automatically — key resolution matches any published key that has a local private key

## First-time setup steps

### 1. Discover available backends

Run:
```
npx @aauth/local-keys discover
```

This returns a JSON array of available backends with their supported algorithms.

### 2. Generate keys on each available hardware backend

For each hardware backend in the discovery output, generate a key and associate it with the agent URL:

```
npx @aauth/local-keys generate --backend yubikey-piv --agent <agent-url>
npx @aauth/local-keys generate --backend secure-enclave --agent <agent-url>
```

Each command outputs JSON with:
- `kid` — key identifier to use in the JWKS
- `publicJwk` — the public key to publish, including `aauth.device` and `aauth.created` metadata

**Only generate a software key if no hardware backends are available:**
```
npx @aauth/local-keys generate --agent <agent-url>
```

### 3. Set the person server (if known)

If the user has a person server URL:
```
npx @aauth/local-keys add-agent <agent-url> --person-server <person-server-url>
```

### 4. Choose a hosting platform

The generated public keys need to be published at `{agentUrl}/.well-known/jwks.json` along with agent metadata at `{agentUrl}/.well-known/aauth-agent.json`. The agent needs to serve these as static files over HTTPS.

**Load the list of supported platforms** by calling:

```ts
import { listPlatforms } from '@aauth/local-keys'
const platforms = listPlatforms()
```

Or via CLI:
```
npx @aauth/local-keys skill
```

Platform skills are in `skills/platforms/`. Each platform's front matter includes discovery metadata:
- `detect_cli` — CLI tool to check for (e.g. `gh`, `glab`, `wrangler`)
- `detect_auth` — command to check if authenticated
- `detect_existing` — command to check for an existing site (uses `{username}` placeholder)
- `pros` / `cons` — trade-offs to present to the user
- `agentUrlPattern` — what the agent URL will look like

**Discovery flow:**

For each platform, run the detection commands:
1. Run `<detect_cli>` — if it succeeds, the CLI is available
2. If available, run `<detect_auth>` — check if authenticated (look for "not authenticated" or similar in output to detect unauthenticated state)
3. If authenticated and `detect_existing` is set, substitute `{username}` and run to check for an existing site

**Presenting the results to the user:**

Present ALL platforms to the user, organized by availability:

1. **Ready** — CLI installed, authenticated, possibly an existing site. Recommend these first.
2. **Available** — CLI installed but not authenticated. Mention what command to run to log in.
3. **Not detected** — CLI not installed. Still present these as options with their pros/cons. The user may want to install one, or may already have an account on the platform's website.

Also mention that any static HTTPS hosting works — the platforms with skills just have step-by-step instructions. If the user has a different hosting provider (Netlify, Vercel, S3+CloudFront, their own server, etc.), they can still publish the `.well-known/` files manually. The required files are:
- `/.well-known/aauth-agent.json` — agent metadata with `jwks_uri`
- `/.well-known/jwks.json` — public key set

**Recommendation logic:**
- If one platform is fully ready (CLI + auth + existing site) → suggest that first
- If multiple are ready → present the choices with pros/cons and let the user choose
- If none are ready but some are available → suggest logging in to the simplest one
- If none are detected → recommend GitHub Pages (lowest barrier) but present all options

After the user chooses, register the hosting platform:
```
npx @aauth/local-keys add-agent <agent-url> --hosting <platform> --repo <repo-identifier>
```

### 5. Publish keys using the platform skill

Load the full instructions for the chosen platform:
```
npx @aauth/local-keys skill <platform-name>
```

Follow the skill instructions to publish the keys.

### 6. Verify setup

```
npx @aauth/local-keys show
```

This shows all configured agents, their keys, and which backends are available.

## How key resolution works

When `@aauth/local-keys` signs an agent token, it resolves a key automatically through this fallback chain:

1. **Fetch JWKS** — fetches `{agentUrl}/.well-known/aauth-agent.json` to find `jwks_uri`, then fetches the JWKS. Tolerates network failure gracefully.

2. **Discover local keys** — scans all backends (YubiKey, Secure Enclave, OS keychain). Only keys on hardware that is currently available are found. If a YubiKey is unplugged, its keys silently don't appear.

3. **Match JWKS against local keys** — compares JWK thumbprints between published keys and local keys. Prefers hardware matches over software. Any hardware match is used immediately.

4. **Fall back to config** — checks `~/.aauth/config.json` for registered keys. Skips entries whose backend is unavailable (e.g. YubiKey unplugged). Verifies the key actually exists before using it. Prefers hardware over software.

5. **Fall back to any local hardware key** — for bootstrap (key just generated, not yet published).

6. **Fall back to any local software key** — backward compatibility with older setups.

7. **Error** — no key found, with a helpful message to run `generate`.

Each step tolerates failure and falls through. Hardware keys are always preferred.

## How signing works

When `createAgentToken({ delegate: 'claude' })` is called:

1. The agent URL is resolved from the call, or defaults to the first configured agent in `~/.aauth/config.json`, or the first agent URL in the OS keychain.
2. A signing key is resolved using the fallback chain above.
3. An ephemeral key pair is generated (software, ES256 or EdDSA).
4. The agent token JWT is signed by the resolved root key, with the ephemeral public key in the `cnf` claim.
5. The ephemeral private key and signed JWT are returned.

For hardware backends, the root key signing happens in hardware — the private key never exists in process memory.

## Notes

- Generate keys on ALL available hardware backends for redundancy.
- Software keys are a last resort — they store the private key in the OS keychain, not hardware.
- The `aauth.device` field in the public JWK is auto-derived from the machine hostname or YubiKey name. It helps identify stale keys in the JWKS but is not sensitive.
- After generating keys, publish them using the skill for your chosen hosting platform.
