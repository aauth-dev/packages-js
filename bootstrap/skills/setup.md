---
name: setup
description: Set up an AAuth agent provider identity — generate a signing key, bind a person server, and publish to a hosting platform
when: User wants to create an AAuth agent provider identity, generate a key, or publish their agent metadata
---

# Skill: Set up an AAuth agent provider identity

## Run `list` first

Run this and use the output to see what keystores this machine has and what is already configured:

```
npx @aauth/bootstrap list
```

The `keystores` array is the source of truth for what this machine supports. Prefer hardware (secure-enclave, yubikey-piv) over software when available.

## Check for a prior setup to reuse (`backups`)

The `list` output includes a `backups` array — snapshots written when a previous
identity was uninstalled. If it's non-empty, this machine was set up before. For
the most recent entry (last in the array):

- Read its `agentUrls`. Offer to set up again with the **same agent URL, person
  server, and hosting** as before — the user almost always wants the same
  identity back. (You'll generate fresh keys; the old private keys are gone.)
- The full prior settings are in `~/.aauth/backups/<file>` (the `file` field) —
  read it to recover `personServerUrl` and `hosting.platform` / `hosting.repo`,
  and pass them to `create` (`--person-server`) and the matching platform skill
  so you republish to the same place.

Confirm with the user before reusing — they may want a different URL.

**`backups` is local-only — an empty array does NOT mean "no prior install
anywhere."** It only reflects uninstalls that ran on THIS machine. A previous
install + uninstall on a different device, or a manually-cleared
`~/.aauth/backups/` directory, will leave `backups: []` here even though the
hosting repo's git history may show prior AAuth commits. Before treating this as
first-time setup, if the user names a hosting repo, also check the remote — see
the platform skill (e.g. `github-pages`), which now pulls first and warns on
recent uninstall commits.

## What `create` does

`create` is the whole first-time setup in one command. It:

1. generates a signing key in the chosen keystore,
2. binds that key to the agent provider, and
3. binds a person server (default `https://person.hello.coop`).

```
npx @aauth/bootstrap create <agent-provider-url> [--keystore <name>] [--algorithm <alg>] [--person-server <url>]
```

It fails if the agent provider already exists — delete it first to re-create.

## Keystore priority

Prefer hardware over software (the private key never leaves the device). When
multiple hardware keystores are available, prefer the one that's always present
and doesn't require plugging anything in:

1. **`secure-enclave`** — macOS Secure Enclave (Apple Silicon), ES256. Always
   present on Apple Silicon, non-exportable, no hardware to insert.
2. **`yubikey-piv`** — YubiKey PIV slot 9e, no PIN, ES256. Portable across
   machines, but requires the YubiKey to be plugged in to sign. Prefer when the
   user explicitly wants a portable hardware key.
3. **`software`** — OS keychain, EdDSA (default) or ES256. Use only if no hardware is present.

Pick the keystore from the `keystores` array that `list` reported. If both
`secure-enclave` and `yubikey-piv` are available, default to `secure-enclave`
and offer YubiKey as an alternative for users who want a portable key.

## Determining the agent provider URL

The agent provider URL is the HTTPS URL where the agent metadata will be
published. Ask the user:

- If they have a domain, use it.
- If using GitHub Pages, ask for their GitHub username — the URL is `https://username.github.io`.
- Run the platform detection commands (below) to suggest hosting.

Do NOT pick a hosting platform or URL without asking the user.

## First-time setup steps

### 1. See what's available

```
npx @aauth/bootstrap list
```

### 2. Create the agent provider

Pick the best available keystore and create the provider. Example with the
default software keystore:

```
npx @aauth/bootstrap create https://username.github.io
```

With a hardware keystore and a custom person server:

```
npx @aauth/bootstrap create https://username.github.io --keystore secure-enclave --person-server https://person.example
```

The output includes `keys[0].publicJwk` — the public key you publish — plus the
resolved `agentId` and `personServer`.

### 3. Choose a hosting platform

The public key must be published at `{agentProviderUrl}/.well-known/jwks.json`,
with agent metadata at `{agentProviderUrl}/.well-known/aauth-agent.json`, served
as static files over HTTPS.

List the platform skills:

```
npx @aauth/bootstrap skill
```

Each platform skill's front matter includes discovery metadata:
- `detect_cli` — CLI tool to check for (e.g. `gh`, `glab`, `wrangler`)
- `detect_auth` — command to check if authenticated
- `detect_existing` — command to check for an existing site (uses `{username}`)
- `pros` / `cons` — trade-offs to present
- `agentUrlPattern` — what the URL will look like

**Discovery flow** — for each platform: run `<detect_cli>`; if it succeeds, run
`<detect_auth>`; if authenticated and `detect_existing` is set, substitute
`{username}` and run it.

**Present results** organized by availability: Ready (CLI + auth + maybe a site)
first, then Available (CLI but not authenticated), then Not detected. Mention
that any static HTTPS host works — the required files are
`/.well-known/aauth-agent.json` and `/.well-known/jwks.json`.

### 4. Publish using the platform skill

```
npx @aauth/bootstrap skill <platform-name>
```

Follow the skill to publish `jwks.json` (containing `keys[0].publicJwk` from
step 2) and `aauth-agent.json`.

### 5. Confirm the local config

```
npx @aauth/bootstrap list
```

Confirm the provider, its key, person server, and agentId are present.

### 6. Verify with a signed call — the install isn't proven until this works

Local config + a successful `git push` are not proof. A signed call that comes back with the agent's `sub` is. Run:

```
npx @aauth/fetch https://whoami.aauth.dev
```

Expect a body like `{ "sub": "aauth:local@<agent-url>", "ps": "<person-server>" }`. If you see your `sub`, the install works end-to-end — the key signs, the JWKS resolves on the public URL, and the resource accepts the signature.

If you get an error instead, debug before continuing. Common causes:
- Pages hasn't finished propagating yet — wait a minute and retry.
- `.nojekyll` is missing — GitHub Pages is hiding the `.well-known/` directory.
- The JWKS URL returns 404 — the publish step didn't land. Re-check the platform skill.

This is the single source of truth for "did setup work." Do not declare success without it.

## How key resolution works

When `@aauth/local-keys` signs an agent token it resolves a key automatically:

1. **Fetch JWKS** — `{agentProviderUrl}/.well-known/aauth-agent.json` → `jwks_uri` → JWKS. Tolerates network failure.
2. **Discover local keys** — scans all keystores; only keys on currently-available hardware are found.
3. **Match JWKS against local keys** — by JWK thumbprint, preferring hardware.
4. **Fall back to config** — `~/.aauth/config.json`, skipping unavailable keystores.
5. **Fall back to any local hardware key**, then **any local software key** (just-created, not yet published).

## Notes

- v1 sets up **one key per agent provider**. Adding more keys (e.g. one per
  machine for multi-device redundancy) is a planned capability, not yet a CLI
  command.
- `delete <agent-provider-url>` removes the provider and wipes its software and
  Secure Enclave keys. A YubiKey PIV key can't be wiped programmatically yet —
  `delete` reports the slot to clear manually (`ykman piv keys delete 9e`).
- The `aauth.device` field in the public JWK is auto-derived from the machine or
  YubiKey name. It helps identify stale keys; it is not sensitive.
