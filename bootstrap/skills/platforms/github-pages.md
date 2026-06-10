---
name: github-pages
description: Publish AAuth agent metadata and public keys to GitHub Pages (username.github.io)
when: User wants to publish their agent identity and keys via GitHub Pages
requires: setup
agentUrlPattern: username.github.io
pros: Free, git-integrated, widely used, simple setup
cons: Tied to GitHub account, public repos only (free tier)
detect_cli: gh --version
detect_auth: gh auth status
detect_existing: gh repo view {username}/{username}.github.io
---

# Skill: Publish AAuth keys to GitHub Pages

## When to use

The user wants to publish their AAuth agent metadata and public keys via GitHub Pages (username.github.io). Keys should already be generated using the `keygen` skill.

## Prerequisites

- `@aauth/local-keys` is installed
- Keys have been generated (run `npx @aauth/bootstrap list` to check)
- `gh` CLI is authenticated

## Steps

### 1. Determine the agent URL

The URL will be `https://username.github.io`. Pre-fill the username from `gh auth status` when there's a single authenticated account — but still ask the user to confirm (multi-account setups need the choice). If `gh` is unauthenticated, just ask.

### 2. Collect public keys to publish

Run:
```
npx @aauth/bootstrap list
```

Take the public key from `agentProviders[].keys[].publicJwk` in the output (it's also returned directly by `create` as `keys[0].publicJwk`). Each key includes an `aauth` metadata object with `device` and `created` fields.

### 3. Locate or create the GitHub Pages repo

- Ask the user whether they have a local clone (paths vary by user — don't guess). Store the path as `REPO` for the rest of this skill.
- If they don't, clone to a known location: `gh repo clone username/username.github.io /tmp/username.github.io` and use `REPO=/tmp/username.github.io`.
- If the repo doesn't exist on GitHub, create it with `gh repo create username.github.io --public` then clone it.

Run all git commands with `git -C "$REPO"` so you don't need to `cd` (Claude Code's bash sessions are configured to discourage `cd`).

### 3a. Sync the local clone with the remote — REQUIRED before editing

**Skipping this step has resurrected uninstalled keys in the past.** If the remote was modified from another machine (in particular, if `uninstall` ran on a different device and deleted `.well-known/jwks.json` / `aauth-agent.json`), the local clone is stale, and the "read existing JWKS and append" step below will silently re-publish keys the user intentionally removed.

```
git -C "$REPO" fetch origin
git -C "$REPO" log --oneline -n 10 origin/HEAD -- .well-known/
git -C "$REPO" pull --ff-only
```

Do NOT proceed if the pull fails — investigate first.

Then decide: are you on a **fresh-start path** or a **merge path**?

- **Fresh-start path** — after pull, `.well-known/jwks.json` does NOT exist locally (and the log shows it was removed by a prior uninstall). Recreate from scratch with just the new key. **No confirm needed** — this is exactly what an uninstall+reinstall looks like; the user already opted into a fresh identity by running setup again.
- **Merge path** — after pull, `.well-known/jwks.json` exists locally AND the log shows a recent uninstall commit. This is the dangerous case — you'd be merging the new key into a JWKS that the uninstall thought it had cleared. Surface it: "the remote shows an uninstall commit at \<SHA\> but the JWKS is still present locally — proceeding would merge the new key with the existing ones — confirm?"
- **Normal path** — no uninstall commits in the log. Continue without confirming.

### 4. Ensure `.nojekyll` exists

GitHub Pages uses Jekyll by default, which ignores dotfiles like `.well-known/`. Create `$REPO/.nojekyll` (empty file) if it doesn't already exist.

### 5. Create or update `.well-known/jwks.json`

Work with `$REPO/.well-known/jwks.json`:
- If it exists, read it and parse the `keys` array.
- If it doesn't exist, create the `.well-known/` directory and start with `{ "keys": [] }`.
- Add all public JWKs from step 2 to the `keys` array.
- If a key with the same `kid` already exists, replace it. Otherwise append.
- Write the file with `JSON.stringify(jwks, null, 2)`.

Each key should have `kty`, `crv`, `x`, `y` (for EC), `kid`, `use`, `alg`, and the `aauth` metadata object.

### 6. Create or update `.well-known/aauth-agent.json`

This file publishes the agent's metadata. Field names follow the AAuth spec
(see `(#agent-provider-metadata)` in `draft-hardt-oauth-aauth-protocol.md`):
`issuer`, `jwks_uri`, `client_name`, `logo_uri`, optional `logo_dark_uri`,
`description`, `tos_uri`, `policy_uri`. Use the GitHub user/org avatar as the
agent logo:
- Get the GitHub avatar URL by running: `gh api /users/username --jq '.avatar_url'`
- If `.well-known/aauth-agent.json` exists, read it and update the fields below.
- If it doesn't exist, create it with:
```json
{
  "issuer": "https://username.github.io",
  "jwks_uri": "https://username.github.io/.well-known/jwks.json",
  "client_name": "Username",
  "logo_uri": "https://avatars.githubusercontent.com/u/USER_ID?v=4"
}
```
- Set `logo_uri` to the avatar URL from `gh api`.
- Set `client_name` to a human-readable agent name — ask the user, or default to
  the GitHub username/org name.
- Optionally add `logo_dark_uri`, `description`, `tos_uri`, `policy_uri`.

**Do NOT use `id` or `name`** — earlier versions of this skill used those
field names, but the spec is `issuer` and `client_name`. If you find an existing
file with `id`/`name`, migrate it to `issuer`/`client_name` while you're here.

### 7. Commit and push

```
git -C "$REPO" add .nojekyll .well-known/jwks.json .well-known/aauth-agent.json
git -C "$REPO" commit -m "Publish AAuth agent metadata and JWKS"
git -C "$REPO" push
```

Files will be published at:
- `https://username.github.io/.well-known/jwks.json`
- `https://username.github.io/.well-known/aauth-agent.json`

### 8. Verify publication

After push, confirm both files are accessible at the public URLs. GitHub Pages may take a minute to update.

### A note on `hosting` in the bootstrap config

This skill doesn't write `hosting.platform = github-pages` into the agent's bootstrap config — `npx @aauth/bootstrap list` will show `hosting: null`. That's fine: the uninstall skill infers the platform from the agent URL host (`*.github.io` → `github-pages`), so the round-trip works for the standard pattern. If the user later moves to a custom domain pointing at GitHub Pages, they'll be asked to confirm the platform on uninstall.

## Example JWKS file

```json
{
  "keys": [
    {
      "kty": "EC",
      "crv": "P-256",
      "x": "...",
      "y": "...",
      "kid": "2026-04-09_a3f",
      "use": "sig",
      "alg": "ES256",
      "aauth": {
        "device": "yubikey-otp+fido+ccid-0775",
        "created": "2026-04-09"
      }
    },
    {
      "kty": "EC",
      "crv": "P-256",
      "x": "...",
      "y": "...",
      "kid": "2026-04-09_b71",
      "use": "sig",
      "alg": "ES256",
      "aauth": {
        "device": "macbook-pro-dick",
        "created": "2026-04-09"
      }
    }
  ]
}
```

## Example aauth-agent.json

```json
{
  "issuer": "https://dickhardt.github.io",
  "jwks_uri": "https://dickhardt.github.io/.well-known/jwks.json",
  "client_name": "Dick Hardt",
  "logo_uri": "https://avatars.githubusercontent.com/u/322034?v=4"
}
```

## Notes

- Old keys should remain in the JWKS for verification of previously issued tokens.
- The `aauth.device` field helps identify which physical device holds the key, for stale key cleanup. It is auto-derived and not sensitive.
- The JWKS file contains only public keys — it is safe to commit.
- The `logo_uri` uses the GitHub avatar.
