---
name: uninstall
description: Tear down an AAuth agent provider identity — remove the published .well-known files, delete local keys, and wipe config so the machine can be bootstrapped fresh
when: User wants to uninstall AAuth, remove an agent provider, delete their keys, or return the machine to a clean pre-bootstrap state
---

# Skill: Uninstall an AAuth agent provider identity

This returns the machine to a clean, pre-bootstrap state. There are two kinds of artifact, in two places:

- **Remote** — the `.well-known/jwks.json` and `aauth-agent.json` files published to a hosting platform (GitHub Pages, Cloudflare Pages, …). Each platform has its own `<platform>-uninstall` skill (e.g. `github-pages-uninstall`) that knows how to take its files down.
- **Local** — signing keys (in the OS keychain / Secure Enclave / YubiKey) and the `~/.aauth` config dir. The `uninstall` command removes these.

## How this skill flows

**One named confirmation, then two automatic teardown steps.** Don't stack additional yes/no questions in front of it — the user already knows the consequence they're agreeing to.

If the caller already asked the user to confirm uninstall (e.g. the walkthrough's §4 Keep/Uninstall choice), **skip step 1's confirmation** — the user already chose. Build the consequence statement from `list` and proceed straight to step 2.

## 1. See what's there (and decide whether to proceed)

```
npx @aauth/bootstrap list
```

If `agentProviders` is empty, the machine is already clean — say so and stop.

Otherwise build the consequence statement from the `list` output. For each agent provider, name:

- The remote URLs that will go down (`<jwksUri>` and the matching `aauth-agent.json` URL)
- The local key(s) being deleted (kid + keystore)
- That the local `~/.aauth/config.json` will be removed
- That **anything currently using this identity will break** — running agents, MCP servers, scripts

Ask the user ONE question: *"Proceed with all of the above?"* Yes / No. Do not ask whether the user wants to handle remote files themselves — they don't; that's not an option this skill offers. If you can't take the remote files down (no platform auth, no connected repo), surface that as a blocker and stop, do not silently leave files published.

## 2. Remove the remote `.well-known` files FIRST

Do this **before** wiping local config — the config holds the `hosting` pointers you need to find the files.

For each agent provider in `list`:

- Read its `hosting.platform` (e.g. `github-pages`). **If `hosting` is `null`** — older installs and manual publishes didn't record it — infer the platform from the agent URL host:
  - `*.github.io` → `github-pages`
  - `*.pages.dev` → `cloudflare-pages`
  - `*.gitlab.io` → `gitlab-pages`
  - `*.netlify.app` → `netlify`
  - Anything else (custom domain) → ask the user which platform hosts the files.
- Load the matching uninstall skill: `npx @aauth/bootstrap skill <platform>-uninstall` (e.g. `github-pages-uninstall`). That skill is the source of truth for *how* to take the files down on that platform — clone/sync the repo, delete the two files, commit, push, BLOCK until 404.
- Run it. Do not improvise from the publish skill; the publish skill describes how to *put files up*, which is the wrong shape for taking them down.

The uninstall skill's exit condition is **both URLs return 404 from the public agent URL**. That is the world-state change. A successful `git push` is not proof; a 404 is. Report it like:

> "JWKS at `https://username.github.io/.well-known/jwks.json` now returns 404 — resources can no longer verify signatures from this agent."

Not the commit SHA, not the deploy ID — what changed in the world the user actually sees.

If a platform doesn't have a `<platform>-uninstall` skill yet, surface that as a blocker. Don't fall back to "the user can delete the files themselves" — without your 404 verification step, that's just leaving files published.

## 3. Tear down local state

`uninstall` is dry-run by default — it prints exactly what it WOULD delete and removes nothing:

```
npx @aauth/bootstrap uninstall
```

Then run for real with `--force`:

```
npx @aauth/bootstrap uninstall --force
```

This **backs up the config first** (agent URL, person server, hosting, key metadata — never private keys) to `~/.aauth/backups/`, then deletes every agent's keys across all keystores, sweeps orphaned keychain entries, and removes the active `config.json`. The output's `backupPath` points at the snapshot. Mention the backup path to the user — they may want to know where their old agent URL / person server settings are recorded, for a future re-install.

- A YubiKey PIV key (slot 9e) can't be wiped programmatically yet — it appears under `hardwareKeysRetained` with a manual command (`ykman piv keys delete 9e`). Relay that to the user.

## 4. Report final state, not commands

Verify and tell the user what's true in the world now:

```
npx @aauth/bootstrap list
```

Confirm `agentProviders: []` and report:

- Local: "Signing key `<kid>` deleted from `<keystore>`. Local config removed; backup saved at `<path>`."
- Remote (already reported in step 2): each `<url>` returns 404.

That's the whole signal — the user shouldn't have to read the commit log or grep the keychain to know it worked.

## No dangling background work

If you started any background task or monitor during this skill (e.g. tailing a deploy log, polling for 404), stop it before ending the turn. The user should never inherit a running task from a previous step.

## Cross-machine note

This uninstall removes the published `.well-known/` files and this machine's local keys + config. It does NOT touch other machines that cloned the hosting repo. The platform publish skills handle this on the next install (they `git pull` and check for recent uninstall commits before re-publishing), so you don't need to do anything special here — just be aware that `backups: []` on another machine doesn't prove the user never installed.
