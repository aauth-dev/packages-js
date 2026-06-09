---
name: uninstall
description: Tear down an AAuth agent provider identity — remove the published .well-known files, delete local keys, and wipe config so the machine can be bootstrapped fresh
when: User wants to uninstall AAuth, remove an agent provider, delete their keys, or return the machine to a clean pre-bootstrap state
---

# Skill: Uninstall an AAuth agent provider identity

This returns the machine to a clean, pre-bootstrap state. There are three kinds
of artifact, in two places:

- **Remote** — the `.well-known/jwks.json` and `aauth-agent.json` files published
  to a hosting platform (GitHub Pages, Cloudflare Pages, …). Only the hosting
  platform's tooling can remove these.
- **Local** — signing keys (in the OS keychain / Secure Enclave / YubiKey) and
  the `~/.aauth` config dir. The `uninstall` command removes these.

## ⚠️ Before you start: this breaks running agents

Tearing down an identity will break **any running agent or MCP server that uses
it**, on two independent layers:

1. Once the local keys/config are gone, the agent can no longer **sign** requests
   — the next call fails.
2. Once the published JWKS is removed, resources can no longer **verify** the
   agent's existing signatures — even a server that cached its key in memory
   starts getting rejected.

**Confirm with the user** that no production service depends on this identity,
and that any running agents/MCP servers using it have been stopped, before doing
anything destructive. Confirm again before each destructive step.

## 1. See what's there

```
npx @aauth/bootstrap list
```

If there are no agent providers, the machine is already clean — stop. Otherwise
the output is the map for everything below: each agent's `hosting`, `jwksUri`,
and `keys`.

## 2. Remove the remote `.well-known` files FIRST

Do this **before** wiping config — the config holds the `hosting` pointers you
need to find the files. For each agent provider in `list`:

- Read its `hosting.platform` and `hosting.repo`.
- Load the matching platform skill (`npx @aauth/bootstrap skill <platform>`,
  e.g. `github-pages`) and use that platform's tooling (`gh`, `wrangler`, …) to
  delete `.well-known/jwks.json` and `.well-known/aauth-agent.json` (or remove
  the whole `.well-known/` directory) and push.

Confirm the files are gone (e.g. `curl -I <jwksUri>` returns 404) before
continuing.

## 3. Preview the local teardown (dry-run)

`uninstall` is dry-run by default — it prints exactly what it WOULD delete and
removes nothing:

```
npx @aauth/bootstrap uninstall
```

Review `agents[].keysToDelete`, `orphanedKeychainUrls`, and `willRemoveConfigDir`
with the user.

## 4. Perform the teardown

After the user confirms, run it for real with `--force`:

```
npx @aauth/bootstrap uninstall --force
```

This **backs up the config first** (agent URL, person server, hosting, key
metadata — never private keys) to `~/.aauth/backups/`, then deletes every agent's
keys across all keystores, sweeps orphaned keychain entries, and removes the
active `config.json`. The output's `backupPath` points at the snapshot.

- A YubiKey PIV key (slot 9e) can't be wiped programmatically yet — it appears
  under `hardwareKeysRetained` with a manual command (`ykman piv keys delete 9e`).
  Relay that to the user.

## 5. Verify

```
npx @aauth/bootstrap list
```

No agent providers means the machine is clean and ready to bootstrap fresh. The
backup remains under `backups` in the `list` output — next time the user sets up,
the `setup` skill can reuse the same agent URL, person server, and hosting (with
fresh keys).

## Cross-machine note: this uninstall is only visible on the remote, not on other machines

Uninstalling here removes:

- The published `.well-known/` files from the hosting repo (step 2).
- This machine's local keys, config, and adds a backup entry under
  `~/.aauth/backups/`.

It does **not** modify any other machine that previously cloned the hosting
repo. Another laptop with the GitHub Pages repo checked out will still have a
stale local copy of `.well-known/jwks.json` containing the keys you just
removed. If `setup` runs there and follows the (older) "read existing JWKS and
append" instruction, it can silently resurrect the deleted keys when it pushes.

The `github-pages` platform skill now requires `git pull` + a check for recent
uninstall commits before publishing, which catches this. But if you wrote
custom tooling around AAuth or are running an out-of-date skill version,
remember: an empty `backups: []` on another machine does NOT mean the user
never installed; it only means *that* machine never uninstalled. Confirm with
the user before treating any setup as "first-time" when a hosting repo with
git history exists.
