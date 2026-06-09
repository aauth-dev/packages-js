# Design: `uninstall` for `@aauth/bootstrap`

Status: proposed
Goal: return a machine to a clean, pre-bootstrap state so it can be bootstrapped again from scratch — deleting local keys, the `~/.aauth` directory, and (guided) the remote `.well-known` files that bootstrap published.

## What bootstrap leaves behind

A bootstrapped machine has artifacts in three places. `uninstall` must account for all of them:

| Artifact | Location | Locally deletable |
|----------|----------|-------------------|
| `config.json`, `.tldr-shown` | `~/.aauth/` (local dir) | ✅ yes |
| Software keys | OS keychain — service `aauth`, account = agent URL | ✅ `deleteKeychain(agentUrl)` |
| Secure Enclave keys | macOS SE hardware — label `com.aauth.agent.*` | ✅ `se-helper delete <label>` |
| YubiKey PIV key | YubiKey slot 9e | ✅ (after native addon adds delete — see Phase A) |
| `.well-known/jwks.json` + `aauth-agent.json` | Remote hosting (GitHub Pages, Cloudflare, Netlify, …) | ❌ remote — removed by the uninstall **skill** via platform tooling |

## Core principle: `~/.aauth/config.json` is the map

**The first step of every uninstall is to check for the `~/.aauth` directory.** Its presence is the signal that the machine was bootstrapped, and `config.json` is the single source of truth that tells you *everything you need to tear down*:

- **Where the keys are** — each agent's `keys` map records, per `kid`, the `backend` (`software` / `secure-enclave` / `yubikey-piv`) and the backend-specific `keyId` (keychain account, SE label, or PIV slot). That's enough to delete each key from the right backend.
- **Where `.well-known` is hosted** — each agent's `hosting.platform` (e.g. `github-pages`) and `hosting.repo` (e.g. `user/user.github.io`), plus `agentServerUrl` / `jwksUri`, point at exactly which remote files to remove and which platform tool (`gh`, `wrangler`, …) to use.

So the teardown is fully discoverable from config:

```
~/.aauth/config.json
└─ agents
   └─ "https://me.github.io"
      ├─ keys: { "<kid>": { backend, keyId, ... } }   → what to delete, and how
      └─ hosting: { platform: "github-pages",          → where .well-known lives
                    repo: "me/me.github.io" }
```

If `~/.aauth` does **not** exist, the machine is already clean (any keychain/hardware keys without config are swept as orphans — see below — but there is nothing to map).

## Command: `aauth-bootstrap uninstall`

### Scope
- `uninstall` (no args) → **full clean slate**: delete every configured agent's keys across all backends, sweep orphaned keychain entries not in config, then remove the entire `~/.aauth` directory.
- `uninstall --agent <url>` → scope to one agent: delete its keys, remove it from `config.json`. Leave `~/.aauth` in place if other agents remain.

### Flags
- `--agent <url>` — scope to a single agent.
- `--dry-run` — print the deletion plan as JSON; delete nothing. Run this first.
- `--log` — narrate each step on stderr (JSONL), matching the other commands.

### Behavior
1. Read `~/.aauth/config.json`. If absent → report already-clean (still sweep orphaned keychain URLs from `listAgentUrls()`).
2. Build the deletion plan from config: for each in-scope agent, list each key `{ backend, keyId }` and the remote `.well-known` files derived from `hosting` / `agentServerUrl` / `jwksUri`.
3. For each key, call `getBackend(meta.backend).deleteKey(meta.keyId)`.
4. Sweep orphaned software keys: any `listAgentUrls()` entry in scope that wasn't covered by config → `deleteKeychain(url)`.
5. Remove config: `deleteAgentConfig(url)` per agent, or `clearConfig()` (rm `~/.aauth`) on a full wipe.
6. Emit JSON: keys deleted (by backend), **remote `.well-known` files still to remove** (with `platform` / `repo`), and any failures.

The CLI is **local-only** — it never touches remote hosting. It *reports* the remote files and where they live so the skill (or user) can remove them. Because `config.json` holds the hosting pointers, **remote files must be removed before the config is wiped** — the skill enforces this ordering.

### Example output (`--dry-run`)
```json
{
  "scope": "all",
  "agents": [
    {
      "agentUrl": "https://me.github.io",
      "keysToDelete": [
        { "kid": "k1", "backend": "secure-enclave", "keyId": "com.aauth.agent.2026-05-18_a3f" },
        { "kid": "k2", "backend": "yubikey-piv", "keyId": "9e" }
      ],
      "remoteFilesToRemove": [
        "https://me.github.io/.well-known/jwks.json",
        "https://me.github.io/.well-known/aauth-agent.json"
      ],
      "hosting": { "platform": "github-pages", "repo": "me/me.github.io" }
    }
  ],
  "orphanedKeychainUrls": [],
  "willRemoveConfigDir": true
}
```

## Skill: `skills/uninstall.md`

Auto-discovered by `listSkills()` (no loader change). Front-matter matches `setup.md` conventions. The body drives the agent through the ordered teardown:

1. **Check for `~/.aauth`** and run `npx @aauth/bootstrap show`. No directory → already clean, stop. Otherwise `show` reveals each agent, its keys, and its hosting — the map for everything below.
2. **Remove remote `.well-known` files first.** For each agent's `hosting.platform`, load the matching `skills/platforms/*.md` and use its tooling (`gh`, `wrangler`, …) to delete `jwks.json` + `aauth-agent.json` (or the whole `.well-known/`) and push. Do this **before** wiping config — config holds the hosting pointers.
3. **Delete keys + config.** Run `npx @aauth/bootstrap uninstall --dry-run` to preview, confirm with the user, then run for real.
4. **Verify.** `npx @aauth/bootstrap show` → clean. Machine is ready to bootstrap fresh.

The skill must confirm with the user before any destructive step.

## Implementation phases (dependency order)

### Phase A — `@aauth/hardware-keys` (Rust addon): native YubiKey delete
- Add `pub fn delete_key(...)` in `yubikey_piv.rs` and a `#[napi] delete_key(backend, key_id)` export in `lib.rs`; rebuild the native module.
- ⚠️ **Caveat:** PIV slot 9e has no clean "erase private key" op without the **management key**; the standard path deletes the cert object / overwrites the slot on next generate. Implement the closest reliable behavior (delete cert + best-effort slot reset) and surface clearly when the management key is required. Secure Enclave already supports `se-helper delete`, so it is unaffected.

### Phase B — `@aauth/local-keys`: deletion primitives
- `config.ts`: add + export `deleteAgentConfig(agentUrl)` and `clearConfig()` (rm `~/.aauth`).
- `keychain.ts`: export the existing `deleteKeychain` via `index.ts`.
- `types.ts`: add optional `deleteKey?(keyId: string): Promise<void>` to `KeyBackendDriver`.
- Implement `deleteKey` in each backend: `software` → `deleteKeychain`; `secure-enclave` → `callHelper('delete', keyId)`; `yubikey-piv` → new addon fn from Phase A.

### Phase C — `@aauth/bootstrap`: the command + skill
- `cmdUninstall(flags, positional)` in `src/cli.ts` implementing the behavior above.
- Wire into the command `switch` and `cmdHelp()`; add a hint to the `cmdShow` footer.
- New `skills/uninstall.md` (`skills/` is already in `package.json` `files`).

### Phase D — Tests
- Unit test for the uninstall path (config-driven plan, full-wipe vs `--agent`, orphan sweep), mirroring `bootstrap-ps.test.ts` style.
- Hardware deletion (SE / YubiKey) behind availability guards.

## Files touched
- `hardware-keys/src/yubikey_piv.rs`, `hardware-keys/src/lib.rs` (+ rebuild)
- `local-keys/src/config.ts`, `local-keys/src/keychain.ts`, `local-keys/src/index.ts`, `local-keys/src/types.ts`
- `local-keys/src/backends/{software,secure-enclave,yubikey-piv}.ts`
- `bootstrap/src/cli.ts`, `bootstrap/skills/uninstall.md`
- Tests under `bootstrap/src/` and `local-keys/src/`
