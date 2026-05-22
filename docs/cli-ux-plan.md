# Questions

Review starts here.

1. **Command name — `list` (vs `show` / `config` / `read`).** Leaning **`list`**, flagged for review. `show` — barely used by anyone. `config` — git/npm use it, but for value get/**set**; ours is read-only. `read` — used by credential tools like us (HashiCorp Vault `read`, 1Password `op read`), **but in those tools `read` fetches one item by path and `list` enumerates** (both have `vault list` / `op item list`). Our command enumerates the whole config, which is the *list* operation in their own vocabulary — so `read` would only fit if reframed as `read <agent-provider-url>` (one provider). `list` — enumerate-all; consistent with create/update/delete and widely used (`gh ... list`, `docker ls`, `kubectl get`, plus `vault list` / `op item list`). Lean: `list`. Open: enumerate-all (`list`) or read-one (`read <provider>`)?
2. **`token` — suggested (mirrors `gh auth token`).** A standalone command to mint an agent token for use elsewhere (curl, debugging). Suggest keeping it with this name, since it mirrors `gh auth token`.
3. **Multiple keys per provider — how do you select and manage them?** The data model already supports multiple keys per agent provider (redundancy across devices, rotation), but there's no way to *invoke* a specific one — e.g. a `--kid` flag on `token` to choose which key signs? There's also no way to add or delete individual keys on an existing provider (`create` only mints the first; `delete` wipes the whole provider). How should key selection and add/delete work?
4. **Multiple agents per agent provider — first-class or ad-hoc?** A provider's key can sign a token for any `sub`, so it can back many agents (`aauth:local@…`, `aauth:claude@…`, `aauth:research-bot@…`). But config stores only **one** `agentId` per provider and there's no command to manage a set. Keep one default + ad-hoc overrides (`--local`/`--agent-id` per call), or make agents first-class (store/list/add/remove agents under a provider)?
5. **Multiple agent providers / a `current` provider marker.** Sole agent provider auto-defaults. For multiple: adopt a `current`/default agent provider (kubectl current-context, aws default profile, git `origin`), used when `--agent-provider` is omitted and switchable (e.g. a `use <url>` command)? Newest `create` auto-becomes current?
6. **Do we need `--quiet`?** Output is always JSON on stdout, errors on stderr — is there any silent/quiet need at all, or is `--quiet` unnecessary for this package?
7. **Single-letter flags — add them, and when?** All dropped for now (long-form only: `--help`, `--version`, `--person-server`). Add shorts later, or now? (Strict-Unix shorts are single-char `-p`, not `-ps`.)
8. **What does `update` cover, and do `--jwks-uri`/`--hosting` belong anywhere?** `update` currently has only `--person-server`; the provider's other settings could be updatable too. And `--jwks-uri`/`--hosting` (carried over from `add-agent`) are metadata that nothing publishes — publishing is via skills — so are they needed at all, and on which command (`create`? `update`?)? Removed from `create` for now. Changing the agent id (`--local`/`agentId`) changes the agent's `sub`, **orphaning existing person bindings**, so it may not belong as a plain `update` flag. (Keys are Q3.)
9. **Breaking changes:** config key `agents` → `agentProviders`; `show` → `list`; `add-agent`/`remove-agent` → `create`/`delete`; dropping `discover`/`public-key`/`generate` (folded into `create`); dropping the `--log`/`--jsonl` output flags; `--agent` → `--agent-provider`; default output text → JSON.

# Contents

- [`npx @aauth/bootstrap`](#npx-aauthbootstrap) — top-level help (also `help`, `--help`)
- [`list`](#npx-aauthbootstrap-list) — list agent providers, keys, keystores
- [`create`](#npx-aauthbootstrap-create) — register an agent provider
  - required: `<agent-provider-url>`
  - optional: `--keystore <name>`, `--algorithm <alg>`, `--person-server <url>`
  - default: software keystore, EdDSA, person.hello.coop
- [`update`](#npx-aauthbootstrap-update) — update an agent provider
  - required: `<agent-provider-url>`
  - optional: `--person-server <url>`
- [`delete`](#npx-aauthbootstrap-delete) — delete an agent provider and its keys
  - required: `<agent-provider-url>`
- [`token`](#npx-aauthbootstrap-token) — generate an agent token
  - optional: `--agent-provider <url>`, `--agent-id <id>`, `--local <name>`, `--lifetime <s>`
  - default: current agent provider + its agent-id, lifetime 3600s
- [`skill`](#npx-aauthbootstrap-skill) — agent setup guides
  - optional: `name`
- [`help`](#npx-aauthbootstrap) — help
  - optional: `command`

# `npx @aauth/bootstrap`

```text
AAuth bootstrap vX.Y.Z — set up an agent provider identity for AAuth.

Agents: run `npx @aauth/bootstrap skill setup` for end-to-end setup.

USAGE
  npx @aauth/bootstrap <command> [flags]

COMMANDS
  skill [name]                          Agent setup guides — start here:
      setup             Set up an agent identity end-to-end
      github-pages      Publish to GitHub Pages
      gitlab-pages      Publish to GitLab Pages
      cloudflare-pages  Publish to Cloudflare Pages
      netlify           Publish to Netlify
  list                                  List agent providers, keys, and keystores
  create <agent-provider-url> [--keystore <name>] [--algorithm <alg>] [--person-server <url>]
                                        Register an agent provider (generates its first key, binds a person server)
  update <agent-provider-url> [--person-server <url>]
                                        Update an agent provider's settings
  delete <agent-provider-url>           Delete an agent provider and its keys
  token [--agent-provider <url>] [--agent-id <id>] [--local <name>] [--lifetime <s>]
                                        Generate an agent token
  help [command]                        Show help for a command

GLOBAL
  --help      Show help
  --version   Print version
```

# `npx @aauth/bootstrap list`

```text
List configured agent providers, their keys (with public JWKs), and the
keystores available on this machine.

USAGE
  npx @aauth/bootstrap list

EXAMPLE
  $ npx @aauth/bootstrap list
  {
    "keystores": [
      { "keystore": "software", "description": "Software keys stored in OS keychain", "algorithms": ["EdDSA", "ES256"] },
      { "keystore": "secure-enclave", "description": "macOS Secure Enclave (Apple Silicon)", "algorithms": ["ES256"] }
    ],
    "agentProviders": [
      {
        "url": "https://descartes.github.io",
        "agentId": "aauth:local@descartes.github.io",
        "personServer": "https://person.hello.coop",
        "keys": [
          {
            "kid": "bd3f9c…",
            "keystore": "software",
            "publicJwk": { "kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS…", "alg": "EdDSA" }
          }
        ]
      }
    ]
  }
```

# `npx @aauth/bootstrap create`

```text
Register a new agent provider. One command does the whole setup:
  - generates a signing key (in the chosen keystore)
  - binds that key to the agent provider
  - binds a person server (default: person.hello.coop, unless --person-server)
Fails if the agent provider already exists (use `update`).

USAGE
  npx @aauth/bootstrap create <agent-provider-url> [flags]

FLAGS
  --keystore <name>       which keystore to use (default: software) — run `list` for available keystores
  --algorithm <alg>       an algorithm the chosen keystore supports (see `list`); defaults to the keystore's default
  --person-server <url>   Person server to bind (default: person.hello.coop)

EXAMPLE
  $ npx @aauth/bootstrap create https://descartes.github.io
  {
    "agentProvider": "https://descartes.github.io",
    "agentId": "aauth:local@descartes.github.io",
    "personServer": "https://person.hello.coop",
    "keys": [
      { "kid": "bd3f9c…", "keystore": "software",
        "publicJwk": { "kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS…", "alg": "EdDSA" } }
    ]
  }
```

# `npx @aauth/bootstrap update`

```text
Update an existing agent provider's settings (e.g. its person server).
Fails if the agent provider doesn't exist (use `create`).

USAGE
  npx @aauth/bootstrap update <agent-provider-url> [flags]

FLAGS
  --person-server <url>   Change the bound person server

EXAMPLE
  $ npx @aauth/bootstrap update https://descartes.github.io --person-server https://person.example
  {
    "agentProvider": "https://descartes.github.io",
    "agentId": "aauth:local@descartes.github.io",
    "personServer": "https://person.example",
    "keys": [
      { "kid": "bd3f9c…", "keystore": "software",
        "publicJwk": { "kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS…", "alg": "EdDSA" } }
    ]
  }
```

# `npx @aauth/bootstrap delete`

```text
Delete an agent provider and its keys, including from hardware keystores.
Fails if the agent provider doesn't exist.

USAGE
  npx @aauth/bootstrap delete <agent-provider-url>

EXAMPLE
  $ npx @aauth/bootstrap delete https://descartes.github.io
  {
    "deleted": "https://descartes.github.io",
    "keysDeleted": 1
  }
```

# `npx @aauth/bootstrap token`

```text
Generate an agent token — the credential an agent presents to make authenticated calls.
With one agent provider configured it needs no arguments — the agent provider and
its agent-id come from config. Output is the agent token (`signatureKey`) plus
the ephemeral private key (`signingKey`) you sign requests with — the token's `cnf`
binds to its public half.

USAGE
  npx @aauth/bootstrap token [flags]

FLAGS
  --agent-provider <url>  Pick the agent provider (default: the only / current one in config)
  --agent-id <id>         Override the agent id (default: the resolved provider's agent)
  --local <name>          Override just the local-part → aauth:<name>@<host>
  --lifetime <seconds>    Token lifetime (default: 3600)

EXAMPLE
  $ npx @aauth/bootstrap token
  {
    "signingKey": { "kty": "OKP", "crv": "Ed25519", "x": "…", "d": "…" },
    "signatureKey": {
      "type": "jwt",
      "jwt": "eyJhbGci…"
    }
  }
```

# `npx @aauth/bootstrap skill`

```text
Print agent setup guides — how to generate keys and publish your agent identity.

USAGE
  npx @aauth/bootstrap skill [name]

  No name   List available skills
  <name>    Print that skill's full instructions (markdown, plain text)

SKILLS
  setup             Set up an agent identity end-to-end
  github-pages      Publish to GitHub Pages
  gitlab-pages      Publish to GitLab Pages
  cloudflare-pages  Publish to Cloudflare Pages
  netlify           Publish to Netlify

EXAMPLE
  $ npx @aauth/bootstrap skill
  [
    { "name": "setup", "description": "Set up AAuth agent identity — generate signing keys, add keys from new devices, and publish to a hosting platform" },
    { "name": "github-pages", "description": "Publish AAuth agent metadata and public keys to GitHub Pages (username.github.io)" },
    { "name": "gitlab-pages", "description": "Publish AAuth agent metadata and public keys to GitLab Pages (username.gitlab.io)" },
    { "name": "cloudflare-pages", "description": "Publish AAuth agent metadata and public keys to Cloudflare Pages" },
    { "name": "netlify", "description": "Publish AAuth agent metadata and public keys to Netlify" }
  ]
```

`skill <name>` prints that guide's full markdown (plain text — the one non-JSON command output besides help).

# Research

Conventions in this plan follow established CLI practice. Sources referenced:

- [Command Line Interface Guidelines (clig.dev)](https://clig.dev/) — stdout vs stderr split, print help on no args, machine-readable output.
- [GitHub CLI — output formatting](https://cli.github.com/manual/gh_help_formatting) — help on bare invocation; `gh auth token` precedent for a token-printing command.

Verified firsthand by running the tools: **npm, docker, gh, aws, kubectl, ssh** — bare-invocation behavior, default-output (text-vs-JSON) conventions, and CRUD verb naming.

## Agent-first: JSON by default

Output is **pretty-printed JSON by default** — no `--json` flag. These tools are built to be driven by agents (agent-first, the way "mobile-first" reframed web design), so structured output is the primary case. Pretty-printing keeps it readable for the occasional human too, and `jq` consumes pretty JSON fine.

This is the **aws model** (JSON-default) rather than the gh/npm model (text-default + `--json`) — but for a different reason than aws's. aws defaults to JSON because it's a thin passthrough over API responses; we default to JSON because the primary *operator* is an agent.

## Bare invocation prints help

Run with no command, the tool prints top-level help — matching npm, gh, git, docker, cargo. Help is **plain text** (not JSON), shows the version, lists every command with its flags inline, and surfaces `skill setup` first so an agent finds the setup path immediately.

## Errors & exit codes

Exit code is `0` on success, non-zero on failure. Errors print to **stderr** as a single JSON object: `{ "error": "<message>" }`. stdout stays clean (empty on error), so `… | jq` never chokes on a non-result; consumers branch on the exit code.

## Naming: agent vs agent provider

The configured entity is an **agent provider** — a URL like `descartes.github.io` that publishes keys/metadata. A specific **agent** is an instance under it, like `claude@descartes.github.io`, identified by the `sub`/agent-id when a token is signed. The term `agentProvider`/`agentProviders` (data) and `--agent-provider`/`<agent-provider-url>` (CLI) is used everywhere for consistency and to avoid clashing with the overloaded auth sense of "provider" (identity/OAuth provider).

The agent itself is never "created" or registered — the agent provider self-asserts it by signing a token with that `sub`, and it becomes person-bound on the first authorized `fetch` request (consent at the person server). bootstrap manages *agent providers*; agents are implicit.

# Implementation notes

- **Output is pretty-printed JSON, syntax-colorized when stdout is a TTY** — easy for a human to read at the terminal.
- **When piped or redirected (non-TTY), or when `NO_COLOR` is set, color is dropped** so the output is plain, valid JSON — machine-readable and safe to pipe straight into `jq` (`… | jq`). Color (ANSI) codes never reach a pipe, so `jq` never sees them.
- **One format either way — no `--json` / `--pretty` flags.** Pretty + colorized for a human at the terminal; clean JSON for a pipe or an agent. The same examples in this doc are what both get (minus the color).
- Help (and `skill <name>` markdown) are the only plain-text, non-JSON outputs.
