# Questions

Review starts here.

1. **Command name — `list` (vs `show` / `config`).** Leaning **`list`**, flagged for review. `show` — barely used by anyone. `config` — git/npm use it, but for value get/**set**; ours is read-only, and a get/set config API is overkill for our ~1 setting (the current agent provider — see Q3). `list` — best CRUD fit (create/list/update/delete) and widely used (`gh ... list`, `docker ls`, `kubectl get`). `read` would be CRUD-correct but no CLI uses it (sounds weird). Confirm `list`?
2. **`sign-token` → `token`?** Suggestion: rename to **`token`** — it prints an agent token, exactly like **`gh auth token`** prints the auth token. It's nearly zero-arg (agent provider + agent-id default from config). Keep, rename, or drop entirely (since `fetch` mints its own token internally)? It earns its place only as "give me a token to use elsewhere (curl/debug)."
3. **Should `create` bundle everything, or split?** `create` does three things in one step: registers the agent provider, generates a signing key, and binds a person server. Keep it as one-step setup (convenience, like `gh repo create` wiring everything), or split into separate orthogonal commands (e.g. bring back a `generate` for keys)? Related: `generate` is dropped for v1 (create mints the first key); multi-key/rotation is deferred — when added, fold into `update` (`--rotate-key`) or a dedicated key verb / `key` sub-group (à la `gh ssh-key add`).
4. **Multiple agent providers / a `current` marker.** Sole agent provider auto-defaults. For multiple: adopt a `current`/default agent provider (kubectl current-context, aws default profile, git `origin`), used when `--agent-provider` is omitted and switchable (e.g. a `use <url>` command)? Newest `create` auto-becomes current?
5. **Do we need `--quiet`?** Output is always JSON on stdout, errors on stderr — is there any silent/quiet need at all, or is `--quiet` unnecessary for this package?
6. **Single-letter flags — add them, and when?** All dropped for now (long-form only: `--help`, `--version`, `--person-server`). Add shorts later, or now? (Strict-Unix shorts are single-char `-p`, not `-ps`.)
7. **Breaking changes — all OK?** No one is using this yet, so presumably yes — confirm we're fine with: config key `agents` → `agentProviders`; `show` → `list`; `add-agent`/`remove-agent` → `create`/`delete`; dropping `discover`/`public-key`/`generate` (folded into `create`)/`--verbose`/`--jsonl`; `--agent` → `--agent-provider`; default output text → JSON.

# Contents

- [`npx @aauth/bootstrap`](#npx-aauthbootstrap) — top-level help (also `help`, `--help`)
- [`list`](#npx-aauthbootstrap-list) — list agent providers, keys, keystores
- [`create`](#npx-aauthbootstrap-create) `<agent-provider-url> [--keystore <name>] [--algorithm <alg>] [--person-server <url>]` — register an agent provider
- [`update`](#npx-aauthbootstrap-update) `<agent-provider-url> [--person-server <url>]` — update an agent provider
- [`delete`](#npx-aauthbootstrap-delete) `<agent-provider-url>` — delete an agent provider and its keys
- [`sign-token`](#npx-aauthbootstrap-sign-token) `[--agent-provider <url>] [--lifetime <s>]` — sign an agent token
- [`skill`](#npx-aauthbootstrap-skill) `[name]` — agent setup guides
- [`help`](#npx-aauthbootstrap) `[command]` — help

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
  sign-token [--agent-provider <url>] [--lifetime <s>]
                                        Sign an agent token
  help [command]                        Show help for a command

GLOBAL
  --help      Show help
  --version   Print version
```

# `npx @aauth/bootstrap list`

```text
List configured agent providers, their keys (with public
JWKs), and the keystores available on this machine.

USAGE
  npx @aauth/bootstrap list

EXAMPLE
  $ npx @aauth/bootstrap list
  {
    "keystores": [
      { "keystore": "software", "algorithms": ["EdDSA", "ES256"] },
      { "keystore": "secure-enclave", "algorithms": ["ES256"] },
      { "keystore": "yubikey-piv", "algorithms": ["ES256", "RS256"] }
    ],
    "agentProviders": [
      {
        "url": "https://descartes.github.io",
        "agentId": "aauth:local@descartes.github.io",
        "personServer": "https://person.hello.coop",
        "keys": [
          {
            "kid": "bd3f9c…",
            "current": true,
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
  --keystore <name>       Where to create the key: software (default), secure-enclave, yubikey-piv
  --algorithm <alg>       EdDSA (default for software), ES256, RS256
  --person-server <url>   Person server to bind (default: person.hello.coop)
  --jwks-uri <uri>        JWKS URI for the agent provider
  --hosting <name>        Hosting platform (with --repo <repo>)

EXAMPLE
  $ npx @aauth/bootstrap create https://descartes.github.io
  {
    "agentProvider": "https://descartes.github.io",
    "agentId": "aauth:local@descartes.github.io",
    "personServer": "https://person.hello.coop",
    "keys": [
      { "kid": "bd3f9c…", "current": true, "keystore": "software" }
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
      { "kid": "bd3f9c…", "current": true, "keystore": "software" }
    ]
  }
```

# `npx @aauth/bootstrap delete`

```text
Delete an agent provider and its keys, including from hardware keystores.
Removing the keys is the whole point — a config file is easy to edit by hand,
a hardware key is not. Fails if the agent provider doesn't exist.

USAGE
  npx @aauth/bootstrap delete <agent-provider-url>

EXAMPLE
  $ npx @aauth/bootstrap delete https://descartes.github.io
  {
    "deleted": "https://descartes.github.io",
    "keysDeleted": 1
  }
```

# `npx @aauth/bootstrap sign-token`

```text
Sign an agent token — the credential an agent presents to make authenticated calls.
With one agent provider configured, takes no flags: the agent provider and its
agent-id come from config.

USAGE
  npx @aauth/bootstrap sign-token [flags]

FLAGS
  --agent-provider <url>  Pick the agent provider (default: the only / current one in config)
  --agent-id <id>         Override the agent id (default: the resolved provider's agent)
  --local <name>          Override just the local-part → aauth:<name>@<host>
  --lifetime <seconds>    Token lifetime (default: 3600)

EXAMPLE
  $ npx @aauth/bootstrap sign-token
  {
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
- [JSON Lines (jsonlines.org)](https://jsonlines.org/) — NDJSON is a *stream*, distinct from one JSON document.

Verified firsthand by running the tools: **npm, docker, gh, aws, kubectl, ssh** — bare-invocation behavior, `--json`/`--output` conventions, and CRUD verb naming.

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
