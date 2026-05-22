# Contents

- [`npx @aauth/bootstrap`](#npx-aauthbootstrap) — top-level help
  - [`npx @aauth/bootstrap help`](#npx-aauthbootstrap)
  - [`npx @aauth/bootstrap --help`](#npx-aauthbootstrap)
  - [`npx @aauth/bootstrap -h`](#npx-aauthbootstrap)
- [`npx @aauth/bootstrap show`](#npx-aauthbootstrap-show) — status: agents, keys, backends
- [`npx @aauth/bootstrap generate`](#npx-aauthbootstrap-generate) — generate a signing key
- [`npx @aauth/bootstrap sign-token`](#npx-aauthbootstrap-sign-token) — sign a one-off agent token
- [`npx @aauth/bootstrap public-key`](#npx-aauthbootstrap-public-key) — print public key(s)
- [`npx @aauth/bootstrap add-agent`](#npx-aauthbootstrap-add-agent) — register an agent URL
- [`npx @aauth/bootstrap remove-agent`](#npx-aauthbootstrap-remove-agent) — remove an agent
- [`npx @aauth/bootstrap skill`](#npx-aauthbootstrap-skill) — agent-readable guide

# `npx @aauth/bootstrap`

### Prints top-level help and lists commands.

## Aliases
- `npx @aauth/bootstrap help`
- `npx @aauth/bootstrap --help`
- `npx @aauth/bootstrap -h`

## Output

### Default
```text
Set up an AAuth agent identity — keys, person server, hosting.

USAGE
  npx @aauth/bootstrap <command> [options]

COMMANDS
  show          Show configured agents, keys, and available backends
  generate      Generate a signing key
  sign-token    Sign a one-off agent token
  public-key    Print public key(s)
  add-agent     Register an agent URL
  remove-agent  Remove an agent from config
  skill         Print agent-readable usage guide
  help          Show help for a command

GLOBAL OPTIONS
  -h, --help       Show help
      --version    Print version
      --json       Output result as JSON
  -v, --verbose    Show detailed progress (stderr)

EXAMPLES
  npx @aauth/bootstrap generate --agent https://me.github.io --ps
  npx @aauth/bootstrap show
  npx @aauth/bootstrap help generate
```

# `npx @aauth/bootstrap show`

### Shows configured agents, keys, and available backends.

## Output

### `--help`/`-h`
```text
Show configured agents, keys, and available backends.

USAGE
  npx @aauth/bootstrap show [options]

OPTIONS
  -h, --help       Show help
      --json       Output result as JSON
  -v, --verbose    Show detailed progress (stderr)
```

### Default
```text
Backends:
  software        EdDSA, ES256
  secure-enclave  ES256
  yubikey-piv     ES256, RS256

Agents:
  https://me.github.io
    person-server  person.hello.coop
    bd3f… [EdDSA] software (this device)  (current)

Next step — make your first authenticated request:
  npx @aauth/fetch https://whoami.aauth.dev
```

### `--json`
```json
{
  "backends": [
    { "backend": "software", "algorithms": ["EdDSA", "ES256"] },
    { "backend": "secure-enclave", "algorithms": ["ES256"] },
    { "backend": "yubikey-piv", "algorithms": ["ES256", "RS256"] }
  ],
  "agents": [
    {
      "url": "https://me.github.io",
      "personServer": "https://person.hello.coop",
      "keys": [
        { "kid": "bd3f…", "alg": "EdDSA", "backend": "software", "device": "this device", "current": true }
      ]
    }
  ]
}
```

### `-v`/`--verbose`
```text
reading config ~/.aauth/config.json…    ← stderr
scanning software keychain…             ← stderr
discovering backends…                   ← stderr
<default output above, on stdout>
```

### `--json` `-v`/`--verbose`
```text
reading config ~/.aauth/config.json…    ← stderr
scanning software keychain…             ← stderr
discovering backends…                   ← stderr
<json output above, on stdout>
```

# `npx @aauth/bootstrap generate`

### Generates a signing key for an agent.

## Flags
- `--backend <name>` — `software` (default), `yubikey-piv`, `secure-enclave`
- `--algorithm <alg>` — `EdDSA` (default for software), `ES256`, `RS256`
- `--agent <url>` — associate the key with an agent URL
- `--ps [url]` — also bind a person server (default: `person.hello.coop`)

## Output

### `--help`/`-h`
```text
Generate a signing key for an agent.

USAGE
  npx @aauth/bootstrap generate [options]

OPTIONS
  --backend <name>    software (default), yubikey-piv, secure-enclave
  --algorithm <alg>   EdDSA (default for software), ES256, RS256
  --agent <url>       Associate the key with an agent URL
  --ps [url]          Also bind a person server (default: person.hello.coop)

  -h, --help          Show help
      --json          Output result as JSON
  -v, --verbose       Show detailed progress (stderr)
```

### Default
```text
Generated EdDSA signing key
  kid      bd3f9c…
  backend  software (this device)
  agent    https://me.github.io
```

### `--json`
```json
{
  "kid": "bd3f9c…",
  "publicJwk": {
    "kty": "OKP",
    "crv": "Ed25519",
    "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
    "alg": "EdDSA"
  }
}
```

### `-v`/`--verbose`
```text
discovering backends… software, secure-enclave      ← stderr
generating EdDSA key on software…                   ← stderr
writing private key to keychain (~/.aauth)…         ← stderr
registering key with agent https://me.github.io…    ← stderr
<default output above, on stdout>
```

### `--json` `-v`/`--verbose`
```text
discovering backends… software, secure-enclave      ← stderr
generating EdDSA key on software…                   ← stderr
writing private key to keychain (~/.aauth)…         ← stderr
registering key with agent https://me.github.io…    ← stderr
<json output above, on stdout>
```

# `npx @aauth/bootstrap sign-token`

### Signs a one-off agent token.

## Flags
- `--agent <url>` — agent URL (required)
- `--agent-id <id>` — agent identifier (default: from config)
- `--lifetime <seconds>` — token lifetime (default: 3600)

## Output

### `--help`/`-h`
```text
Sign a one-off agent token.

USAGE
  npx @aauth/bootstrap sign-token --agent <url> [options]

OPTIONS
  --agent <url>          Agent URL (required)
  --agent-id <id>        Agent identifier (default: from config)
  --lifetime <seconds>   Token lifetime in seconds (default: 3600)

  -h, --help             Show help
      --json             Output result as JSON
  -v, --verbose          Show detailed progress (stderr)
```

### Default
```text
Signed agent token for https://me.github.io
  expires  in 1h (2026-05-22 11:30 UTC)
  token    eyJhbGci…
```

### `--json`
```json
{
  "signatureKey": {
    "type": "jwt",
    "jwt": "eyJhbGci…"
  }
}
```

### `-v`/`--verbose`
```text
reading config ~/.aauth/config.json…              ← stderr
resolving signing key for https://me.github.io…   ← stderr
signing agent token (ttl=3600s)…                  ← stderr
<default output above, on stdout>
```

### `--json` `-v`/`--verbose`
```text
reading config ~/.aauth/config.json…              ← stderr
resolving signing key for https://me.github.io…   ← stderr
signing agent token (ttl=3600s)…                  ← stderr
<json output above, on stdout>
```

### error
```text
error: --agent is required
```

# `npx @aauth/bootstrap public-key`

### Prints public key(s).

## Flags
- `--agent <url>` — print the key for this agent (default: all keys)

## Output

### `--help`/`-h`
```text
Print public key(s).

USAGE
  npx @aauth/bootstrap public-key [options]

OPTIONS
  --agent <url>   Print the key for this agent (default: all keys)

  -h, --help      Show help
      --json      Output result as JSON
  -v, --verbose   Show detailed progress (stderr)
```

### Default
```text
Public key for https://me.github.io
  kid      bd3f9c…
  alg      EdDSA
  backend  software
```

### `--json`
```json
{
  "kty": "OKP",
  "crv": "Ed25519",
  "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
  "kid": "bd3f9c…",
  "alg": "EdDSA"
}
```

### `-v`/`--verbose`
```text
resolving key for https://me.github.io…       ← stderr
reading public key from software backend…     ← stderr
<default output above, on stdout>
```

### `--json` `-v`/`--verbose`
```text
resolving key for https://me.github.io…       ← stderr
reading public key from software backend…     ← stderr
<json output above, on stdout>
```

# `npx @aauth/bootstrap add-agent`

### Registers an agent URL in config.

## Flags
- `--jwks-uri <uri>` — JWKS URI for the agent
- `--hosting <name>` — hosting platform (with `--repo <repo>`)
- `--kid <kid>` + `--backend <name>` + `--key-id <id>` — attach an existing key (optional `--algorithm`, `--device`)

## Output

### `--help`/`-h`
```text
Register an agent URL in config.

USAGE
  npx @aauth/bootstrap add-agent <url> [options]

OPTIONS
  --jwks-uri <uri>    JWKS URI for the agent
  --hosting <name>    Hosting platform (with --repo <repo>)
  --kid <kid>         Attach an existing key: its key id …
  --backend <name>    … its backend …
  --key-id <id>       … and backend-specific key id

  -h, --help          Show help
      --json          Output result as JSON
  -v, --verbose       Show detailed progress (stderr)
```

### Default
```text
Registered agent https://me.github.io
  person-server  (none)
  keys           (none)
```

### `--json`
```json
{
  "agentUrl": "https://me.github.io",
  "config": {
    "keys": {}
  }
}
```

### `-v`/`--verbose`
```text
validating https://me.github.io…        ← stderr
writing config ~/.aauth/config.json…    ← stderr
<default output above, on stdout>
```

### `--json` `-v`/`--verbose`
```text
validating https://me.github.io…        ← stderr
writing config ~/.aauth/config.json…    ← stderr
<json output above, on stdout>
```

### error
```text
error: invalid agent URL "htps://typo"
```

# `npx @aauth/bootstrap remove-agent`

### Removes an agent from config.

## Flags
- `--purge` — also delete the agent's keys (irreversible for hardware backends)
- `-y`, `--yes` — skip the confirmation prompt (required with `--json` / non-interactive)

## Output

### `--help`/`-h`
```text
Remove an agent from config.

USAGE
  npx @aauth/bootstrap remove-agent <url> [options]

OPTIONS
  --purge         Also delete the agent's keys (irreversible for hardware keys)
  -y, --yes       Skip the confirmation prompt

  -h, --help      Show help
      --json      Output result as JSON
  -v, --verbose   Show detailed progress (stderr)

List configured agents with: npx @aauth/bootstrap show
```

### Default
```text
Remove agent https://me.github.io and keep its keys? [y/N] y    ← stderr (prompt)
Removed agent https://me.github.io
```

### `--json`
```json
{
  "removed": "https://me.github.io",
  "keysDeleted": 0
}
```

### `-v`/`--verbose`
```text
reading config ~/.aauth/config.json…      ← stderr
removing agent https://me.github.io…      ← stderr
writing config…                           ← stderr
<default output above, on stdout>
```

### `--json` `-v`/`--verbose`
```text
reading config ~/.aauth/config.json…      ← stderr
removing agent https://me.github.io…      ← stderr
writing config…                           ← stderr
<json output above, on stdout>
```

### error
```text
error: no agent registered for https://unknown.example
```

# `npx @aauth/bootstrap skill`

### Prints agent-readable skill guides.

## Output

### `--help`/`-h`
```text
Print agent-readable skill guides.

USAGE
  npx @aauth/bootstrap skill [name]

  No name  — list available skills
  <name>   — print that skill's full instructions (markdown)

OPTIONS
  -h, --help      Show help
      --json      Output result as JSON
```

### Default (list)
```text
Available skills:
  bootstrap-agent   Set up an agent identity end-to-end
  publish-jwks      Publish your JWKS to a hosting platform
```

### `skill <name>`
```text
# Bootstrap an AAuth agent

1. Detect the strongest available key backend…
2. Generate a signing key…
3. Bind a person server…
…(full markdown instructions)
```

### `--json`
```json
[
  { "name": "bootstrap-agent", "description": "Set up an agent identity end-to-end" },
  { "name": "publish-jwks", "description": "Publish your JWKS to a hosting platform" }
]
```

# Research

Conventions in this plan follow established CLI practice. Sources referenced:

- [Command Line Interface Guidelines (clig.dev)](https://clig.dev/) — stdout vs stderr split, "show output on success but keep it brief", print help on no args, prefer JSON for machine output.
- [GitHub CLI — output formatting](https://cli.github.com/manual/gh_help_formatting) — `--json` for machine-readable output; `-h`/`--help` treated identically.
- [JSON Lines (jsonlines.org)](https://jsonlines.org/) — NDJSON / JSONL is a newline-delimited *stream*, distinct from one JSON document.
- [HTTPie docs](https://httpie.io/docs/cli) — human-readable/colorized by default at a TTY, machine output when piped.

Verified firsthand by running the tools: **npm, docker, gh, aws, curl, kubectl, ssh** — default-vs-`--json` output, `-v`/`--verbose` and `-q`/`--quiet` conventions, and single-dash (`-h`) vs double-dash (`--help`) flag forms.

## Bare invocation prints help

Run with no command, the tool prints top-level help — matching **npm, gh, git, docker, cargo**, which all print help on bare invocation. Bare invocation and `--help` are expected to agree. (We considered a status dashboard on bare invocation but rejected it to follow this convention; status lives behind the explicit `show` verb.)

## Human-readable by default (aws is the exception)

Most comparable tools default to human-readable text and take an explicit `--json` (or `--format json` / `-o json`) for machine output — verified with **gh, npm, docker, kubectl**. **aws is the exception: it defaults to JSON**, because it's a thin passthrough over API responses where there's no natural human form. bootstrap is a `gh auth login`-style setup tool, not an API passthrough, so it follows the human-default majority.

## Errors & exit codes

Exit code is `0` on success, non-zero on failure. Errors print to **stderr**. With
`--json`, an error is emitted as a single JSON object: `{ "error": "<message>" }`.

## Why no `--jsonl` / `--ndjson`

JSON Lines (NDJSON) is a *stream* format for unbounded or large sequences — one JSON object per line, processed incrementally. In the wild it shows up in loggers (pino, bunyan), watch/streaming commands (`docker events`, `kubectl --watch`), and LLM token streams — **not as a general-purpose CLI flag.** None of the comparable tools (gh, npm, docker, kubectl) expose a `--jsonl` flag, and developers don't expect one.

A command's *result* is bounded, so the convention is **one JSON document** via `--json` — which pipes to `jq` just as well as a stream does (`jq` reads both). "Only JSONL is pipeable" is a myth; the real difference is streaming, which a bounded result doesn't need.

Dropping `--jsonl` also removes a genuine ambiguity: `--json` (the result, as data) vs `--jsonl` (which a user could reasonably read as "my result, one record per line"). One result format, `--json`, keeps the mental model clean.

## TBD / to revisit later

- **`-q` / `--quiet`** — suppress non-essential output (brief confirmations, progress, warnings), leaving only the result and errors. It's the low end of the same verbosity axis as `-v` (`-q` errors-only → default brief → `-v` detailed). Standard convention (curl `-s`, git `-q`, npm `--quiet`), but deferred for now — add once the default vs `-v` behavior is settled.
- **`protocol` / `spec` skill** — print the AAuth spec from a single source of truth (not vendored in this repo). Lean toward a **skill** (`skill protocol`) over a new command, since it's agent-readable reference text — the same channel/consumer as existing skills, and avoids re-growing the command surface. Source via **live-fetch from the canonical spec URL** (version-pinned) with a cached offline fallback; vendoring a snapshot would drift and contradicts "single source of truth." Open: spec version to pin, network/offline behavior.
- **Keep `discover` / `config` as deprecated aliases of `show`?** Both were dropped as subsets of `show` (`discover` ≈ `show`'s backends, `config` ≈ `show --json`). To avoid breaking existing scripts, consider keeping them as deprecated aliases (`discover` → `show`, `config` → `show --json`) that print a deprecation notice, rather than removing them outright.
