# @aauth/fetch

CLI for making AAuth-authenticated HTTP requests. Handles HTTP Message Signatures, agent tokens, and the full AAuth authorization flow including R3 (Rich Resource Requests).

Part of [aauth-dev/packages-js](https://github.com/aauth-dev/packages-js). Protocol spec: [dickhardt/AAuth](https://github.com/dickhardt/AAuth).

## Prerequisites

The agent must be bootstrapped before making authorized requests — it needs a signing key and a person server in config. Use [`@aauth/bootstrap`](../bootstrap):

```bash
# Register an agent provider: generate a key, bind it, and bind the default
# person server (person.hello.coop) — all in one command.
npx @aauth/bootstrap create <your-agent-provider-url>

# ...or point at a specific person server
npx @aauth/bootstrap create <your-agent-provider-url> --person-server https://person.example
```

## Quick Start

```bash
# Call an AAuth-protected API — handles 401 challenges and auth flow automatically
npx @aauth/fetch https://whoami.aauth.dev

# Request specific scopes
npx @aauth/fetch "https://whoami.aauth.dev?scope=email+profile"
```

## Authorize-then-call (recommended for multi-call workflows)

Capture an auth token once, then reuse it for subsequent calls.

```bash
# 1. Authorize and capture tokens (writes JSON to stdout)
npx @aauth/fetch authorize "https://whoami.aauth.dev?scope=email"

# For R3 resources, POST to the authorize endpoint with operations:
npx @aauth/fetch authorize https://notes.aauth.dev/authorize \
  --operations listNotes,createNote
```

Returns the auth token and ephemeral signing key. Or capture the credential *with*
the call using `--emit`, then export it so later calls reuse it:

```bash
OUT=$(npx @aauth/fetch --emit https://notes.aauth.dev/notes)
export AAUTH_AUTH_TOKEN=$(jq -r .auth_token  <<<"$OUT")
export AAUTH_SIGNING_KEY=$(jq -c .signingKey <<<"$OUT")
npx @aauth/fetch https://notes.aauth.dev/notes      # signs with the saved auth token
```

Tokens are never written to disk — you decide how to reuse them (export to env,
pipe between commands). Only the public person-server metadata is cached, under
`~/.aauth/cache/`.

## Usage

```
npx @aauth/fetch <resource> [flags]          # authenticated fetch (full flow)
npx @aauth/fetch authorize <resource> [flags] # auth flow only; print tokens for reuse
npx @aauth/fetch skill                   # print the fetch guide (+ site & protocol URLs)
npx @aauth/fetch help                    # show help (--help also works)

Request:
  -X, --method <method>       HTTP method (default: GET)
  -d, --data <body>           Request body
  -H, --header <header>       Additional header (repeatable)
  --json                      Read full request from stdin as JSON (input only)

AAuth:
  --agent-provider <url>      Agent provider to sign as (default: from config)
  --local <name>              Local part of agent identifier (default: from config)
  --person-server <url>       Override person server URL

Modes:
  --agent-only                Sign with agent token only; don't handle 401
  --auth-token <jwt> --signing-key <jwk>   Use an existing auth token + signing key (three-party)
  --aauth-access-token <token>  Reuse an AAuth-Access token (two-party; no signing key)
  --emit                      Emit the reusable credential(s) to stdout alongside the body.
                              Three-party: { auth_token, expires_in, signingKey, response }
                              Two-party:   { aauth_access_token, response }  (no signingKey)
                              `response` is the body (same as bare fetch)

Authorize (with the `authorize` command):
  --operations <ops>          R3 operationIds (comma-separated)
  --scope <scope>             Requested scopes

Person server (passed during consent) / consent handling:
  --login-hint / --domain-hint / --tenant / --justification
  --prompt-login / --prompt-consent   (force re-auth / force the consent prompt)
  --browser / --non-interactive   (consent URL + QR print by default; --browser auto-opens)

Output (response body → stdout; these add detail on stderr, clean for `… | jq`):
  --explain                   Teaching view: per-step request/response with
                              summaries, descriptions, real RFC 9421 signed
                              headers, and bodies. Pretty + colorized at a TTY;
                              compact JSONL when piped/captured.
  --explain-log <path>        Write the --explain event stream (JSONL) to this
                              file (default: ~/.aauth/fetch/logs/<timestamp>.jsonl).
  --debug, -v, --verbose      Raw wire view: every HTTP hop as { request } /
                              { response } objects (with bodies); no descriptions.
```

> The CLI's full flag list is generated from one spec (`src/args.ts`) — run
> `npx @aauth/fetch --help` for the authoritative, always-current reference.

## For AI Agents

Run `npx @aauth/fetch skill` to print the agent usage guide (markdown), which also
links to https://www.aauth.dev, the llms.txt index, and the AAuth protocol spec.

## Related Packages

- [`@aauth/bootstrap`](../bootstrap) — set up agent keys and configure a person server (run this first)
- [`@aauth/mcp-agent`](../mcp-agent) — programmatic agent-side AAuth for use inside applications

## License

MIT
