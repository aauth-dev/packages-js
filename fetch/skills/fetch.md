---
name: fetch
description: How to use @aauth/fetch to make AAuth-authenticated HTTP requests
when: Agent needs to call an AAuth-protected API
---

# @aauth/fetch

Make HTTP requests to AAuth-protected APIs. Handles HTTP message signatures, agent tokens, and the full AAuth authorization flow including R3 (Rich Resource Requests).

> **More for agents:** machine-readable index at https://www.aauth.dev/llms.txt · overview at https://www.aauth.dev · protocol spec linked under "Learn more" below.

## Prerequisites

The agent must have a signing key and a person server configured before making authorized requests:

```bash
# Register an agent provider: generate a key, bind it, and bind the default
# person server (person.hello.coop) — all in one command.
npx @aauth/bootstrap create <your-agent-provider-url>

# ...or point at a specific person server
npx @aauth/bootstrap create <your-agent-provider-url> --person-server https://person.example
```

`create` validates the PS metadata and stores the PS URL plus agent identifier (e.g., `aauth:local@yourdomain.com`) in `~/.aauth/config.json`. Person binding then happens lazily on the first authorized request. See `npx @aauth/bootstrap` for the full setup flow.

## Discovery

Before calling an API, discover what it supports:

```bash
# Fetch resource metadata
curl https://example.aauth.dev/.well-known/aauth-resource.json
```

The metadata tells you:
- What scopes are available (`scope_descriptions`)
- Whether it uses R3 vocabularies (`r3_vocabularies`) and which authorization endpoint to use
- The resource's signing keys (`jwks_uri`)

For R3 resources with OpenAPI vocabularies:
```bash
# Fetch the OpenAPI spec to see available operationIds
curl https://notes.aauth.dev/openapi.json
```

## One-shot request (simplest)

For resources that work with just an agent token (no authorization needed):

```bash
npx @aauth/fetch https://whoami.aauth.dev
```

If the resource returns a 401 challenge, fetch automatically handles the authorization flow — exchanging tokens with the person server, surfacing a consent URL (+ QR) if approval is needed, and retrying. (Pass `--browser` to auto-open the URL instead of printing it.)

## One-shot with scopes

To request specific identity scopes (triggers 401 challenge → auth flow):

```bash
npx @aauth/fetch "https://whoami.aauth.dev?scope=email+profile"
```

## Multi-call workflow (recommended for APIs)

When making multiple calls to the same resource, authorize once (one consent) and
reuse the returned `auth_token` + `signingKey` so later calls skip the
person-server round-trip. Two ways to capture the credential:

- **`authorize <resource>`** — runs the auth flow only and returns the credential (no resource call).
- **`--emit`** on a normal fetch — makes the call *and* returns the credential alongside the response.

### Step 1: Authorize once and capture

Run `authorize` **once**, capturing stdout — don't print it and then run it again to
capture (each run re-mints the token and may re-prompt for consent). `$OUT` then
holds the reusable credential:

```bash
OUT=$(npx @aauth/fetch authorize https://notes.aauth.dev/authorize --operations listNotes,createNote)
```

- For a standard 401-challenge resource (e.g. whoami with scopes), pass the resource
  URL instead: `OUT=$(npx @aauth/fetch authorize "https://whoami.aauth.dev?scope=email")`.
- Or capture *with* the call in one shot via `--emit` (makes the request AND
  returns the credential): `OUT=$(npx @aauth/fetch --emit https://notes.aauth.dev/notes)`.

**Output shape — fields appear only when relevant:**
- Three-party (PS-asserted): `{ auth_token, expires_in, signingKey, response? }`. `response` is the resource body (omitted by `authorize` since it makes no resource call); `signingKey` is the ephemeral private key the auth_token is `cnf`-bound to — needed on every reuse.
- Two-party (resource-managed): `{ aauth_access_token, response? }`. **No `signingKey`** — the AAuth-Access token binds per-request to the agent identity, so reuse only needs the token.
- Agent-token-only 200 (resource accepted the agent token directly): `{ signingKey, signatureKey, response }` — both emitted so you can reuse that exact agent token without re-minting.

(Spec-defined fields use snake_case — `auth_token`/`expires_in`/`aauth_access_token`; our own artifacts like `signingKey`/`signatureKey` stay camelCase.)

### Step 2: Reuse the captured token

**Why:** authorizing runs the consent flow. Do it once, then reuse the `auth_token`
+ `signingKey` so every later call is a single signed request — no consent, no
person-server round-trip. The token is **never written to disk**; you reuse it.

**Important for agents:** a command can't set its parent shell's environment. So
you (the caller) capture the output and reuse it — build a **shell script or a
connected sequence of commands/pipes** that runs Step 1 and Step 2 in order,
passing the captured value forward. Below, `$OUT` holds the Step 1 output. Three
ways to reuse it — pick one:

**A. Export to the environment (recommended).** fetch auto-reads `AAUTH_AUTH_TOKEN`
and `AAUTH_SIGNING_KEY`, so later calls pick the token up with no extra flags:

```bash
export AAUTH_AUTH_TOKEN=$(jq -r .auth_token  <<<"$OUT")   # $OUT captured in Step 1
export AAUTH_SIGNING_KEY=$(jq -c .signingKey <<<"$OUT")

# Next — call the protected resource. Each call is one signed request: no consent,
# no person-server round-trip.
npx @aauth/fetch https://notes.aauth.dev/notes
npx @aauth/fetch -X POST -d '{"title":"hi"}' https://notes.aauth.dev/notes

# When done, drop them from your shell so they don't shadow later calls to other
# resources (the auth_token's `aud` claim is bound to one resource):
unset AAUTH_AUTH_TOKEN AAUTH_SIGNING_KEY
```

> **Tip — scope to a subshell instead of `unset`.** If you'd rather not pollute the
> outer shell at all, wrap the whole sequence in `( … )` — exported env vars
> vanish when the subshell exits.

**B. Pass as flags explicitly** on the next call:

```bash
npx @aauth/fetch \
  --auth-token  "$(jq -r .auth_token  <<<"$OUT")" \
  --signing-key "$(jq -c .signingKey <<<"$OUT")" \
  https://notes.aauth.dev/notes
```

**C. Pass via JSON stdin** (keeps keys out of the process list / argv):

```bash
echo '{
  "url": "https://notes.aauth.dev/notes",
  "method": "POST",
  "body": {"title": "My Note", "content": "Content here"},
  "auth_token": "eyJ...",
  "signingKey": {"kty":"EC","crv":"P-256","d":"...","x":"...","y":"..."}
}' | npx @aauth/fetch --json
```

In all three, `signingKey` is the ephemeral private key bound to the auth token —
you **must** use the same key on every reuse (it isn't re-minted).

### Two-party (resource-managed) reuse

Some resources manage authorization themselves instead of delegating to a person
server. After authorizing, they hand back an **`AAuth-Access` token** (in the
`aauth_access_token` field of `authorize` / `--emit` output). Reuse it with
`--aauth-access-token` — it's sent under the `AAuth` scheme and bound to the request
signature, so **no signing key is needed** (your agent identity from config signs it):

```bash
OUT=$(npx @aauth/fetch --emit https://resource.example/api)
export AAUTH_ACCESS_TOKEN=$(jq -r .aauth_access_token <<<"$OUT")   # or pass --aauth-access-token "$TOKEN"
npx @aauth/fetch https://resource.example/api                     # reuses the AAuth-Access token
```

The resource may return a new `AAuth-Access` token on any response (rolling refresh);
`--emit` surfaces the latest one. Unlike the three-party auth token, this token
is opaque and resource-specific — only send it back to the resource that issued it.

### Token expiration

Auth tokens have a limited lifetime (typically 1 hour). If a call returns a 401 after previously working, the token has expired. Re-run the `authorize` step (or `--emit`) to get fresh tokens.

## Agent-only mode

To sign with just an agent token without triggering the authorization flow:

```bash
npx @aauth/fetch --agent-only https://whoami.aauth.dev
```

Useful when the resource accepts agent identity without requiring an auth token.

## R3 (Rich Resource Requests)

For resources that use R3 vocabularies (like OpenAPI-based APIs), you must specify which operations to authorize:

```bash
# Authorize specific operations
npx @aauth/fetch authorize https://notes.aauth.dev/authorize \
  --operations listNotes,createNote,deleteNote

# Then make calls with the returned tokens
echo '{"url":"https://notes.aauth.dev/notes","method":"GET","auth_token":"...","signingKey":{...}}' \
  | npx @aauth/fetch --json
```

The `--operations` flag takes comma-separated operationIds from the resource's OpenAPI spec. The person server presents these to the user for consent, showing what data access and actions are being requested.

## Agent identifier

The `--local` flag overrides the local part of the agent identifier (`aauth:<local>@<domain>`). By default, fetch reads the agent identifier from config (set during bootstrap).

```bash
# Use a specific agent identifier
npx @aauth/fetch --local claude https://whoami.aauth.dev
```

This produces `aauth:claude@yourdomain.com` as the agent identifier in the agent token.

## Hint parameters

Hints help the person server route authorization requests. They are optional and passed during token exchange.

| Flag | JSON field | Purpose |
|------|-----------|---------|
| `--login-hint <hint>` | `login_hint` | Hint about who to authorize — a user identifier, email, or account name. Helps the person server identify the correct user. |
| `--domain-hint <domain>` | `domain_hint` | Hints at which domain or organization the user belongs to. Used in enterprise/multi-tenant systems to route to the correct identity provider. |
| `--tenant <id>` | `tenant` | Tenant identifier for multi-tenant systems. Specifies which organization context should be used for authorization. |

Example:
```bash
npx @aauth/fetch authorize https://resource.example \
  --login-hint user@acme.com \
  --tenant acme.com
```

Or via JSON stdin:
```json
{
  "url": "https://resource.example",
  "authorize": true,
  "login_hint": "user@acme.com",
  "tenant": "acme.com"
}
```

## Justification

The `--justification` flag provides a Markdown string explaining **why** the agent is requesting access. The person server presents this to the user during consent review.

```bash
npx @aauth/fetch authorize https://notes.aauth.dev/authorize \
  --operations listNotes \
  --justification "Read the user's notes to summarize action items from today's meeting"
```

Via JSON stdin:
```json
{
  "url": "https://notes.aauth.dev/authorize",
  "authorize": true,
  "operations": "listNotes",
  "justification": "Read the user's notes to summarize action items from today's meeting"
}
```

Justification is especially important for autonomous agents — it enables human reviewers to make informed consent decisions that policy engines cannot make automatically.

## Interaction capability

fetch declares the `interaction` capability to the person server — meaning the
agent can direct the user to a URL to authenticate, consent, or otherwise act.
Pass `--non-interactive` to declare no capability (and fail rather than prompt
if consent turns out to be required).

## Commands

<!-- AUTOGEN:COMMANDS -->

## All flags

<!-- AUTOGEN:FLAGS -->

## Inspecting requests (`--explain` / `--debug`)

Both write to stderr, so stdout stays clean for `jq`. Pick by intent:

- **`--explain`** — the *teaching* view. Each protocol step is a pretty JSON
  object `{ type, step, description, … }` with method/url/status, the real RFC 9421
  signed headers, and the request/response bodies.
- **`--debug`** (also `-v` / `--verbose`) — the *raw wire* view. Every HTTP hop is
  a `{ request }` object (method, url, headers, body) followed by a `{ response }`
  object (status, headers, body). No descriptions, no `info` events — just what
  went over the wire.

In `--explain`:

- **`type`** — `request` | `response` | `info`.
- **`step`** — which protocol step this is, named by what it targets / the token
  it carries (a request pairs with the response right after it). Vocabulary:

| step | what it is |
|------|------------|
| `agent_token_request` | the call to the resource signed with your agent token (may get a 401 challenge) |
| `auth_token_request` | the call to the resource signed with the person-authorized auth token (the retry, or a pre-authed reuse) |
| `challenge` | parsed the 401 — exchange the resource token for an auth token |
| `authorize_request` | (R3) POST operations to the resource's authorize endpoint |
| `ps_metadata` | discover the person server's endpoints |
| `token_exchange` | trade the resource token for an auth token at the person server |
| `consent_required` | the person must consent; the approval URL is opened |
| `consent_prompt` | waiting for the person to approve |
| `consent_poll` | poll for the consent result (repeats while waiting) |
| `consent_granted` | the person approved |
| `auth_token` | the auth token was received |

- **`description`** — a one-line beat in the flow: a request states intent; a
  response states what came back (never the bare status code).

## Error handling

Errors are output as JSON to stderr:
```json
{"error": "description of what went wrong"}
```

When consent is needed, the approval URL is printed on stderr (`Approve at: https://…`)
along with a scannable QR code — open the link or scan it from your phone. fetch does
**not** open a browser by default (an agent / CI / SSH session has no GUI to open one
on); pass `--browser` to auto-open it on a machine that does. With `--explain`, a
`consent_required` event also appears in the stream:
```json
{"type": "info", "step": "consent_required", "description": "Consent required — opening the approval URL for the person."}
```

## Environment variables

<!-- AUTOGEN:ENV -->

## Caching

- **Tokens are never cached to disk.** The `auth_token` and any access token are
  output (with `authorize` / `--emit`) for you to reuse as you see fit —
  there is no automatic on-disk token reuse. See "Step 2: Reuse the captured token".
- **Person-server metadata is cached** (it's public, not a secret) under
  `~/.aauth/cache/<host>/aauth-person.json`, with expiry tracked in
  `~/.aauth/cache/index.json`. `bootstrap` seeds it (a one-time setup step), but the
  cache is then read, refreshed, and self-healed by `fetch` on use — honoring the
  server's `Cache-Control: max-age` (default ~1 day). This lets the token exchange
  skip the `/.well-known/aauth-person.json` round-trip. If a cached endpoint goes
  stale (404/410 or unreachable), fetch evicts it and refetches once automatically.
