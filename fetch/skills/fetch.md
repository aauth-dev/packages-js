---
name: fetch
description: How to use @aauth/fetch to make AAuth-authenticated HTTP requests
when: Agent needs to call an AAuth-protected API
---

# @aauth/fetch

Make HTTP requests to AAuth-protected APIs. Handles HTTP message signatures, agent tokens, and the full AAuth authorization flow including R3 (Rich Resource Requests).

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

If the resource returns a 401 challenge, fetch automatically handles the authorization flow — exchanging tokens with the person server, opening a browser for consent if needed, and retrying.

## One-shot with scopes

To request specific identity scopes (triggers 401 challenge → auth flow):

```bash
npx @aauth/fetch "https://whoami.aauth.dev?scope=email+profile"
```

## Multi-call workflow (recommended for APIs)

When making multiple calls to the same resource, use the authorize-then-call pattern to avoid repeating the auth flow.

### Step 1: Authorize and capture tokens

For resources with standard 401 challenge (e.g., whoami with scopes):
```bash
npx @aauth/fetch authorize "https://whoami.aauth.dev?scope=email"
```

For R3 resources (e.g., notes), POST to the authorize endpoint with operations:
```bash
npx @aauth/fetch authorize https://notes.aauth.dev/authorize \
  --operations listNotes,createNote
```

Both return JSON with the auth token and ephemeral signing key:
```json
{
  "auth_token": "eyJ...",
  "expires_in": 3600,
  "signingKey": { "kty": "EC", "crv": "P-256", "d": "...", "x": "...", "y": "..." },
  "response": { "status": 200 }
}
```

If the resource accepts an agent token directly (no auth needed), returns:
```json
{
  "signingKey": { "kty": "EC", "crv": "P-256", "d": "...", "x": "...", "y": "..." },
  "signatureKey": { "type": "jwt", "jwt": "eyJ..." },
  "response": { "status": 200, "body": { ... } }
}
```

Save `auth_token` and `signingKey` for subsequent calls. The `signingKey` is the ephemeral private key bound to the auth token — you must use the same key for all requests. (Spec-defined fields use the spec's snake_case names, e.g. `auth_token`/`expires_in`; our own artifacts like `signingKey` stay camelCase.)

### Step 2: Make calls with saved tokens

Pass tokens via JSON stdin (recommended — avoids exposing keys in process list):

```bash
echo '{
  "url": "https://notes.aauth.dev/notes",
  "method": "GET",
  "auth_token": "eyJ...",
  "signingKey": {"kty":"EC","crv":"P-256","d":"...","x":"...","y":"..."}
}' | npx @aauth/fetch --json
```

Or for POST/PUT:
```bash
echo '{
  "url": "https://notes.aauth.dev/notes",
  "method": "POST",
  "body": {"title": "My Note", "content": "Content here"},
  "auth_token": "eyJ...",
  "signingKey": {"kty":"EC","crv":"P-256","d":"...","x":"...","y":"..."}
}' | npx @aauth/fetch --json
```

### Token expiration

Auth tokens have a limited lifetime (typically 1 hour). If a call returns a 401 after previously working, the token has expired. Re-run the `authorize` step to get fresh tokens.

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

## Capabilities

Capabilities declare which protocol features the agent supports. By default, fetch declares `interaction` capability (unless `--non-interactive` is set).

```bash
npx @aauth/fetch --capabilities interaction,clarification https://resource.example
```

| Capability | Meaning |
|-----------|---------|
| `interaction` | Agent can direct a user to a URL for authentication, consent, payment, or other actions. Declared by default. |
| `clarification` | Agent can engage in back-and-forth clarification chat with the user through the person server. |
| `payment` | Agent can handle payment flows — either directly or via its person server. |

Via JSON stdin:
```json
{
  "url": "https://resource.example",
  "capabilities": ["interaction", "clarification"]
}
```

## Commands

| Command | Description |
|---------|-------------|
| `<resource>` | Authenticated fetch — full flow (sign → 401 → token exchange → consent → retry) |
| `authorize <resource>` | Auth flow only; return auth token + signing key as JSON (no resource call). R3 via `--operations` |
| `skill` | Print this usage guide (markdown), plus the AAuth protocol spec URL to fetch yourself |
| (bare) / `--help` | Top-level help |

## All flags

| Flag | Description |
|------|-------------|
| `--agent-only` | Sign with agent token only; don't handle 401 |
| `--auth-token` / `--signing-key` | Use an existing auth token + signing key (skip the auth flow) |
| `--json` | Read full request from stdin as JSON (input only) |
| `-X, --method` | HTTP method (default: GET) |
| `-d, --data` | Request body (use `-` for stdin) |
| `-H, --header` | Additional header (repeatable) |
| `--agent-provider` | Agent provider to sign as (default: from config) |
| `--local` | Local part of agent identifier (default: from config) |
| `--scope` | Requested scopes |
| `--operations` | R3 operationIds (comma-separated, with `authorize`) |
| `--person-server` | Override person server URL |
| `--login-hint` | Hint about who to authorize |
| `--domain-hint` | Domain/org routing hint |
| `--tenant` | Tenant identifier |
| `--justification` | Markdown explaining why access is needed |
| `--capabilities` | Agent capabilities (comma-separated) |
| `--no-browser` | Don't open browser for consent |
| `--non-interactive` | Fail if consent is needed |
| `-v, --verbose` | Print every request/response on stderr as pretty JSON (type/step/description + real RFC 9421 headers) |

## Verbose output (`-v`)

Each `-v` event is `{ type, step, description, … }` on stderr (stdout stays clean
for `jq`):

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

When consent is needed, a browser opens at the approval URL by default. With
`--no-browser`, the URL is printed on stderr (`Approve at: https://…`) along with a
scannable QR code — open the link or scan it from your phone. With `-v`, a
`consent_required` event also appears in the stream:
```json
{"type": "info", "step": "consent_required", "description": "Consent required — opening the approval URL for the person."}
```

## Environment variables

| Variable | Equivalent flag |
|----------|----------------|
| `AAUTH_AGENT_URL` | `--agent-provider` |
| `AAUTH_LOCAL` | `--local` |
| `AAUTH_AUTH_TOKEN` | `--auth-token` |
| `AAUTH_SIGNING_KEY` | `--signing-key` |
| `AAUTH_PERSON_SERVER` | `--person-server` |
