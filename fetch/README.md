# @aauth/fetch

CLI for making AAuth-authenticated HTTP requests. Handles HTTP Message Signatures, agent tokens, and the full AAuth authorization flow including R3 (Rich Resource Requests).

Part of [aauth-dev/packages-js](https://github.com/aauth-dev/packages-js). Protocol spec: [dickhardt/AAuth](https://github.com/dickhardt/AAuth).

## Prerequisites

The agent must be bootstrapped with a person server before making authorized requests. Use [`@aauth/bootstrap`](../bootstrap):

```bash
npx @aauth/bootstrap --ps <your-ps-url>
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
npx @aauth/fetch --authorize "https://whoami.aauth.dev?scope=email"

# For R3 resources, POST to the authorize endpoint with operations:
npx @aauth/fetch --authorize https://notes.aauth.dev/authorize \
  --operations listNotes,createNote
```

Returns the auth token and ephemeral signing key. Save them and pass back in via JSON stdin to avoid exposing keys on the process command line.

## Usage

```
aauth-fetch [options] <url>

Meta:
  --skill                     Output LLM-readable usage guide

Modes:
  --authorize                 Auth only: return authToken + signingKey JSON
  --agent-only                Sign with agent token only, don't handle 401
  --operations <ops>          R3 operationIds (comma-separated, with --authorize)
  --scope <scope>             Requested scopes

Request:
  -X, --method <method>       HTTP method (default: GET)
  -d, --data <body>           Request body (use - for stdin)
  -H, --header <header>       Additional header (repeatable)
  --json                      Read full request from stdin as JSON

AAuth:
  --agent-url <url>           Agent URL (default: from config)
  --local <name>              Local part of agent identifier (default: from config)
  --auth-token <jwt>          Pre-existing auth token
  --signing-key <jwk>         Ephemeral private key (with --auth-token)
  --person-server <url>       Override person server URL

Hints & prompt:
  --login-hint <hint>         Hint about who to authorize (user/account)
  --domain-hint <domain>      Domain/org hint for identity provider routing
  --tenant <tenant>           Tenant identifier for multi-tenant systems
  --justification <text>      Markdown explaining why access is needed

Capabilities:
  --capabilities <list>       Agent capabilities: interaction, clarification, payment

Interaction:
  --browser                   Force open browser for consent
  --no-browser                Never open browser
```

## For AI Agents

Run `npx @aauth/fetch --skill` to print a structured LLM-readable usage guide covering discovery, one-shot requests, the authorize-then-call workflow, and how to pipe JSON tokens between calls.

## Related Packages

- [`@aauth/bootstrap`](../bootstrap) — set up agent keys and configure a person server (run this first)
- [`@aauth/mcp-agent`](../mcp-agent) — programmatic agent-side AAuth for use inside applications

## License

MIT
