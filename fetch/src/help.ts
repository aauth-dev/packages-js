export function topLevelHelp(version: string): string {
  return `DESCRIPTION
  AAuth fetch v${version} — curl for agents. Make a signed, authenticated HTTP
  request that handles the AAuth challenge flow (401 → token exchange → consent → retry)
  for you, then prints the response. Bare <url> is the full flow.

USAGE
  npx @aauth/fetch <url> [flags]
  npx @aauth/fetch authorize <url> [flags]
  npx @aauth/fetch skill [name]

COMMANDS
  authorize <url>
    Run the auth flow only and print tokens for reuse — no resource call.
    See \`npx @aauth/fetch authorize --help\`.

  skill [name]
    Print agent skills (markdown). No name lists them; <name> prints one.

REQUEST
  -X, --method <method>
    HTTP method (default: GET)

  -d, --data <body>
    Request body (use - for stdin)

  -H, --header <header>
    Add a request header (repeatable)

  --json
    Read the whole request (method/headers/body) from stdin as a JSON object.

AAUTH
  --agent-provider <url>
    Agent provider to sign as (default: from config)

  --local <name>
    Local part of the agent id (default: from config)

  --person-server <url>
    Person server for token exchange (default: from config)

MODE (modifiers — still return the resource response)
  --agent-only
    Sign with the agent token and send; do not handle a 401 challenge.

  --auth-token <jwt>  --signing-key <jwk>
    Use an existing auth token + signing key (skip the auth flow).

HINTS (passed through the auth flow)
  --login-hint <hint>      Hint about who to authorize (user / account)
  --domain-hint <domain>   Domain/org hint for identity-provider routing
  --tenant <id>            Tenant identifier for multi-tenant systems

CONSENT
  --justification <md>     Markdown shown at the consent prompt
  --no-browser             Don't open a browser for consent
  --non-interactive        Fail instead of prompting for consent

CAPABILITIES
  --capabilities <list>    Agent capabilities — interaction, clarification,
                           payment (comma-separated; default: interaction)

OUTPUT
  -v, --verbose
    Also print every protocol event on stderr as a pretty JSON object: "type"
    (request|response|info), "step" (pairs a request with its response), a
    "description", and method/url/status + the real RFC 9421 signed headers.

EXAMPLE
  $ npx @aauth/fetch https://whoami.aauth.dev
  {
    "sub": "aauth:local@descartes.github.io",
    "scope": "openid profile"
  }

  Add -v to also stream every request/response (with real signed headers) on
  stderr — the result on stdout stays clean for \`… | jq\`.`
}

export const COMMAND_HELP: Record<string, string> = {
  authorize: `DESCRIPTION
  Run the AAuth auth flow only and print the auth token + signing key for reuse —
  it does NOT make the final resource call. With --operations, uses the R3
  authorize endpoint to authorize specific operations. The auth token is
  person-authorized (issued by the person server after consent) — distinct from
  the agent token that \`bootstrap token\` mints locally.

USAGE
  npx @aauth/fetch authorize <url> [flags]

FLAGS
  --operations <ids>       Comma-separated operationIds to authorize (R3)
  --scope <scope>          Requested scopes

  (also accepts the AAUTH, HINTS, CONSENT, and CAPABILITIES flags)

EXAMPLE
  $ npx @aauth/fetch authorize https://notes.aauth.dev/authorize --operations listNotes,createNote
  {
    "auth_token": "eyJ…",
    "expires_in": 3600,
    "signingKey": { "kty": "OKP", "crv": "Ed25519", "x": "…", "d": "…" },
    "response": { "status": 200 }
  }`,

  skill: `DESCRIPTION
  Print agent skills as markdown — how to use fetch, plus a pointer to the AAuth
  protocol spec.

USAGE
  npx @aauth/fetch skill [name]

  No name   List available skills (markdown)
  <name>    Print that skill's full instructions (markdown)

SKILLS
  fetch       How to use @aauth/fetch to make AAuth-authenticated requests
  protocol    Fetch URL for the AAuth protocol spec`,
}
