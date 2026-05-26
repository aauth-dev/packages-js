export function topLevelHelp(version: string): string {
  return `DESCRIPTION
  AAuth fetch v${version} — make a signed, authenticated request to <resource> and
  print its response. Runs the full AAuth flow adaptively: sign with the agent token
  and send; on a 401/202 challenge, exchange the resource token for an auth token
  (consent if needed) and retry; for a resource-managed (two-party) resource, carry
  the opaque AAuth-Access token instead. Result on stdout is the response body
  (pretty JSON when JSON, else raw); --with-token returns the reusable credential
  alongside it.

USAGE
  npx @aauth/fetch <resource> [flags]
  npx @aauth/fetch authorize <resource> [flags]
  npx @aauth/fetch skill
  npx @aauth/fetch help [command]

COMMANDS
  authorize <resource>
    Run the auth flow only and print tokens for reuse — no resource call.
    See \`npx @aauth/fetch help authorize\`.

  skill
    Print the agent guide for using fetch (markdown), plus the AAuth protocol
    spec URL to fetch yourself.

  help [command]
    Show help for a command.

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

MODE (modifiers)
  --agent-only
    Sign with the agent token and send; do not handle a 401 challenge.

  --auth-token <jwt>  --signing-key <jwk>
    Use an existing auth token + signing key (skip the auth flow). Three-party reuse.

  --opaque-token <token>
    Reuse an opaque AAuth-Access token (two-party / resource-managed). Sent under
    the AAuth scheme and bound to the request signature; no signing key needed.

  --with-token
    Return the reusable credential alongside the response — the call plus the
    next-call shortcut in one invocation. Shape (fields appear only when relevant):
      { auth_token, expires_in, signingKey, response }     three-party
      { opaque_token, response }                           two-party
    \`response\` is the resource's response body (same as bare fetch). \`signingKey\`
    is emitted only with \`auth_token\` (three-party reuse needs it); two-party
    reuse needs only the opaque_token. See EXAMPLES.

HINTS (passed through the auth flow)
  --login-hint <hint>      Hint about who to authorize (user / account)
  --domain-hint <domain>   Domain/org hint for identity-provider routing
  --tenant <id>            Tenant identifier for multi-tenant systems

CONSENT (when the person must approve)
  --justification <md>     Markdown shown at the consent prompt
  --no-browser             Don't open a browser — print the approval URL + a QR to scan
  --non-interactive        Don't prompt at all — fail if consent is required

CAPABILITIES
  --capabilities <list>    Agent capabilities — interaction, clarification,
                           payment (comma-separated; default: interaction)

OUTPUT
  -v, --verbose
    Also print every protocol event on stderr as a pretty JSON object: "type"
    (request|response|info), "step" (pairs a request with its response), a
    "description", and method/url/status + the real RFC 9421 signed headers.

EXAMPLES
  One-shot — run the full flow and print the response body:

  $ npx @aauth/fetch https://whoami.aauth.dev
  {
    "sub": "aauth:local@me.github.io",
    "ps": "https://person.hello.coop"
  }

  Reuse across calls — add --with-token to get the response AND the auth token in one
  call, then export the token so later calls reuse it (no consent, no person-server
  round-trip):

  $ OUT=$(npx @aauth/fetch --with-token https://notes.aauth.dev/notes)
  $ export AAUTH_AUTH_TOKEN=$(jq -r .auth_token  <<<"$OUT")
  $ export AAUTH_SIGNING_KEY=$(jq -c .signingKey <<<"$OUT")
  $ npx @aauth/fetch https://notes.aauth.dev/notes      # reuses the saved token`
}

export const COMMAND_HELP: Record<string, string> = {
  authorize: `DESCRIPTION
  Run the AAuth auth flow only and print the auth token + signing key for reuse —
  it does NOT make the final resource call. With --operations, uses the R3
  authorize endpoint to authorize specific operations. The auth token is
  person-authorized (issued by the person server after consent) — distinct from
  the agent token that \`bootstrap token\` mints locally.

USAGE
  npx @aauth/fetch authorize <resource> [flags]

FLAGS
  --operations <ids>       Comma-separated operationIds to authorize (R3)
  --scope <scope>          Requested scopes

  (also accepts the AAUTH, HINTS, CONSENT, and CAPABILITIES flags)

EXAMPLE
  Authorize once, capture the output, and export the token to call a protected resource:

  $ OUT=$(npx @aauth/fetch authorize https://notes.aauth.dev/authorize --operations listNotes,createNote)
  $ export AAUTH_AUTH_TOKEN=$(jq -r .auth_token  <<<"$OUT")
  $ export AAUTH_SIGNING_KEY=$(jq -c .signingKey <<<"$OUT")

  Next — call the protected resource with the saved credential. Each call is a
  single signed request: no consent, no person-server round-trip.

  $ npx @aauth/fetch https://notes.aauth.dev/notes
  $ npx @aauth/fetch -X POST -d '{"title":"x","content":"y"}' https://notes.aauth.dev/notes

  The ephemeral signing key is emitted so it isn't re-minted — the same key must
  sign every reuse.`,

  skill: `DESCRIPTION
  Print the agent guide for using @aauth/fetch (markdown), plus a URL pointer to
  the AAuth protocol spec to fetch yourself. There is one guide — no name needed.

USAGE
  npx @aauth/fetch skill`,
}
