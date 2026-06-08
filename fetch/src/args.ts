export interface FetchArgs {
  /** Subcommand: 'authorize' | 'skill' | 'help'. Undefined = default fetch (or help if no url). */
  command?: 'authorize' | 'skill' | 'help'
  /** Target URL (default fetch / authorize). */
  url?: string
  /** Skill name (skill command). */
  skillName?: string

  // Request
  method: string
  data?: string
  headers: string[]
  jsonInput: boolean

  // AAuth
  agentProvider?: string
  local?: string
  personServer?: string
  authToken?: string
  signingKey?: string
  /** Opaque AAuth-Access token (two-party reuse) sent under the AAuth scheme. */
  opaqueToken?: string

  // Mode (modifiers)
  agentOnly: boolean
  /** --emit: print { auth_token, expires_in, signingKey, response } (the reusable credential) instead of the raw body. */
  emit: boolean

  // Authorize
  operations?: string
  scope?: string

  // Person-server hints (sent during consent)
  loginHint?: string
  domainHint?: string
  tenant?: string
  justification?: string

  // Interaction (local consent handling)
  browser?: boolean // true = --browser (open browser); default/undefined = print URL + QR
  nonInteractive: boolean

  // Output / meta
  /** --explain: teaching view — per-step request/response with descriptions + bodies. */
  explain: boolean
  /** --debug (also -v/--verbose): raw view — every HTTP hop's request/response with bodies. */
  debug: boolean
  help: boolean
  version: boolean
}

// ── Single source of truth ────────────────────────────────────────────────────
//
// Every flag is declared once, here. The parser, the `--help` text (help.ts), the
// `--json` merge (json-input.ts), the env-var fallbacks, and the `skill` guide's
// flag table (skill.ts) are all derived from this list — so they can't drift.
// To add or change a flag, edit this array and nothing else.

/** Help section a flag belongs to (also the order they render in). */
export type FlagGroup =
  | 'Request' | 'AAuth' | 'Mode' | 'Authorize' | 'PersonServer' | 'Consent' | 'Output'

export const FLAG_GROUPS: { group: FlagGroup; heading: string }[] = [
  { group: 'Request',      heading: 'REQUEST' },
  { group: 'AAuth',        heading: 'AAUTH' },
  { group: 'Mode',         heading: 'MODE (modifiers)' },
  { group: 'Authorize',    heading: 'AUTHORIZE (with the `authorize` command)' },
  { group: 'PersonServer', heading: 'PERSON SERVER (passed to your person server during consent)' },
  { group: 'Consent',      heading: 'CONSENT (how the local consent prompt is handled)' },
  { group: 'Output',       heading: 'OUTPUT (response body → stdout; these add detail on stderr)' },
]

/**
 * How a JSON-stdin field maps onto a FetchArgs field:
 *   'string'/'boolean'/'array' — assign as-is (`json[field] ?? current`)
 *   'json'      — JSON.stringify the value if present (JWK → string)
 *   'body'      — JSON.stringify if `!== undefined` (the request body; → `data`)
 *   'headers'   — object → `["k: v", …]` array (→ `headers`)
 */
type JsonKind = 'string' | 'boolean' | 'array' | 'json' | 'body' | 'headers'

export interface FlagSpec {
  /** Canonical long flag (without `--`). */
  long: string
  /** Single-char short alias (without `-`). */
  short?: string
  /** Additional long aliases (without `--`). */
  aliases?: string[]
  kind: 'value' | 'boolean'
  /** FetchArgs property this sets. */
  field: keyof FetchArgs
  /** For value flags: the metavar shown in help, e.g. `<url>`. */
  metavar?: string
  group: FlagGroup
  /** One-line description (help + skill table). */
  summary: string
  /** Extra indented help lines under the summary (CLI `--help` only). */
  details?: string[]
  /** `--json` stdin field name (omit when the flag isn't accepted via JSON). */
  json?: string
  /** How the JSON field maps onto the FetchArgs field (default 'string'). */
  jsonKind?: JsonKind
  /** Env-var fallback (CLI flag wins). */
  env?: string
  /** Boolean flag that sets its field to `false` instead of `true` (e.g. --no-browser). */
  setsFalse?: boolean
}

export const FLAGS: FlagSpec[] = [
  // Request
  { long: 'method', short: 'X', kind: 'value', field: 'method', metavar: '<method>', group: 'Request',
    summary: 'HTTP method (default: GET)', json: 'method' },
  { long: 'data', short: 'd', kind: 'value', field: 'data', metavar: '<body>', group: 'Request',
    summary: 'Request body', json: 'body', jsonKind: 'body' },
  { long: 'header', short: 'H', kind: 'value', field: 'headers', metavar: '<header>', group: 'Request',
    summary: 'Add a request header (repeatable)', json: 'headers', jsonKind: 'headers' },
  { long: 'json', kind: 'boolean', field: 'jsonInput', group: 'Request',
    summary: 'Read the whole request (method/headers/body) from stdin as a JSON object' },

  // AAuth
  { long: 'agent-provider', kind: 'value', field: 'agentProvider', metavar: '<url>', group: 'AAuth',
    summary: 'Agent provider to sign as (default: from config)', json: 'agentProvider', env: 'AAUTH_AGENT_URL' },
  { long: 'local', kind: 'value', field: 'local', metavar: '<name>', group: 'AAuth',
    summary: 'Local part of the agent id (default: from config)', json: 'local', env: 'AAUTH_LOCAL' },
  { long: 'person-server', kind: 'value', field: 'personServer', metavar: '<url>', group: 'AAuth',
    summary: 'Person server for token exchange (default: from config)', json: 'personServer', env: 'AAUTH_PERSON_SERVER' },

  // Mode (modifiers)
  { long: 'agent-only', kind: 'boolean', field: 'agentOnly', group: 'Mode',
    summary: 'Sign with the agent token and send; do not handle a 401 challenge', json: 'agentOnly', jsonKind: 'boolean' },
  { long: 'auth-token', kind: 'value', field: 'authToken', metavar: '<jwt>', group: 'Mode',
    summary: 'Use an existing auth token (with --signing-key; three-party reuse)', json: 'auth_token', env: 'AAUTH_AUTH_TOKEN' },
  { long: 'signing-key', kind: 'value', field: 'signingKey', metavar: '<jwk>', group: 'Mode',
    summary: 'Ephemeral signing key for --auth-token (the auth token is cnf-bound to it)', json: 'signingKey', jsonKind: 'json', env: 'AAUTH_SIGNING_KEY' },
  { long: 'aauth-access-token', kind: 'value', field: 'opaqueToken', metavar: '<token>', group: 'Mode',
    summary: 'Reuse an AAuth-Access token (two-party / resource-managed); no signing key needed', json: 'aauth_access_token', env: 'AAUTH_ACCESS_TOKEN' },
  { long: 'emit', kind: 'boolean', field: 'emit', group: 'Mode',
    summary: 'Emit the reusable credential(s) to stdout alongside the response', json: 'emit', jsonKind: 'boolean',
    details: [
      'Shape (fields appear only when relevant):',
      '  { auth_token, expires_in, signingKey, response }     three-party',
      '  { aauth_access_token, response }                     two-party',
      '`response` is the resource body (same as bare fetch); `signingKey` is emitted',
      'only with `auth_token` (three-party reuse needs it).',
    ] },

  // Authorize
  { long: 'operations', kind: 'value', field: 'operations', metavar: '<ids>', group: 'Authorize',
    summary: 'R3 operationIds to authorize (comma-separated)', json: 'operations' },
  { long: 'scope', kind: 'value', field: 'scope', metavar: '<scope>', group: 'Authorize',
    summary: 'Requested scopes', json: 'scope' },

  // Person-server hints (passed during consent)
  { long: 'login-hint', kind: 'value', field: 'loginHint', metavar: '<hint>', group: 'PersonServer',
    summary: 'Hint about who to authorize (user / account)', json: 'login_hint' },
  { long: 'domain-hint', kind: 'value', field: 'domainHint', metavar: '<domain>', group: 'PersonServer',
    summary: 'Domain/org hint for identity-provider routing', json: 'domain_hint' },
  { long: 'tenant', kind: 'value', field: 'tenant', metavar: '<id>', group: 'PersonServer',
    summary: 'Tenant identifier for multi-tenant systems', json: 'tenant' },
  { long: 'justification', kind: 'value', field: 'justification', metavar: '<md>', group: 'PersonServer',
    summary: 'Markdown shown at the consent prompt explaining why access is needed', json: 'justification' },

  // Consent (local handling)
  { long: 'browser', kind: 'boolean', field: 'browser', group: 'Consent',
    summary: 'Open the approval URL in your system browser (default: print the URL + a QR to scan)' },
  { long: 'non-interactive', kind: 'boolean', field: 'nonInteractive', group: 'Consent',
    summary: "Don't prompt at all — fail if consent is required (sends no interaction capability)" },

  // Output
  { long: 'explain', kind: 'boolean', field: 'explain', group: 'Output',
    summary: 'Teaching view: per-step request/response on stderr with descriptions, real RFC 9421 signed headers, and bodies' },
  { long: 'debug', short: 'v', aliases: ['verbose'], kind: 'boolean', field: 'debug', group: 'Output',
    summary: 'Raw wire view: every HTTP hop on stderr as { request } / { response } objects (with bodies); no descriptions' },
]

export interface CommandSpec {
  name: string
  usage: string
  summary: string
}

export const COMMANDS: CommandSpec[] = [
  { name: '<resource>', usage: 'npx @aauth/fetch <resource> [flags]',
    summary: 'Authenticated fetch — full flow (sign → 401 → token exchange → consent → retry)' },
  { name: 'authorize', usage: 'npx @aauth/fetch authorize <resource> [flags]',
    summary: 'Auth flow only; print tokens for reuse — no resource call. R3 via --operations' },
  { name: 'skill', usage: 'npx @aauth/fetch skill',
    summary: 'Print the agent guide (markdown) + the AAuth protocol spec URL' },
  { name: 'help', usage: 'npx @aauth/fetch help',
    summary: 'Show this help (--help also works)' },
]

// ── Derived lookups (built once from FLAGS) ─────────────────────────────────────

/** Every accepted token (--long, -short, --alias) → its spec. */
const FLAG_BY_TOKEN = new Map<string, FlagSpec>()
for (const f of FLAGS) {
  FLAG_BY_TOKEN.set(`--${f.long}`, f)
  if (f.short) FLAG_BY_TOKEN.set(`-${f.short}`, f)
  for (const a of f.aliases ?? []) FLAG_BY_TOKEN.set(`--${a}`, f)
}

/** The flag invocation as shown in help, e.g. `-X, --method <method>` or `--debug, -v, --verbose`. */
export function flagInvocation(f: FlagSpec): string {
  const names: string[] = []
  if (f.short) names.push(`-${f.short}`)
  names.push(`--${f.long}`)
  for (const a of f.aliases ?? []) names.push(`--${a}`)
  return f.metavar ? `${names.join(', ')} ${f.metavar}` : names.join(', ')
}

export function parseArgs(argv: string[]): FetchArgs {
  const args = argv.slice(2)
  const a: FetchArgs = {
    method: 'GET',
    headers: [],
    jsonInput: false,
    agentOnly: false,
    emit: false,
    nonInteractive: false,
    explain: false,
    debug: false,
    help: false,
    version: false,
  }
  const ref = a as unknown as Record<string, unknown>
  const positional: string[] = []

  for (let i = 0; i < args.length; i++) {
    const arg = args[i]

    // Meta short-circuits (not in FLAGS — surfaced in USAGE, handled by cli.ts).
    if (arg === '-h' || arg === '--help') { a.help = true; continue }
    if (arg === '--version') { a.version = true; continue }

    if (arg.startsWith('-') && arg !== '-') {
      const spec = FLAG_BY_TOKEN.get(arg)
      if (!spec) continue // unknown flag — ignored (long-form only; never a positional)
      if (spec.kind === 'boolean') {
        ref[spec.field] = !spec.setsFalse
        continue
      }
      // value flag
      const raw = args[++i]
      if (spec.field === 'headers') { a.headers.push(raw); continue }
      ref[spec.field] = raw
      continue
    }
    positional.push(arg)
  }

  // First positional is a subcommand keyword or the URL.
  if (positional[0] === 'authorize') {
    a.command = 'authorize'
    a.url = positional[1]
  } else if (positional[0] === 'skill') {
    a.command = 'skill'
    a.skillName = positional[1]
  } else if (positional[0] === 'help') {
    a.command = 'help'
  } else {
    a.url = positional[0]
  }

  // Env-var fallbacks (CLI flags win), derived from FLAGS.
  for (const f of FLAGS) {
    if (f.env && ref[f.field] === undefined) {
      const v = process.env[f.env]
      if (v !== undefined) ref[f.field] = v
    }
  }

  return a
}
