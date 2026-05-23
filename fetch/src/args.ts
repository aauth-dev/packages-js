export interface FetchArgs {
  /** Subcommand: 'authorize' | 'skill'. Undefined = default fetch (or help if no url). */
  command?: 'authorize' | 'skill'
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

  // Mode (modifiers)
  agentOnly: boolean

  // Authorize
  operations?: string
  scope?: string

  // Hints
  loginHint?: string
  domainHint?: string
  tenant?: string
  justification?: string

  // Capabilities
  capabilities?: string[]

  // Interaction
  browser?: boolean // undefined = auto; false = --no-browser
  nonInteractive: boolean

  // Output / meta
  verbose: boolean
  help: boolean
  version: boolean
}

/** Long value-flags → FetchArgs field (or 'header'/'capabilities' special-cased). */
const VALUE_FLAGS: Record<string, string> = {
  method: 'method',
  data: 'data',
  header: 'header',
  'agent-provider': 'agentProvider',
  local: 'local',
  'person-server': 'personServer',
  'auth-token': 'authToken',
  'signing-key': 'signingKey',
  operations: 'operations',
  scope: 'scope',
  'login-hint': 'loginHint',
  'domain-hint': 'domainHint',
  tenant: 'tenant',
  justification: 'justification',
  capabilities: 'capabilities',
}

export function parseArgs(argv: string[]): FetchArgs {
  const args = argv.slice(2)
  const a: FetchArgs = {
    method: 'GET',
    headers: [],
    jsonInput: false,
    agentOnly: false,
    nonInteractive: false,
    verbose: false,
    help: false,
    version: false,
  }
  const positional: string[] = []

  for (let i = 0; i < args.length; i++) {
    const arg = args[i]
    // Short flags (curl parity)
    if (arg === '-X') { a.method = args[++i]; continue }
    if (arg === '-d') { a.data = args[++i]; continue }
    if (arg === '-H') { a.headers.push(args[++i]); continue }
    if (arg === '-v') { a.verbose = true; continue }
    if (arg === '-h' || arg === '--help') { a.help = true; continue }
    if (arg === '--version') { a.version = true; continue }

    if (arg.startsWith('--')) {
      const key = arg.slice(2)
      // boolean flags
      if (key === 'verbose') { a.verbose = true; continue }
      if (key === 'agent-only') { a.agentOnly = true; continue }
      if (key === 'json') { a.jsonInput = true; continue }
      if (key === 'no-browser') { a.browser = false; continue }
      if (key === 'non-interactive') { a.nonInteractive = true; continue }
      // value flags
      const target = VALUE_FLAGS[key]
      if (target === 'header') { a.headers.push(args[++i]); continue }
      if (target === 'capabilities') {
        a.capabilities = (args[++i] ?? '').split(',').map(s => s.trim()).filter(Boolean)
        continue
      }
      if (target) { (a as unknown as Record<string, unknown>)[target] = args[++i]; continue }
      // unknown long flag — ignore (long-form only; don't mistake for a positional)
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
  } else {
    a.url = positional[0]
  }

  // Env-var fallbacks (CLI flags win).
  a.agentProvider = a.agentProvider ?? process.env.AAUTH_AGENT_URL
  a.local = a.local ?? process.env.AAUTH_LOCAL
  a.personServer = a.personServer ?? process.env.AAUTH_PERSON_SERVER
  a.authToken = a.authToken ?? process.env.AAUTH_AUTH_TOKEN
  a.signingKey = a.signingKey ?? process.env.AAUTH_SIGNING_KEY

  return a
}
