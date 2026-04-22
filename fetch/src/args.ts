export interface FetchArgs {
  // Meta
  skill: boolean

  // Mode
  authorize: boolean
  agentOnly: boolean

  // Request
  url?: string
  method: string
  data?: string
  headers: string[]
  jsonInput: boolean

  // AAuth
  agentUrl?: string
  local?: string
  operations?: string
  scope?: string
  personServer?: string
  authToken?: string
  signingKey?: string

  // Hints & prompt
  loginHint?: string
  domainHint?: string
  tenant?: string
  justification?: string

  // Capabilities
  capabilities?: string[]

  // Interaction
  browser?: boolean  // undefined = auto-detect
  nonInteractive: boolean

  // Output
  verbose: boolean
  debug: boolean
}

function usage(): never {
  console.error(`Usage: aauth-fetch [options] <url>

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
  --local <name>           Local part of agent identifier (default: from config)
  --auth-token <jwt>          Pre-existing auth token
  --signing-key <jwk>         Ephemeral private key (with --auth-token)
  --person-server <url>       Override person server URL

Hints & prompt:
  --login-hint <hint>         Hint about who to authorize (user/account)
  --domain-hint <domain>      Domain/org hint for identity provider routing
  --tenant <tenant>           Tenant identifier for multi-tenant systems
  --justification <text>      Markdown explaining why access is needed

Capabilities:
  --capabilities <list>       Agent capabilities (comma-separated)
                              Values: interaction, clarification, payment

Interaction:
  --browser                   Force open browser for consent
  --no-browser                Never open browser
  --non-interactive           Fail if consent is needed

Output:
  -v, --verbose               Show headers + status on stderr
  --debug                     Show all requests/responses with headers on stderr
`)
  process.exit(1)
}

export function parseArgs(argv: string[]): FetchArgs {
  const args = argv.slice(2)

  const result: FetchArgs = {
    skill: false,
    authorize: false,
    agentOnly: false,
    method: 'GET',
    headers: [],
    jsonInput: false,
    local: undefined,
    nonInteractive: false,
    verbose: false,
    debug: false,
  }

  for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
      // Meta
      case '--skill':
        result.skill = true
        break
      case '--help':
      case '-h':
        usage()
        break

      // Modes
      case '--authorize':
        result.authorize = true
        break
      case '--agent-only':
        result.agentOnly = true
        break
      case '--operations':
        result.operations = args[++i]
        break
      case '--scope':
        result.scope = args[++i]
        break

      // Request
      case '-X':
      case '--method':
        result.method = args[++i]
        break
      case '-d':
      case '--data':
        result.data = args[++i]
        break
      case '-H':
      case '--header':
        result.headers.push(args[++i])
        break
      case '--json':
        result.jsonInput = true
        break

      // AAuth
      case '--agent-url':
        result.agentUrl = args[++i]
        break
      case '--local':
        result.local = args[++i]
        break
      case '--auth-token':
        result.authToken = args[++i]
        break
      case '--signing-key':
        result.signingKey = args[++i]
        break
      case '--person-server':
        result.personServer = args[++i]
        break

      // Hints & prompt
      case '--login-hint':
        result.loginHint = args[++i]
        break
      case '--domain-hint':
        result.domainHint = args[++i]
        break
      case '--tenant':
        result.tenant = args[++i]
        break
      case '--justification':
        result.justification = args[++i]
        break

      // Capabilities
      case '--capabilities':
        result.capabilities = args[++i].split(',').map(s => s.trim())
        break

      // Interaction
      case '--browser':
        result.browser = true
        break
      case '--no-browser':
        result.browser = false
        break
      case '--non-interactive':
        result.nonInteractive = true
        break

      // Output
      case '-v':
      case '--verbose':
        result.verbose = true
        break
      case '--debug':
        result.debug = true
        result.verbose = true
        break

      default:
        if (args[i].startsWith('-')) {
          console.error(JSON.stringify({ error: `Unknown option: ${args[i]}` }))
          process.exit(1)
        }
        // Positional = URL
        result.url = args[i]
        break
    }
  }

  // Env var fallbacks
  result.agentUrl = result.agentUrl ?? process.env.AAUTH_AGENT_URL
  result.local = result.local || process.env.AAUTH_LOCAL
  result.authToken = result.authToken ?? process.env.AAUTH_AUTH_TOKEN
  result.signingKey = result.signingKey ?? process.env.AAUTH_SIGNING_KEY
  result.personServer = result.personServer ?? process.env.AAUTH_PERSON_SERVER

  return result
}
