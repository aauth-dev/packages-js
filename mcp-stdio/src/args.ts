export interface StdioArgs {
  serverUrl: string
  agentUrl?: string
  local?: string
  tokenLifetime?: number
  /** Person server (PS) URL. The agent token's `ps` claim, and the origin whose
   *  metadata carries `person_token_endpoint` and `auth_token_endpoint`. */
  personServer?: string
}

function usage(): never {
  console.error(`Usage: aauth-mcp-stdio <server-url> [--agent-url <url>] [--local <name>] [--person-server <url>] [--token-lifetime <sec>]

Arguments:
  server-url               Remote MCP server URL

Options:
  --agent-url <url>        Agent URL (or AAUTH_AGENT_URL env var, or from ~/.aauth/config.json)
  --local <name>           Local part of agent identifier (or AAUTH_LOCAL env var)
  --person-server <url>    Person server URL (or AAUTH_PERSON_SERVER env var, or from ~/.aauth/config.json)
  --token-lifetime <sec>   Token lifetime in seconds (or AAUTH_TOKEN_LIFETIME env var, default: 3600)
  --version                Print version and exit

Environment variables:
  AAUTH_AGENT_URL          Agent URL
  AAUTH_LOCAL              Local part of agent identifier
  AAUTH_PERSON_SERVER      Person server URL
  AAUTH_TOKEN_LIFETIME     Token lifetime in seconds`)
  process.exit(1)
}

export function parseArgs(argv: string[]): StdioArgs {
  const args = argv.slice(2)

  if (args.length === 0) {
    usage()
  }

  const serverUrl = args[0]
  if (!serverUrl || serverUrl.startsWith('--')) {
    usage()
  }

  let agentUrl: string | undefined
  let local: string | undefined
  let tokenLifetime: number | undefined
  let personServer: string | undefined

  for (let i = 1; i < args.length; i++) {
    switch (args[i]) {
      case '--agent-url':
        agentUrl = args[++i]
        break
      case '--local':
        local = args[++i]
        break
      case '--person-server':
        personServer = args[++i]
        break
      case '--token-lifetime':
        tokenLifetime = parseInt(args[++i], 10)
        if (isNaN(tokenLifetime)) {
          console.error('Error: --token-lifetime must be a number')
          process.exit(1)
        }
        break
      default:
        console.error(`Unknown option: ${args[i]}`)
        usage()
    }
  }

  agentUrl = agentUrl ?? process.env.AAUTH_AGENT_URL
  local = local ?? process.env.AAUTH_LOCAL
  personServer = personServer ?? process.env.AAUTH_PERSON_SERVER
  const envLifetime = process.env.AAUTH_TOKEN_LIFETIME
  if (!tokenLifetime && envLifetime) {
    tokenLifetime = parseInt(envLifetime, 10)
  }

  // agentUrl is optional — createAgentToken resolves it from ~/.aauth/config.json.
  // personServer is optional here too — cli.ts falls back to the agent's
  // configured personServerUrl before deciding the PS is genuinely absent.
  return {
    serverUrl,
    agentUrl,
    local,
    tokenLifetime,
    personServer,
  }
}
