export interface StdioArgs {
  serverUrl: string
  agentUrl?: string
  delegate?: string
  tokenLifetime?: number
}

function usage(): never {
  console.error(`Usage: aauth-mcp-stdio <server-url> [--agent-url <url>] [--delegate <name>] [--token-lifetime <sec>]

Arguments:
  server-url               Remote MCP server URL

Options:
  --agent-url <url>        Agent URL (or AAUTH_AGENT_URL env var, or from ~/.aauth/config.json)
  --delegate <name>        Delegate name (or AAUTH_DELEGATE env var)
  --token-lifetime <sec>   Token lifetime in seconds (or AAUTH_TOKEN_LIFETIME env var, default: 3600)

Environment variables:
  AAUTH_AGENT_URL          Agent URL
  AAUTH_DELEGATE           Delegate name
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
  let delegate: string | undefined
  let tokenLifetime: number | undefined

  for (let i = 1; i < args.length; i++) {
    switch (args[i]) {
      case '--agent-url':
        agentUrl = args[++i]
        break
      case '--delegate':
        delegate = args[++i]
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
  delegate = delegate ?? process.env.AAUTH_DELEGATE
  const envLifetime = process.env.AAUTH_TOKEN_LIFETIME
  if (!tokenLifetime && envLifetime) {
    tokenLifetime = parseInt(envLifetime, 10)
  }

  // agentUrl is now optional — createAgentToken will resolve from ~/.aauth/config.json
  return {
    serverUrl,
    agentUrl,
    delegate,
    tokenLifetime,
  }
}
