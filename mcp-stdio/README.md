# @aauth/mcp-stdio

Stdio-to-HTTP proxy for MCP with AAuth signatures. Bridges a local stdio MCP client (like Claude Code) to a remote HTTP MCP server, signing all requests with AAuth.

Part of [aauth-dev/packages-js](https://github.com/aauth-dev/packages-js). Protocol spec: [dickhardt/AAuth](https://github.com/dickhardt/AAuth).

## Install

```bash
npm install @aauth/mcp-stdio
```

## CLI

```bash
npx @aauth/mcp-stdio https://api.example.com/mcp --agent-url https://user.github.io
```

### Options

The remote MCP server URL is the first positional argument and is required.

| Flag | Env var | Description |
|------|---------|-------------|
| `--agent-url` | `AAUTH_AGENT_URL` | Agent URL (default: from `~/.aauth/config.json`) |
| `--local` | `AAUTH_LOCAL` | Local part of the agent identifier |
| `--person-server` | `AAUTH_PERSON_SERVER` | Person server URL (default: from `~/.aauth/config.json`) |
| `--token-lifetime` | `AAUTH_TOKEN_LIFETIME` | Agent token lifetime in seconds (default: `3600`) |

### Person server

The proxy needs a person server to reach a resource that asks for a person or an
auth token. It stamps the PS as the agent token's `ps` claim, obtains a person
token from the PS's `person_token_endpoint` when a resource answers
`requirement=person-token`, and exchanges the resource token that follows at the
PS's `auth_token_endpoint`. Without one it can only reach resources that serve on
agent identity alone, and it says so on stderr at startup.

### Claude Code Configuration

Add to your MCP server config:

```json
{
  "mcpServers": {
    "my-server": {
      "command": "npx",
      "args": ["@aauth/mcp-stdio", "https://api.example.com/mcp", "--agent-url", "https://user.github.io"]
    }
  }
}
```

Or with environment variables:

```json
{
  "mcpServers": {
    "my-server": {
      "command": "npx",
      "args": ["@aauth/mcp-stdio", "https://api.example.com/mcp"],
      "env": {
        "AAUTH_AGENT_URL": "https://user.github.io",
        "AAUTH_PERSON_SERVER": "https://ps.example.com"
      }
    }
  }
}
```

## API

### `bridgeTransports(local, remote): Promise<void>`

Bridges two MCP transports for bidirectional message forwarding.

```ts
import { bridgeTransports } from '@aauth/mcp-stdio'
```

### `serializeAuthFlows(fetch): ProxyFetch`

Wraps a fetch so that only one POST — and so only one AAuth flow, and one
browser interaction — is in flight at a time. GET passes straight through, since
the transport's GET is the long-lived SSE stream.

```ts
import { serializeAuthFlows } from '@aauth/mcp-stdio'
```

### `parseArgs(argv): StdioArgs`

Parses CLI arguments with env var fallbacks. Takes the full `process.argv`.

```ts
import { parseArgs } from '@aauth/mcp-stdio'

const args = parseArgs(process.argv)
// { serverUrl, agentUrl?, local?, personServer?, tokenLifetime? }
```

## License

MIT
