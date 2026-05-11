# @aauth/mcp-stdio

Stdio-to-HTTP proxy for MCP with AAuth signatures. Bridges a local stdio MCP client (like Claude Code) to a remote HTTP MCP server, signing all requests with AAuth.

Part of [aauth-dev/packages-js](https://github.com/aauth-dev/packages-js). Protocol spec: [dickhardt/AAuth](https://github.com/dickhardt/AAuth).

## Install

```bash
npm install @aauth/mcp-stdio
```

## CLI

```bash
npx @aauth/mcp-stdio --server https://api.example.com/mcp --agent https://user.github.io
```

### Options

| Flag | Env var | Description |
|------|---------|-------------|
| `--server`, `-s` | `AAUTH_MCP_SERVER` | Remote MCP server URL (required) |
| `--agent`, `-a` | `AAUTH_AGENT_URL` | Agent identity URL (required) |
| `--delegate`, `-d` | `AAUTH_DELEGATE` | Delegate name (default: `claude`) |
| `--token-lifetime` | `AAUTH_TOKEN_LIFETIME` | Agent token lifetime in seconds (default: `3600`) |

### Claude Code Configuration

Add to your MCP server config:

```json
{
  "mcpServers": {
    "my-server": {
      "command": "npx",
      "args": ["@aauth/mcp-stdio", "--server", "https://api.example.com/mcp", "--agent", "https://user.github.io"]
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
      "args": ["@aauth/mcp-stdio"],
      "env": {
        "AAUTH_MCP_SERVER": "https://api.example.com/mcp",
        "AAUTH_AGENT_URL": "https://user.github.io"
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

### `parseArgs(argv): StdioArgs`

Parses CLI arguments with env var fallbacks.

```ts
import { parseArgs } from '@aauth/mcp-stdio'

const args = parseArgs(process.argv.slice(2))
// { serverUrl, agentUrl, delegate?, tokenLifetime? }
```

## License

MIT
