# @aauth/mcp-openclaw

OpenClaw plugin for connecting to AAuth-authenticated MCP servers. Discovers remote tools via MCP and registers them as OpenClaw tools with AAuth signing.

See the [AAuth repo](https://github.com/AAuth-dev/packages-js) for protocol overview.

## Install

```bash
npm install @aauth/mcp-openclaw
```

## OpenClaw Configuration

Add to `~/.openclaw/openclaw.json`:

```json
{
  "plugins": {
    "entries": {
      "aauth-mcp": {
        "enabled": true,
        "config": {
          "agent_url": "https://user.github.io",
          "mcp_servers": {
            "my-files": "https://files-api.example.com/mcp",
            "my-db": "https://db-api.example.com/mcp"
          }
        }
      }
    }
  }
}
```

The plugin id is `aauth-mcp` and must match the manifest id.

Tools from remote servers are registered with a prefix: `my-files_read_file`, `my-db_query`, etc.

## API

### `register(api)`

Plugin entry point called by OpenClaw. Connects to configured MCP servers via
a `registerService` lifecycle and registers each remote tool as an OpenClaw
tool. The plugin reads its config from `api.pluginConfig`.

```ts
import register from '@aauth/mcp-openclaw'
```

### `ServerManager`

Manages connections to multiple MCP servers with AAuth authentication.

```ts
import { ServerManager } from '@aauth/mcp-openclaw'

const manager = new ServerManager({
  servers: {
    'my-files': 'https://files-api.example.com/mcp',
    'my-db': 'https://db-api.example.com/mcp',
  },
  getKeyMaterial: async () => ({
    signingKey: privateKeyJwk,
    signatureKey: { type: 'jwt', jwt: agentToken }
  }),
})

await manager.connectAll()

// List discovered tools (prefixed by server name)
const tools = manager.getTools()
// [{ prefixedName: 'my-files_read', serverName: 'my-files', originalName: 'read', description: '...' }]

// Call a tool
const result = await manager.callTool('my-files_read', { path: '/data.json' })

await manager.shutdown()
```

## License

MIT
