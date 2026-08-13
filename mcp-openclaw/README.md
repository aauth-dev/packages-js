# @aauth/mcp-openclaw

OpenClaw plugin for connecting to AAuth-authenticated MCP servers. Discovers remote tools via MCP and registers them as OpenClaw tools with AAuth signing.

Part of [aauth-dev/packages-js](https://github.com/aauth-dev/packages-js). Protocol spec: [dickhardt/AAuth](https://github.com/dickhardt/AAuth).

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
      "aauth": {
        "enabled": true,
        "config": {
          "agent_url": "https://user.github.io",
          "delegate": "openclaw",
          "person_server": "https://ps.example",
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

Tools from remote servers are registered with a prefix: `my-files_read_file`, `my-db_query`, etc.

`person_server` is optional — it defaults to the `ps` claim of the agent token. It is used for
both the token's `ps` claim and the person token requests below.

## Person tokens

An MCP server is an AAuth resource. Under AAuth -11 a resource MUST have verified a person token
before it issues a resource token, so the plugin obtains one per server from the person server's
`person_token_endpoint`, for `resource` = the MCP server's origin. The person token is presented
via `Signature-Key` in place of the agent token.

It is obtained up front when the server's `/.well-known/aauth-resource.json` declares
`access_mode: person-token` or `auth-token`, and otherwise on demand, when the server answers
`401` with `AAuth-Requirement: requirement=person-token`. A server whose declared access mode this
agent cannot satisfy — `auth-token` with no person server, say — is skipped rather than connected;
see `getSkippedServers()`.

## API

### `register(api, config)`

Plugin entry point called by OpenClaw. Connects to configured MCP servers and registers their tools.

```ts
import { register } from '@aauth/mcp-openclaw'
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
  // optional — defaults to the agent token's `ps` claim
  personServerUrl: 'https://ps.example',
})

await manager.connectAll()

// List discovered tools (prefixed by server name)
const tools = manager.getTools()
// [{ prefixedName: 'my-files_read', serverName: 'my-files', originalName: 'read', description: '...' }]

// Servers skipped because this agent cannot satisfy their access mode
const skipped = manager.getSkippedServers()
// [{ name: 'my-db', url: '...', mode: 'auth-token', reason: 'agent has no person server' }]

// Call a tool
const result = await manager.callTool('my-files_read', { path: '/data.json' })

await manager.shutdown()
```

## License

MIT
