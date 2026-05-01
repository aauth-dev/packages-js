import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js'
import { createSignedFetch } from '@aauth/mcp-agent'
import type { GetKeyMaterial } from '@aauth/mcp-agent'
import type { Transport } from '@modelcontextprotocol/sdk/shared/transport.js'

interface ManagedTool {
  originalName: string
  description?: string
  inputSchema?: Record<string, unknown>
}

interface ManagedServer {
  name: string
  client: Client
  transport: Transport
  tools: Map<string, ManagedTool> // prefixed name → tool metadata
}

export interface ServerManagerOptions {
  servers: Record<string, string> // name → url
  getKeyMaterial: GetKeyMaterial
}

export class ServerManager {
  private servers = new Map<string, ManagedServer>()

  constructor(private options: ServerManagerOptions) {}

  async connectAll(): Promise<void> {
    const entries = Object.entries(this.options.servers)
    await Promise.all(entries.map(([name, url]) => this.connect(name, url)))
  }

  private async connect(name: string, url: string): Promise<void> {
    const signedFetch = createSignedFetch(this.options.getKeyMaterial)
    const transport = new StreamableHTTPClientTransport(new URL(url), {
      fetch: signedFetch,
    })

    const client = new Client({ name: `aauth-${name}`, version: '0.0.1' })
    await client.connect(transport)

    const { tools } = await client.listTools()
    const toolMap = new Map<string, ManagedTool>()
    for (const tool of tools) {
      toolMap.set(`${name}_${tool.name}`, {
        originalName: tool.name,
        description: tool.description,
        inputSchema: tool.inputSchema as Record<string, unknown> | undefined,
      })
    }

    this.servers.set(name, { name, client, transport, tools: toolMap })
  }

  getTools(): Array<{
    prefixedName: string
    serverName: string
    originalName: string
    description?: string
    inputSchema?: Record<string, unknown>
  }> {
    const result: Array<{
      prefixedName: string
      serverName: string
      originalName: string
      description?: string
      inputSchema?: Record<string, unknown>
    }> = []
    for (const [, server] of this.servers) {
      for (const [prefixedName, meta] of server.tools) {
        result.push({
          prefixedName,
          serverName: server.name,
          originalName: meta.originalName,
          description: meta.description,
          inputSchema: meta.inputSchema,
        })
      }
    }
    return result
  }

  async callTool(
    prefixedName: string,
    args: Record<string, unknown>,
  ): Promise<unknown> {
    for (const [, server] of this.servers) {
      const meta = server.tools.get(prefixedName)
      if (meta) {
        return server.client.callTool({ name: meta.originalName, arguments: args })
      }
    }
    throw new Error(`Unknown tool: ${prefixedName}`)
  }

  async shutdown(): Promise<void> {
    const closers = Array.from(this.servers.values()).map((s) =>
      s.transport.close().catch(() => {}),
    )
    await Promise.all(closers)
    this.servers.clear()
  }
}
