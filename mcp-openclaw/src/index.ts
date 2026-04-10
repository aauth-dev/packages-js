import { createAgentToken } from '@aauth/local-keys'
import { ServerManager } from './server-manager.js'

export interface PluginConfig {
  agent_url?: string
  delegate?: string
  token_lifetime?: number
  mcp_servers: Record<string, string>
}

export interface OpenClawPluginApi {
  getConfig(): PluginConfig
  registerTool(name: string, handler: (args: Record<string, unknown>) => Promise<unknown>): void
  onShutdown(fn: () => Promise<void>): void
}

export const id = 'aauth-mcp'

export function register(api: OpenClawPluginApi): void {
  const config = api.getConfig()
  const { agent_url, delegate = 'openclaw', token_lifetime, mcp_servers } = config

  const getKeyMaterial = () =>
    createAgentToken({
      agentUrl: agent_url,
      delegate,
      tokenLifetime: token_lifetime,
    })

  const manager = new ServerManager({
    servers: mcp_servers,
    getKeyMaterial,
  })

  manager.connectAll().then(() => {
    const tools = manager.getTools()
    for (const tool of tools) {
      api.registerTool(tool.prefixedName, (args) =>
        manager.callTool(tool.prefixedName, args),
      )
    }
  })

  api.onShutdown(() => manager.shutdown())
}

export { ServerManager } from './server-manager.js'
export type { ServerManagerOptions } from './server-manager.js'
