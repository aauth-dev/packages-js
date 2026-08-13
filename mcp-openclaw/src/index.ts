import { createAgentToken } from '@aauth/local-keys'
import { ServerManager } from './server-manager.js'

export interface PluginConfig {
  agent_url?: string
  local?: string
  token_lifetime?: number
  /** Person server. Defaults to the one in the agent's local config. */
  person_server?: string
  /** Mission the agent is operating under; stamped into person tokens. */
  mission_s256?: string
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
  const { agent_url, local, token_lifetime, person_server, mission_s256, mcp_servers } = config

  const getKeyMaterial = () =>
    createAgentToken({
      agentUrl: agent_url,
      local: local ?? 'openclaw',
      tokenLifetime: token_lifetime,
      personServerUrl: person_server,
    })

  const manager = new ServerManager({
    servers: mcp_servers,
    getKeyMaterial,
    personServerUrl: person_server,
    missionS256: mission_s256,
  })

  manager.connectAll().then(() => {
    for (const skipped of manager.getSkippedServers()) {
      console.warn(
        `[aauth] skipping MCP server ${skipped.name} (${skipped.url}): ${skipped.reason}`,
      )
    }
    const tools = manager.getTools()
    for (const tool of tools) {
      api.registerTool(tool.prefixedName, (args) =>
        manager.callTool(tool.prefixedName, args),
      )
    }
  }).catch((error: unknown) => {
    console.error(
      `[aauth] failed to connect MCP servers: ${error instanceof Error ? error.message : String(error)}`,
    )
  })

  api.onShutdown(() => manager.shutdown())
}

export { ServerManager } from './server-manager.js'
export type {
  ServerManagerOptions,
  PersonServerMetadata,
  SkippedServer,
} from './server-manager.js'
