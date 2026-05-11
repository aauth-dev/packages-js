/**
 * @aauth/mcp-openclaw — OpenClaw plugin for AAuth-authenticated MCP servers.
 *
 * Discovers tools on remote MCP servers reachable over HTTP and registers each
 * as an OpenClaw tool. All HTTP traffic is signed with an AAuth agent token
 * via `@aauth/mcp-agent`'s `createSignedFetch`.
 */

import { createAgentToken } from '@aauth/local-keys'
import { ServerManager } from './server-manager.js'

export const id = 'aauth-mcp'
export const name = 'AAuth MCP'
export const description =
  'Connect to remote MCP servers with AAuth agent authentication'

export interface PluginConfig {
  agent_url?: string
  local?: string
  token_lifetime?: number
  mcp_servers: Record<string, string>
}

/**
 * Minimal slice of OpenClaw's plugin API surface used by this plugin.
 * The real type is exported from `openclaw/plugin-sdk/plugin-entry`, but we
 * inline the slice we need to keep the plugin dependency-free.
 */
interface OpenClawPluginApi {
  pluginConfig?: PluginConfig
  logger: {
    info(msg: string, ...args: unknown[]): void
    warn(msg: string, ...args: unknown[]): void
    error(msg: string, ...args: unknown[]): void
  }
  registerTool(
    tool: {
      name: string
      label?: string
      description: string
      parameters: Record<string, unknown>
      execute(toolCallId: string, params: Record<string, unknown>): Promise<unknown>
    },
    opts?: { optional?: boolean },
  ): void
  registerService(service: {
    id: string
    start(): Promise<void> | void
    stop(): Promise<void> | void
  }): void
}

export default function register(api: OpenClawPluginApi): void {
  const config = (api.pluginConfig ?? { mcp_servers: {} }) as PluginConfig
  const { agent_url, local, token_lifetime, mcp_servers } = config

  if (!agent_url) {
    api.logger.error(
      `[${id}] missing required config "agent_url"; plugin will not connect to any MCP servers.`,
    )
    return
  }

  if (!mcp_servers || Object.keys(mcp_servers).length === 0) {
    api.logger.warn(
      `[${id}] no MCP servers configured (config.mcp_servers is empty); nothing to register.`,
    )
    return
  }

  const manager = new ServerManager({
    servers: mcp_servers,
    getKeyMaterial: () =>
      createAgentToken({
        agentUrl: agent_url,
        local: local ?? 'openclaw',
        tokenLifetime: token_lifetime,
      }),
  })

  api.registerService({
    id: `${id}/connection-manager`,
    async start() {
      try {
        await manager.connectAll()
      } catch (err) {
        api.logger.error(
          `[${id}] failed to connect to one or more MCP servers: ${(err as Error).message}`,
        )
        return
      }

      const tools = manager.getTools()
      for (const tool of tools) {
        api.registerTool({
          name: tool.prefixedName,
          description:
            tool.description ??
            `${tool.serverName}: ${tool.originalName} (AAuth MCP)`,
          parameters: tool.inputSchema ?? {
            type: 'object',
            additionalProperties: true,
          },
          execute: (_toolCallId, params) =>
            manager.callTool(tool.prefixedName, params).then((r) => r as unknown),
        })
      }

      api.logger.info(
        `[${id}] connected to ${Object.keys(mcp_servers).length} server(s); registered ${tools.length} tool(s).`,
      )
    },
    async stop() {
      await manager.shutdown()
    },
  })
}

export { ServerManager } from './server-manager.js'
export type { ServerManagerOptions } from './server-manager.js'
