import { signAgentToken } from './agent-token.js'
import { listConfiguredAgents, getAgentConfig } from './config.js'
import { listAgentUrls } from './keychain.js'
import type { CreateAgentTokenOptions, AgentTokenResult } from './types.js'

interface CacheEntry {
  result: AgentTokenResult
  expiresAt: number
}

const cache = new Map<string, CacheEntry>()

/**
 * Create an agent token with caching.
 *
 * If agentUrl is omitted, uses the first agent URL from config,
 * or falls back to the first agent URL in the OS keychain.
 *
 * If agentId is omitted, reads it from config (set during bootstrap).
 */
export async function createAgentToken(
  options: CreateAgentTokenOptions,
): Promise<AgentTokenResult> {
  const { tokenLifetime = 3600, local } = options
  let { agentUrl, agentId } = options

  // Default agentUrl from config or keychain
  if (!agentUrl) {
    const configured = listConfiguredAgents()
    if (configured.length > 0) {
      agentUrl = configured[0]
    } else {
      const keychainUrls = listAgentUrls()
      if (keychainUrls.length > 0) {
        agentUrl = keychainUrls[0]
      } else {
        throw new Error(
          'No agent URL provided and none configured. ' +
          "Run 'npx @aauth/bootstrap generate --agent <url>' to set one up.",
        )
      }
    }
  }

  // Resolve agentId: explicit > local + domain > config
  if (!agentId) {
    if (local) {
      const domain = new URL(agentUrl).hostname
      agentId = `aauth:${local}@${domain}`
    } else {
      const agentConfig = getAgentConfig(agentUrl)
      agentId = agentConfig?.agentId
      if (!agentId) {
        throw new Error(
          `No agent identifier configured for ${agentUrl}. ` +
          "Run 'npx @aauth/bootstrap --ps <person-server>' to register.",
        )
      }
    }
  }

  const cacheKey = `${agentUrl}::${agentId}`

  const cached = cache.get(cacheKey)
  if (cached) {
    const now = Math.floor(Date.now() / 1000)
    if (now < cached.expiresAt) {
      return cached.result
    }
  }

  const result = await signAgentToken({
    agentUrl,
    sub: agentId,
    lifetime: tokenLifetime,
  })

  const now = Math.floor(Date.now() / 1000)
  cache.set(cacheKey, {
    result,
    expiresAt: now + Math.floor(tokenLifetime * 0.8),
  })

  return result
}
