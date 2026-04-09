import { signAgentToken } from './agent-token.js'
import { listConfiguredAgents } from './config.js'
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
 */
export async function createAgentToken(
  options: CreateAgentTokenOptions,
): Promise<AgentTokenResult> {
  const { delegate, tokenLifetime = 3600 } = options
  let { agentUrl } = options

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
          "Run 'npx @aauth/local-keys generate --agent <url>' to set one up.",
        )
      }
    }
  }

  const delegateUrl = `${agentUrl.replace(/\/$/, '')}/${delegate}`
  const cacheKey = `${agentUrl}::${delegate}`

  const cached = cache.get(cacheKey)
  if (cached) {
    const now = Math.floor(Date.now() / 1000)
    if (now < cached.expiresAt) {
      return cached.result
    }
  }

  const result = await signAgentToken({
    agentUrl,
    delegateUrl,
    lifetime: tokenLifetime,
  })

  const now = Math.floor(Date.now() / 1000)
  cache.set(cacheKey, {
    result,
    expiresAt: now + Math.floor(tokenLifetime * 0.8),
  })

  return result
}
