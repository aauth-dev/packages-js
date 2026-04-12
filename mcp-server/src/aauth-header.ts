import type { Mission } from './resource-token.js'

type RequirementLevel = 'auth-token' | 'approval' | 'interaction' | 'clarification' | 'claims'

export type Capability = 'interaction' | 'clarification' | 'payment'

/**
 * Parse an AAuth-Capabilities request header value into capability tokens.
 */
export function parseCapabilitiesHeader(headerValue: string): Capability[] {
  const valid: Capability[] = ['interaction', 'clarification', 'payment']
  return headerValue.split(',')
    .map(s => s.trim())
    .filter((s): s is Capability => valid.includes(s as Capability))
}

/**
 * Parse an AAuth-Mission request header value into a Mission object.
 */
export function parseMissionHeader(headerValue: string): Mission {
  const approverMatch = headerValue.match(/approver="([^"]+)"/)
  const s256Match = headerValue.match(/s256="([^"]+)"/)
  if (!approverMatch || !s256Match) {
    throw new Error('Invalid AAuth-Mission header: missing approver or s256')
  }
  return { approver: approverMatch[1], s256: s256Match[1] }
}

/**
 * Build an AAuth-Access response header value (opaque access token for two-party mode).
 */
export function buildAAuthAccessHeader(token: string): string {
  return token
}

/**
 * Build an AAuth-Requirement response header value per the AAuth spec.
 */
export function buildAAuthHeader(requirement: 'auth-token', params: { resourceToken: string }): string
export function buildAAuthHeader(requirement: 'approval'): string
export function buildAAuthHeader(requirement: 'interaction', params: { url: string; code: string }): string
export function buildAAuthHeader(requirement: 'clarification'): string
export function buildAAuthHeader(requirement: 'claims'): string
export function buildAAuthHeader(
  requirement: RequirementLevel,
  params?: { resourceToken?: string; url?: string; code?: string },
): string {
  switch (requirement) {
    case 'approval':
      return 'requirement=approval'

    case 'clarification':
      return 'requirement=clarification'

    case 'claims':
      return 'requirement=claims'

    case 'auth-token': {
      if (!params?.resourceToken) {
        throw new Error('auth-token requires resourceToken')
      }
      return `requirement=auth-token; resource-token="${params.resourceToken}"`
    }

    case 'interaction': {
      if (!params?.url || !params?.code) {
        throw new Error('interaction requires url and code')
      }
      return `requirement=interaction; url="${params.url}"; code="${params.code}"`
    }

    default:
      throw new Error(`Unknown requirement level: ${requirement}`)
  }
}
