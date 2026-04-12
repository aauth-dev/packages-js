export type RequirementLevel = 'auth-token' | 'approval' | 'interaction' | 'clarification' | 'claims'

/** @deprecated Use RequirementLevel instead */
export type RequireLevel = RequirementLevel

export type Capability = 'interaction' | 'clarification' | 'payment'

export interface AAuthChallenge {
  requirement: RequirementLevel
  resourceToken?: string
  url?: string
  code?: string
}

export interface AAuthMission {
  approver: string
  s256: string
}

/**
 * Build an AAuth-Capabilities request header value.
 * Per the spec, this is an RFC 8941 List of Tokens.
 *
 *   AAuth-Capabilities: interaction, clarification, payment
 */
export function buildCapabilitiesHeader(capabilities: Capability[]): string {
  return capabilities.join(', ')
}

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
 * Build an AAuth-Mission request header value.
 *
 *   AAuth-Mission: approver="https://ps.example"; s256="hash..."
 */
export function buildMissionHeader(mission: AAuthMission): string {
  return `approver="${mission.approver}"; s256="${mission.s256}"`
}

/**
 * Parse an AAuth-Mission request header value.
 */
export function parseMissionHeader(headerValue: string): AAuthMission {
  const approverMatch = headerValue.match(/approver="([^"]+)"/)
  const s256Match = headerValue.match(/s256="([^"]+)"/)
  if (!approverMatch || !s256Match) {
    throw new Error('Invalid AAuth-Mission header: missing approver or s256')
  }
  return { approver: approverMatch[1], s256: s256Match[1] }
}

/**
 * Parse an AAuth-Requirement response header value into a structured challenge.
 *
 * Formats:
 *   AAuth-Requirement: requirement=auth-token; resource-token="..."
 *   AAuth-Requirement: requirement=approval
 *   AAuth-Requirement: requirement=interaction; url="https://..."; code="ABCD1234"
 *   AAuth-Requirement: requirement=clarification
 *   AAuth-Requirement: requirement=claims
 */
export function parseAAuthHeader(headerValue: string): AAuthChallenge {
  const trimmed = headerValue.trim()
  if (!trimmed) {
    throw new Error('Empty AAuth-Requirement header')
  }

  // Parse the requirement= value (unquoted token)
  const requirementMatch = trimmed.match(/^requirement=([a-z-]+)/)
  if (!requirementMatch) {
    throw new Error('Missing requirement= in AAuth-Requirement header')
  }

  const validLevels: RequirementLevel[] = ['auth-token', 'approval', 'interaction', 'clarification', 'claims']
  const requirementStr = requirementMatch[1]
  if (!validLevels.includes(requirementStr as RequirementLevel)) {
    throw new Error(`Unknown requirement level: ${requirementStr}`)
  }
  const requirement = requirementStr as RequirementLevel

  const challenge: AAuthChallenge = { requirement }

  // Parse semicolon-separated parameters
  const params = trimmed.slice(requirementMatch[0].length)
  if (params.trim()) {
    const paramPairs = params.split(';').slice(1) // skip first empty segment
    for (const pair of paramPairs) {
      const eqIdx = pair.indexOf('=')
      if (eqIdx === -1) continue
      const key = pair.slice(0, eqIdx).trim()
      let value = pair.slice(eqIdx + 1).trim()
      // Strip quotes
      if (value.startsWith('"') && value.endsWith('"')) {
        value = value.slice(1, -1)
      }
      switch (key) {
        case 'resource-token':
          challenge.resourceToken = value
          break
        case 'url':
          challenge.url = value
          break
        case 'code':
          challenge.code = value
          break
      }
    }
  }

  // Validate required params for specific levels
  if (requirement === 'auth-token') {
    if (!challenge.resourceToken) {
      throw new Error('auth-token challenge missing resource-token')
    }
  }

  if (requirement === 'interaction') {
    if (!challenge.url) {
      throw new Error('interaction challenge missing url')
    }
    if (!challenge.code) {
      throw new Error('interaction challenge missing code')
    }
  }

  return challenge
}
