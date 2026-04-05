export type RequirementLevel = 'pseudonym' | 'identity' | 'auth-token' | 'approval' | 'interaction' | 'clarification' | 'claims'

/** @deprecated Use RequirementLevel instead */
export type RequireLevel = RequirementLevel

export interface AAuthChallenge {
  requirement: RequirementLevel
  resourceToken?: string
  url?: string
  code?: string
}

/**
 * Parse an AAuth-Requirement response header value into a structured challenge.
 *
 * Formats:
 *   AAuth-Requirement: requirement=pseudonym
 *   AAuth-Requirement: requirement=identity
 *   AAuth-Requirement: requirement=auth-token; resource-token="..."
 *   AAuth-Requirement: requirement=approval
 *   AAuth-Requirement: requirement=interaction; url="https://..."; code="ABCD1234"
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

  const validLevels: RequirementLevel[] = ['pseudonym', 'identity', 'auth-token', 'approval', 'interaction']
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
