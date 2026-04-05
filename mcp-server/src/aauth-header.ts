type RequirementLevel = 'pseudonym' | 'identity' | 'auth-token' | 'approval' | 'interaction' | 'clarification' | 'claims'

/**
 * Build an AAuth-Requirement response header value per the AAuth spec.
 */
export function buildAAuthHeader(requirement: 'pseudonym'): string
export function buildAAuthHeader(requirement: 'identity'): string
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
    case 'pseudonym':
      return 'requirement=pseudonym'

    case 'identity':
      return 'requirement=identity'

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
