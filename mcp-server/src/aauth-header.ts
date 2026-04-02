type RequirementLevel = 'pseudonym' | 'identity' | 'auth-token' | 'approval' | 'interaction'

/**
 * Build an AAuth-Requirement response header value per the AAuth spec.
 *
 * Overloads:
 *   buildAAuthHeader('pseudonym')          → 'requirement=pseudonym'
 *   buildAAuthHeader('identity')           → 'requirement=identity'
 *   buildAAuthHeader('auth-token', {...})  → 'requirement=auth-token; resource-token="..."'
 *   buildAAuthHeader('approval')           → 'requirement=approval'
 *   buildAAuthHeader('interaction', {...}) → 'requirement=interaction; url="..."; code="..."'
 */
export function buildAAuthHeader(requirement: 'pseudonym'): string
export function buildAAuthHeader(requirement: 'identity'): string
export function buildAAuthHeader(requirement: 'auth-token', params: { resourceToken: string }): string
export function buildAAuthHeader(requirement: 'approval'): string
export function buildAAuthHeader(requirement: 'interaction', params: { url: string; code: string }): string
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
