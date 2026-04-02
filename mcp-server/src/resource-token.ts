export interface ResourceTokenOptions {
  resource: string      // resource URL (iss)
  authServer: string    // auth server URL (aud)
  agent: string         // agent identifier
  agentJkt: string      // JWK thumbprint of agent's signing key
  scope?: string        // space-separated scopes
  lifetime?: number     // default: 300s
}

export type SignFn = (payload: Record<string, unknown>, header: Record<string, unknown>) => Promise<string>

/**
 * Create a resource token (typ: resource+jwt) for an AAuth 401 challenge.
 *
 * The resource token is signed by the resource and sent to the agent,
 * who forwards it to the auth server to obtain an auth token.
 *
 * The caller provides a sign function — this decouples signing from
 * any particular key management (KMS, vault, ephemeral, etc.).
 */
export async function createResourceToken(
  options: ResourceTokenOptions,
  sign: SignFn,
): Promise<string> {
  const {
    resource,
    authServer,
    agent,
    agentJkt,
    scope,
    lifetime = 300,
  } = options

  const now = Math.floor(Date.now() / 1000)

  const payload: Record<string, unknown> = {
    iss: resource,
    dwk: 'aauth-resource.json',
    aud: authServer,
    agent,
    agent_jkt: agentJkt,
    iat: now,
    exp: now + lifetime,
  }

  if (scope) {
    payload.scope = scope
  }

  const header: Record<string, unknown> = {
    alg: 'EdDSA',
    typ: 'resource+jwt',
  }

  return sign(payload, header)
}
