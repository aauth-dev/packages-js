import { fetch as httpSigFetch } from '@hellocoop/httpsig'
import { buildCapabilitiesHeader, buildMissionHeader } from './aauth-header.js'
import type { GetKeyMaterial, FetchLike } from './types.js'
import type { Capability, AAuthMission } from './aauth-header.js'

export interface SignedFetchOptions {
  capabilities?: Capability[]
  mission?: AAuthMission
}

export function createSignedFetch(getKeyMaterial: GetKeyMaterial, options?: SignedFetchOptions): FetchLike {
  const hasExtraHeaders = (options?.capabilities?.length ?? 0) > 0 || !!options?.mission

  return async (url: string | URL, init?: RequestInit): Promise<Response> => {
    const { signingKey, signatureKey } = await getKeyMaterial()
    // Map jkt-jwt to jwt for @hellocoop/httpsig (same wire format)
    const httpSigKey = signatureKey.type === 'jkt-jwt'
      ? { type: 'jwt' as const, jwt: signatureKey.jwt }
      : signatureKey

    let fetchInit: Record<string, unknown> = {
      ...init,
      signingKey,
      signatureKey: httpSigKey,
    }

    if (hasExtraHeaders) {
      const headers = new Headers(init?.headers)
      if (options?.capabilities?.length) {
        headers.set('aauth-capabilities', buildCapabilitiesHeader(options.capabilities))
      }
      if (options?.mission) {
        headers.set('aauth-mission', buildMissionHeader(options.mission))
      }
      fetchInit.headers = headers
    }

    const response = await httpSigFetch(url, fetchInit)
    return response as Response
  }
}
