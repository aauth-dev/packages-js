import { fetch as httpSigFetch } from '@hellocoop/httpsig'
import type { GetKeyMaterial, FetchLike } from './types.js'

export function createSignedFetch(getKeyMaterial: GetKeyMaterial): FetchLike {
  return async (url: string | URL, init?: RequestInit): Promise<Response> => {
    const { signingKey, signatureKey } = await getKeyMaterial()
    // Map jkt-jwt to jwt for @hellocoop/httpsig (same wire format)
    const httpSigKey = signatureKey.type === 'jkt-jwt'
      ? { type: 'jwt' as const, jwt: signatureKey.jwt }
      : signatureKey
    const response = await httpSigFetch(url, {
      ...init,
      signingKey,
      signatureKey: httpSigKey,
    })
    return response as Response
  }
}
