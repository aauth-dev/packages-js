import { fetch as httpSigFetch } from '@hellocoop/httpsig'
import type { SentRequest } from '@hellocoop/httpsig'
import { buildCapabilitiesHeader, buildMissionHeader } from './aauth-header.js'
import type { GetKeyMaterial, FetchLike, CapturedSent } from './types.js'
import type { Capability, AAuthMission } from './aauth-header.js'

export interface SignedFetchOptions {
  capabilities?: Capability[]
  mission?: AAuthMission
  /**
   * Called synchronously after each signed request returns, with the actual
   * on-the-wire headers + body. Used by the AAuth flow to capture the
   * signed request data for --log rendering.
   */
  onSigned?: (sent: CapturedSent) => void
}

function headersToRecord(headers: Headers): Record<string, string> {
  const out: Record<string, string> = {}
  headers.forEach((value, key) => { out[key] = value })
  return out
}

function captureSent(sent: SentRequest): CapturedSent {
  let body: string | undefined
  if (typeof sent.body === 'string') {
    body = sent.body
  }
  return {
    method: sent.method,
    url: sent.url,
    headers: headersToRecord(sent.headers),
    body,
  }
}

export function createSignedFetch(getKeyMaterial: GetKeyMaterial, options?: SignedFetchOptions): FetchLike {
  const hasExtraHeaders = (options?.capabilities?.length ?? 0) > 0 || !!options?.mission

  return async (url: string | URL, init?: RequestInit): Promise<Response> => {
    const { signingKey, signatureKey } = await getKeyMaterial()
    // Map jkt-jwt to jwt for @hellocoop/httpsig (same wire format)
    const httpSigKey = signatureKey.type === 'jkt-jwt'
      ? { type: 'jwt' as const, jwt: signatureKey.jwt }
      : signatureKey

    const wantSent = !!options?.onSigned

    if (hasExtraHeaders) {
      const headers = new Headers(init?.headers)
      if (options?.capabilities?.length) {
        headers.set('aauth-capabilities', buildCapabilitiesHeader(options.capabilities))
      }
      if (options?.mission) {
        headers.set('aauth-mission', buildMissionHeader(options.mission))
      }
      if (wantSent) {
        const { response, sent } = await httpSigFetch(url, {
          ...init,
          headers,
          signingKey,
          signatureKey: httpSigKey,
          returnSent: true,
        })
        options!.onSigned!(captureSent(sent))
        return response
      }
      return await httpSigFetch(url, {
        ...init,
        headers,
        signingKey,
        signatureKey: httpSigKey,
      })
    }

    if (wantSent) {
      const { response, sent } = await httpSigFetch(url, {
        ...init,
        signingKey,
        signatureKey: httpSigKey,
        returnSent: true,
      })
      options!.onSigned!(captureSent(sent))
      return response
    }
    return await httpSigFetch(url, {
      ...init,
      signingKey,
      signatureKey: httpSigKey,
    })
  }
}
