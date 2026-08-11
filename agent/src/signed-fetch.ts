import { fetch as httpSigFetch } from '@hellocoop/httpsig'
import type { SentRequest, HttpSigFetchOptions } from '@hellocoop/httpsig'
import { buildCapabilitiesHeader } from '@aauth/protocol'
import type { Capability } from '@aauth/protocol'
import type { GetKeyMaterial, FetchLike, CapturedSent } from './types.js'

/**
 * Covered components for a request that carries a body to a PS or AS endpoint.
 *
 * Protocol -11 (#covered-components): on such a request the signature MUST
 * additionally cover `content-digest` and `content-type`, because PS and AS
 * request bodies carry the members that decide what is authorized
 * (`resource`, `mission_s256`, `justification`, …) and only the tokens among
 * them are self-protecting. @hellocoop/httpsig generates the Content-Digest
 * header only when the covered-component list names it, so the list has to be
 * passed explicitly — its DEFAULT_COMPONENTS_BODY omits `content-digest`.
 *
 * Resources are deliberately excluded: they declare what they need through
 * `additional_signature_components` in their metadata, so a blanket body
 * mandate toward a resource would be wrong.
 */
export const PS_COMPONENTS_BODY: readonly string[] = [
  '@method',
  '@authority',
  '@path',
  'content-type',
  'content-digest',
  'signature-key',
]

export interface SignedFetchOptions {
  capabilities?: Capability[]
  /**
   * Set on a fetch aimed at PS or AS endpoints. Requests carrying a body then
   * sign `content-digest` and `content-type` as well (PS_COMPONENTS_BODY).
   * Leave unset for resource-facing fetches — a resource states its own extra
   * components via `additional_signature_components`.
   */
  signBody?: boolean
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
  const capabilities = options?.capabilities ?? []

  return async (url: string | URL, init?: RequestInit): Promise<Response> => {
    const { signingKey, signatureKey } = await getKeyMaterial()
    // Map jkt-jwt to jwt for @hellocoop/httpsig (same wire format)
    const httpSigKey = signatureKey.type === 'jkt-jwt'
      ? { type: 'jwt' as const, jwt: signatureKey.jwt }
      : signatureKey

    const fetchInit: HttpSigFetchOptions = {
      ...init,
      signingKey,
      signatureKey: httpSigKey,
    }

    if (capabilities.length) {
      const headers = new Headers(init?.headers)
      headers.set('aauth-capabilities', buildCapabilitiesHeader(capabilities))
      fetchInit.headers = headers
    }

    if (options?.signBody && init?.body != null) {
      fetchInit.components = [...PS_COMPONENTS_BODY]
    }

    if (options?.onSigned) {
      const { response, sent } = await httpSigFetch(url, { ...fetchInit, returnSent: true })
      options.onSigned(captureSent(sent))
      return response
    }
    return await httpSigFetch(url, fetchInit)
  }
}
