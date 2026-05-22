import type { SignatureKeyJwt, SignatureKeyJktJwt, SignatureKeyHwk, CapturedSent } from './types.js'
import type { SentRequest } from '@hellocoop/httpsig'
import { decodeJwtPayload } from './decode-jwt.js'

/**
 * Response headers exposed in --log events. Filtered to AAuth-relevant set so
 * the default --log output isn't drowned in irrelevant headers (CF-*, etc.).
 * Lowercase keys per HTTP/2 / fetch API convention.
 */
const AAUTH_RELEVANT_RESPONSE_HEADERS = [
  'www-authenticate',
  'aauth-requirement',
  'aauth-access',
  'content-type',
  'location',
] as const

export function summarizeResponseHeaders(headers: Headers): Record<string, string> {
  const out: Record<string, string> = {}
  for (const k of AAUTH_RELEVANT_RESPONSE_HEADERS) {
    const v = headers.get(k)
    if (v) out[k] = v
  }
  return out
}

/**
 * Extract the JWT string from a SignatureKey, if present. Returns undefined
 * for hardware-wrapped keys (no transmitted JWT).
 */
export function jwtFromSignatureKey(
  sk: SignatureKeyJwt | SignatureKeyJktJwt | SignatureKeyHwk,
): string | undefined {
  return sk.type === 'hwk' ? undefined : sk.jwt
}

/**
 * Decode the agent token carried by a SignatureKey, if any. Returns undefined
 * for hwk (no JWT) or malformed tokens.
 */
export function decodeSignatureKey(
  sk: SignatureKeyJwt | SignatureKeyJktJwt | SignatureKeyHwk,
): Record<string, unknown> | undefined {
  const jwt = jwtFromSignatureKey(sk)
  return jwt ? decodeJwtPayload(jwt) : undefined
}

/**
 * Convert @hellocoop/httpsig's SentRequest (Headers object) to a plain
 * Record-based CapturedSent suitable for inclusion in --log events and
 * JSON serialisation.
 */
export function captureSentFromHttpsig(sent: SentRequest): CapturedSent {
  const headers: Record<string, string> = {}
  sent.headers.forEach((value, key) => { headers[key] = value })
  return {
    method: sent.method,
    url: sent.url,
    headers,
    body: typeof sent.body === 'string' ? sent.body : undefined,
  }
}

/**
 * Read a Response's body as text without consuming it for downstream
 * consumers. Uses Response.clone() so the caller can still read body
 * afterwards. Returns undefined if the body can't be read as text.
 */
export async function peekResponseBody(response: Response): Promise<string | undefined> {
  try {
    return await response.clone().text()
  } catch {
    return undefined
  }
}
