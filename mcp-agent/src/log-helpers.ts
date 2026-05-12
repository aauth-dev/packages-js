import type { SignatureKeyJwt, SignatureKeyJktJwt, SignatureKeyHwk } from './types.js'
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
