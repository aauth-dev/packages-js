/**
 * JWT decoding with NO signature verification.
 *
 * These read a token's own claims for routing, logging and dispatch. They prove
 * nothing. Never make a trust decision on their output.
 */

function decodeSegment(jwt: string, index: number, label: string): Record<string, unknown> {
  if (typeof jwt !== 'string' || jwt.length === 0) {
    throw new Error(`Cannot decode JWT ${label}: not a string`)
  }

  const parts = jwt.split('.')
  if (parts.length < 3) {
    throw new Error(`Cannot decode JWT ${label}: expected 3 dot-separated segments, got ${parts.length}`)
  }

  let json: string
  try {
    json = Buffer.from(parts[index], 'base64url').toString('utf8')
  } catch {
    throw new Error(`Cannot decode JWT ${label}: segment is not valid base64url`)
  }

  let parsed: unknown
  try {
    parsed = JSON.parse(json)
  } catch {
    throw new Error(`Cannot decode JWT ${label}: segment is not valid JSON`)
  }

  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new Error(`Cannot decode JWT ${label}: segment is not a JSON object`)
  }

  return parsed as Record<string, unknown>
}

/** Decode a JWT's header. No signature verification. */
export function decodeJwtHeader(jwt: string): Record<string, unknown> {
  return decodeSegment(jwt, 0, 'header')
}

/** Decode a JWT's payload. No signature verification. */
export function decodeJwtPayload(jwt: string): Record<string, unknown> {
  return decodeSegment(jwt, 1, 'payload')
}
