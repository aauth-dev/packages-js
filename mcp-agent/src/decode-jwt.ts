/**
 * Decode a JWT's payload (no signature verification).
 * Returns parsed JSON, or undefined if the token is malformed.
 *
 * Used by --log narration to surface token contents — not for security checks.
 */
export function decodeJwtPayload(jwt: string): Record<string, unknown> | undefined {
  const parts = jwt.split('.')
  if (parts.length < 2) return undefined
  try {
    const payload = Buffer.from(parts[1], 'base64url').toString('utf8')
    return JSON.parse(payload) as Record<string, unknown>
  } catch {
    return undefined
  }
}
