import { randomBytes } from 'node:crypto'

// Crockford base32 alphabet — omits I, L, O, U to avoid visual ambiguity.
// Spec: draft-hardt-oauth-aauth-protocol §2.6 (interaction-code-format)
export const CROCKFORD32 = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'

/**
 * Generate an 8-symbol Crockford base32 interaction code (40 bits of entropy)
 * in canonical form: "XXXX-XXXX".
 *
 * The returned value is ready to store as-is. No further normalization needed.
 */
export function generateCode(): string {
  const buf = randomBytes(5) // 40 bits = 8 × 5-bit symbols
  let n = 0n
  for (const b of buf) n = (n << 8n) | BigInt(b)
  const raw = Array.from(
    { length: 8 },
    (_, i) => CROCKFORD32[Number((n >> BigInt((7 - i) * 5)) & 31n)],
  ).join('')
  return raw.slice(0, 4) + '-' + raw.slice(4)
}

/**
 * Canonicalize a user-presented interaction code to "XXXX-XXXX" form for lookup.
 *
 * Strips hyphens, uppercases, folds Crockford decode aliases (I/L → 1, O → 0),
 * then reinserts the presentational hyphen at position 4.
 *
 * Typical usage:
 *   store.set(generateCode(), pendingData)       // store as-is
 *   store.get(canonicalizeCode(userInput))        // normalize user input for lookup
 */
export function canonicalizeCode(code: string): string {
  const bare = code
    .replace(/-/g, '')
    .toUpperCase()
    .replace(/[IL]/g, '1')
    .replace(/O/g, '0')
  return bare.slice(0, 4) + '-' + bare.slice(4)
}
