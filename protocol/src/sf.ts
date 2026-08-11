/**
 * Minimal RFC 8941 Structured Fields helpers.
 *
 * Only what the AAuth headers need: quote-aware splitting on a delimiter, and
 * quoting/unquoting of sf-strings. Not a general Structured Fields parser.
 */

/**
 * Split `input` on `delimiter`, ignoring delimiters inside a quoted string.
 * Quotes and escapes are preserved in the returned segments; use `unquote`.
 */
export function splitOutsideQuotes(input: string, delimiter: string): string[] {
  const out: string[] = []
  let current = ''
  let inQuotes = false
  let escaped = false

  for (const ch of input) {
    if (escaped) {
      current += ch
      escaped = false
      continue
    }
    if (inQuotes) {
      current += ch
      if (ch === '\\') escaped = true
      else if (ch === '"') inQuotes = false
      continue
    }
    if (ch === '"') {
      current += ch
      inQuotes = true
      continue
    }
    if (ch === delimiter) {
      out.push(current)
      current = ''
      continue
    }
    current += ch
  }

  out.push(current)
  return out
}

/**
 * Render a value as an sf-string (RFC 8941 §3.3.3): wrapped in double quotes
 * with `\` and `"` backslash-escaped.
 */
export function quoteString(value: string): string {
  return `"${value.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`
}

/**
 * Undo `quoteString`. A bare (unquoted) token is returned as-is, so that a
 * sender which omitted the quotes is still understood.
 */
export function unquoteString(value: string): string {
  const trimmed = value.trim()
  if (trimmed.length >= 2 && trimmed.startsWith('"') && trimmed.endsWith('"')) {
    return trimmed.slice(1, -1).replace(/\\(.)/g, '$1')
  }
  return trimmed
}

/** Split `key=value`. Returns undefined when there is no `=`. */
export function splitPair(segment: string): { key: string; value: string } | undefined {
  const eq = segment.indexOf('=')
  if (eq === -1) return undefined
  return { key: segment.slice(0, eq).trim(), value: segment.slice(eq + 1).trim() }
}
