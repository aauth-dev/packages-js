import {
  parseList,
  serializeList,
  isInnerList,
  bareItemToString,
  Token,
  type List,
} from '@hellocoop/httpsig/structured-fields'

/** The capability values defined by AAuth -11 (§AAuth-Capabilities). */
export type Capability = 'interaction' | 'clarification' | 'payment'

const CAPABILITIES: readonly Capability[] = ['interaction', 'clarification', 'payment']

/** Is `value` a capability value this library recognizes? */
export function isCapability(value: string): value is Capability {
  return (CAPABILITIES as readonly string[]).includes(value)
}

/**
 * Build an `AAuth-Capabilities` request header value — an RFC 8941 List of
 * Tokens.
 *
 *   AAuth-Capabilities: interaction, clarification, payment
 *
 * Values are not filtered: an agent unions its own capabilities with those its
 * PS reports, and the PS may name a capability newer than this library. They
 * are validated as Tokens, though — a value that cannot be serialized as one
 * would produce a header no recipient could parse, so it throws instead.
 */
export function buildCapabilitiesHeader(capabilities: string[]): string {
  const list: List = capabilities
    .map((c) => c.trim())
    .filter((c) => c.length > 0)
    .map((c) => [new Token(c), new Map()])

  return serializeList(list)
}

/**
 * Parse an `AAuth-Capabilities` request header value.
 *
 * Unrecognized values are filtered out and never throw: "Recipients MUST ignore
 * unrecognized capability values." A header that is not a well-formed List is
 * ignored whole, for the same reason. An absent header is not the same as an
 * empty one — when the header is absent, recipients MUST NOT assume any
 * capabilities.
 */
export function parseCapabilitiesHeader(headerValue: string): string[] {
  let list: List
  try {
    list = parseList(headerValue)
  } catch {
    return []
  }

  const out: string[] = []
  for (const member of list) {
    if (isInnerList(member)) continue
    let value: string
    try {
      value = bareItemToString(member[0])
    } catch {
      continue
    }
    if (isCapability(value)) out.push(value)
  }
  return out
}
