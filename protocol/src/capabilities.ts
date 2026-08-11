import { splitOutsideQuotes } from './sf.js'

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
 * PS reports, and the PS may name a capability newer than this library.
 */
export function buildCapabilitiesHeader(capabilities: string[]): string {
  return capabilities
    .map((c) => c.trim())
    .filter((c) => c.length > 0)
    .join(', ')
}

/**
 * Parse an `AAuth-Capabilities` request header value.
 *
 * Unrecognized values are filtered out and never throw: "Recipients MUST ignore
 * unrecognized capability values." An absent header is not the same as an empty
 * one — when the header is absent, recipients MUST NOT assume any capabilities.
 */
export function parseCapabilitiesHeader(headerValue: string): string[] {
  return splitOutsideQuotes(headerValue, ',')
    .map((s) => s.trim())
    .filter((s) => isCapability(s))
}
