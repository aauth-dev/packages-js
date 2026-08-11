import { splitOutsideQuotes, splitPair, quoteString, unquoteString } from './sf.js'

/**
 * The `requirement` values defined by AAuth -11 (§Requirement Values).
 * The value space is an extension point; extensions are recorded in the AAuth
 * Requirement Value Registry and are NOT recognized by this library.
 */
export type RequirementValue =
  | 'agent-token'
  | 'person-token'
  | 'auth-token'
  | 'approval'
  | 'interaction'
  | 'clarification'
  | 'claims'

const REQUIREMENT_VALUES: readonly RequirementValue[] = [
  'agent-token',
  'person-token',
  'auth-token',
  'approval',
  'interaction',
  'clarification',
  'claims',
]

export interface AAuthChallenge {
  requirement: RequirementValue
  /** REQUIRED when `requirement === 'auth-token'`. */
  resourceToken?: string
  /** REQUIRED when `requirement === 'interaction'`. */
  url?: string
  /** REQUIRED when `requirement === 'interaction'`. */
  code?: string
}

/**
 * Thrown when the `requirement=` value is not recognized.
 *
 * Protocol -11: "An agent that does not recognize the `requirement` value MUST
 * NOT treat the response as satisfiable. It surfaces the unsupported
 * requirement to the caller as an error."
 *
 * For a `202` response the caller MAY keep polling the `Location` URL in case a
 * later response carries a requirement it does understand — that decision
 * belongs to the caller, which is why the raw `value` is carried on the error.
 */
export class UnsupportedRequirementError extends Error {
  readonly value: string

  constructor(value: string) {
    super(`Unsupported AAuth requirement value: ${value}`)
    this.name = 'UnsupportedRequirementError'
    this.value = value
  }
}

/** Is `value` a requirement value this library recognizes? */
export function isRequirementValue(value: string): value is RequirementValue {
  return (REQUIREMENT_VALUES as readonly string[]).includes(value)
}

/**
 * Build an `AAuth-Requirement` response header value.
 *
 *   requirement=auth-token; resource-token="eyJ..."
 *   requirement=interaction; url="https://example.com/interact"; code="A1B2-C3D4"
 *   requirement=approval
 *
 * Throws when the challenge is missing a parameter its requirement value
 * requires.
 */
export function buildRequirementHeader(challenge: AAuthChallenge): string {
  const { requirement } = challenge

  if (!isRequirementValue(requirement)) {
    throw new UnsupportedRequirementError(String(requirement))
  }

  if (requirement === 'auth-token') {
    if (!challenge.resourceToken) {
      throw new Error('requirement=auth-token requires a resourceToken')
    }
    return `requirement=auth-token; resource-token=${quoteString(challenge.resourceToken)}`
  }

  if (requirement === 'interaction') {
    if (!challenge.url || !challenge.code) {
      throw new Error('requirement=interaction requires both url and code')
    }
    return `requirement=interaction; url=${quoteString(challenge.url)}; code=${quoteString(challenge.code)}`
  }

  return `requirement=${requirement}`
}

/**
 * Parse an `AAuth-Requirement` response header value.
 *
 * The header is an RFC 8941 Dictionary whose `requirement` member carries the
 * requirement-specific data as parameters. Unknown parameters are ignored, as
 * are any other dictionary members.
 *
 * @throws {UnsupportedRequirementError} the `requirement=` value is not one this
 *   library recognizes — the response MUST NOT be treated as satisfiable.
 * @throws {Error} the header is empty, has no `requirement` member, or omits a
 *   parameter its requirement value requires.
 */
export function parseRequirementHeader(headerValue: string): AAuthChallenge {
  // Header line folding arrives as embedded whitespace; normalize it away.
  const trimmed = headerValue.replace(/\s+/g, ' ').trim()
  if (!trimmed) {
    throw new Error('Empty AAuth-Requirement header')
  }

  const members = splitOutsideQuotes(trimmed, ',')
  const member = members.find((m) => {
    const pair = splitPair(splitOutsideQuotes(m, ';')[0])
    return pair?.key === 'requirement'
  })
  if (member === undefined) {
    throw new Error('AAuth-Requirement header has no requirement member')
  }

  const segments = splitOutsideQuotes(member, ';')
  const head = splitPair(segments[0])
  const rawValue = unquoteString(head!.value)
  if (!rawValue) {
    throw new Error('AAuth-Requirement header has an empty requirement value')
  }
  if (!isRequirementValue(rawValue)) {
    throw new UnsupportedRequirementError(rawValue)
  }

  const challenge: AAuthChallenge = { requirement: rawValue }

  for (const segment of segments.slice(1)) {
    const pair = splitPair(segment)
    if (!pair) continue
    const value = unquoteString(pair.value)
    switch (pair.key) {
      case 'resource-token':
        challenge.resourceToken = value
        break
      case 'url':
        challenge.url = value
        break
      case 'code':
        challenge.code = value
        break
      // Recipients MUST ignore unknown parameters.
    }
  }

  if (challenge.requirement === 'auth-token' && !challenge.resourceToken) {
    throw new Error('requirement=auth-token is missing the resource-token parameter')
  }
  if (challenge.requirement === 'interaction' && (!challenge.url || !challenge.code)) {
    throw new Error('requirement=interaction is missing the url or code parameter')
  }

  return challenge
}
