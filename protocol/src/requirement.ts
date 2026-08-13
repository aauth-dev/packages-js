import {
  parseDictionary,
  serializeDictionary,
  isInnerList,
  bareItemToString,
  Token,
  type Dictionary,
  type Parameters,
} from '@hellocoop/httpsig/structured-fields'

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
 *   requirement=auth-token;resource-token="eyJ..."
 *   requirement=interaction;url="https://example.com/interact";code="A1B2-C3D4"
 *   requirement=approval
 *
 * The header is serialized as an RFC 8941 Dictionary, so parameters are
 * emitted in the canonical form — `;` with no following space. A recipient
 * that splits on `; ` is not an RFC 8941 parser; the spaced form and this one
 * parse identically.
 *
 * Throws when the challenge is missing a parameter its requirement value
 * requires.
 */
export function buildRequirementHeader(challenge: AAuthChallenge): string {
  const { requirement } = challenge

  if (!isRequirementValue(requirement)) {
    throw new UnsupportedRequirementError(String(requirement))
  }

  const parameters: Parameters = new Map()

  if (requirement === 'auth-token') {
    if (!challenge.resourceToken) {
      throw new Error('requirement=auth-token requires a resourceToken')
    }
    parameters.set('resource-token', challenge.resourceToken)
  }

  if (requirement === 'interaction') {
    if (!challenge.url || !challenge.code) {
      throw new Error('requirement=interaction requires both url and code')
    }
    parameters.set('url', challenge.url)
    parameters.set('code', challenge.code)
  }

  const dictionary: Dictionary = new Map()
  dictionary.set('requirement', [new Token(requirement), parameters])

  return serializeDictionary(dictionary)
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
 * @throws {Error} the header is empty, is not a well-formed Dictionary, has no
 *   `requirement` member, or omits a parameter its requirement value requires.
 */
export function parseRequirementHeader(headerValue: string): AAuthChallenge {
  // RFC 7230 obs-fold: a header continued across lines arrives with the line
  // break and its leading whitespace embedded. Unfold those, and only those —
  // whitespace *inside* a quoted parameter value is part of the value.
  const unfolded = headerValue.replace(/\r?\n[ \t]+/g, ' ').trim()
  if (!unfolded) {
    throw new Error('Empty AAuth-Requirement header')
  }

  let dictionary: Dictionary
  try {
    dictionary = parseDictionary(unfolded)
  } catch (e) {
    throw new Error(
      `Malformed AAuth-Requirement header: ${e instanceof Error ? e.message : String(e)}`,
    )
  }

  const member = dictionary.get('requirement')
  if (member === undefined) {
    throw new Error('AAuth-Requirement header has no requirement member')
  }
  if (isInnerList(member)) {
    throw new Error('AAuth-Requirement requirement member must be an Item, not an Inner List')
  }

  const [bareValue, parameters] = member
  let rawValue: string
  try {
    rawValue = bareItemToString(bareValue)
  } catch {
    throw new Error('AAuth-Requirement requirement value must be a Token or a String')
  }
  if (!rawValue) {
    throw new Error('AAuth-Requirement header has an empty requirement value')
  }
  if (!isRequirementValue(rawValue)) {
    throw new UnsupportedRequirementError(rawValue)
  }

  const challenge: AAuthChallenge = { requirement: rawValue }

  // Recipients MUST ignore unknown parameters. A recognized parameter whose
  // value cannot be read as text is treated as absent, so the requirement's
  // own "missing parameter" error is what surfaces.
  for (const key of ['resource-token', 'url', 'code'] as const) {
    if (!parameters.has(key)) continue
    let value: string
    try {
      value = bareItemToString(parameters.get(key)!)
    } catch {
      continue
    }
    if (key === 'resource-token') challenge.resourceToken = value
    else if (key === 'url') challenge.url = value
    else challenge.code = value
  }

  if (challenge.requirement === 'auth-token' && !challenge.resourceToken) {
    throw new Error('requirement=auth-token is missing the resource-token parameter')
  }
  if (challenge.requirement === 'interaction' && (!challenge.url || !challenge.code)) {
    throw new Error('requirement=interaction is missing the url or code parameter')
  }

  return challenge
}
