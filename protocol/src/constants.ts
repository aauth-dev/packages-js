/** JWT `typ` header values for the four AAuth token types. */
export const TOKEN_TYP = {
  agent: 'aa-agent+jwt',
  person: 'aa-person+jwt',
  resource: 'aa-resource+jwt',
  auth: 'aa-auth+jwt',
} as const

/**
 * Discoverable well-known key (`dwk`) document names. The `dwk` claim names
 * the `/.well-known/` document under `iss` that publishes the signing key.
 */
export const DWK = {
  agent: 'aauth-agent.json',
  person: 'aauth-person.json',
  resource: 'aauth-resource.json',
  access: 'aauth-access.json',
} as const

/**
 * The AAuth signing algorithm, fully specified per RFC 9864. The polymorphic
 * `EdDSA` identifier MUST NOT be used.
 */
export const SIGNING_ALG = 'Ed25519' as const
