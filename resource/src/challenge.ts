import {
  buildRequirementHeader,
  parseRequirementHeader,
  parseCapabilitiesHeader,
  buildCapabilitiesHeader,
  UnsupportedRequirementError,
  TOKEN_TYP,
  DWK,
  SIGNING_ALG,
} from '@aauth/protocol'
import type {
  AAuthChallenge,
  RequirementValue,
  Capability,
  KnownAccessMode,
} from '@aauth/protocol'

/**
 * Header construction and parsing live in `@aauth/protocol`; this package
 * re-exports the pieces a resource needs so a resource has one import.
 *
 * `buildMissionHeader` / `parseMissionHeader` / `AAuthMission` are GONE. The
 * `AAuth-Mission` header and its IANA registration were removed in AAuth -11.
 * A mission reaches a resource only inside a PS-issued token, as `mission_s256`.
 */
export {
  buildRequirementHeader,
  parseRequirementHeader,
  parseCapabilitiesHeader,
  buildCapabilitiesHeader,
  UnsupportedRequirementError,
  TOKEN_TYP,
  DWK,
  SIGNING_ALG,
}
export type { AAuthChallenge, RequirementValue, Capability, KnownAccessMode }

/** Requirements that carry no parameters. */
export type SimpleRequirement =
  | 'agent-token' | 'person-token' | 'approval' | 'clarification' | 'claims'

/**
 * Build an `AAuth-Requirement` response header value.
 *
 * Resource-side convenience over `buildRequirementHeader`, with the overloads
 * that make the required parameters a compile error to omit.
 *
 *   401 + `requirement=agent-token`  — the resource needs the agent's identity.
 *   401 + `requirement=person-token` — the resource needs the person's identity
 *                                      before it will issue a resource token.
 *   401 + `requirement=auth-token`   — carries the resource token.
 *   202 + `requirement=interaction`  — carries the interaction url and code.
 */
export function buildAAuthHeader(requirement: 'auth-token', params: { resourceToken: string }): string
export function buildAAuthHeader(requirement: 'interaction', params: { url: string; code: string }): string
export function buildAAuthHeader(requirement: SimpleRequirement): string
export function buildAAuthHeader(
  requirement: RequirementValue,
  params?: { resourceToken?: string; url?: string; code?: string },
): string {
  return buildRequirementHeader({ requirement, ...params } as AAuthChallenge)
}

/**
 * Build an `AAuth-Access` response header value — the resource's own session
 * token, opaque to the agent.
 *
 * The value is a `token68` (RFC 9110 §11.2): no whitespace, no control
 * characters, non-empty.
 */
export function buildAAuthAccessHeader(token: string): string {
  if (!/^[A-Za-z0-9._~+/-]+=*$/.test(token)) {
    throw new Error('AAuth-Access value must be a non-empty token68')
  }
  return token
}
