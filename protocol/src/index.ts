/**
 * @aauth/protocol — the AAuth wire format, on its own.
 *
 * Header build/parse, `access_mode` planning, protocol constants and
 * unverified JWT decoding. No I/O, no crypto, no runtime dependencies.
 *
 * Tracks draft-hardt-oauth-aauth-protocol-11.
 */

// ---------- AAuth-Requirement ----------
export type { RequirementValue, AAuthChallenge } from './requirement.js'
export {
  UnsupportedRequirementError,
  isRequirementValue,
  buildRequirementHeader,
  parseRequirementHeader,
} from './requirement.js'

// ---------- AAuth-Capabilities ----------
export type { Capability } from './capabilities.js'
export { isCapability, buildCapabilitiesHeader, parseCapabilitiesHeader } from './capabilities.js'

// ---------- access_mode ----------
export type { KnownAccessMode, AgentSetup, AccessModePlan } from './access-mode.js'
export { isKnownAccessMode, planAccessMode } from './access-mode.js'

// ---------- constants ----------
export { TOKEN_TYP, DWK, SIGNING_ALG } from './constants.js'

// ---------- JWT decoding (no verification) ----------
export { decodeJwtHeader, decodeJwtPayload } from './jwt.js'
