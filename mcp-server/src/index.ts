/**
 * `@aauth/resource` — the resource-side reference implementation of AAuth.
 *
 * Verify what an agent presents, mint what a resource issues, publish and
 * enforce R3. Runs on Cloudflare Workers: no `node:*` imports, only `crypto`,
 * `crypto.subtle`, `fetch`, `TextEncoder`/`TextDecoder`.
 */

// --- Challenges and headers (thin layer over @aauth/protocol) ---
export {
  buildAAuthHeader,
  buildAAuthAccessHeader,
  buildRequirementHeader,
  parseRequirementHeader,
  parseCapabilitiesHeader,
  buildCapabilitiesHeader,
  UnsupportedRequirementError,
  TOKEN_TYP,
  DWK,
  SIGNING_ALG,
} from './challenge.js'
export type {
  AAuthChallenge,
  RequirementValue,
  SimpleRequirement,
  Capability,
  KnownAccessMode,
} from './challenge.js'

// --- Token verification ---
export { verifyToken } from './verify-token.js'
export { AAuthTokenError, R3Error } from './errors.js'
export { clearMetadataCache, discoverJwks } from './jwks.js'
export type { FetchLike } from './jwks.js'
export type {
  TokenKind,
  VerifyTokenOptions,
  VerifiedAgentToken,
  VerifiedPersonToken,
  VerifiedAuthToken,
  VerifiedToken,
} from './verify-token.js'

// --- Resource tokens ---
export {
  createResourceToken,
  clampToMission,
  DEFAULT_RESOURCE_TOKEN_LIFETIME,
} from './resource-token.js'
export type {
  ResourceTokenOptions,
  PersonTokenReference,
  SignFn,
} from './resource-token.js'

// --- R3 documents ---
export {
  serializeR3Document,
  computeR3Hash,
  publishR3Document,
  generateR3Id,
  getR3ByUri,
  getR3ByHash,
  parseR3Record,
  serveR3Document,
  isAuthorizedR3Fetcher,
  assertAuthorizedR3Fetcher,
  verifyR3Hash,
  MemoryR3Store,
  R3_MEDIA_TYPE,
  R3_DEFAULT_TTL_SECONDS,
} from './r3.js'
export type {
  R3Document,
  R3Display,
  R3OperationSet,
  R3ParameterDigest,
  R3ParameterValue,
  R3Record,
  R3Store,
  R3Response,
  PublishR3Options,
  PublishedR3,
  SerializedR3,
  ServeR3Options,
} from './r3.js'

// --- Per-call proposals ---
export {
  buildProposal,
  publishProposal,
  digestParameter,
  isParameterDigest,
  verifyProposalParameters,
} from './proposal.js'
export type {
  ProposalOptions,
  PublishProposalOptions,
  VerifyProposalOptions,
  VerifiedProposal,
} from './proposal.js'

// --- Interaction (202 deferred responses) ---
export { InteractionManager } from './interaction.js'
export type { PendingRequest, InteractionManagerOptions } from './interaction.js'

// --- Utilities ---
export { isServerIdentifier, sha256Base64url, base64url } from './util.js'
