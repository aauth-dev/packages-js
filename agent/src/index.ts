export { createSignedFetch, PS_COMPONENTS_BODY } from './signed-fetch.js'
export { createAAuthFetch } from './aauth-fetch.js'
export {
  exchangeToken,
  fetchPersonServerMetadata,
  resolvePersonServerMetadata,
  /** @deprecated pre-11 names */
  fetchAuthServerMetadata,
  resolveAuthServerMetadata,
  TokenExchangeError,
} from './token-exchange.js'
export {
  requestPersonToken,
  createPersonTokenCache,
  PersonTokenError,
} from './person-token.js'
export { pollDeferred, parseErrorBody, describeAAuthError } from './deferred.js'
export type {
  GetKeyMaterial,
  KeyMaterial,
  SignatureKeyJwt,
  SignatureKeyJktJwt,
  SignatureKeyHwk,
  FetchLike,
  AAuthEvent,
  OnEvent,
  CapturedSent,
} from './types.js'
export type { SignedFetchOptions } from './signed-fetch.js'
export type { DeferredOptions, DeferredResult, AAuthError } from './deferred.js'
export type {
  TokenExchangeOptions,
  TokenExchangeResult,
  PersonServerMetadata,
  /** @deprecated pre-11 name for PersonServerMetadata */
  AuthServerMetadata,
  PersonServerMetadataOptions,
  /** @deprecated pre-11 name for PersonServerMetadataOptions */
  AuthServerMetadataOptions,
} from './token-exchange.js'
export type {
  PersonTokenOptions,
  PersonTokenResult,
  PersonTokenCache,
  PersonTokenCacheOptions,
} from './person-token.js'
export type { AAuthFetchOptions } from './aauth-fetch.js'
