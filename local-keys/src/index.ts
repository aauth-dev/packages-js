export { readKeychain, writeKeychain, listAgentUrls } from './keychain.js'
export { generateKey, generateKid, toPublicJwk } from './keygen.js'
export { signAgentToken } from './agent-token.js'
export { createAgentToken } from './create-agent-token.js'
export { discoverBackends, getBackend } from './backends/index.js'
export {
  readConfig,
  getAgentConfig,
  setAgentConfig,
  addKeyToAgent,
  setPersonServer,
  setHosting,
  listConfiguredAgents,
  validateUrl,
  ensureAgentUrls,
} from './config.js'
export { resolveKey, checkKeyAvailability } from './resolve-key.js'
export { machineLabel, yubikeyLabel } from './device-label.js'
export type {
  KeychainData,
  GeneratedKeyPair,
  SignAgentTokenOptions,
  AgentTokenResult,
  SignatureKeyJwt,
  CreateAgentTokenOptions,
  KeyBackend,
  KeyAlgorithm,
  BackendInfo,
  KeyReference,
  KeyBackendDriver,
  AAuthConfig,
  AgentConfig,
  AgentHosting,
  LocalKeyMeta,
  AAuthPublicJwk,
  AAuthJwkMetadata,
  ResolvedKey,
} from './types.js'
