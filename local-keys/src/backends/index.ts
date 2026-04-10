import { softwareBackend } from './software.js'
import { yubikeyPivBackend } from './yubikey-piv.js'
import { secureEnclaveBackend } from './secure-enclave.js'
import type { BackendInfo, KeyBackend, KeyBackendDriver } from '../types.js'

const backends: Record<KeyBackend, KeyBackendDriver> = {
  software: softwareBackend,
  'yubikey-piv': yubikeyPivBackend,
  'secure-enclave': secureEnclaveBackend,
}

export function getBackend(name: KeyBackend): KeyBackendDriver {
  const backend = backends[name]
  if (!backend) throw new Error(`Unknown backend: ${name}`)
  return backend
}

export function discoverBackends(): BackendInfo[] {
  const found: BackendInfo[] = []
  for (const driver of Object.values(backends)) {
    const info = driver.discover()
    if (info) found.push(info)
  }
  return found
}

export { softwareBackend } from './software.js'
export { yubikeyPivBackend } from './yubikey-piv.js'
export { secureEnclaveBackend } from './secure-enclave.js'
