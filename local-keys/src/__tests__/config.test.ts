import { describe, it, expect, afterEach } from 'vitest'
import {
  readConfig,
  writeConfig,
  getAgentConfig,
  addKeyToAgent,
  setPersonServer,
  listConfiguredAgents,
} from '../config.js'

describe('Config', () => {
  const originalConfig = readConfig()

  afterEach(() => {
    writeConfig(originalConfig)
  })

  it('reads empty config when none exists', () => {
    writeConfig({ agents: {} })
    const config = readConfig()
    expect(config.agents).toEqual({})
  })

  it('stores and retrieves agent config', () => {
    writeConfig({ agents: {} })
    addKeyToAgent('https://test.example', '2026-04-09_a3f', {
      backend: 'yubikey-piv',
      algorithm: 'ES256',
      keyId: '9e',
      deviceLabel: 'yubikey-5c-0775',
    })

    const ac = getAgentConfig('https://test.example')
    expect(ac).toBeDefined()
    expect(ac!.keys['2026-04-09_a3f'].backend).toBe('yubikey-piv')
    expect(ac!.keys['2026-04-09_a3f'].keyId).toBe('9e')
    expect(ac!.keys['2026-04-09_a3f'].deviceLabel).toBe('yubikey-5c-0775')
  })

  it('sets person server URL', () => {
    writeConfig({ agents: {} })
    setPersonServer('https://test.example', 'https://person.example')

    const ac = getAgentConfig('https://test.example')
    expect(ac!.personServerUrl).toBe('https://person.example')
  })

  it('supports multiple agents', () => {
    writeConfig({ agents: {} })
    addKeyToAgent('https://personal.example', 'kid1', {
      backend: 'secure-enclave',
      algorithm: 'ES256',
      keyId: 'com.aauth.agent.kid1',
      deviceLabel: 'macbook-pro',
    })
    addKeyToAgent('https://work.example', 'kid2', {
      backend: 'yubikey-piv',
      algorithm: 'ES256',
      keyId: '9e',
      deviceLabel: 'yubikey-5c-0775',
    })

    const agents = listConfiguredAgents()
    expect(agents).toContain('https://personal.example')
    expect(agents).toContain('https://work.example')
  })

  it('supports multiple keys per agent', () => {
    writeConfig({ agents: {} })
    addKeyToAgent('https://test.example', 'kid-yk', {
      backend: 'yubikey-piv',
      algorithm: 'ES256',
      keyId: '9e',
      deviceLabel: 'yubikey-5c-0775',
    })
    addKeyToAgent('https://test.example', 'kid-se', {
      backend: 'secure-enclave',
      algorithm: 'ES256',
      keyId: 'com.aauth.agent.kid-se',
      deviceLabel: 'macbook-pro',
    })

    const ac = getAgentConfig('https://test.example')
    expect(Object.keys(ac!.keys)).toHaveLength(2)
    expect(ac!.keys['kid-yk'].backend).toBe('yubikey-piv')
    expect(ac!.keys['kid-se'].backend).toBe('secure-enclave')
  })
})
