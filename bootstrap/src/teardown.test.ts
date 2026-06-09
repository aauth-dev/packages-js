import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mkdtempSync, rmSync, existsSync, readFileSync, readdirSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import type { AgentConfig } from '@aauth/local-keys'

// Fully mock local-keys so teardown logic is exercised without touching the real
// OS keychain or ~/.aauth. getConfigDir is pointed at a per-test temp dir, so the
// real backup file I/O in teardown.ts (writeBackup / listBackups) runs in
// isolation. The mocked KeyDeletionUnsupportedError is the same class reference
// teardown.ts imports, so its `instanceof` check still works.
vi.mock('@aauth/local-keys', () => {
  class KeyDeletionUnsupportedError extends Error {
    constructor(public readonly hint: string) {
      super(hint)
      this.name = 'KeyDeletionUnsupportedError'
    }
  }
  return {
    getAgentConfig: vi.fn(),
    listAgentProviders: vi.fn(() => []),
    listAgentUrls: vi.fn(() => []),
    readKeychain: vi.fn(() => null),
    deleteKeychain: vi.fn(),
    deleteAgentProvider: vi.fn(),
    deleteConfigFile: vi.fn(),
    getConfigDir: vi.fn(() => '/tmp/test-aauth'),
    getBackend: vi.fn(),
    KeyDeletionUnsupportedError,
  }
})

import * as lk from '@aauth/local-keys'
import { planAgent, executeTeardown, deleteAgent, uninstall, listBackups } from './teardown.js'

const mocked = vi.mocked(lk)

const softwareAgent = (url: string): AgentConfig => ({
  agentId: `aauth:local@${url.replace('https://', '')}`,
  personServerUrl: 'https://person.hello.coop',
  agentServerUrl: `${url}/.well-known/aauth-agent.json`,
  jwksUri: `${url}/.well-known/jwks.json`,
  hosting: { platform: 'github-pages', repo: 'me/me.github.io' },
  keys: { '2026-05-22_ab': { backend: 'software', algorithm: 'EdDSA', keyId: url, deviceLabel: 'mac' } },
})

let dir: string

beforeEach(() => {
  vi.clearAllMocks()
  dir = mkdtempSync(join(tmpdir(), 'aauth-teardown-'))
  mocked.getConfigDir.mockReturnValue(dir)
  mocked.listAgentProviders.mockReturnValue([])
  mocked.listAgentUrls.mockReturnValue([])
  mocked.readKeychain.mockReturnValue(null)
})

afterEach(() => {
  rmSync(dir, { recursive: true, force: true })
})

describe('planAgent', () => {
  it('lists keys + remote files derived from config, deleting nothing', () => {
    const plan = planAgent('https://me.github.io', softwareAgent('https://me.github.io'))
    expect(plan.keysToDelete).toEqual([{ kid: '2026-05-22_ab', backend: 'software', keyId: 'https://me.github.io' }])
    expect(plan.remoteFilesToRemove).toEqual([
      'https://me.github.io/.well-known/jwks.json',
      'https://me.github.io/.well-known/aauth-agent.json',
    ])
    expect(plan.hosting).toEqual({ platform: 'github-pages', repo: 'me/me.github.io' })
    expect(mocked.deleteKeychain).not.toHaveBeenCalled()
  })
})

describe('executeTeardown', () => {
  it('wipes a software key via the keychain and removes config when asked', async () => {
    mocked.readKeychain.mockReturnValue({ keys: {} } as never)
    const res = await executeTeardown('https://me.github.io', softwareAgent('https://me.github.io'), { removeConfig: true })
    expect(res.keysDeleted).toBe(1)
    expect(res.hardwareKeysRetained).toEqual([])
    expect(mocked.deleteKeychain).toHaveBeenCalledWith('https://me.github.io')
    expect(mocked.deleteAgentProvider).toHaveBeenCalledWith('https://me.github.io')
  })

  it('records a YubiKey key as retained instead of failing', async () => {
    const cfg: AgentConfig = {
      keys: { k1: { backend: 'yubikey-piv', algorithm: 'ES256', keyId: '9e', deviceLabel: 'yk' } },
    }
    mocked.getBackend.mockReturnValue({
      deleteKey: vi.fn().mockRejectedValue(new lk.KeyDeletionUnsupportedError('run: ykman piv keys delete 9e')),
    } as never)
    const res = await executeTeardown('https://me.github.io', cfg, { removeConfig: false })
    expect(res.keysDeleted).toBe(0)
    expect(res.hardwareKeysRetained).toEqual([
      { kid: 'k1', keystore: 'yubikey-piv', keyId: '9e', hint: 'run: ykman piv keys delete 9e' },
    ])
    expect(mocked.deleteAgentProvider).not.toHaveBeenCalled()
  })

  it('propagates an unexpected backend error', async () => {
    const cfg: AgentConfig = { keys: { k1: { backend: 'secure-enclave', algorithm: 'ES256', keyId: 'lbl', deviceLabel: 'se' } } }
    mocked.getBackend.mockReturnValue({ deleteKey: vi.fn().mockRejectedValue(new Error('boom')) } as never)
    await expect(executeTeardown('https://me.github.io', cfg, { removeConfig: false })).rejects.toThrow('boom')
  })
})

describe('deleteAgent', () => {
  it('returns null for an unknown agent', async () => {
    mocked.getAgentConfig.mockReturnValue(null)
    expect(await deleteAgent('https://nope.example')).toBeNull()
  })

  it('deletes the agent and reports remote files to remove', async () => {
    mocked.getAgentConfig.mockReturnValue(softwareAgent('https://me.github.io'))
    const r = await deleteAgent('https://me.github.io')
    expect(r).toMatchObject({
      deleted: 'https://me.github.io',
      keysDeleted: 1,
      remoteFilesToRemove: [
        'https://me.github.io/.well-known/jwks.json',
        'https://me.github.io/.well-known/aauth-agent.json',
      ],
      hosting: { platform: 'github-pages', repo: 'me/me.github.io' },
    })
    expect(mocked.deleteAgentProvider).toHaveBeenCalledWith('https://me.github.io')
  })
})

describe('uninstall', () => {
  it('reports alreadyClean when there is nothing configured or orphaned', async () => {
    const r = await uninstall({ force: false })
    expect(r).toMatchObject({ alreadyClean: true })
    expect(mocked.deleteConfigFile).not.toHaveBeenCalled()
  })

  it('dry-run lists the plan and deletes nothing', async () => {
    mocked.listAgentProviders.mockReturnValue(['https://me.github.io'])
    mocked.getAgentConfig.mockReturnValue(softwareAgent('https://me.github.io'))
    mocked.listAgentUrls.mockReturnValue(['https://me.github.io', 'https://orphan.example'])

    const r = await uninstall({ force: false })
    expect(r.dryRun).toBe(true)
    expect(r.willBackUpConfig).toBe(true)
    expect(r.orphanedKeychainUrls).toEqual(['https://orphan.example'])
    expect((r.agents as unknown[]).length).toBe(1)
    expect(mocked.deleteConfigFile).not.toHaveBeenCalled()
    expect(mocked.deleteKeychain).not.toHaveBeenCalled()
    expect(mocked.deleteAgentProvider).not.toHaveBeenCalled()
    expect(existsSync(join(dir, 'backups'))).toBe(false)
  })

  it('--force backs up config, deletes keys, sweeps orphans, and removes config.json', async () => {
    mocked.listAgentProviders.mockReturnValue(['https://me.github.io'])
    mocked.getAgentConfig.mockReturnValue(softwareAgent('https://me.github.io'))
    mocked.readKeychain.mockReturnValue({ keys: {} } as never)
    mocked.listAgentUrls.mockReturnValue(['https://me.github.io', 'https://orphan.example'])

    const r = await uninstall({ force: true })
    expect(r.uninstalled).toBe(true)
    expect(r.orphanedKeychainUrlsSwept).toEqual(['https://orphan.example'])
    // configured agent's software key wiped + orphan swept
    expect(mocked.deleteKeychain).toHaveBeenCalledWith('https://me.github.io')
    expect(mocked.deleteKeychain).toHaveBeenCalledWith('https://orphan.example')
    // active config.json removed (dir kept), no full clear
    expect(mocked.deleteConfigFile).toHaveBeenCalledOnce()

    // a backup file was written, containing the agent's config (no private keys)
    const backupPath = r.backupPath as string
    expect(existsSync(backupPath)).toBe(true)
    const backup = JSON.parse(readFileSync(backupPath, 'utf-8'))
    expect(Object.keys(backup.agents)).toEqual(['https://me.github.io'])
    expect(backup.agents['https://me.github.io'].hosting).toEqual({ platform: 'github-pages', repo: 'me/me.github.io' })
    expect(JSON.stringify(backup)).not.toContain('"d"') // no EC/OKP private scalar
  })

  it('listBackups surfaces written backups (newest last)', async () => {
    expect(listBackups()).toEqual([])
    mocked.listAgentProviders.mockReturnValue(['https://me.github.io'])
    mocked.getAgentConfig.mockReturnValue(softwareAgent('https://me.github.io'))

    await uninstall({ force: true })
    const backups = listBackups()
    expect(backups).toHaveLength(1)
    expect(backups[0].agentUrls).toEqual(['https://me.github.io'])
    expect(backups[0].file).toMatch(/^uninstall-.*\.json$/)
    // the file listBackups names actually exists under backups/
    expect(readdirSync(join(dir, 'backups'))).toContain(backups[0].file)
  })
})
