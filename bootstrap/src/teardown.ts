// Teardown logic shared by the `delete` (per-agent) and `uninstall` (full wipe)
// commands. Kept separate from cli.ts so it can be unit-tested without the CLI's
// import-time `run()`. Functions return the printable result object — they never
// write to stdout — so tests can assert the exact JSON shape.

import { mkdirSync, writeFileSync, readdirSync, readFileSync, existsSync } from 'node:fs'
import { join } from 'node:path'
import {
  getAgentConfig,
  listAgentProviders,
  listAgentUrls,
  readKeychain,
  deleteKeychain,
  deleteAgentProvider,
  deleteConfigFile,
  getConfigDir,
  getBackend,
  KeyDeletionUnsupportedError,
} from '@aauth/local-keys'
import type { AgentConfig, AgentHosting } from '@aauth/local-keys'

/** Directory under the config dir where uninstall snapshots are written. */
export function backupsDir(): string {
  return join(getConfigDir(), 'backups')
}

/**
 * Snapshot the agents being removed so a later setup can reuse their settings
 * (agent URL, person server, hosting). Contains config only — NEVER private key
 * material, which never lives in config. Returns the backup file path.
 */
function writeBackup(agents: Record<string, AgentConfig>): string {
  const dir = backupsDir()
  mkdirSync(dir, { recursive: true })
  const stamp = new Date().toISOString().replace(/[:.]/g, '-')
  const path = join(dir, `uninstall-${stamp}.json`)
  writeFileSync(path, JSON.stringify({ uninstalledAt: new Date().toISOString(), agents }, null, 2) + '\n')
  return path
}

export interface BackupSummary {
  file: string
  uninstalledAt?: string
  agentUrls: string[]
}

/**
 * Available uninstall backups (newest last), so `list` can surface them and the
 * setup skill can offer to reuse a prior identity's settings.
 */
export function listBackups(): BackupSummary[] {
  const dir = backupsDir()
  if (!existsSync(dir)) return []
  let files: string[]
  try {
    files = readdirSync(dir).filter((f) => f.endsWith('.json')).sort()
  } catch {
    return []
  }
  return files.map((file) => {
    try {
      const data = JSON.parse(readFileSync(join(dir, file), 'utf-8')) as { uninstalledAt?: string; agents?: Record<string, unknown> }
      return { file, uninstalledAt: data.uninstalledAt, agentUrls: Object.keys(data.agents ?? {}) }
    } catch {
      return { file, agentUrls: [] }
    }
  })
}

export type HardwareRetained = { kid: string; keystore: string; keyId: string; hint: string }

export interface AgentPlan {
  agentUrl: string
  keysToDelete: Array<{ kid: string; backend: string; keyId: string }>
  remoteFilesToRemove: string[]
  hosting: AgentHosting | null
}

/** Remote `.well-known` files an agent published, derived from config. */
export function remoteFilesFor(cfg: AgentConfig): string[] {
  const files: string[] = []
  if (cfg.jwksUri) files.push(cfg.jwksUri)
  if (cfg.agentServerUrl) files.push(cfg.agentServerUrl)
  return files
}

/** What a teardown *would* touch for one agent — pure, deletes nothing. */
export function planAgent(agentUrl: string, cfg: AgentConfig): AgentPlan {
  return {
    agentUrl,
    keysToDelete: Object.entries(cfg.keys).map(([kid, meta]) => ({ kid, backend: meta.backend, keyId: meta.keyId })),
    remoteFilesToRemove: remoteFilesFor(cfg),
    hosting: cfg.hosting ?? null,
  }
}

/**
 * Delete one agent's keys across every backend (and optionally its config entry).
 * Software keys live under the agent URL in the OS keychain (wiped in one shot);
 * hardware keys go through each backend's `deleteKey`. A backend that can't wipe a
 * key (e.g. YubiKey PIV) throws `KeyDeletionUnsupportedError` — recorded, not fatal.
 * Never touches remote hosting — that's the skill's job.
 */
export async function executeTeardown(
  agentUrl: string,
  cfg: AgentConfig,
  opts: { removeConfig: boolean },
): Promise<{ keysDeleted: number; hardwareKeysRetained: HardwareRetained[] }> {
  let keysDeleted = 0
  const hardwareKeysRetained: HardwareRetained[] = []

  if (readKeychain(agentUrl)) deleteKeychain(agentUrl)

  for (const [kid, meta] of Object.entries(cfg.keys)) {
    if (meta.backend === 'software') {
      keysDeleted++
      continue
    }
    const driver = getBackend(meta.backend)
    try {
      await driver.deleteKey?.(meta.keyId)
      keysDeleted++
    } catch (e) {
      if (e instanceof KeyDeletionUnsupportedError) {
        hardwareKeysRetained.push({ kid, keystore: meta.backend, keyId: meta.keyId, hint: e.hint })
      } else {
        throw e
      }
    }
  }

  if (opts.removeConfig) deleteAgentProvider(agentUrl)

  return { keysDeleted, hardwareKeysRetained }
}

/** Attach the remote-files footer (and hosting) to a result when there is one. */
function withRemoteFooter(target: Record<string, unknown>, plan: AgentPlan): void {
  if (plan.remoteFilesToRemove.length > 0) {
    target.remoteFilesToRemove = plan.remoteFilesToRemove
    if (plan.hosting) target.hosting = plan.hosting
  }
}

/**
 * `delete <url>` — per-agent, immediate. Deletes the agent's keys and removes it
 * from config, and reports the remote files still to remove. Returns null if the
 * agent provider isn't configured.
 */
export async function deleteAgent(agentUrl: string): Promise<Record<string, unknown> | null> {
  const cfg = getAgentConfig(agentUrl)
  if (!cfg) return null

  const plan = planAgent(agentUrl, cfg)
  const { keysDeleted, hardwareKeysRetained } = await executeTeardown(agentUrl, cfg, { removeConfig: true })

  const result: Record<string, unknown> = { deleted: agentUrl, keysDeleted }
  if (hardwareKeysRetained.length > 0) result.hardwareKeysRetained = hardwareKeysRetained
  withRemoteFooter(result, plan)
  return result
}

/**
 * `uninstall` — return the machine to a clean, pre-bootstrap state. Dry-run by
 * default: computes and returns the plan, deleting nothing. With `force`, it
 * backs up the config first (so a later setup can reuse the agent URL, person
 * server, and hosting), deletes every configured agent's keys, sweeps orphaned
 * keychain entries, and removes the active `config.json` — keeping the config dir
 * and its `backups/`. Reports the remote `.well-known` files still to remove — it
 * never touches remote hosting.
 */
export async function uninstall(opts: { force: boolean }): Promise<Record<string, unknown>> {
  const agentUrls = listAgentProviders()
  const plans: AgentPlan[] = []
  const configs: Record<string, AgentConfig> = {}
  for (const url of agentUrls) {
    const cfg = getAgentConfig(url)
    if (cfg) {
      plans.push(planAgent(url, cfg))
      configs[url] = cfg
    }
  }
  // Software keys in the keychain whose agent URL isn't in config — orphans to sweep.
  const orphanedKeychainUrls = listAgentUrls().filter((u) => !agentUrls.includes(u))

  if (plans.length === 0 && orphanedKeychainUrls.length === 0) {
    return { alreadyClean: true, configDir: getConfigDir() }
  }

  if (!opts.force) {
    return {
      dryRun: true,
      scope: 'all',
      agents: plans,
      orphanedKeychainUrls,
      willBackUpConfig: Object.keys(configs).length > 0,
      hint: 'Nothing was deleted. Re-run with --force to delete the keys — the config is backed up first so setup can reuse it later.',
    }
  }

  const agents: Array<Record<string, unknown>> = []
  for (const url of agentUrls) {
    const cfg = configs[url]
    if (!cfg) continue
    const plan = planAgent(url, cfg)
    // removeConfig:false — config.json is removed in one shot below (deleteConfigFile).
    const { keysDeleted, hardwareKeysRetained } = await executeTeardown(url, cfg, { removeConfig: false })
    const entry: Record<string, unknown> = { agentUrl: url, keysDeleted }
    if (hardwareKeysRetained.length > 0) entry.hardwareKeysRetained = hardwareKeysRetained
    withRemoteFooter(entry, plan)
    agents.push(entry)
  }
  for (const url of orphanedKeychainUrls) deleteKeychain(url)

  const result: Record<string, unknown> = {
    uninstalled: true,
    agents,
    orphanedKeychainUrlsSwept: orphanedKeychainUrls,
  }
  // Back up before removing config so a later setup can reuse it; keep the dir.
  if (Object.keys(configs).length > 0) result.backupPath = writeBackup(configs)
  deleteConfigFile()
  result.configDir = getConfigDir()
  result.note = 'Config backed up. The setup skill can reuse it (agent URL, person server, hosting) next time — you generate fresh keys.'
  return result
}
