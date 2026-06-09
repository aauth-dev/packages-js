import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { execFileSync } from 'node:child_process'
import { mkdtempSync, rmSync, existsSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { fileURLToPath } from 'node:url'

// Opt-in end-to-end test of the real CLI: setup (`create`) → `list` → `uninstall`
// dry-run → scoped `delete`. Skipped in CI and by default — run with:
//
//   npm run build && AAUTH_E2E=1 npx vitest run src/uninstall.e2e.test.ts
//
// Notes on why it's shaped this way:
//  - Needs the built dist (it spawns dist/cli.js) — skips with a message if absent.
//  - Touches the REAL OS keychain (software keys aren't isolated by AAUTH_DIR), so
//    it uses a unique throwaway agent URL and tears it down with the SCOPED `delete`
//    command — never `uninstall --force`, whose orphan-sweep would delete unrelated
//    software keys that might exist on the machine. The destructive full-wipe path
//    is covered by the mocked unit tests in teardown.test.ts.
//  - `create` binds a person server, so it needs network access.

const CLI = join(fileURLToPath(new URL('.', import.meta.url)), '..', 'dist', 'cli.js')
const ENABLED = !!process.env.AAUTH_E2E && existsSync(CLI)

function run(env: Record<string, string>, ...args: string[]): unknown {
  const out = execFileSync('node', [CLI, ...args], {
    env: { ...process.env, ...env, NO_COLOR: '1' },
    encoding: 'utf-8',
  })
  return JSON.parse(out)
}

describe.skipIf(!ENABLED)('uninstall e2e (setup ↔ teardown)', () => {
  let dir: string
  let url: string
  let env: Record<string, string>

  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), 'aauth-e2e-'))
    url = `https://aauth-e2e-${process.pid}.example`
    env = { AAUTH_DIR: dir }
  })

  afterAll(() => {
    // Best-effort cleanup of the throwaway key + temp dir.
    try { run(env, 'delete', url) } catch { /* already gone */ }
    rmSync(dir, { recursive: true, force: true })
  })

  it('creates, lists, previews teardown, then deletes the identity', () => {
    // 1. setup
    const created = run(env, 'create', url, '--keystore', 'software') as { agentProvider: string; keys: unknown[] }
    expect(created.agentProvider).toBe(url)
    expect(created.keys).toHaveLength(1)

    // 2. list shows it
    const listed = run(env, 'list') as { agentProviders: Array<{ url: string }> }
    expect(listed.agentProviders.map((a) => a.url)).toContain(url)

    // 3. uninstall dry-run previews the plan and deletes nothing
    const preview = run(env, 'uninstall') as {
      dryRun: boolean
      agents: Array<{ agentUrl: string }>
      willBackUpConfig: boolean
    }
    expect(preview.dryRun).toBe(true)
    expect(preview.willBackUpConfig).toBe(true)
    expect(preview.agents.map((a) => a.agentUrl)).toContain(url)
    // still present after a dry-run
    expect((run(env, 'list') as { agentProviders: unknown[] }).agentProviders).toHaveLength(1)

    // 4. scoped teardown (safe: no orphan sweep) reports the remote files to remove
    const deleted = run(env, 'delete', url) as { deleted: string; keysDeleted: number; remoteFilesToRemove: string[] }
    expect(deleted.deleted).toBe(url)
    expect(deleted.keysDeleted).toBe(1)
    expect(deleted.remoteFilesToRemove).toContain(`${url}/.well-known/jwks.json`)

    // 5. clean
    expect((run(env, 'list') as { agentProviders: unknown[] }).agentProviders).toHaveLength(0)
  })
})
