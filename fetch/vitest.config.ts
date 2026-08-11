import { existsSync } from 'node:fs'
import path from 'node:path'
import { defineConfig } from 'vitest/config'

/**
 * Package-local vitest config, so `@aauth/fetch`'s tests can run before the AAuth -11
 * package renames land in the workspace. It mirrors the root config's
 * source-resolution aliases and adds the two packages this version depends on:
 *
 *   @aauth/agent    — `@aauth/mcp-agent` renamed (WP-3); falls back to the old
 *                     directory until that rename lands.
 *   @aauth/protocol — new in -11 (WP-1); falls back to `test/protocol-shim.ts`,
 *                     which implements the `planAccessMode` slice of the contract.
 *
 * Both branches self-heal: once `agent/` and `protocol/` exist the real sources win.
 * At integration these aliases belong in the root `vitest.config.ts` and this file
 * (with `test/protocol-shim.ts`) goes away.
 *
 * Run with: npx vitest run --config fetch/vitest.config.ts
 */
const repo = path.resolve(__dirname, '..')
const firstExisting = (...candidates: string[]): string =>
  candidates.find((c) => existsSync(c)) ?? candidates[candidates.length - 1]

export default defineConfig({
  resolve: {
    alias: {
      '@aauth/agent': firstExisting(
        path.join(repo, 'agent/src/index.ts'),
        path.join(repo, 'mcp-agent/src/index.ts'),
      ),
      '@aauth/protocol': firstExisting(
        path.join(repo, 'protocol/src/index.ts'),
        path.resolve(__dirname, 'test/protocol-shim.ts'),
      ),
      '@aauth/local-keys': path.join(repo, 'local-keys/src/index.ts'),
      '@aauth/hardware-keys': path.join(repo, 'hardware-keys/index.js'),
    },
  },
  test: {
    include: ['src/**/*.test.ts'],
    pool: 'forks',
    poolOptions: { forks: { singleFork: true } },
  },
})
