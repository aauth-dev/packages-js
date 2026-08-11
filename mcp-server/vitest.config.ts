import { defineConfig } from 'vitest/config'
import path from 'node:path'

/**
 * Package-local vitest config.
 *
 * `@aauth/protocol` (WP-1) does not exist in this worktree, so tests resolve it
 * against the contract-faithful stub in `test/protocol-stub`.
 *
 * INTEGRATION: delete this file and `test/protocol-stub/`, and add
 *   '@aauth/protocol': path.resolve(__dirname, 'protocol/src/index.ts')
 * plus a rename of '@aauth/mcp-server' -> '@aauth/resource'
 * to the root `packages-js/vitest.config.ts` aliases.
 */
export default defineConfig({
  resolve: {
    alias: {
      '@aauth/protocol': path.resolve(__dirname, 'test/protocol-stub/index.ts'),
      '@aauth/resource': path.resolve(__dirname, 'src/index.ts'),
    },
  },
  test: {
    include: ['src/**/*.test.ts'],
    pool: 'forks',
    poolOptions: { forks: { singleFork: true } },
  },
})
