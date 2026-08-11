import { defineConfig } from 'vitest/config'
import path from 'path'

export default defineConfig({
  resolve: {
    alias: {
      '@aauth/protocol': path.resolve(__dirname, 'protocol/src/index.ts'),
      '@aauth/agent': path.resolve(__dirname, 'agent/src/index.ts'),
      '@aauth/resource': path.resolve(__dirname, 'resource/src/index.ts'),
      '@aauth/mcp-openclaw': path.resolve(__dirname, 'mcp-openclaw/src/index.ts'),
      '@aauth/local-keys': path.resolve(__dirname, 'local-keys/src/index.ts'),
      // Required once `resource/vitest.config.ts` is deleted: `@aauth/resource`
      // imports `@aauth/interaction-code`, whose package entry points at an
      // unbuilt `dist/`. Resolve it from source like every other workspace.
      '@aauth/interaction-code': path.resolve(__dirname, 'interaction-code/src/index.ts'),
      '@aauth/hardware-keys': path.resolve(__dirname, 'hardware-keys/index.js'),
    },
  },
  test: {
    pool: 'forks',
    poolOptions: {
      forks: {
        singleFork: true,
      },
    },
  },
})
