import { defineConfig } from 'vitest/config'
import path from 'path'

export default defineConfig({
  resolve: {
    alias: {
      '@aauth/mcp-server': path.resolve(__dirname, 'mcp-server/src/index.ts'),
      '@aauth/mcp-agent': path.resolve(__dirname, 'mcp-agent/src/index.ts'),
      '@aauth/mcp-openclaw': path.resolve(__dirname, 'mcp-openclaw/src/index.ts'),
      '@aauth/local-keys': path.resolve(__dirname, 'local-keys/src/index.ts'),
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
