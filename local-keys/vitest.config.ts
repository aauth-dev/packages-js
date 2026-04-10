import { defineConfig } from 'vitest/config'
import path from 'path'

export default defineConfig({
  resolve: {
    alias: {
      '@aauth/hardware-keys': path.resolve(__dirname, '..', 'hardware-keys', 'index.js'),
    },
  },
  test: {
    // YubiKey requires exclusive access — tests must run sequentially
    pool: 'forks',
    poolOptions: {
      forks: {
        singleFork: true,
      },
    },
  },
})
