#!/usr/bin/env node

import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js'
import { createAAuthFetch } from '@aauth/agent'
import { createAgentToken, getAgentConfig, readConfig } from '@aauth/local-keys'
import open from 'open'
import { createRequire } from 'node:module'
import { parseArgs } from './args.js'
import { bridgeTransports, serializeAuthFlows } from './proxy.js'

if (process.argv.includes('--version')) {
  const pkg = createRequire(import.meta.url)('../package.json') as { version: string }
  console.log(pkg.version)
  process.exit(0)
}

const { serverUrl, agentUrl, local, tokenLifetime, personServer } = parseArgs(process.argv)

/**
 * Resolve the person server: explicit flag/env first, then the PS recorded for
 * this agent provider at bootstrap. Matches how `@aauth/fetch` resolves it.
 */
function resolvePersonServer(): string | undefined {
  if (personServer) return personServer
  if (agentUrl) return getAgentConfig(agentUrl)?.personServerUrl
  const providers = Object.entries(readConfig().agents)
  if (providers.length === 1) return providers[0][1].personServerUrl
  return undefined
}

const personServerUrl = resolvePersonServer()

// Without a PS the agent has no `ps` claim, so it can obtain neither a person
// token nor an auth token. Two-party resources (agent identity only, or an
// AAuth-Access session token) still work, so this is a warning, not a fatal —
// but a resource answering `requirement=person-token` will fail, and saying so
// up front beats an opaque error mid-session.
if (!personServerUrl) {
  console.error(
    '[aauth-stdio] No person server configured — this agent can only reach resources ' +
    'that accept agent identity alone. Pass --person-server <url> (or set ' +
    'AAUTH_PERSON_SERVER) to satisfy requirement=person-token and requirement=auth-token.',
  )
}

const innerFetch = createAAuthFetch({
  getKeyMaterial: () =>
    createAgentToken({
      agentUrl,
      local,
      tokenLifetime,
      // Stamps the `ps` claim on the agent token. The resource reads it to
      // decide where a resource token's `aud` points, and the PS reads the
      // signing key to bind the person token's `cnf`.
      ...(personServerUrl ? { personServerUrl } : {}),
    }),
  // The PS whose metadata carries `person_token_endpoint` (person-token hop) and
  // `auth_token_endpoint` (the -11 name for what -10 called `token_endpoint`).
  // INTEGRATION: `@aauth/mcp-agent` 2.0.0 spelled this option `authServerUrl`.
  // If `@aauth/agent` 3.0.0 keeps that spelling, rename this one key.
  ...(personServerUrl ? { personServerUrl } : {}),
  // pollDeferred and the PS/resource interaction paths call this as
  // (url, code) — the interaction endpoint first, the user-visible code second.
  onInteraction: (url: string, code: string) => {
    const interactionUrl = `${url}?code=${code}`
    console.error(`[aauth-stdio] Opening browser for consent: ${interactionUrl}`)
    open(interactionUrl)
  },
})

const aAuthFetch = serializeAuthFlows(innerFetch)

const remote = new StreamableHTTPClientTransport(new URL(serverUrl), {
  fetch: aAuthFetch,
})

const localTransport = new StdioServerTransport()

bridgeTransports(localTransport, remote).catch((err) => {
  console.error('Fatal error:', err)
  process.exit(1)
})
