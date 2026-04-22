#!/usr/bin/env node

import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js'
import { createAAuthFetch } from '@aauth/mcp-agent'
import { createAgentToken } from '@aauth/local-keys'
import open from 'open'
import { parseArgs } from './args.js'
import { bridgeTransports } from './proxy.js'

const { serverUrl, agentUrl, local, tokenLifetime } = parseArgs(process.argv)

const innerFetch = createAAuthFetch({
  getKeyMaterial: () =>
    createAgentToken({
      agentUrl,
      local,
      tokenLifetime,
    }),
  onInteraction: (code, interactionEndpoint) => {
    const url = `${interactionEndpoint}?code=${code}`
    console.error(`[aauth-stdio] Opening browser for consent: ${url}`)
    open(url)
  },
})

// Serialize requests that trigger auth — createAAuthFetch has no internal mutex,
// so concurrent 401s would each open a browser tab. This wrapper ensures only one
// auth flow runs at a time; others wait then retry with the cached token.
let authInFlight: Promise<void> | null = null
const aAuthFetch: typeof innerFetch = async (url, init) => {
  const method = (init as RequestInit)?.method ?? 'GET'

  // Only serialize POST requests — GET (SSE) is long-lived and must not block
  if (method !== 'POST') {
    return innerFetch(url, init)
  }

  if (authInFlight) {
    await authInFlight
    return innerFetch(url, init)
  }
  let resolve: () => void
  authInFlight = new Promise<void>((r) => { resolve = r })
  try {
    return await innerFetch(url, init)
  } finally {
    authInFlight = null
    resolve!()
  }
}

const remote = new StreamableHTTPClientTransport(new URL(serverUrl), {
  fetch: aAuthFetch,
})

const localTransport = new StdioServerTransport()

bridgeTransports(localTransport, remote).catch((err) => {
  console.error('Fatal error:', err)
  process.exit(1)
})
