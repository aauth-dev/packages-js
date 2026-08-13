import type { Transport } from '@modelcontextprotocol/sdk/shared/transport.js'
import type { JSONRPCMessage } from '@modelcontextprotocol/sdk/types.js'

/** The fetch shape `StreamableHTTPClientTransport` is handed, and the shape
 *  `createAAuthFetch` returns. Declared here so this module stays free of
 *  `@aauth/agent` — the AAuth flow itself lives there, not in the proxy. */
export type ProxyFetch = (url: string | URL, init?: RequestInit) => Promise<Response>

/**
 * Serialize the requests that can trigger an AAuth flow.
 *
 * `createAAuthFetch` has no internal mutex. A fresh flow against a resource is
 * now several round trips — 401 `requirement=person-token`, POST the PS's
 * `person_token_endpoint`, retry, 401 `requirement=auth-token`, POST the PS's
 * `auth_token_endpoint` (possibly with a browser interaction in between),
 * retry — so the window in which concurrent requests would each start their own
 * flow, and each open their own browser tab, is wider than it was under -10.
 *
 * Only POSTs are gated. The transport's GET is the long-lived SSE stream and
 * must never wait behind an auth flow.
 *
 * Waiters re-take the gate one at a time rather than all resuming together, so
 * the second request through uses the token the first one obtained.
 */
export function serializeAuthFlows(inner: ProxyFetch): ProxyFetch {
  let inFlight: Promise<void> | null = null

  return async (url, init) => {
    const method = init?.method ?? 'GET'
    if (method !== 'POST') {
      return inner(url, init)
    }

    while (inFlight) {
      await inFlight
    }

    let release!: () => void
    inFlight = new Promise<void>((resolve) => { release = resolve })
    try {
      return await inner(url, init)
    } finally {
      inFlight = null
      release()
    }
  }
}

export async function bridgeTransports(
  local: Transport,
  remote: Transport,
): Promise<void> {
  local.onmessage = (message) => {
    remote.send(message).catch((err) => {
      console.error('Error forwarding to remote:', err)
      // Send JSON-RPC error back for requests (have an id) so the client
      // gets a proper error instead of hanging until the connection dies.
      const msg = message as { id?: unknown; method?: string }
      if (msg.id !== undefined) {
        const errorResponse: JSONRPCMessage = {
          jsonrpc: '2.0',
          error: { code: -32001, message: `${err.message || err}` },
          id: msg.id as number,
        }
        local.send(errorResponse).catch(() => {})
      }
    })
  }

  remote.onmessage = (message) => {
    local.send(message).catch((err) => {
      console.error('Error forwarding to local:', err)
    })
  }

  local.onclose = () => {
    remote.close().catch(() => {})
  }

  remote.onclose = () => {
    local.close().catch(() => {})
  }

  local.onerror = (err) => {
    console.error('Local transport error:', err)
    remote.close().catch(() => {})
  }

  remote.onerror = (err) => {
    console.error('Remote transport error:', err)
    // Don't close local on remote errors — individual request failures
    // are handled by sending JSON-RPC errors back. Only close if the
    // transport itself is permanently broken (handled by onclose).
  }

  await Promise.all([local.start(), remote.start()])
}
