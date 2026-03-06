import type { Transport } from '@modelcontextprotocol/sdk/shared/transport.js'
import type { JSONRPCMessage } from '@modelcontextprotocol/sdk/types.js'

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
          error: { code: -32603, message: `${err.message || err}` },
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
