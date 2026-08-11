import { describe, it, expect, vi, beforeEach } from 'vitest'
import { bridgeTransports, serializeAuthFlows } from './proxy.js'
import type { ProxyFetch } from './proxy.js'
import type { Transport } from '@modelcontextprotocol/sdk/shared/transport.js'

function createMockTransport(): Transport {
  return {
    start: vi.fn().mockResolvedValue(undefined),
    send: vi.fn().mockResolvedValue(undefined),
    close: vi.fn().mockResolvedValue(undefined),
    onmessage: undefined,
    onclose: undefined,
    onerror: undefined,
  } as unknown as Transport
}

describe('bridgeTransports', () => {
  let local: Transport
  let remote: Transport

  beforeEach(() => {
    local = createMockTransport()
    remote = createMockTransport()
  })

  it('calls start() on both transports', async () => {
    await bridgeTransports(local, remote)

    expect(local.start).toHaveBeenCalledOnce()
    expect(remote.start).toHaveBeenCalledOnce()
  })

  it('forwards local messages to remote', async () => {
    await bridgeTransports(local, remote)

    const msg = { jsonrpc: '2.0', method: 'test', id: 1 }
    local.onmessage!(msg as any)

    expect(remote.send).toHaveBeenCalledWith(msg)
  })

  it('forwards remote messages to local', async () => {
    await bridgeTransports(local, remote)

    const msg = { jsonrpc: '2.0', result: {}, id: 1 }
    remote.onmessage!(msg as any)

    expect(local.send).toHaveBeenCalledWith(msg)
  })

  it('closes remote when local closes', async () => {
    await bridgeTransports(local, remote)

    local.onclose!()

    expect(remote.close).toHaveBeenCalledOnce()
  })

  it('closes local when remote closes', async () => {
    await bridgeTransports(local, remote)

    remote.onclose!()

    expect(local.close).toHaveBeenCalledOnce()
  })

  it('closes remote on local error', async () => {
    await bridgeTransports(local, remote)

    local.onerror!(new Error('local broke'))

    expect(remote.close).toHaveBeenCalledOnce()
  })

  it('does not close local on remote error', async () => {
    await bridgeTransports(local, remote)

    remote.onerror!(new Error('remote broke'))

    expect(local.close).not.toHaveBeenCalled()
  })
})

function deferred<T>(): { promise: Promise<T>; resolve: (v: T) => void; reject: (e: unknown) => void } {
  let resolve!: (v: T) => void
  let reject!: (e: unknown) => void
  const promise = new Promise<T>((res, rej) => { resolve = res; reject = rej })
  return { promise, resolve, reject }
}

const ok = () => new Response('ok', { status: 200 })

describe('serializeAuthFlows', () => {
  it('passes GET straight through without gating', async () => {
    const started: string[] = []
    const gate = deferred<void>()
    const inner: ProxyFetch = async (url) => {
      started.push(String(url))
      await gate.promise
      return ok()
    }
    const fetchLike = serializeAuthFlows(inner)

    const a = fetchLike('https://r.example/a')
    const b = fetchLike('https://r.example/b')
    await Promise.resolve()

    // Both GETs are in flight — the SSE stream must never wait on a token.
    expect(started).toEqual(['https://r.example/a', 'https://r.example/b'])

    gate.resolve()
    await Promise.all([a, b])
  })

  it('runs POSTs one at a time', async () => {
    const started: number[] = []
    const gates = [deferred<void>(), deferred<void>(), deferred<void>()]
    let n = 0
    const inner: ProxyFetch = async () => {
      const i = n++
      started.push(i)
      await gates[i].promise
      return ok()
    }
    const fetchLike = serializeAuthFlows(inner)

    const calls = [0, 1, 2].map(() => fetchLike('https://r.example/mcp', { method: 'POST' }))
    await Promise.resolve()
    expect(started).toEqual([0])

    gates[0].resolve()
    await calls[0]
    await Promise.resolve()
    expect(started).toEqual([0, 1])

    gates[1].resolve()
    await calls[1]
    await Promise.resolve()
    expect(started).toEqual([0, 1, 2])

    gates[2].resolve()
    await calls[2]
  })

  it('lets a waiting POST reuse the token the first flow obtained', async () => {
    // Stands in for the -11 flow: the first POST walks person-token then
    // auth-token and caches the result; queued POSTs must see the cached token
    // rather than each starting their own flow (and their own browser tab).
    let token: string | undefined
    let flows = 0
    const release = deferred<void>()
    const seen: (string | undefined)[] = []

    const inner: ProxyFetch = async () => {
      seen.push(token)
      if (!token) {
        flows++
        await release.promise
        token = 'auth-token-1'
      }
      return ok()
    }
    const fetchLike = serializeAuthFlows(inner)

    const first = fetchLike('https://r.example/mcp', { method: 'POST' })
    const second = fetchLike('https://r.example/mcp', { method: 'POST' })
    await Promise.resolve()

    release.resolve()
    await Promise.all([first, second])

    expect(flows).toBe(1)
    expect(seen).toEqual([undefined, 'auth-token-1'])
  })

  it('releases the gate when a POST rejects', async () => {
    let n = 0
    const inner: ProxyFetch = async () => {
      if (n++ === 0) throw new Error('interaction timed out')
      return ok()
    }
    const fetchLike = serializeAuthFlows(inner)

    await expect(fetchLike('https://r.example/mcp', { method: 'POST' }))
      .rejects.toThrow('interaction timed out')

    const retry = await fetchLike('https://r.example/mcp', { method: 'POST' })
    expect(retry.status).toBe(200)
  })

  it('does not make a GET wait behind an in-flight POST', async () => {
    const started: string[] = []
    const post = deferred<void>()
    const inner: ProxyFetch = async (url, init) => {
      started.push(`${init?.method ?? 'GET'} ${url}`)
      if (init?.method === 'POST') await post.promise
      return ok()
    }
    const fetchLike = serializeAuthFlows(inner)

    const p = fetchLike('https://r.example/mcp', { method: 'POST' })
    const g = fetchLike('https://r.example/mcp')
    await g

    expect(started).toEqual(['POST https://r.example/mcp', 'GET https://r.example/mcp'])

    post.resolve()
    await p
  })
})
