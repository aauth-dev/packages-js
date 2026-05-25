import { describe, it, expect, vi, beforeEach } from 'vitest'
import type { KeyMaterial, AAuthFetchOptions } from '@aauth/mcp-agent'

// --- Mocks ---

const { mockCreateSignedFetch, mockSignedFetch } = vi.hoisted(() => {
  const mockSignedFetch = vi.fn()
  return {
    mockSignedFetch,
    mockCreateSignedFetch: vi.fn(() => mockSignedFetch),
  }
})

const { mockCreateAAuthFetch, mockAAuthFetch } = vi.hoisted(() => {
  const mockAAuthFetch = vi.fn()
  return {
    mockAAuthFetch,
    mockCreateAAuthFetch: vi.fn((_opts: AAuthFetchOptions) => mockAAuthFetch),
  }
})

const { mockExchangeToken } = vi.hoisted(() => ({
  mockExchangeToken: vi.fn(),
}))

const { mockParseAAuthHeader } = vi.hoisted(() => ({
  mockParseAAuthHeader: vi.fn(),
}))

const { FakeTokenExchangeError } = vi.hoisted(() => ({
  FakeTokenExchangeError: class extends Error {
    constructor(public readonly status: number) {
      super(`Token exchange failed with status ${status}`)
      this.name = 'TokenExchangeError'
    }
  },
}))

vi.mock('@aauth/mcp-agent', () => ({
  createSignedFetch: mockCreateSignedFetch,
  createAAuthFetch: mockCreateAAuthFetch,
  exchangeToken: mockExchangeToken,
  parseAAuthHeader: mockParseAAuthHeader,
  TokenExchangeError: FakeTokenExchangeError,
}))

vi.mock('@aauth/local-keys', () => ({
  createAgentToken: vi.fn(),
  readConfig: vi.fn(() => ({ agents: {} })),
  getAgentConfig: vi.fn(() => null),
  readCachedMetadata: vi.fn(() => null),
  writeCachedMetadata: vi.fn(),
  evictCachedMetadata: vi.fn(),
}))

vi.mock('open', () => ({ default: vi.fn() }))

import {
  handleAuthorize,
  handlePreAuthed,
  handleAgentOnly,
  handleFullFlow,
  buildRequestInit,
  resolvePersonServer,
  resolvePersonServerMetadata,
  savePersonServerMetadata,
  runWithMetadataSelfHeal,
  tryParseJson,
} from './handlers.js'
import { readConfig, getAgentConfig, readCachedMetadata, writeCachedMetadata, evictCachedMetadata } from '@aauth/local-keys'
import { TokenExchangeError } from '@aauth/mcp-agent'
import open from 'open'

// --- Helpers ---

const fakeKeyMaterial: KeyMaterial = {
  signingKey: { kty: 'OKP', crv: 'Ed25519', x: 'testpub', d: 'testpriv' },
  signatureKey: { type: 'jwt', jwt: 'eyJ.agent.token' },
}
const fakeGetKeyMaterial = vi.fn().mockResolvedValue(fakeKeyMaterial)

function captureStdout(): { output: string[]; restore: () => void } {
  const output: string[] = []
  const orig = console.log
  console.log = (...args: unknown[]) => output.push(args.join(' '))
  return { output, restore: () => { console.log = orig } }
}

function captureStderr(): { output: string[]; restore: () => void } {
  const output: string[] = []
  const orig = console.error
  console.error = (...args: unknown[]) => output.push(args.join(' '))
  return { output, restore: () => { console.error = orig } }
}

// --- Tests ---

describe('utility functions', () => {
  it('tryParseJson parses valid JSON', () => {
    expect(tryParseJson('{"a":1}')).toEqual({ a: 1 })
  })

  it('tryParseJson returns undefined for invalid JSON', () => {
    expect(tryParseJson('not json')).toBeUndefined()
  })
})

describe('buildRequestInit', () => {
  it('sets method and parses headers', () => {
    const init = buildRequestInit({
      method: 'POST',
      data: '{"a":1}',
      headers: ['Accept: text/plain', 'X-Custom: foo'],
    })
    expect(init.method).toBe('POST')
    expect(init.body).toBe('{"a":1}')
    const h = init.headers as Headers
    expect(h.get('accept')).toBe('text/plain')
    expect(h.get('x-custom')).toBe('foo')
    expect(h.get('content-type')).toBe('application/json')
  })

  it('skips invalid headers without colon', () => {
    const init = buildRequestInit({ method: 'GET', headers: ['no-colon-here'] })
    const h = init.headers as Headers
    expect(h.get('no-colon-here')).toBeNull()
  })

  it('does not set content-type without data', () => {
    const init = buildRequestInit({ method: 'GET', headers: [] })
    const h = init.headers as Headers
    expect(h.get('content-type')).toBeNull()
  })

  it('does not override explicit content-type', () => {
    const init = buildRequestInit({
      method: 'POST',
      data: '<xml/>',
      headers: ['Content-Type: application/xml'],
    })
    const h = init.headers as Headers
    expect(h.get('content-type')).toBe('application/xml')
  })
})

describe('resolvePersonServer', () => {
  beforeEach(() => vi.clearAllMocks())

  it('returns override when provided', () => {
    expect(resolvePersonServer('https://agent.com', 'https://override.com')).toBe('https://override.com')
  })

  it('reads from config when agentUrl provided', () => {
    vi.mocked(getAgentConfig).mockReturnValueOnce({
      personServerUrl: 'https://config-ps.com',
      keys: {},
    })
    expect(resolvePersonServer('https://agent.com', undefined)).toBe('https://config-ps.com')
  })

  it('reads sole agent from config when no agentUrl', () => {
    vi.mocked(readConfig).mockReturnValueOnce({
      agents: {
        'https://sole-agent.com': { personServerUrl: 'https://sole-ps.com', keys: {} },
      },
    })
    expect(resolvePersonServer(undefined, undefined)).toBe('https://sole-ps.com')
  })

  it('returns undefined when multiple agents and no agentUrl', () => {
    vi.mocked(readConfig).mockReturnValueOnce({
      agents: {
        'https://a.com': { keys: {} },
        'https://b.com': { keys: {} },
      },
    })
    expect(resolvePersonServer(undefined, undefined)).toBeUndefined()
  })
})

describe('resolvePersonServerMetadata', () => {
  beforeEach(() => vi.clearAllMocks())
  const meta = { token_endpoint: 'https://ps.com/aauth/token', jwks_uri: 'https://ps.com/jwks' }

  it('returns the cached metadata for the PS host', () => {
    vi.mocked(readCachedMetadata).mockReturnValueOnce(meta)
    expect(resolvePersonServerMetadata('https://ps.com')).toEqual(meta)
    expect(readCachedMetadata).toHaveBeenCalledWith('ps.com')
  })

  it('returns undefined when nothing is cached (or it expired)', () => {
    vi.mocked(readCachedMetadata).mockReturnValueOnce(null)
    expect(resolvePersonServerMetadata('https://ps.com')).toBeUndefined()
  })

  it('returns undefined (no cache lookup) when no person server is given', () => {
    expect(resolvePersonServerMetadata(undefined)).toBeUndefined()
    expect(readCachedMetadata).not.toHaveBeenCalled()
  })
})

describe('savePersonServerMetadata', () => {
  beforeEach(() => vi.clearAllMocks())
  const meta = { token_endpoint: 'https://ps.com/aauth/token', jwks_uri: 'https://ps.com/jwks' }

  it('writes the fetched metadata to the cache, keyed by PS host', () => {
    savePersonServerMetadata('https://ps.com', meta)
    expect(writeCachedMetadata).toHaveBeenCalledWith('ps.com', meta)
  })

  it('is a no-op when no person server is given', () => {
    savePersonServerMetadata(undefined, meta)
    expect(writeCachedMetadata).not.toHaveBeenCalled()
  })
})

describe('runWithMetadataSelfHeal', () => {
  beforeEach(() => vi.clearAllMocks())
  const meta = { token_endpoint: 'https://ps.com/aauth/token' }

  it('passes the cached metadata through on success (no eviction)', async () => {
    const run = vi.fn().mockResolvedValue(undefined)
    await runWithMetadataSelfHeal('https://ps.com', meta, run)
    expect(run).toHaveBeenCalledTimes(1)
    expect(run).toHaveBeenCalledWith(meta)
    expect(evictCachedMetadata).not.toHaveBeenCalled()
  })

  it('evicts and retries once (fresh fetch) on a 404 from the cached endpoint', async () => {
    const run = vi.fn()
      .mockRejectedValueOnce(new TokenExchangeError(404))
      .mockResolvedValueOnce(undefined)
    await runWithMetadataSelfHeal('https://ps.com', meta, run)
    expect(evictCachedMetadata).toHaveBeenCalledWith('ps.com')
    expect(run).toHaveBeenCalledTimes(2)
    expect(run).toHaveBeenNthCalledWith(2, undefined) // retry forces a fresh fetch
  })

  it('self-heals on a network error (TypeError) reaching the cached endpoint', async () => {
    const run = vi.fn()
      .mockRejectedValueOnce(new TypeError('fetch failed'))
      .mockResolvedValueOnce(undefined)
    await runWithMetadataSelfHeal('https://ps.com', meta, run)
    expect(evictCachedMetadata).toHaveBeenCalledOnce()
    expect(run).toHaveBeenCalledTimes(2)
  })

  it('does NOT self-heal a 401 challenge (rethrows, no retry)', async () => {
    const run = vi.fn().mockRejectedValue(new TokenExchangeError(401))
    await expect(runWithMetadataSelfHeal('https://ps.com', meta, run)).rejects.toThrow()
    expect(evictCachedMetadata).not.toHaveBeenCalled()
    expect(run).toHaveBeenCalledTimes(1)
  })

  it('does NOT self-heal a 5xx (rethrows, no retry)', async () => {
    const run = vi.fn().mockRejectedValue(new TokenExchangeError(503))
    await expect(runWithMetadataSelfHeal('https://ps.com', meta, run)).rejects.toThrow()
    expect(run).toHaveBeenCalledTimes(1)
  })

  it('does not retry when there was no cached metadata to blame', async () => {
    const run = vi.fn().mockRejectedValue(new TokenExchangeError(404))
    await expect(runWithMetadataSelfHeal('https://ps.com', undefined, run)).rejects.toThrow()
    expect(run).toHaveBeenCalledTimes(1)
    expect(evictCachedMetadata).not.toHaveBeenCalled()
  })

  it('does not loop: a second stale failure on retry propagates', async () => {
    const run = vi.fn().mockRejectedValue(new TokenExchangeError(404))
    await expect(runWithMetadataSelfHeal('https://ps.com', meta, run)).rejects.toThrow()
    // one eviction, exactly two attempts (original + single retry)
    expect(evictCachedMetadata).toHaveBeenCalledOnce()
    expect(run).toHaveBeenCalledTimes(2)
  })
})

describe('handleAgentOnly', () => {
  beforeEach(() => vi.clearAllMocks())

  it('calls signedFetch and outputs response body', async () => {
    mockSignedFetch.mockResolvedValueOnce(new Response('{"data":"ok"}', { status: 200 }))

    const stdout = captureStdout()
    try {
      await handleAgentOnly(
        { url: 'https://resource.example/api', verbose: false },
        { method: 'GET', headers: new Headers() },
        fakeGetKeyMaterial,
      )
    } finally {
      stdout.restore()
    }

    expect(mockCreateSignedFetch).toHaveBeenCalledWith(fakeGetKeyMaterial, undefined)
    expect(mockSignedFetch).toHaveBeenCalledWith('https://resource.example/api', expect.any(Object))
    expect(stdout.output[0]).toContain('"data": "ok"')
  })

  it('with -v, writes request/response events to stderr', async () => {
    mockSignedFetch.mockResolvedValueOnce(new Response('ok', { status: 200 }))

    const lines: string[] = []
    const origWrite = process.stderr.write.bind(process.stderr)
    process.stderr.write = ((s: string) => { lines.push(String(s)); return true }) as typeof process.stderr.write
    const stdout = captureStdout()
    try {
      await handleAgentOnly(
        { url: 'https://resource.example/api', verbose: true },
        { method: 'GET', headers: new Headers() },
        fakeGetKeyMaterial,
      )
    } finally {
      process.stderr.write = origWrite
      stdout.restore()
    }

    const joined = lines.join('')
    expect(joined).toContain('"step": "agent_token_request"')
    expect(joined).toContain('"type": "response"')
    expect(joined).toContain('"status": 200')
  })
})

describe('handlePreAuthed', () => {
  beforeEach(() => vi.clearAllMocks())

  it('uses provided auth token and signing key', async () => {
    mockSignedFetch.mockResolvedValueOnce(new Response('{"result":"secret"}', { status: 200 }))

    const stdout = captureStdout()
    try {
      await handlePreAuthed(
        {
          url: 'https://resource.example/api',
          method: 'GET',
          authToken: 'eyJ.auth.token',
          signingKey: '{"kty":"OKP","crv":"Ed25519","x":"pub","d":"priv"}',
          verbose: false,
          headers: [],
        },
        { method: 'GET', headers: new Headers() },
      )
    } finally {
      stdout.restore()
    }

    // createSignedFetch should have been called with a getKeyMaterial that returns the provided key
    expect(mockCreateSignedFetch).toHaveBeenCalled()
    const getKM = mockCreateSignedFetch.mock.calls[mockCreateSignedFetch.mock.calls.length - 1][0]
    const km = await getKM()
    expect(km.signingKey).toEqual({ kty: 'OKP', crv: 'Ed25519', x: 'pub', d: 'priv' })
    expect(km.signatureKey).toEqual({ type: 'jwt', jwt: 'eyJ.auth.token' })
  })

  it('errors on invalid signing key JSON', async () => {
    const stderr = captureStderr()
    const origExitCode = process.exitCode
    try {
      await handlePreAuthed(
        {
          url: 'https://resource.example/api',
          method: 'GET',
          authToken: 'eyJ.auth.token',
          signingKey: 'not-json',
          verbose: false,
          headers: [],
        },
        { method: 'GET', headers: new Headers() },
      )
    } finally {
      stderr.restore()
    }

    expect(stderr.output[0]).toContain('Invalid --signing-key')
    expect(process.exitCode).toBe(1)
    process.exitCode = origExitCode
  })
})

describe('handleFullFlow', () => {
  beforeEach(() => vi.clearAllMocks())

  it('calls createAAuthFetch and outputs response', async () => {
    mockAAuthFetch.mockResolvedValueOnce(new Response('{"data":"full"}', { status: 200 }))

    const stdout = captureStdout()
    try {
      await handleFullFlow(
        { url: 'https://resource.example/api', nonInteractive: false, verbose: false },
        { method: 'GET', headers: new Headers() },
        fakeGetKeyMaterial,
        'https://ps.example.com',
      )
    } finally {
      stdout.restore()
    }

    expect(mockCreateAAuthFetch).toHaveBeenCalledWith(expect.objectContaining({
      authServerUrl: 'https://ps.example.com',
    }))
    // getKeyMaterial is pinned, so it's a wrapper — not the original
    const passedGetKM = mockCreateAAuthFetch.mock.calls[0][0].getKeyMaterial
    expect(passedGetKM).not.toBe(fakeGetKeyMaterial)
    expect(await passedGetKM()).toBe(fakeKeyMaterial)
    expect(stdout.output[0]).toContain('"data": "full"')
  })

  it('passes cached PS metadata through to createAAuthFetch', async () => {
    mockAAuthFetch.mockResolvedValueOnce(new Response('{}', { status: 200 }))
    const meta = { token_endpoint: 'https://ps.example.com/aauth/token' }

    const stdout = captureStdout()
    try {
      await handleFullFlow(
        { url: 'https://resource.example/api', nonInteractive: false, verbose: false },
        { method: 'GET', headers: new Headers() },
        fakeGetKeyMaterial,
        'https://ps.example.com',
        meta,
      )
    } finally {
      stdout.restore()
    }

    expect(mockCreateAAuthFetch).toHaveBeenCalledWith(expect.objectContaining({
      authServerMetadata: meta,
    }))
  })

  it('works without person server (identity-only resources)', async () => {
    mockAAuthFetch.mockResolvedValueOnce(new Response('ok', { status: 200 }))

    const stdout = captureStdout()
    try {
      await handleFullFlow(
        { url: 'https://resource.example/api', nonInteractive: false, verbose: false },
        { method: 'GET', headers: new Headers() },
        fakeGetKeyMaterial,
        undefined,
      )
    } finally {
      stdout.restore()
    }

    expect(mockCreateAAuthFetch).toHaveBeenCalledWith(expect.objectContaining({
      authServerUrl: undefined,
    }))
  })

  it('--with-token returns { auth_token, expires_in, signingKey, response }', async () => {
    // Simulate an auth token being minted during the flow (resource challenged).
    mockCreateAAuthFetch.mockImplementationOnce((opts: { onAuthToken?: (t: string, e: number) => void }) => {
      opts.onAuthToken?.('eyJ.minted.token', 3600)
      return mockAAuthFetch
    })
    mockAAuthFetch.mockResolvedValueOnce(new Response('{"data":"secret"}', { status: 200 }))

    const stdout = captureStdout()
    try {
      await handleFullFlow(
        { url: 'https://resource.example/api', nonInteractive: false, verbose: false, withToken: true },
        { method: 'GET', headers: new Headers() },
        fakeGetKeyMaterial,
        'https://ps.example.com',
      )
    } finally {
      stdout.restore()
    }

    const result = JSON.parse(stdout.output[0])
    expect(result.auth_token).toBe('eyJ.minted.token')
    expect(result.expires_in).toBe(3600)
    expect(result.signingKey).toEqual(fakeKeyMaterial.signingKey)
    expect(result.response).toEqual({ status: 200, body: { data: 'secret' } })
    // The onAuthToken callback was wired in.
    expect(typeof mockCreateAAuthFetch.mock.calls[0][0].onAuthToken).toBe('function')
  })

  it('--with-token omits auth_token when none was minted (agent-token 200)', async () => {
    mockAAuthFetch.mockResolvedValueOnce(new Response('{"ok":true}', { status: 200 }))

    const stdout = captureStdout()
    try {
      await handleFullFlow(
        { url: 'https://resource.example/api', nonInteractive: false, verbose: false, withToken: true },
        { method: 'GET', headers: new Headers() },
        fakeGetKeyMaterial,
        'https://ps.example.com',
      )
    } finally {
      stdout.restore()
    }

    const result = JSON.parse(stdout.output[0])
    expect(result.auth_token).toBeUndefined()
    expect(result.expires_in).toBeUndefined()
    expect(result.signingKey).toEqual(fakeKeyMaterial.signingKey)
    expect(result.response.status).toBe(200)
  })

  it('default (no --with-token) prints the raw resource body', async () => {
    mockAAuthFetch.mockResolvedValueOnce(new Response('{"data":"full"}', { status: 200 }))

    const stdout = captureStdout()
    try {
      await handleFullFlow(
        { url: 'https://resource.example/api', nonInteractive: false, verbose: false },
        { method: 'GET', headers: new Headers() },
        fakeGetKeyMaterial,
        'https://ps.example.com',
      )
    } finally {
      stdout.restore()
    }

    // Raw body, not wrapped in a { response } object.
    expect(stdout.output[0]).toContain('"data": "full"')
    expect(stdout.output[0]).not.toContain('signingKey')
  })

  it('--with-token includes access_token in two-party mode', async () => {
    // Simulate a resource handing back an opaque AAuth-Access token.
    mockCreateAAuthFetch.mockImplementationOnce((opts) => {
      opts.onAccessToken?.('opaque-xyz')
      return mockAAuthFetch
    })
    mockAAuthFetch.mockResolvedValueOnce(new Response('{"ok":true}', { status: 200 }))

    const stdout = captureStdout()
    try {
      await handleFullFlow(
        { url: 'https://resource.example/api', nonInteractive: false, verbose: false, withToken: true },
        { method: 'GET', headers: new Headers() },
        fakeGetKeyMaterial,
        undefined,
      )
    } finally {
      stdout.restore()
    }

    const result = JSON.parse(stdout.output[0])
    expect(result.access_token).toBe('opaque-xyz')
    expect(result.auth_token).toBeUndefined()
    expect(result.signingKey).toEqual(fakeKeyMaterial.signingKey)
  })

  it('--access-token seeds the opaque token into createAAuthFetch', async () => {
    mockAAuthFetch.mockResolvedValueOnce(new Response('ok', { status: 200 }))

    const stdout = captureStdout()
    try {
      await handleFullFlow(
        { url: 'https://resource.example/api', nonInteractive: false, verbose: false, accessToken: 'reuse-me' },
        { method: 'GET', headers: new Headers() },
        fakeGetKeyMaterial,
        undefined,
      )
    } finally {
      stdout.restore()
    }

    expect(mockCreateAAuthFetch).toHaveBeenCalledWith(expect.objectContaining({
      accessToken: 'reuse-me',
    }))
  })
})

describe('handleAuthorize', () => {
  beforeEach(() => vi.clearAllMocks())

  it('returns signingKey + signatureKey when resource returns 200', async () => {
    mockSignedFetch.mockResolvedValueOnce(new Response('{"identity":"me"}', { status: 200 }))

    const stdout = captureStdout()
    try {
      await handleAuthorize(
        { url: 'https://whoami.aauth.dev', nonInteractive: false, verbose: false },
        fakeGetKeyMaterial,
        undefined,
      )
    } finally {
      stdout.restore()
    }

    const result = JSON.parse(stdout.output[0])
    expect(result.signingKey).toEqual(fakeKeyMaterial.signingKey)
    expect(result.signatureKey).toEqual(fakeKeyMaterial.signatureKey)
    expect(result.response.status).toBe(200)
    expect(result.response.body).toEqual({ identity: 'me' })
    expect(result.access_token).toBeUndefined() // no AAuth-Access header → no field
  })

  it('surfaces access_token from a two-party 200 (AAuth-Access header)', async () => {
    mockSignedFetch.mockResolvedValueOnce(new Response('{"data":1}', {
      status: 200,
      headers: { 'aauth-access': 'opaque-aaa' },
    }))

    const stdout = captureStdout()
    try {
      await handleAuthorize(
        { url: 'https://resource.example', nonInteractive: false, verbose: false },
        fakeGetKeyMaterial,
        undefined,
      )
    } finally {
      stdout.restore()
    }

    const result = JSON.parse(stdout.output[0])
    expect(result.access_token).toBe('opaque-aaa')
    expect(result.response.status).toBe(200)
  })

  it('exchanges token on 401 challenge and returns authToken + signingKey', async () => {
    mockSignedFetch.mockResolvedValueOnce(new Response('', {
      status: 401,
      headers: { 'aauth-requirement': 'requirement=auth-token; resource-token="rt123"' },
    }))
    mockParseAAuthHeader.mockReturnValueOnce({
      requirement: 'auth-token',
      resourceToken: 'rt123',
    })
    mockExchangeToken.mockResolvedValueOnce({
      authToken: 'eyJ.auth.result',
      expiresIn: 3600,
    })

    const stdout = captureStdout()
    try {
      await handleAuthorize(
        { url: 'https://resource.example', local: 'fetch', nonInteractive: false, verbose: false },
        fakeGetKeyMaterial,
        'https://ps.example.com',
      )
    } finally {
      stdout.restore()
    }

    const result = JSON.parse(stdout.output[0])
    expect(result.auth_token).toBe('eyJ.auth.result')
    expect(result.expires_in).toBe(3600)
    expect(result.signingKey).toEqual(fakeKeyMaterial.signingKey)

    expect(mockExchangeToken).toHaveBeenCalledWith(expect.objectContaining({
      authServerUrl: 'https://ps.example.com',
      resourceToken: 'rt123',
    }))
  })

  it('errors on 401 without AAuth-Requirement header', async () => {
    mockSignedFetch.mockResolvedValueOnce(new Response('', { status: 401 }))

    const stderr = captureStderr()
    const origExitCode = process.exitCode
    try {
      await handleAuthorize(
        { url: 'https://resource.example', local: 'fetch', nonInteractive: false, verbose: false },
        fakeGetKeyMaterial,
        'https://ps.example.com',
      )
    } finally {
      stderr.restore()
    }

    expect(stderr.output[0]).toContain('401 response without AAuth-Requirement')
    expect(process.exitCode).toBe(1)
    process.exitCode = origExitCode
  })

  it('errors on 401 challenge without person server', async () => {
    mockSignedFetch.mockResolvedValueOnce(new Response('', {
      status: 401,
      headers: { 'aauth-requirement': 'requirement=auth-token; resource-token="rt"' },
    }))
    mockParseAAuthHeader.mockReturnValueOnce({
      requirement: 'auth-token',
      resourceToken: 'rt',
    })

    const stderr = captureStderr()
    const origExitCode = process.exitCode
    try {
      await handleAuthorize(
        { url: 'https://resource.example', local: 'fetch', nonInteractive: false, verbose: false },
        fakeGetKeyMaterial,
        undefined,
      )
    } finally {
      stderr.restore()
    }

    expect(stderr.output[0]).toContain('Person server URL required')
    expect(process.exitCode).toBe(1)
    process.exitCode = origExitCode
  })

  it('errors on unexpected challenge requirement', async () => {
    mockSignedFetch.mockResolvedValueOnce(new Response('', {
      status: 401,
      headers: { 'aauth-requirement': 'requirement=approval' },
    }))
    mockParseAAuthHeader.mockReturnValueOnce({
      requirement: 'approval',
    })

    const stderr = captureStderr()
    const origExitCode = process.exitCode
    try {
      await handleAuthorize(
        { url: 'https://resource.example', local: 'fetch', nonInteractive: false, verbose: false },
        fakeGetKeyMaterial,
        'https://ps.example.com',
      )
    } finally {
      stderr.restore()
    }

    expect(stderr.output[0]).toContain('Unexpected challenge requirement: approval')
    expect(process.exitCode).toBe(1)
    process.exitCode = origExitCode
  })

  it('errors on unexpected response status', async () => {
    mockSignedFetch.mockResolvedValueOnce(new Response('server error', { status: 500 }))

    const stderr = captureStderr()
    const origExitCode = process.exitCode
    try {
      await handleAuthorize(
        { url: 'https://resource.example', local: 'fetch', nonInteractive: false, verbose: false },
        fakeGetKeyMaterial,
        'https://ps.example.com',
      )
    } finally {
      stderr.restore()
    }

    expect(stderr.output[0]).toContain('Unexpected response status: 500')
    expect(process.exitCode).toBe(1)
    process.exitCode = origExitCode
  })

  it('appends scope to URL as query parameter', async () => {
    mockSignedFetch.mockResolvedValueOnce(new Response('{}', { status: 200 }))

    const stdout = captureStdout()
    try {
      await handleAuthorize(
        { url: 'https://whoami.aauth.dev', local: 'fetch', scope: 'email profile', nonInteractive: false, verbose: false },
        fakeGetKeyMaterial,
        undefined,
      )
    } finally {
      stdout.restore()
    }

    const calledUrl = mockSignedFetch.mock.calls[0][0] as string
    expect(calledUrl).toContain('scope=email+profile')
  })

  it('pins key material so same ephemeral key is used', async () => {
    mockSignedFetch.mockResolvedValueOnce(new Response('{}', { status: 200 }))

    const stdout = captureStdout()
    try {
      await handleAuthorize(
        { url: 'https://resource.example', local: 'fetch', nonInteractive: false, verbose: false },
        fakeGetKeyMaterial,
        undefined,
      )
    } finally {
      stdout.restore()
    }

    // getKeyMaterial should be called exactly once, then pinned
    expect(fakeGetKeyMaterial).toHaveBeenCalledOnce()
    // createSignedFetch gets a pinned function, not the original
    const pinnedFn = mockCreateSignedFetch.mock.calls[mockCreateSignedFetch.mock.calls.length - 1][0]
    expect(pinnedFn).not.toBe(fakeGetKeyMaterial)
    // But it returns the same key material
    const km = await pinnedFn()
    expect(km).toBe(fakeKeyMaterial)
  })

  // --- R3 (--operations) branch ---

  it('R3: POSTs operations to the authorize endpoint and exchanges the resource token', async () => {
    mockSignedFetch.mockResolvedValueOnce(new Response('{"resource_token":"rt_r3"}', { status: 200 }))
    mockExchangeToken.mockResolvedValueOnce({ authToken: 'eyJ.r3.auth', expiresIn: 1800 })

    const stdout = captureStdout()
    try {
      await handleAuthorize(
        { url: 'https://notes.aauth.dev/authorize', operations: 'listNotes, createNote', nonInteractive: false, verbose: false },
        fakeGetKeyMaterial,
        'https://ps.example.com',
      )
    } finally {
      stdout.restore()
    }

    // POSTed an R3 body with the requested operationIds
    const [calledUrl, init] = mockSignedFetch.mock.calls[0]
    expect(calledUrl).toBe('https://notes.aauth.dev/authorize')
    expect((init as RequestInit).method).toBe('POST')
    const body = JSON.parse((init as RequestInit).body as string)
    expect(body.r3_operations.vocabulary).toBe('urn:aauth:vocabulary:openapi')
    expect(body.r3_operations.operations).toEqual([{ operationId: 'listNotes' }, { operationId: 'createNote' }])

    // exchanged the resource token from the authorize response
    expect(mockExchangeToken).toHaveBeenCalledWith(expect.objectContaining({
      authServerUrl: 'https://ps.example.com',
      resourceToken: 'rt_r3',
    }))

    const result = JSON.parse(stdout.output[0])
    expect(result.auth_token).toBe('eyJ.r3.auth')
    expect(result.expires_in).toBe(1800)
    expect(result.signingKey).toEqual(fakeKeyMaterial.signingKey)
  })

  it('R3: errors when the authorize endpoint returns non-200', async () => {
    mockSignedFetch.mockResolvedValueOnce(new Response('{"error":"forbidden"}', { status: 403 }))

    const stderr = captureStderr()
    const origExitCode = process.exitCode
    try {
      await handleAuthorize(
        { url: 'https://notes.aauth.dev/authorize', operations: 'listNotes', nonInteractive: false, verbose: false },
        fakeGetKeyMaterial,
        'https://ps.example.com',
      )
    } finally {
      stderr.restore()
    }

    expect(stderr.output[0]).toContain('Authorize endpoint returned status 403')
    expect(mockExchangeToken).not.toHaveBeenCalled()
    expect(process.exitCode).toBe(1)
    process.exitCode = origExitCode
  })

  it('R3: errors when the authorize response has no resource_token', async () => {
    mockSignedFetch.mockResolvedValueOnce(new Response('{"not_a_token":1}', { status: 200 }))

    const stderr = captureStderr()
    const origExitCode = process.exitCode
    try {
      await handleAuthorize(
        { url: 'https://notes.aauth.dev/authorize', operations: 'listNotes', nonInteractive: false, verbose: false },
        fakeGetKeyMaterial,
        'https://ps.example.com',
      )
    } finally {
      stderr.restore()
    }

    expect(stderr.output[0]).toContain('missing resource_token')
    expect(mockExchangeToken).not.toHaveBeenCalled()
    expect(process.exitCode).toBe(1)
    process.exitCode = origExitCode
  })
})
