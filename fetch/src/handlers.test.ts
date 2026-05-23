import { describe, it, expect, vi, beforeEach } from 'vitest'
import type { KeyMaterial } from '@aauth/mcp-agent'

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
    mockCreateAAuthFetch: vi.fn(() => mockAAuthFetch),
  }
})

const { mockExchangeToken } = vi.hoisted(() => ({
  mockExchangeToken: vi.fn(),
}))

const { mockParseAAuthHeader } = vi.hoisted(() => ({
  mockParseAAuthHeader: vi.fn(),
}))

vi.mock('@aauth/mcp-agent', () => ({
  createSignedFetch: mockCreateSignedFetch,
  createAAuthFetch: mockCreateAAuthFetch,
  exchangeToken: mockExchangeToken,
  parseAAuthHeader: mockParseAAuthHeader,
}))

vi.mock('@aauth/local-keys', () => ({
  createAgentToken: vi.fn(),
  readConfig: vi.fn(() => ({ agents: {} })),
  getAgentConfig: vi.fn(() => null),
}))

vi.mock('open', () => ({ default: vi.fn() }))

import {
  handleAuthorize,
  handlePreAuthed,
  handleAgentOnly,
  handleFullFlow,
  buildRequestInit,
  resolvePersonServer,
  headersToObject,
  tryParseJson,
} from './handlers.js'
import { readConfig, getAgentConfig } from '@aauth/local-keys'
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
  it('headersToObject converts Headers', () => {
    const h = new Headers({ 'content-type': 'application/json', 'x-test': 'yes' })
    const obj = headersToObject(h)
    expect(obj['content-type']).toBe('application/json')
    expect(obj['x-test']).toBe('yes')
  })

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

    expect(mockCreateSignedFetch).toHaveBeenCalledWith(fakeGetKeyMaterial)
    expect(mockSignedFetch).toHaveBeenCalledWith('https://resource.example/api', expect.any(Object))
    expect(stdout.output[0]).toContain('"data": "ok"')
  })

  it('outputs verbose status and headers to stderr', async () => {
    mockSignedFetch.mockResolvedValueOnce(new Response('ok', {
      status: 200,
      headers: { 'x-test': 'yes' },
    }))

    const stdout = captureStdout()
    const stderr = captureStderr()
    try {
      await handleAgentOnly(
        { url: 'https://resource.example/api', verbose: true },
        { method: 'GET', headers: new Headers() },
        fakeGetKeyMaterial,
      )
    } finally {
      stdout.restore()
      stderr.restore()
    }

    const info = JSON.parse(stderr.output[0])
    expect(info.status).toBe(200)
    expect(info.headers['x-test']).toBe('yes')
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
    expect(result.authToken).toBe('eyJ.auth.result')
    expect(result.expiresIn).toBe(3600)
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
})
