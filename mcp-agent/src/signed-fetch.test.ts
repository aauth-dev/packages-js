import { describe, it, expect, vi, beforeEach } from 'vitest'

const { mockHttpSigFetch } = vi.hoisted(() => ({
  mockHttpSigFetch: vi.fn(),
}))

vi.mock('@hellocoop/httpsig', () => ({
  fetch: mockHttpSigFetch,
}))

import { createSignedFetch } from './signed-fetch.js'

describe('createSignedFetch', () => {
  const fakeKeyMaterial = {
    signingKey: { kty: 'OKP', crv: 'Ed25519', x: 'test' },
    signatureKey: { type: 'jwt' as const, jwt: 'eyJ...' },
  }

  const getKeyMaterial = vi.fn().mockResolvedValue(fakeKeyMaterial)

  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('returns a function', () => {
    const signedFetch = createSignedFetch(getKeyMaterial)
    expect(typeof signedFetch).toBe('function')
  })

  it('calls getKeyMaterial and httpsig fetch', async () => {
    const fakeResponse = new Response('ok', { status: 200 })
    mockHttpSigFetch.mockResolvedValue(fakeResponse)

    const signedFetch = createSignedFetch(getKeyMaterial)
    const result = await signedFetch('https://example.com/mcp', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{"jsonrpc":"2.0"}',
    })

    expect(getKeyMaterial).toHaveBeenCalledOnce()
    expect(mockHttpSigFetch).toHaveBeenCalledWith('https://example.com/mcp', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{"jsonrpc":"2.0"}',
      signingKey: fakeKeyMaterial.signingKey,
      signatureKey: fakeKeyMaterial.signatureKey,
    })
    expect(result).toBe(fakeResponse)
  })

  it('passes through RequestInit options', async () => {
    mockHttpSigFetch.mockResolvedValue(new Response())

    const signedFetch = createSignedFetch(getKeyMaterial)
    await signedFetch('https://example.com', {
      method: 'PUT',
      headers: { Authorization: 'Bearer xyz' },
    })

    expect(mockHttpSigFetch).toHaveBeenCalledWith(
      'https://example.com',
      expect.objectContaining({
        method: 'PUT',
        headers: { Authorization: 'Bearer xyz' },
      }),
    )
  })

  it('works with no init argument', async () => {
    mockHttpSigFetch.mockResolvedValue(new Response())

    const signedFetch = createSignedFetch(getKeyMaterial)
    await signedFetch('https://example.com')

    expect(mockHttpSigFetch).toHaveBeenCalledWith('https://example.com', {
      signingKey: fakeKeyMaterial.signingKey,
      signatureKey: fakeKeyMaterial.signatureKey,
    })
  })

  it('sets AAuth-Capabilities header when capabilities provided', async () => {
    mockHttpSigFetch.mockResolvedValue(new Response())

    const signedFetch = createSignedFetch(getKeyMaterial, {
      capabilities: ['interaction', 'clarification'],
    })
    await signedFetch('https://example.com')

    const call = mockHttpSigFetch.mock.calls[0]
    const headers = new Headers(call[1].headers)
    expect(headers.get('aauth-capabilities')).toBe('interaction, clarification')
  })

  it('sets AAuth-Mission header when mission provided', async () => {
    mockHttpSigFetch.mockResolvedValue(new Response())

    const signedFetch = createSignedFetch(getKeyMaterial, {
      mission: { approver: 'https://ps.example', s256: 'abc123' },
    })
    await signedFetch('https://example.com')

    const call = mockHttpSigFetch.mock.calls[0]
    const headers = new Headers(call[1].headers)
    expect(headers.get('aauth-mission')).toBe('approver="https://ps.example"; s256="abc123"')
  })

  it('does not set AAuth-Capabilities or AAuth-Mission when not provided', async () => {
    mockHttpSigFetch.mockResolvedValue(new Response())

    const signedFetch = createSignedFetch(getKeyMaterial)
    await signedFetch('https://example.com')

    const call = mockHttpSigFetch.mock.calls[0]
    const headers = new Headers(call[1].headers)
    expect(headers.has('aauth-capabilities')).toBe(false)
    expect(headers.has('aauth-mission')).toBe(false)
  })
})
