import { describe, it, expect, vi, beforeEach } from 'vitest'

const { mockHttpSigFetch } = vi.hoisted(() => ({
  mockHttpSigFetch: vi.fn(),
}))

vi.mock('@hellocoop/httpsig', () => ({
  fetch: mockHttpSigFetch,
}))

import { createSignedFetch, PS_COMPONENTS_BODY } from './signed-fetch.js'

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

  it('does not set AAuth-Capabilities when not provided', async () => {
    mockHttpSigFetch.mockResolvedValue(new Response())

    const signedFetch = createSignedFetch(getKeyMaterial)
    await signedFetch('https://example.com')

    const call = mockHttpSigFetch.mock.calls[0]
    const headers = new Headers(call[1].headers)
    expect(headers.has('aauth-capabilities')).toBe(false)
  })

  it('does not send an AAuth-Mission header — the header was removed in -11', async () => {
    mockHttpSigFetch.mockResolvedValue(new Response())

    const signedFetch = createSignedFetch(getKeyMaterial, { capabilities: ['interaction'] })
    await signedFetch('https://example.com')

    const call = mockHttpSigFetch.mock.calls[0]
    const headers = new Headers(call[1].headers)
    expect(headers.has('aauth-mission')).toBe(false)
  })

  describe('PS/AS body signing', () => {
    it('covers content-digest and content-type on a PS request with a body', async () => {
      mockHttpSigFetch.mockResolvedValue(new Response())

      const psFetch = createSignedFetch(getKeyMaterial, { signBody: true })
      await psFetch('https://ps.example/aauth/token/person', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          resource: 'https://resource.example',
          mission_s256: 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
        }),
      })

      const components: string[] = mockHttpSigFetch.mock.calls[0][1].components
      expect(components).toEqual([...PS_COMPONENTS_BODY])
      expect(components).toContain('content-digest')
      expect(components).toContain('content-type')
      // The four base components stay mandatory.
      expect(components).toEqual(expect.arrayContaining([
        '@method', '@authority', '@path', 'signature-key',
      ]))
    })

    it('passes no component list on a bodyless PS request', async () => {
      mockHttpSigFetch.mockResolvedValue(new Response())

      const psFetch = createSignedFetch(getKeyMaterial, { signBody: true })
      await psFetch('https://ps.example/.well-known/aauth-person.json', { method: 'GET' })

      expect(mockHttpSigFetch.mock.calls[0][1].components).toBeUndefined()
    })

    it('never mandates body components toward a resource', async () => {
      mockHttpSigFetch.mockResolvedValue(new Response())

      const resourceFetch = createSignedFetch(getKeyMaterial)
      await resourceFetch('https://resource.example/api', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: '{"q":1}',
      })

      // A resource declares what it needs via additional_signature_components;
      // the agent must not impose content-digest on it.
      expect(mockHttpSigFetch.mock.calls[0][1].components).toBeUndefined()
    })
  })
})
