import { describe, it, expect, vi, beforeEach } from 'vitest'

const { mockHttpSigFetch } = vi.hoisted(() => ({
  mockHttpSigFetch: vi.fn(),
}))

vi.mock('@hellocoop/httpsig', () => ({
  fetch: mockHttpSigFetch,
}))

const { mockExchangeToken } = vi.hoisted(() => ({
  mockExchangeToken: vi.fn(),
}))

vi.mock('./token-exchange.js', () => ({
  exchangeToken: mockExchangeToken,
}))

const { mockPollDeferred } = vi.hoisted(() => ({
  mockPollDeferred: vi.fn(),
}))

vi.mock('./deferred.js', () => ({
  pollDeferred: mockPollDeferred,
}))

import { createAAuthFetch } from './aauth-fetch.js'
import type { KeyMaterial } from './types.js'

describe('createAAuthFetch', () => {
  const fakeKeyMaterial: KeyMaterial = {
    signingKey: { kty: 'OKP', crv: 'Ed25519', x: 'testkey' },
    signatureKey: { type: 'jwt', jwt: 'eyJ.agent.token' },
  }
  const getKeyMaterial = vi.fn().mockResolvedValue(fakeKeyMaterial)

  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('returns 200 directly without challenge', async () => {
    const okResponse = new Response('ok', { status: 200 })
    mockHttpSigFetch.mockResolvedValueOnce(okResponse)

    const fetch = createAAuthFetch({ getKeyMaterial })
    const result = await fetch('https://resource.example/api')

    expect(result).toBe(okResponse)
    expect(mockHttpSigFetch).toHaveBeenCalledOnce()
  })

  it('handles 401 AAuth-Requirement challenge → token exchange → retry', async () => {
    // First request → 401 with AAuth-Requirement challenge
    const challengeResponse = new Response('unauthorized', {
      status: 401,
      headers: {
        'aauth-requirement': 'requirement=auth-token; resource-token="rt123"',
      },
    })
    mockHttpSigFetch.mockResolvedValueOnce(challengeResponse)

    // Token exchange returns auth token
    mockExchangeToken.mockResolvedValueOnce({
      authToken: 'eyJ.auth.token',
      expiresIn: 3600,
    })

    // Retry with auth token → 200
    const okResponse = new Response('{"data":"secret"}', { status: 200 })
    mockHttpSigFetch.mockResolvedValueOnce(okResponse)

    const fetch = createAAuthFetch({
      getKeyMaterial,
      authServerUrl: 'https://auth.example',
      justification: 'read files',
    })
    const result = await fetch('https://resource.example/api', { method: 'GET' })

    expect(result).toBe(okResponse)

    // Verify exchangeToken was called
    expect(mockExchangeToken).toHaveBeenCalledOnce()
    expect(mockExchangeToken).toHaveBeenCalledWith(expect.objectContaining({
      authServerUrl: 'https://auth.example',
      resourceToken: 'rt123',
      justification: 'read files',
    }))

    // Verify retry used the auth token in signatureKey
    expect(mockHttpSigFetch).toHaveBeenCalledTimes(2)
    const retryCall = mockHttpSigFetch.mock.calls[1]
    expect(retryCall[1].signatureKey).toEqual({ type: 'jwt', jwt: 'eyJ.auth.token' })
  })

  it('returns 401 without AAuth-Requirement header as-is', async () => {
    const response = new Response('unauthorized', { status: 401 })
    mockHttpSigFetch.mockResolvedValueOnce(response)

    const fetch = createAAuthFetch({ getKeyMaterial })
    const result = await fetch('https://resource.example/api')

    expect(result).toBe(response)
    expect(mockExchangeToken).not.toHaveBeenCalled()
  })

  it('handles 202 resource interaction with polling', async () => {
    // Request → 202 with Location and interaction
    const pendingResponse = new Response(null, {
      status: 202,
      headers: {
        Location: 'https://resource.example/pending/xyz',
        'aauth-requirement': 'requirement=interaction; url="https://resource.example/interact"; code="CODE1234"',
      },
    })
    mockHttpSigFetch.mockResolvedValueOnce(pendingResponse)

    // pollDeferred returns terminal 200
    const terminalResponse = new Response('{"result":"done"}', { status: 200 })
    mockPollDeferred.mockResolvedValueOnce({ response: terminalResponse })

    const onInteraction = vi.fn()
    const fetch = createAAuthFetch({ getKeyMaterial, onInteraction })
    const result = await fetch('https://resource.example/api')

    expect(result).toBe(terminalResponse)
    expect(mockPollDeferred).toHaveBeenCalledOnce()
    expect(mockPollDeferred).toHaveBeenCalledWith(expect.objectContaining({
      locationUrl: 'https://resource.example/pending/xyz',
      interactionUrl: 'https://resource.example/interact',
      interactionCode: 'CODE1234',
    }))
  })

  it('caches auth token and reuses on second request', async () => {
    // First request: 401 challenge → exchange → retry → 200
    mockHttpSigFetch.mockResolvedValueOnce(new Response('', {
      status: 401,
      headers: {
        'aauth-requirement': 'requirement=auth-token; resource-token="rt1"',
      },
    }))
    mockExchangeToken.mockResolvedValueOnce({
      authToken: 'eyJ.cached.token',
      expiresIn: 3600,
    })
    mockHttpSigFetch.mockResolvedValueOnce(new Response('ok1', { status: 200 }))

    const fetch = createAAuthFetch({
      getKeyMaterial,
      authServerUrl: 'https://auth.example',
    })

    // First request
    await fetch('https://resource.example/api')
    expect(mockExchangeToken).toHaveBeenCalledOnce()

    // Second request — should use cached token directly
    mockHttpSigFetch.mockResolvedValueOnce(new Response('ok2', { status: 200 }))
    await fetch('https://resource.example/other')

    // No additional exchange call
    expect(mockExchangeToken).toHaveBeenCalledOnce()
    // But the second request used the cached auth token
    expect(mockHttpSigFetch).toHaveBeenCalledTimes(3)
    const cachedCall = mockHttpSigFetch.mock.calls[2]
    expect(cachedCall[1].signatureKey).toEqual({ type: 'jwt', jwt: 'eyJ.cached.token' })
  })

  it('returns approval 401 challenge as-is (no exchange needed)', async () => {
    const response = new Response('', {
      status: 401,
      headers: { 'aauth-requirement': 'requirement=approval' },
    })
    mockHttpSigFetch.mockResolvedValueOnce(response)

    const fetch = createAAuthFetch({ getKeyMaterial })
    const result = await fetch('https://resource.example/api')

    expect(result).toBe(response)
    expect(mockExchangeToken).not.toHaveBeenCalled()
  })

  it('caches AAuth-Access token and sends as Authorization on next request', async () => {
    // First request → 200 with AAuth-Access header
    const firstResponse = new Response('ok', {
      status: 200,
      headers: { 'aauth-access': 'opaque-token-123' },
    })
    mockHttpSigFetch.mockResolvedValueOnce(firstResponse)

    const fetch = createAAuthFetch({ getKeyMaterial })
    await fetch('https://resource.example/api')

    // Second request should use the access token via Authorization header
    const secondResponse = new Response('ok2', { status: 200 })
    mockHttpSigFetch.mockResolvedValueOnce(secondResponse)
    await fetch('https://resource.example/other')

    // Verify the second call included the Authorization header
    const secondCall = mockHttpSigFetch.mock.calls[1]
    const headers = new Headers(secondCall[1].headers)
    expect(headers.get('authorization')).toBe('Bearer opaque-token-123')
  })

  it('replaces cached access token when response includes new AAuth-Access', async () => {
    // First request → 200 with AAuth-Access
    mockHttpSigFetch.mockResolvedValueOnce(new Response('ok', {
      status: 200,
      headers: { 'aauth-access': 'token-v1' },
    }))

    const fetch = createAAuthFetch({ getKeyMaterial })
    await fetch('https://resource.example/api')

    // Second request uses token-v1, gets back token-v2
    mockHttpSigFetch.mockResolvedValueOnce(new Response('ok', {
      status: 200,
      headers: { 'aauth-access': 'token-v2' },
    }))
    await fetch('https://resource.example/api')

    // Third request should use token-v2
    mockHttpSigFetch.mockResolvedValueOnce(new Response('ok', { status: 200 }))
    await fetch('https://resource.example/api')

    const thirdCall = mockHttpSigFetch.mock.calls[2]
    const headers = new Headers(thirdCall[1].headers)
    expect(headers.get('authorization')).toBe('Bearer token-v2')
  })

  it('passes enterprise hints to token exchange', async () => {
    mockHttpSigFetch.mockResolvedValueOnce(new Response('', {
      status: 401,
      headers: {
        'aauth-requirement': 'requirement=auth-token; resource-token="rt"',
      },
    }))
    mockExchangeToken.mockResolvedValueOnce({
      authToken: 'tok',
      expiresIn: 3600,
    })
    mockHttpSigFetch.mockResolvedValueOnce(new Response('ok', { status: 200 }))

    const fetch = createAAuthFetch({
      getKeyMaterial,
      authServerUrl: 'https://auth.example',
      loginHint: 'user@acme.com',
      tenant: 'acme.com',
      domainHint: 'acme.com',
    })
    await fetch('https://resource.example/api')

    expect(mockExchangeToken).toHaveBeenCalledWith(expect.objectContaining({
      loginHint: 'user@acme.com',
      tenant: 'acme.com',
      domainHint: 'acme.com',
    }))
  })
})
