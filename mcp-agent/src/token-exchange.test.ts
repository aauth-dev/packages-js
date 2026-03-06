import { describe, it, expect, vi, beforeEach } from 'vitest'

const { mockPollDeferred } = vi.hoisted(() => ({
  mockPollDeferred: vi.fn(),
}))

vi.mock('./deferred.js', () => ({
  pollDeferred: mockPollDeferred,
}))

import { exchangeToken, TokenExchangeError } from './token-exchange.js'

describe('exchangeToken', () => {
  let mockFetch: ReturnType<typeof vi.fn>

  const metadata = {
    token_endpoint: 'https://auth.example/aauth/token',
    interaction_endpoint: 'https://auth.example/aauth/interaction',
    jwks_uri: 'https://auth.example/aauth/jwks',
  }

  beforeEach(() => {
    vi.clearAllMocks()
    mockFetch = vi.fn()
  })

  it('direct grant — 200 returns tokens immediately', async () => {
    // Metadata fetch
    mockFetch.mockResolvedValueOnce(new Response(JSON.stringify(metadata), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    }))
    // Token endpoint → 200
    mockFetch.mockResolvedValueOnce(new Response(JSON.stringify({
      auth_token: 'eyJ.auth.token',
      expires_in: 3600,
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    }))

    const result = await exchangeToken({
      signedFetch: mockFetch,
      authServerUrl: 'https://auth.example',
      resourceToken: 'eyJ.resource.token',
      purpose: 'access files',
    })

    expect(result).toEqual({
      authToken: 'eyJ.auth.token',
      expiresIn: 3600,
    })

    // Verify metadata was fetched
    expect(mockFetch).toHaveBeenNthCalledWith(1,
      'https://auth.example/.well-known/aauth-issuer.json',
      { method: 'GET' },
    )

    // Verify token request
    expect(mockFetch).toHaveBeenNthCalledWith(2,
      'https://auth.example/aauth/token',
      expect.objectContaining({
        method: 'POST',
        headers: expect.objectContaining({
          'Content-Type': 'application/json',
          Prefer: 'wait=45',
        }),
      }),
    )

    // Verify body contains resource_token and purpose
    const body = JSON.parse(mockFetch.mock.calls[1][1].body)
    expect(body).toEqual({
      resource_token: 'eyJ.resource.token',
      purpose: 'access files',
    })
  })

  it('202 flow — polls until token is received', async () => {
    // Metadata fetch
    mockFetch.mockResolvedValueOnce(new Response(JSON.stringify(metadata), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    }))
    // Token endpoint → 202 with Location
    mockFetch.mockResolvedValueOnce(new Response(null, {
      status: 202,
      headers: {
        Location: '/aauth/pending/abc123',
        aauth: 'require=interaction; code="XYZW9999"',
      },
    }))

    // pollDeferred resolves with 200
    mockPollDeferred.mockResolvedValueOnce({
      response: new Response(JSON.stringify({
        auth_token: 'eyJ.polled.token',
        expires_in: 1800,
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    })

    const onInteraction = vi.fn()
    const result = await exchangeToken({
      signedFetch: mockFetch,
      authServerUrl: 'https://auth.example',
      resourceToken: 'eyJ.resource.token',
      onInteraction,
    })

    expect(result).toEqual({
      authToken: 'eyJ.polled.token',
      expiresIn: 1800,
    })

    // Verify pollDeferred was called with correct args
    expect(mockPollDeferred).toHaveBeenCalledOnce()
    const pollOpts = mockPollDeferred.mock.calls[0][0]
    expect(pollOpts.locationUrl).toBe('https://auth.example/aauth/pending/abc123')
    expect(pollOpts.interactionCode).toBe('XYZW9999')
  })

  it('includes all hints in token request body', async () => {
    mockFetch.mockResolvedValueOnce(new Response(JSON.stringify(metadata), {
      status: 200,
    }))
    mockFetch.mockResolvedValueOnce(new Response(JSON.stringify({
      auth_token: 'tok',
      expires_in: 3600,
    }), { status: 200 }))

    await exchangeToken({
      signedFetch: mockFetch,
      authServerUrl: 'https://auth.example',
      resourceToken: 'rt',
      purpose: 'read logs',
      loginHint: 'user@acme.com',
      tenant: 'acme.com',
      domainHint: 'acme.com',
      localhostCallback: 'http://localhost:8080/callback',
    })

    const body = JSON.parse(mockFetch.mock.calls[1][1].body)
    expect(body).toEqual({
      resource_token: 'rt',
      purpose: 'read logs',
      login_hint: 'user@acme.com',
      tenant: 'acme.com',
      domain_hint: 'acme.com',
      localhost_callback: 'http://localhost:8080/callback',
    })
  })

  it('throws on failed metadata fetch', async () => {
    mockFetch.mockResolvedValueOnce(new Response('not found', { status: 404 }))

    await expect(exchangeToken({
      signedFetch: mockFetch,
      authServerUrl: 'https://auth.example',
      resourceToken: 'rt',
    })).rejects.toThrow('Failed to fetch auth server metadata: 404')
  })

  it('throws on metadata missing token_endpoint', async () => {
    mockFetch.mockResolvedValueOnce(new Response(JSON.stringify({ jwks_uri: 'x' }), {
      status: 200,
    }))

    await expect(exchangeToken({
      signedFetch: mockFetch,
      authServerUrl: 'https://auth.example',
      resourceToken: 'rt',
    })).rejects.toThrow('Auth server metadata missing token_endpoint')
  })

  it('throws on unexpected token endpoint status', async () => {
    mockFetch.mockResolvedValueOnce(new Response(JSON.stringify(metadata), { status: 200 }))
    mockFetch.mockResolvedValueOnce(new Response('error', { status: 500 }))

    await expect(exchangeToken({
      signedFetch: mockFetch,
      authServerUrl: 'https://auth.example',
      resourceToken: 'rt',
    })).rejects.toThrow('Token exchange failed with status 500')
  })

  it('throws on 202 without Location header', async () => {
    mockFetch.mockResolvedValueOnce(new Response(JSON.stringify(metadata), { status: 200 }))
    mockFetch.mockResolvedValueOnce(new Response(null, { status: 202 }))

    await expect(exchangeToken({
      signedFetch: mockFetch,
      authServerUrl: 'https://auth.example',
      resourceToken: 'rt',
    })).rejects.toThrow('202 response missing Location header')
  })

  it('throws on poll terminal failure', async () => {
    mockFetch.mockResolvedValueOnce(new Response(JSON.stringify(metadata), { status: 200 }))
    mockFetch.mockResolvedValueOnce(new Response(null, {
      status: 202,
      headers: { Location: 'https://auth.example/pending/x' },
    }))
    mockPollDeferred.mockResolvedValueOnce({
      response: new Response('forbidden', { status: 403 }),
    })

    await expect(exchangeToken({
      signedFetch: mockFetch,
      authServerUrl: 'https://auth.example',
      resourceToken: 'rt',
    })).rejects.toThrow('Token exchange failed with status 403')
  })

  it('throws TokenExchangeError with error details on denial', async () => {
    mockFetch.mockResolvedValueOnce(new Response(JSON.stringify(metadata), { status: 200 }))
    mockFetch.mockResolvedValueOnce(new Response(null, {
      status: 202,
      headers: { Location: 'https://auth.example/pending/x' },
    }))
    mockPollDeferred.mockResolvedValueOnce({
      response: new Response(null, { status: 403 }),
      error: { error: 'denied', error_description: 'User denied the request' },
    })

    const promise = exchangeToken({
      signedFetch: mockFetch,
      authServerUrl: 'https://auth.example',
      resourceToken: 'rt',
    })
    await expect(promise).rejects.toBeInstanceOf(TokenExchangeError)
    try {
      await promise
    } catch (err) {
      const texErr = err as TokenExchangeError
      expect(texErr.status).toBe(403)
      expect(texErr.aauthError?.error).toBe('denied')
      expect(texErr.message).toBe('User denied the request')
    }
  })
})
