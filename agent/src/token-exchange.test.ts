import { describe, it, expect, vi, beforeEach } from 'vitest'

const { mockPollDeferred } = vi.hoisted(() => ({
  mockPollDeferred: vi.fn(),
}))

vi.mock('./deferred.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('./deferred.js')>()),
  pollDeferred: mockPollDeferred,
}))

import { exchangeToken, TokenExchangeError } from './token-exchange.js'

describe('exchangeToken', () => {
  let mockFetch: ReturnType<typeof vi.fn>

  const metadata = {
    auth_token_endpoint: 'https://auth.example/aauth/token/auth',
    person_token_endpoint: 'https://auth.example/aauth/token/person',
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
      presentedToken: 'eyJ.presented',
      justification: 'access files',
    })

    expect(result).toEqual({
      authToken: 'eyJ.auth.token',
      expiresIn: 3600,
    })

    // Verify metadata was fetched
    expect(mockFetch).toHaveBeenNthCalledWith(1,
      'https://auth.example/.well-known/aauth-person.json',
      { method: 'GET' },
    )

    // Verify token request
    expect(mockFetch).toHaveBeenNthCalledWith(2,
      'https://auth.example/aauth/token/auth',
      expect.objectContaining({
        method: 'POST',
        headers: expect.objectContaining({
          'Content-Type': 'application/json',
          Prefer: 'wait=45',
        }),
      }),
    )

    // Verify body contains resource_token and justification
    const body = JSON.parse(mockFetch.mock.calls[1][1].body)
    expect(body).toEqual({
      resource_token: 'eyJ.resource.token',
      presented_token: 'eyJ.presented',
      justification: 'access files',
    })
  })

  it('uses provided authServerMetadata and skips the /.well-known fetch', async () => {
    // Only the token endpoint responds — no metadata GET should happen.
    mockFetch.mockResolvedValueOnce(new Response(JSON.stringify({
      auth_token: 'eyJ.auth.token',
      expires_in: 3600,
    }), { status: 200, headers: { 'Content-Type': 'application/json' } }))

    const result = await exchangeToken({
      signedFetch: mockFetch,
      authServerUrl: 'https://auth.example',
      authServerMetadata: metadata,
      resourceToken: 'eyJ.resource.token',
      presentedToken: 'eyJ.presented',
    })

    expect(result).toEqual({ authToken: 'eyJ.auth.token', expiresIn: 3600 })
    // The very first (and only) call is the token POST — no metadata GET.
    expect(mockFetch).toHaveBeenCalledTimes(1)
    expect(mockFetch).toHaveBeenNthCalledWith(1,
      'https://auth.example/aauth/token/auth',
      expect.objectContaining({ method: 'POST' }),
    )
  })

  it('cached metadata emits a ps_metadata_cached info event and does not call onMetadata', async () => {
    mockFetch.mockResolvedValueOnce(new Response(JSON.stringify({
      auth_token: 'eyJ.auth.token', expires_in: 3600,
    }), { status: 200, headers: { 'Content-Type': 'application/json' } }))
    const onEvent = vi.fn()
    const onMetadata = vi.fn()

    await exchangeToken({
      signedFetch: mockFetch,
      authServerUrl: 'https://auth.example',
      authServerMetadata: metadata,
      resourceToken: 'rt',
      presentedToken: 'eyJ.presented',
      onEvent,
      onMetadata,
    })

    expect(onEvent).toHaveBeenCalledWith(expect.objectContaining({ step: 'ps_metadata_cached', phase: 'info' }))
    expect(onMetadata).not.toHaveBeenCalled()
  })

  it('fresh fetch hands the metadata to onMetadata so the caller can persist it', async () => {
    mockFetch.mockResolvedValueOnce(new Response(JSON.stringify(metadata), {
      status: 200, headers: { 'Content-Type': 'application/json' },
    }))
    mockFetch.mockResolvedValueOnce(new Response(JSON.stringify({
      auth_token: 'eyJ.auth.token', expires_in: 3600,
    }), { status: 200, headers: { 'Content-Type': 'application/json' } }))
    const onMetadata = vi.fn()

    await exchangeToken({
      signedFetch: mockFetch,
      authServerUrl: 'https://auth.example',
      resourceToken: 'rt',
      presentedToken: 'eyJ.presented',
      onMetadata,
    })

    expect(onMetadata).toHaveBeenCalledWith(expect.objectContaining({
      auth_token_endpoint: 'https://auth.example/aauth/token/auth',
      person_token_endpoint: 'https://auth.example/aauth/token/person',
    }))
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
        'aauth-requirement': 'requirement=interaction; url="https://auth.example/interact"; code="XYZW9999"',
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
      presentedToken: 'eyJ.presented',
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
    expect(pollOpts.interactionUrl).toBe('https://auth.example/interact')
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
      presentedToken: 'eyJ.presented',
      justification: 'read logs',
      loginHint: 'user@acme.com',
      tenant: 'acme.com',
      domainHint: 'acme.com',
      localhostCallback: 'http://localhost:8080/callback',
    })

    const body = JSON.parse(mockFetch.mock.calls[1][1].body)
    expect(body).toEqual({
      resource_token: 'rt',
      presented_token: 'eyJ.presented',
      justification: 'read logs',
      login_hint: 'user@acme.com',
      tenant: 'acme.com',
      domain_hint: 'acme.com',
      localhost_callback: 'http://localhost:8080/callback',
    })
  })

  it('does not send mission_s256 — the mission travels inside the resource token', async () => {
    mockFetch.mockResolvedValueOnce(new Response(JSON.stringify(metadata), { status: 200 }))
    mockFetch.mockResolvedValueOnce(new Response(JSON.stringify({
      auth_token: 'tok', expires_in: 3600,
    }), { status: 200 }))

    await exchangeToken({
      signedFetch: mockFetch,
      authServerUrl: 'https://auth.example',
      // A resource token minted under a mission carries mission_s256, copied
      // from the person token the agent presented. The auth token request
      // itself has no mission parameter (#agent-token-request).
      resourceToken: 'eyJ.resource.token.with.mission_s256',
      presentedToken: 'eyJ.presented',
      justification: 'book the flights',
    })

    const body = JSON.parse(mockFetch.mock.calls[1][1].body)
    expect(body).not.toHaveProperty('mission_s256')
    expect(body).toEqual({
      resource_token: 'eyJ.resource.token.with.mission_s256',
      presented_token: 'eyJ.presented',
      justification: 'book the flights',
    })
  })

  it('throws on failed metadata fetch', async () => {
    mockFetch.mockResolvedValueOnce(new Response('not found', { status: 404 }))

    await expect(exchangeToken({
      signedFetch: mockFetch,
      authServerUrl: 'https://auth.example',
      resourceToken: 'rt',
      presentedToken: 'eyJ.presented',
    })).rejects.toThrow('Failed to fetch auth server metadata: 404')
  })

  it('throws on metadata missing auth_token_endpoint', async () => {
    mockFetch.mockResolvedValueOnce(new Response(JSON.stringify({ jwks_uri: 'x' }), {
      status: 200,
    }))

    await expect(exchangeToken({
      signedFetch: mockFetch,
      authServerUrl: 'https://auth.example',
      resourceToken: 'rt',
      presentedToken: 'eyJ.presented',
    })).rejects.toThrow('Auth server metadata missing auth_token_endpoint')
  })

  it('rejects a PS with no person_token_endpoint as non-conformant', async () => {
    // -11 makes person_token_endpoint REQUIRED: without it the PS cannot mint
    // the person token a resource demands before issuing a resource token, so
    // nothing downstream of this document can succeed.
    mockFetch.mockResolvedValueOnce(new Response(JSON.stringify({
      auth_token_endpoint: 'https://auth.example/aauth/token/auth',
    }), { status: 200 }))

    await expect(exchangeToken({
      signedFetch: mockFetch,
      authServerUrl: 'https://auth.example',
      resourceToken: 'rt',
      presentedToken: 'eyJ.presented',
    })).rejects.toThrow('missing person_token_endpoint')
  })

  it('throws on unexpected token endpoint status', async () => {
    mockFetch.mockResolvedValueOnce(new Response(JSON.stringify(metadata), { status: 200 }))
    mockFetch.mockResolvedValueOnce(new Response('error', { status: 500 }))

    await expect(exchangeToken({
      signedFetch: mockFetch,
      authServerUrl: 'https://auth.example',
      resourceToken: 'rt',
      presentedToken: 'eyJ.presented',
    })).rejects.toThrow('Token exchange failed with status 500')
  })

  it('throws on 202 without Location header', async () => {
    mockFetch.mockResolvedValueOnce(new Response(JSON.stringify(metadata), { status: 200 }))
    mockFetch.mockResolvedValueOnce(new Response(null, { status: 202 }))

    await expect(exchangeToken({
      signedFetch: mockFetch,
      authServerUrl: 'https://auth.example',
      resourceToken: 'rt',
      presentedToken: 'eyJ.presented',
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
      presentedToken: 'eyJ.presented',
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
      presentedToken: 'eyJ.presented',
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
  describe('presented_token (AAuth -11, issue #152)', () => {
    const b64 = (o: Record<string, unknown>) => Buffer.from(JSON.stringify(o)).toString('base64url')
    const jwt = (payload: Record<string, unknown>) => `${b64({ alg: 'Ed25519' })}.${b64(payload)}.sig`

    it('is REQUIRED', async () => {
      await expect(exchangeToken({
        signedFetch: mockFetch,
        authServerUrl: 'https://auth.example',
        resourceToken: 'rt',
      } as never)).rejects.toThrow(/presentedToken/)
      expect(mockFetch).not.toHaveBeenCalled()
    })

    it('refuses a resource token whose presented_jti does not name the presented token', async () => {
      // §Resource Token Verification (agent side) step 5 — the resource named
      // some other token; the PS would say invalid_resource_token, and the
      // agent can say so without the round trip.
      const resourceToken = jwt({ iss: 'https://rs.example', presented_jti: 'pt-other' })
      const presentedToken = jwt({ iss: 'https://ps.example', jti: 'pt-mine' })
      await expect(exchangeToken({
        signedFetch: mockFetch,
        authServerUrl: 'https://auth.example',
        resourceToken,
        presentedToken,
      })).rejects.toThrow(/presented_jti "pt-other" does not name the token the agent presented/)
      expect(mockFetch).not.toHaveBeenCalled()
    })

    it('sends a resource token that names the presented token', async () => {
      mockFetch.mockResolvedValueOnce(new Response(JSON.stringify(metadata), { status: 200 }))
      mockFetch.mockResolvedValueOnce(new Response(JSON.stringify({ auth_token: 'tok', expires_in: 3600 }), { status: 200 }))
      const resourceToken = jwt({ iss: 'https://rs.example', presented_jti: 'pt-mine' })
      const presentedToken = jwt({ iss: 'https://ps.example', jti: 'pt-mine' })
      await exchangeToken({
        signedFetch: mockFetch,
        authServerUrl: 'https://auth.example',
        resourceToken,
        presentedToken,
      })
      const body = JSON.parse(mockFetch.mock.calls[1][1].body)
      expect(body.presented_token).toBe(presentedToken)
    })

    it('clock_skew: reports how long to wait, from the server Date header', async () => {
      // §Expiry and the Refresh Margin: the presented token's iat is ahead of
      // the server's clock by more than its window. Refreshing does not help
      // — a fresh token carries the same skew — so the error says how long
      // to wait before presenting the same token again.
      const serverNow = 1_700_000_000
      const presentedToken = jwt({ iss: 'https://ps.example', jti: 'pt-1', iat: serverNow + 150 })
      mockFetch.mockResolvedValueOnce(new Response(JSON.stringify(metadata), { status: 200 }))
      mockFetch.mockResolvedValueOnce(new Response(
        JSON.stringify({ error: 'clock_skew', detail: 'presented_token iat is 150s ahead' }),
        {
          status: 400,
          headers: {
            'Content-Type': 'application/problem+json',
            Date: new Date(serverNow * 1000).toUTCString(),
          },
        },
      ))
      const failure = await exchangeToken({
        signedFetch: mockFetch,
        authServerUrl: 'https://auth.example',
        resourceToken: 'rt',
        presentedToken,
      }).catch((e: unknown) => e)
      expect(failure).toBeInstanceOf(TokenExchangeError)
      expect((failure as TokenExchangeError).error).toBe('clock_skew')
      // 150 s ahead, 60 s window → wait 90 s.
      expect((failure as TokenExchangeError).retryAfterSeconds).toBe(90)
    })
  })

})
