import { describe, it, expect, vi, beforeEach } from 'vitest'

const { mockHttpSigFetch } = vi.hoisted(() => ({
  mockHttpSigFetch: vi.fn(),
}))

vi.mock('@hellocoop/httpsig', () => ({
  fetch: mockHttpSigFetch,
  DEFAULT_COMPONENTS_GET: ['@method', '@authority', '@path', 'signature-key'],
  DEFAULT_COMPONENTS_BODY: ['@method', '@authority', '@path', 'content-type', 'signature-key'],
}))

const { mockExchangeToken } = vi.hoisted(() => ({
  mockExchangeToken: vi.fn(),
}))

vi.mock('./token-exchange.js', () => ({
  exchangeToken: mockExchangeToken,
}))

// The person-token client is stubbed here; its own suite covers minting,
// deferred interaction, and (resource, mission_s256) cache keying.
const { mockPersonTokenGet, mockCreatePersonTokenCache } = vi.hoisted(() => {
  const mockPersonTokenGet = vi.fn()
  return {
    mockPersonTokenGet,
    mockCreatePersonTokenCache: vi.fn((_options: Record<string, unknown>) => ({
      get: mockPersonTokenGet,
      peek: vi.fn(),
      set: vi.fn(),
      delete: vi.fn(),
      clear: vi.fn(),
      size: 0,
    })),
  }
})

vi.mock('./person-token.js', () => ({
  createPersonTokenCache: mockCreatePersonTokenCache,
}))

const { mockPollDeferred } = vi.hoisted(() => ({
  mockPollDeferred: vi.fn(),
}))

vi.mock('./deferred.js', () => ({
  pollDeferred: mockPollDeferred,
}))

import { createAAuthFetch } from './aauth-fetch.js'
import type { KeyMaterial } from './types.js'

const MISSION = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'

/** The options object of the most recent httpsig fetch call. */
const lastCall = (): Record<string, any> =>
  mockHttpSigFetch.mock.calls[mockHttpSigFetch.mock.calls.length - 1][1]

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
    // -11: the resource challenges for a person token first, and only a
    // request carrying one draws the auth-token challenge — the resource token
    // names what the agent presented.
    mockHttpSigFetch.mockResolvedValueOnce(new Response('', {
      status: 401,
      headers: { 'aauth-requirement': 'requirement=person-token' },
    }))
    mockPersonTokenGet.mockResolvedValueOnce('eyJ.person.token')
    // Person-token request → 401 with AAuth-Requirement challenge
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

    const onAuthToken = vi.fn()
    const fetch = createAAuthFetch({
      getKeyMaterial,
      personServerUrl: 'https://auth.example',
      justification: 'read files',
      missionS256: MISSION,
      onAuthToken,
    })
    const result = await fetch('https://resource.example/api', { method: 'GET' })

    expect(result).toBe(okResponse)

    // Verify exchangeToken was called
    expect(mockExchangeToken).toHaveBeenCalledOnce()
    expect(mockExchangeToken).toHaveBeenCalledWith(expect.objectContaining({
      authServerUrl: 'https://auth.example',
      resourceToken: 'rt123',
      // the token the agent presented to the resource, named by presented_jti
      presentedToken: 'eyJ.person.token',
      justification: 'read files',
    }))

    // Verify retry used the auth token in signatureKey
    expect(mockHttpSigFetch).toHaveBeenCalledTimes(3)
    const retryCall = mockHttpSigFetch.mock.calls[2]
    expect(retryCall[1].signatureKey).toEqual({ type: 'jwt', jwt: 'eyJ.auth.token' })

    // The minted auth token is surfaced for reuse (fetch --with-token / export).
    expect(onAuthToken).toHaveBeenCalledWith('eyJ.auth.token', 3600)
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
    // -11: the resource challenges for a person token first, and only a
    // request carrying one draws the auth-token challenge — the resource token
    // names what the agent presented.
    mockHttpSigFetch.mockResolvedValueOnce(new Response('', {
      status: 401,
      headers: { 'aauth-requirement': 'requirement=person-token' },
    }))
    mockPersonTokenGet.mockResolvedValueOnce('eyJ.person.token')
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
      personServerUrl: 'https://auth.example',
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
    expect(mockHttpSigFetch).toHaveBeenCalledTimes(4)
    const cachedCall = mockHttpSigFetch.mock.calls[3]
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

    // Verify the second call sent the token under the AAuth scheme...
    const secondCall = mockHttpSigFetch.mock.calls[1]
    const headers = new Headers(secondCall[1].headers)
    expect(headers.get('authorization')).toBe('AAuth opaque-token-123')
    // ...and bound it to the signature (authorization in covered components).
    expect(secondCall[1].components).toContain('authorization')
  })

  it('fires onOpaqueToken when a resource returns an AAuth-Access token', async () => {
    mockHttpSigFetch.mockResolvedValueOnce(new Response('ok', {
      status: 200,
      headers: { 'aauth-access': 'fresh-opaque-token' },
    }))

    const onOpaqueToken = vi.fn()
    const fetch = createAAuthFetch({ getKeyMaterial, onOpaqueToken })
    await fetch('https://resource.example/api')

    expect(onOpaqueToken).toHaveBeenCalledWith('fresh-opaque-token')
  })

  it('sends a seeded opaqueToken on the first request (two-party reuse)', async () => {
    mockHttpSigFetch.mockResolvedValueOnce(new Response('ok', { status: 200 }))

    const fetch = createAAuthFetch({ getKeyMaterial, opaqueToken: 'seeded-token' })
    await fetch('https://resource.example/api')

    // The very first call carries the seeded token, bound to the signature.
    expect(mockHttpSigFetch).toHaveBeenCalledOnce()
    const firstCall = mockHttpSigFetch.mock.calls[0]
    const headers = new Headers(firstCall[1].headers)
    expect(headers.get('authorization')).toBe('AAuth seeded-token')
    expect(firstCall[1].components).toContain('authorization')
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
    expect(headers.get('authorization')).toBe('AAuth token-v2')
  })

  it('passes enterprise hints to token exchange', async () => {
    // -11: the resource challenges for a person token first, and only a
    // request carrying one draws the auth-token challenge — the resource token
    // names what the agent presented.
    mockHttpSigFetch.mockResolvedValueOnce(new Response('', {
      status: 401,
      headers: { 'aauth-requirement': 'requirement=person-token' },
    }))
    mockPersonTokenGet.mockResolvedValueOnce('eyJ.person.token')
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
      personServerUrl: 'https://auth.example',
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

  describe('person tokens', () => {
    it('401 requirement=person-token → mints one for the resource and retries with it', async () => {
      mockHttpSigFetch.mockResolvedValueOnce(new Response('', {
        status: 401,
        headers: { 'aauth-requirement': 'requirement=person-token' },
      }))
      mockPersonTokenGet.mockResolvedValueOnce('eyJ.person.token')
      const okResponse = new Response('{"data":"ok"}', { status: 200 })
      mockHttpSigFetch.mockResolvedValueOnce(okResponse)

      const onPersonToken = vi.fn()
      const fetch = createAAuthFetch({
        getKeyMaterial,
        personServerUrl: 'https://ps.example',
        missionS256: MISSION,
        onPersonToken,
      })
      const result = await fetch('https://resource.example/api')

      expect(result).toBe(okResponse)

      // One cache per fetch instance, pointed at the agent's person server...
      expect(mockCreatePersonTokenCache).toHaveBeenCalledOnce()
      expect(mockCreatePersonTokenCache).toHaveBeenCalledWith(expect.objectContaining({
        personServerUrl: 'https://ps.example',
      }))
      // ...and the token is asked for by resource identifier, under the mission.
      expect(mockPersonTokenGet).toHaveBeenCalledWith('https://resource.example', MISSION)

      // The retry presents it via Signature-Key in place of the agent token.
      expect(mockHttpSigFetch).toHaveBeenCalledTimes(2)
      expect(mockHttpSigFetch.mock.calls[1][1].signatureKey)
        .toEqual({ type: 'jwt', jwt: 'eyJ.person.token' })
      expect(onPersonToken).toHaveBeenCalledWith('eyJ.person.token', 'https://resource.example')
    })

    it('asks for a missionless person token when no mission is configured', async () => {
      mockHttpSigFetch.mockResolvedValueOnce(new Response('', {
        status: 401,
        headers: { 'aauth-requirement': 'requirement=person-token' },
      }))
      mockPersonTokenGet.mockResolvedValueOnce('pt')
      mockHttpSigFetch.mockResolvedValueOnce(new Response('ok', { status: 200 }))

      const fetch = createAAuthFetch({ getKeyMaterial, personServerUrl: 'https://ps.example' })
      await fetch('https://resource.example/api')

      expect(mockPersonTokenGet).toHaveBeenCalledWith('https://resource.example', undefined)
    })

    it('after a person token the auth-token challenge still runs', async () => {
      // person-token challenge → person token → resource now issues a resource
      // token, which the agent takes to its PS.
      mockHttpSigFetch.mockResolvedValueOnce(new Response('', {
        status: 401,
        headers: { 'aauth-requirement': 'requirement=person-token' },
      }))
      mockPersonTokenGet.mockResolvedValueOnce('pt')
      mockHttpSigFetch.mockResolvedValueOnce(new Response('', {
        status: 401,
        headers: { 'aauth-requirement': 'requirement=auth-token; resource-token="rt-with-mission"' },
      }))
      mockExchangeToken.mockResolvedValueOnce({ authToken: 'at', expiresIn: 3600 })
      const okResponse = new Response('ok', { status: 200 })
      mockHttpSigFetch.mockResolvedValueOnce(okResponse)

      const fetch = createAAuthFetch({
        getKeyMaterial,
        personServerUrl: 'https://ps.example',
        missionS256: MISSION,
      })
      const result = await fetch('https://resource.example/api')

      expect(result).toBe(okResponse)
      expect(mockExchangeToken).toHaveBeenCalledWith(expect.objectContaining({
        resourceToken: 'rt-with-mission',
        presentedToken: 'pt',
      }))
      expect(mockHttpSigFetch.mock.calls[2][1].signatureKey)
        .toEqual({ type: 'jwt', jwt: 'at' })
    })

    it('returns the 401 as-is when the agent has no person server', async () => {
      const challenge = new Response('', {
        status: 401,
        headers: { 'aauth-requirement': 'requirement=person-token' },
      })
      mockHttpSigFetch.mockResolvedValueOnce(challenge)

      // No personServerUrl → no person server → the requirement is unsatisfiable.
      const fetch = createAAuthFetch({ getKeyMaterial })
      const result = await fetch('https://resource.example/api')

      expect(result).toBe(challenge)
      expect(mockCreatePersonTokenCache).not.toHaveBeenCalled()
    })
  })

  describe('presented tokens (AAuth -11, issue #152)', () => {
    it('refuses an auth-token challenge on a request that presented nothing', async () => {
      // A resource MUST NOT issue this challenge to a request carrying neither
      // a person token nor an auth token: it has nothing to name.
      mockHttpSigFetch.mockResolvedValueOnce(new Response('', {
        status: 401,
        headers: { 'aauth-requirement': 'requirement=auth-token; resource-token="rt"' },
      }))
      const fetch = createAAuthFetch({ getKeyMaterial, personServerUrl: 'https://ps.example' })
      await expect(fetch('https://resource.example/api')).rejects.toThrow(/presented no person token or auth token/)
      expect(mockExchangeToken).not.toHaveBeenCalled()
    })

    it('step-up: a cached auth token drawing requirement=auth-token is what the agent presents', async () => {
      // First call: person token → resource token → auth token, cached.
      mockHttpSigFetch.mockResolvedValueOnce(new Response('', {
        status: 401,
        headers: { 'aauth-requirement': 'requirement=person-token' },
      }))
      mockPersonTokenGet.mockResolvedValueOnce('pt')
      mockHttpSigFetch.mockResolvedValueOnce(new Response('', {
        status: 401,
        headers: { 'aauth-requirement': 'requirement=auth-token; resource-token="rt-1"' },
      }))
      mockExchangeToken.mockResolvedValueOnce({ authToken: 'at-1', expiresIn: 3600 })
      mockHttpSigFetch.mockResolvedValueOnce(new Response('ok', { status: 200 }))
      const fetch = createAAuthFetch({ getKeyMaterial, personServerUrl: 'https://ps.example' })
      await fetch('https://resource.example/read')

      // Second call presents the cached auth token; the resource wants more
      // (a step-up) and names that auth token in a new resource token.
      mockHttpSigFetch.mockResolvedValueOnce(new Response('', {
        status: 401,
        headers: { 'aauth-requirement': 'requirement=auth-token; resource-token="rt-2"' },
      }))
      mockExchangeToken.mockResolvedValueOnce({ authToken: 'at-2', expiresIn: 1800 })
      const okResponse = new Response('written', { status: 200 })
      mockHttpSigFetch.mockResolvedValueOnce(okResponse)
      const result = await fetch('https://resource.example/write', { method: 'POST' })

      expect(result).toBe(okResponse)
      expect(mockExchangeToken).toHaveBeenLastCalledWith(expect.objectContaining({
        resourceToken: 'rt-2',
        presentedToken: 'at-1',
      }))
      // No new person token was requested for the step-up.
      expect(mockPersonTokenGet).toHaveBeenCalledTimes(1)
      // The retry carried the stepped-up token.
      expect(lastCall().signatureKey).toEqual({ type: 'jwt', jwt: 'at-2' })
    })

    it('clock_skew on a cached auth token: returns the 401 and keeps the token (wait, do not refresh)', async () => {
      mockHttpSigFetch.mockResolvedValueOnce(new Response('', {
        status: 401,
        headers: { 'aauth-requirement': 'requirement=person-token' },
      }))
      mockPersonTokenGet.mockResolvedValueOnce('pt')
      mockHttpSigFetch.mockResolvedValueOnce(new Response('', {
        status: 401,
        headers: { 'aauth-requirement': 'requirement=auth-token; resource-token="rt-1"' },
      }))
      mockExchangeToken.mockResolvedValueOnce({ authToken: 'at-1', expiresIn: 3600 })
      mockHttpSigFetch.mockResolvedValueOnce(new Response('ok', { status: 200 }))
      const fetch = createAAuthFetch({ getKeyMaterial, personServerUrl: 'https://ps.example' })
      await fetch('https://resource.example/read')

      const skewed = new Response('', {
        status: 401,
        headers: { 'signature-error': 'error=clock_skew' },
      })
      mockHttpSigFetch.mockResolvedValueOnce(skewed)
      const result = await fetch('https://resource.example/read')
      expect(result).toBe(skewed)
      expect(mockExchangeToken).toHaveBeenCalledTimes(1)
      expect(mockPersonTokenGet).toHaveBeenCalledTimes(1)

      // The cached token is still presented next time.
      mockHttpSigFetch.mockResolvedValueOnce(new Response('ok', { status: 200 }))
      await fetch('https://resource.example/read')
      expect(lastCall().signatureKey).toEqual({ type: 'jwt', jwt: 'at-1' })
    })
  })

  describe('PS/AS body signing', () => {
    it('hands token exchange a PS-flavoured signedFetch, and the resource one an unflavoured one', async () => {
      // -11: the resource challenges for a person token first, and only a
      // request carrying one draws the auth-token challenge — the resource token
      // names what the agent presented.
      mockHttpSigFetch.mockResolvedValueOnce(new Response('', {
        status: 401,
        headers: { 'aauth-requirement': 'requirement=person-token' },
      }))
      mockPersonTokenGet.mockResolvedValueOnce('eyJ.person.token')
      mockHttpSigFetch.mockResolvedValueOnce(new Response('', {
        status: 401,
        headers: { 'aauth-requirement': 'requirement=auth-token; resource-token="rt"' },
      }))
      mockExchangeToken.mockResolvedValueOnce({ authToken: 'at', expiresIn: 3600 })
      mockHttpSigFetch.mockResolvedValueOnce(new Response('ok', { status: 200 }))

      const fetch = createAAuthFetch({
        getKeyMaterial,
        personServerUrl: 'https://ps.example',
        missionS256: MISSION,
      })
      await fetch('https://resource.example/api', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: '{"q":1}',
      })

      // The resource-facing POST carries no component list — a resource states
      // its own needs via additional_signature_components.
      expect(mockHttpSigFetch.mock.calls[0][1].components).toBeUndefined()

      // Prove the fetch passed to exchangeToken signs bodies: run a POST
      // through it and check the covered components.
      const psSignedFetch = mockExchangeToken.mock.calls[0][0].signedFetch
      mockHttpSigFetch.mockResolvedValueOnce(new Response('{}', { status: 200 }))
      await psSignedFetch('https://ps.example/aauth/token/auth', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: '{"resource_token":"rt"}',
      })
      const psComponents: string[] = lastCall().components
      expect(psComponents).toContain('content-digest')
      expect(psComponents).toContain('content-type')
    })

    it('gives the person token client the same PS-flavoured fetch', async () => {
      mockHttpSigFetch.mockResolvedValueOnce(new Response('', {
        status: 401,
        headers: { 'aauth-requirement': 'requirement=person-token' },
      }))
      mockPersonTokenGet.mockResolvedValueOnce('pt')
      mockHttpSigFetch.mockResolvedValueOnce(new Response('ok', { status: 200 }))

      const fetch = createAAuthFetch({
        getKeyMaterial,
        personServerUrl: 'https://ps.example',
        missionS256: MISSION,
      })
      await fetch('https://resource.example/api')

      const psSignedFetch = mockCreatePersonTokenCache.mock.calls[0][0].signedFetch as
        (url: string, init: RequestInit) => Promise<Response>
      mockHttpSigFetch.mockResolvedValueOnce(new Response('{}', { status: 200 }))
      await psSignedFetch('https://ps.example/aauth/token/person', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ resource: 'https://resource.example', mission_s256: MISSION }),
      })
      const psComponents: string[] = lastCall().components
      expect(psComponents).toContain('content-digest')
      expect(psComponents).toContain('content-type')
    })
  })
})
