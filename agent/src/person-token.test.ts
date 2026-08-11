import { describe, it, expect, vi, beforeEach } from 'vitest'

const { mockPollDeferred } = vi.hoisted(() => ({
  mockPollDeferred: vi.fn(),
}))

vi.mock('./deferred.js', () => ({
  pollDeferred: mockPollDeferred,
}))

import {
  requestPersonToken,
  createPersonTokenCache,
  PersonTokenError,
} from './person-token.js'

const MISSION = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
const RESOURCE = 'https://resource.example'

const metadata = {
  auth_token_endpoint: 'https://ps.example/token',
  person_token_endpoint: 'https://ps.example/person',
  jwks_uri: 'https://ps.example/jwks',
}

function json(body: unknown, init?: ResponseInit): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
    ...init,
  })
}

describe('requestPersonToken', () => {
  let mockFetch: ReturnType<typeof vi.fn>

  beforeEach(() => {
    vi.clearAllMocks()
    mockFetch = vi.fn()
  })

  it('discovers the endpoint, POSTs resource + mission_s256, returns the token', async () => {
    mockFetch.mockResolvedValueOnce(json(metadata))
    mockFetch.mockResolvedValueOnce(json({ person_token: 'eyJ.person.token', expires_in: 3600 }))

    const result = await requestPersonToken({
      signedFetch: mockFetch,
      personServerUrl: 'https://ps.example',
      resource: RESOURCE,
      missionS256: MISSION,
    })

    expect(result).toEqual({ personToken: 'eyJ.person.token', expiresIn: 3600 })

    expect(mockFetch).toHaveBeenNthCalledWith(1,
      'https://ps.example/.well-known/aauth-person.json',
      { method: 'GET' },
    )
    expect(mockFetch).toHaveBeenNthCalledWith(2,
      'https://ps.example/person',
      expect.objectContaining({
        method: 'POST',
        headers: expect.objectContaining({
          'Content-Type': 'application/json',
          Prefer: 'wait=45',
        }),
      }),
    )
    expect(JSON.parse(mockFetch.mock.calls[1][1].body)).toEqual({
      resource: RESOURCE,
      mission_s256: MISSION,
    })
  })

  it('omits mission_s256 when the agent is not on a mission', async () => {
    mockFetch.mockResolvedValueOnce(json(metadata))
    mockFetch.mockResolvedValueOnce(json({ person_token: 'pt', expires_in: 3600 }))

    await requestPersonToken({
      signedFetch: mockFetch,
      personServerUrl: 'https://ps.example',
      resource: RESOURCE,
    })

    expect(JSON.parse(mockFetch.mock.calls[1][1].body)).toEqual({ resource: RESOURCE })
  })

  it('carries subagent_token when a parent requests for a sub-agent', async () => {
    mockFetch.mockResolvedValueOnce(json(metadata))
    mockFetch.mockResolvedValueOnce(json({ person_token: 'pt', expires_in: 3600 }))

    await requestPersonToken({
      signedFetch: mockFetch,
      personServerUrl: 'https://ps.example',
      resource: RESOURCE,
      missionS256: MISSION,
      subagentToken: 'eyJ.subagent.token',
    })

    expect(JSON.parse(mockFetch.mock.calls[1][1].body)).toEqual({
      resource: RESOURCE,
      mission_s256: MISSION,
      subagent_token: 'eyJ.subagent.token',
    })
  })

  it('never sends upstream_token — call chaining is deferred', async () => {
    mockFetch.mockResolvedValueOnce(json(metadata))
    mockFetch.mockResolvedValueOnce(json({ person_token: 'pt', expires_in: 3600 }))

    await requestPersonToken({
      signedFetch: mockFetch,
      personServerUrl: 'https://ps.example',
      resource: RESOURCE,
      missionS256: MISSION,
    })

    expect(JSON.parse(mockFetch.mock.calls[1][1].body)).not.toHaveProperty('upstream_token')
  })

  it('uses provided metadata and skips the /.well-known fetch', async () => {
    mockFetch.mockResolvedValueOnce(json({ person_token: 'pt', expires_in: 3600 }))

    await requestPersonToken({
      signedFetch: mockFetch,
      personServerUrl: 'https://ps.example',
      personServerMetadata: metadata,
      resource: RESOURCE,
      missionS256: MISSION,
    })

    expect(mockFetch).toHaveBeenCalledOnce()
    expect(mockFetch.mock.calls[0][0]).toBe('https://ps.example/person')
  })

  it('202 with requirement=interaction — polls the Location URL', async () => {
    mockFetch.mockResolvedValueOnce(json(metadata))
    mockFetch.mockResolvedValueOnce(new Response(null, {
      status: 202,
      headers: {
        Location: '/person/pending/abc123',
        'aauth-requirement': 'requirement=interaction; url="https://ps.example/interact"; code="A1B2-C3D4"',
      },
    }))
    mockPollDeferred.mockResolvedValueOnce({
      response: json({ person_token: 'eyJ.deferred.token', expires_in: 1800 }),
    })

    const onInteraction = vi.fn()
    const result = await requestPersonToken({
      signedFetch: mockFetch,
      personServerUrl: 'https://ps.example',
      resource: RESOURCE,
      missionS256: MISSION,
      onInteraction,
    })

    expect(result).toEqual({ personToken: 'eyJ.deferred.token', expiresIn: 1800 })
    expect(mockPollDeferred).toHaveBeenCalledOnce()
    const pollOpts = mockPollDeferred.mock.calls[0][0]
    expect(pollOpts.locationUrl).toBe('https://ps.example/person/pending/abc123')
    expect(pollOpts.interactionUrl).toBe('https://ps.example/interact')
    expect(pollOpts.interactionCode).toBe('A1B2-C3D4')
    expect(pollOpts.onInteraction).toBe(onInteraction)
  })

  it('throws on a 202 with no Location header', async () => {
    mockFetch.mockResolvedValueOnce(json(metadata))
    mockFetch.mockResolvedValueOnce(new Response(null, { status: 202 }))

    await expect(requestPersonToken({
      signedFetch: mockFetch,
      personServerUrl: 'https://ps.example',
      resource: RESOURCE,
    })).rejects.toThrow('202 response missing Location header')
  })

  it('throws PersonTokenError with the PS error detail on refusal', async () => {
    mockFetch.mockResolvedValueOnce(json(metadata))
    mockFetch.mockResolvedValueOnce(new Response(null, {
      status: 202,
      headers: { Location: 'https://ps.example/person/pending/x' },
    }))
    mockPollDeferred.mockResolvedValueOnce({
      response: new Response(null, { status: 403 }),
      error: { error: 'access_denied', error_description: 'Person declined' },
    })

    const promise = requestPersonToken({
      signedFetch: mockFetch,
      personServerUrl: 'https://ps.example',
      resource: RESOURCE,
      missionS256: MISSION,
    })
    await expect(promise).rejects.toBeInstanceOf(PersonTokenError)
    await expect(promise).rejects.toThrow('Person declined')
  })

  it('throws PersonTokenError on an unexpected status', async () => {
    mockFetch.mockResolvedValueOnce(json(metadata))
    mockFetch.mockResolvedValueOnce(new Response('nope', { status: 500 }))

    await expect(requestPersonToken({
      signedFetch: mockFetch,
      personServerUrl: 'https://ps.example',
      resource: RESOURCE,
    })).rejects.toThrow('Person token request failed with status 500')
  })

  it('rejects a PS with no person_token_endpoint as non-conformant', async () => {
    mockFetch.mockResolvedValueOnce(json({ auth_token_endpoint: 'https://ps.example/token' }))

    await expect(requestPersonToken({
      signedFetch: mockFetch,
      personServerUrl: 'https://ps.example',
      resource: RESOURCE,
    })).rejects.toThrow('missing person_token_endpoint')
  })

  it('throws when the 200 body has no person_token', async () => {
    mockFetch.mockResolvedValueOnce(json(metadata))
    mockFetch.mockResolvedValueOnce(json({ expires_in: 3600 }))

    await expect(requestPersonToken({
      signedFetch: mockFetch,
      personServerUrl: 'https://ps.example',
      resource: RESOURCE,
    })).rejects.toThrow('Person token response missing person_token')
  })
})

describe('createPersonTokenCache', () => {
  let mockFetch: ReturnType<typeof vi.fn>

  const cacheFor = () => createPersonTokenCache({
    signedFetch: mockFetch,
    personServerUrl: 'https://ps.example',
    personServerMetadata: metadata,
  })

  beforeEach(() => {
    vi.clearAllMocks()
    mockFetch = vi.fn()
  })

  it('mints once and serves the cached token afterwards', async () => {
    mockFetch.mockResolvedValueOnce(json({ person_token: 'pt-1', expires_in: 3600 }))

    const cache = cacheFor()
    expect(await cache.get(RESOURCE, MISSION)).toBe('pt-1')
    expect(await cache.get(RESOURCE, MISSION)).toBe('pt-1')
    expect(mockFetch).toHaveBeenCalledOnce()
  })

  it('keys on (resource, mission_s256) — one token per combination', async () => {
    mockFetch.mockResolvedValueOnce(json({ person_token: 'pt-a-m1', expires_in: 3600 }))
    mockFetch.mockResolvedValueOnce(json({ person_token: 'pt-a-m2', expires_in: 3600 }))
    mockFetch.mockResolvedValueOnce(json({ person_token: 'pt-b-m1', expires_in: 3600 }))

    const cache = cacheFor()
    expect(await cache.get(RESOURCE, MISSION)).toBe('pt-a-m1')
    expect(await cache.get(RESOURCE, 'other-mission')).toBe('pt-a-m2')
    expect(await cache.get('https://other.example', MISSION)).toBe('pt-b-m1')
    expect(cache.size).toBe(3)

    // Each combination is still served from cache.
    expect(await cache.get(RESOURCE, MISSION)).toBe('pt-a-m1')
    expect(mockFetch).toHaveBeenCalledTimes(3)
  })

  it('a missionless token is a different entry from a mission-scoped one', async () => {
    mockFetch.mockResolvedValueOnce(json({ person_token: 'pt-no-mission', expires_in: 3600 }))
    mockFetch.mockResolvedValueOnce(json({ person_token: 'pt-mission', expires_in: 3600 }))

    const cache = cacheFor()
    expect(await cache.get(RESOURCE)).toBe('pt-no-mission')
    expect(await cache.get(RESOURCE, MISSION)).toBe('pt-mission')
    expect(cache.size).toBe(2)
  })

  it('shares one in-flight request between concurrent gets for the same key', async () => {
    mockFetch.mockResolvedValueOnce(json({ person_token: 'pt-1', expires_in: 3600 }))

    const cache = cacheFor()
    const [a, b] = await Promise.all([
      cache.get(RESOURCE, MISSION),
      cache.get(RESOURCE, MISSION),
    ])

    expect(a).toBe('pt-1')
    expect(b).toBe('pt-1')
    expect(mockFetch).toHaveBeenCalledOnce()
  })

  it('clear() drops every entry — one key rotation invalidates them all', async () => {
    mockFetch.mockResolvedValueOnce(json({ person_token: 'pt-a', expires_in: 3600 }))
    mockFetch.mockResolvedValueOnce(json({ person_token: 'pt-b', expires_in: 3600 }))

    const cache = cacheFor()
    await cache.get(RESOURCE, MISSION)
    await cache.get('https://other.example', MISSION)
    expect(cache.size).toBe(2)

    // Every cached token binds the old key through cnf.
    cache.clear()
    expect(cache.size).toBe(0)
    expect(cache.peek(RESOURCE, MISSION)).toBeUndefined()

    // ...and they are re-requested lazily, on next use of each resource.
    mockFetch.mockResolvedValueOnce(json({ person_token: 'pt-a-rotated', expires_in: 3600 }))
    expect(await cache.get(RESOURCE, MISSION)).toBe('pt-a-rotated')
    expect(cache.size).toBe(1)
  })

  it('treats a token inside the expiry buffer as gone', async () => {
    mockFetch.mockResolvedValueOnce(json({ person_token: 'pt-fresh', expires_in: 3600 }))

    const cache = cacheFor()
    // 30s of life left — inside the 60s buffer.
    cache.set(RESOURCE, MISSION, 'pt-nearly-dead', 30)
    expect(cache.peek(RESOURCE, MISSION)).toBeUndefined()
    expect(await cache.get(RESOURCE, MISSION)).toBe('pt-fresh')
  })

  it('set() seeds a token obtained elsewhere (e.g. a mission approval)', async () => {
    const cache = cacheFor()
    cache.set(RESOURCE, MISSION, 'pt-from-mission-approval', 3600)

    expect(cache.peek(RESOURCE, MISSION)).toBe('pt-from-mission-approval')
    expect(await cache.get(RESOURCE, MISSION)).toBe('pt-from-mission-approval')
    expect(mockFetch).not.toHaveBeenCalled()
  })

  it('delete() drops a single entry', async () => {
    mockFetch.mockResolvedValueOnce(json({ person_token: 'pt-1', expires_in: 3600 }))
    mockFetch.mockResolvedValueOnce(json({ person_token: 'pt-2', expires_in: 3600 }))

    const cache = cacheFor()
    await cache.get(RESOURCE, MISSION)
    cache.delete(RESOURCE, MISSION)
    expect(await cache.get(RESOURCE, MISSION)).toBe('pt-2')
    expect(mockFetch).toHaveBeenCalledTimes(2)
  })

  it('does not cache a failed request', async () => {
    mockFetch.mockResolvedValueOnce(new Response('boom', { status: 500 }))
    mockFetch.mockResolvedValueOnce(json({ person_token: 'pt-ok', expires_in: 3600 }))

    const cache = cacheFor()
    await expect(cache.get(RESOURCE, MISSION)).rejects.toBeInstanceOf(PersonTokenError)
    expect(cache.size).toBe(0)
    expect(await cache.get(RESOURCE, MISSION)).toBe('pt-ok')
  })
})
