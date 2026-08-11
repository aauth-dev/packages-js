import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { pollDeferred } from './deferred.js'

describe('pollDeferred', () => {
  let mockFetch: ReturnType<typeof vi.fn>

  beforeEach(() => {
    vi.clearAllMocks()
    vi.useFakeTimers({ shouldAdvanceTime: true })
    mockFetch = vi.fn()
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  it('returns immediately on 200', async () => {
    const response = new Response('{"result":"ok"}', { status: 200 })
    mockFetch.mockResolvedValueOnce(response)

    const result = await pollDeferred({
      signedFetch: mockFetch,
      locationUrl: 'https://auth.example/pending/123',
    })

    expect(result.response).toBe(response)
    expect(mockFetch).toHaveBeenCalledOnce()
    expect(mockFetch).toHaveBeenCalledWith('https://auth.example/pending/123', {
      method: 'GET',
      headers: { Prefer: 'wait=45' },
    })
  })

  it('returns on terminal 400', async () => {
    const response = new Response(
      JSON.stringify({ error: 'invalid_request', error_description: 'Missing field' }),
      { status: 400, headers: { 'Content-Type': 'application/json' } },
    )
    mockFetch.mockResolvedValueOnce(response)

    const result = await pollDeferred({
      signedFetch: mockFetch,
      locationUrl: 'https://auth.example/pending/123',
    })

    expect(result.response.status).toBe(400)
    expect(result.error).toEqual({
      error: 'invalid_request',
      error_description: 'Missing field',
      error_uri: undefined,
    })
  })

  it('returns on terminal 401', async () => {
    const response = new Response(
      JSON.stringify({ error: 'invalid_signature' }),
      { status: 401, headers: { 'Content-Type': 'application/json' } },
    )
    mockFetch.mockResolvedValueOnce(response)

    const result = await pollDeferred({
      signedFetch: mockFetch,
      locationUrl: 'https://auth.example/pending/123',
    })

    expect(result.response.status).toBe(401)
    expect(result.error).toEqual({
      error: 'invalid_signature',
      error_description: undefined,
      error_uri: undefined,
    })
  })

  it('returns on terminal 403 with error body', async () => {
    const response = new Response(
      JSON.stringify({ error: 'denied', error_description: 'User denied the request' }),
      { status: 403, headers: { 'Content-Type': 'application/json' } },
    )
    mockFetch.mockResolvedValueOnce(response)

    const result = await pollDeferred({
      signedFetch: mockFetch,
      locationUrl: 'https://auth.example/pending/123',
    })

    expect(result.response.status).toBe(403)
    expect(result.error).toEqual({
      error: 'denied',
      error_description: 'User denied the request',
      error_uri: undefined,
    })
  })

  it('returns on terminal 408', async () => {
    const response = new Response(
      JSON.stringify({ error: 'expired' }),
      { status: 408, headers: { 'Content-Type': 'application/json' } },
    )
    mockFetch.mockResolvedValueOnce(response)

    const result = await pollDeferred({
      signedFetch: mockFetch,
      locationUrl: 'https://auth.example/pending/123',
    })

    expect(result.response.status).toBe(408)
    expect(result.error?.error).toBe('expired')
  })

  it('returns on terminal 410', async () => {
    const response = new Response(
      JSON.stringify({ error: 'invalid_code' }),
      { status: 410, headers: { 'Content-Type': 'application/json' } },
    )
    mockFetch.mockResolvedValueOnce(response)

    const result = await pollDeferred({
      signedFetch: mockFetch,
      locationUrl: 'https://auth.example/pending/123',
    })

    expect(result.response.status).toBe(410)
    expect(result.error?.error).toBe('invalid_code')
  })

  it('returns undefined error when no JSON body', async () => {
    const response = new Response('forbidden', { status: 403 })
    mockFetch.mockResolvedValueOnce(response)

    const result = await pollDeferred({
      signedFetch: mockFetch,
      locationUrl: 'https://auth.example/pending/123',
    })

    expect(result.response.status).toBe(403)
    expect(result.error).toBeUndefined()
  })

  it('polls 202 then returns terminal 200', async () => {
    const pending = new Response(null, { status: 202, headers: { 'Retry-After': '1' } })
    const done = new Response('{"auth_token":"tok"}', { status: 200 })
    mockFetch.mockResolvedValueOnce(pending).mockResolvedValueOnce(done)

    const result = await pollDeferred({
      signedFetch: mockFetch,
      locationUrl: 'https://auth.example/pending/123',
    })

    expect(result.response.status).toBe(200)
    expect(mockFetch).toHaveBeenCalledTimes(2)
  })

  it('handles multiple 202 then 200', async () => {
    const make202 = () => new Response(null, { status: 202, headers: { 'Retry-After': '1' } })
    const done = new Response('ok', { status: 200 })
    mockFetch
      .mockResolvedValueOnce(make202())
      .mockResolvedValueOnce(make202())
      .mockResolvedValueOnce(done)

    const result = await pollDeferred({
      signedFetch: mockFetch,
      locationUrl: 'https://auth.example/pending/123',
    })

    expect(result.response.status).toBe(200)
    expect(mockFetch).toHaveBeenCalledTimes(3)
  })

  it('calls onInteraction with initial interaction url and code', async () => {
    const onInteraction = vi.fn()
    const done = new Response('ok', { status: 200 })
    mockFetch.mockResolvedValueOnce(done)

    await pollDeferred({
      signedFetch: mockFetch,
      locationUrl: 'https://auth.example/pending/123',
      interactionUrl: 'https://auth.example/interact',
      interactionCode: 'ABCD1234',
      onInteraction,
    })

    expect(onInteraction).toHaveBeenCalledWith('https://auth.example/interact', 'ABCD1234')
  })

  it('calls onInteraction from 202 AAuth-Requirement header', async () => {
    const onInteraction = vi.fn()
    const pending = new Response(null, {
      status: 202,
      headers: {
        'aauth-requirement': 'requirement=interaction; url="https://auth.example/interact"; code="WXYZ5678"',
        'Retry-After': '1',
      },
    })
    const done = new Response('ok', { status: 200 })
    mockFetch.mockResolvedValueOnce(pending).mockResolvedValueOnce(done)

    await pollDeferred({
      signedFetch: mockFetch,
      locationUrl: 'https://auth.example/pending/123',
      onInteraction,
    })

    expect(onInteraction).toHaveBeenCalledWith('https://auth.example/interact', 'WXYZ5678')
  })

  it('handles clarification flow', async () => {
    const onClarification = vi.fn().mockResolvedValue('42 widgets')
    const clarificationResponse = new Response(
      JSON.stringify({ clarification: 'How many widgets?' }),
      {
        status: 202,
        headers: {
          'Content-Type': 'application/json',
          'Retry-After': '1',
        },
      },
    )
    // POST response for clarification_response
    const postResponse = new Response(null, { status: 200 })
    const done = new Response('{"result":"ok"}', { status: 200 })

    mockFetch
      .mockResolvedValueOnce(clarificationResponse) // GET poll → 202 with clarification
      .mockResolvedValueOnce(postResponse) // POST clarification_response
      .mockResolvedValueOnce(done) // GET poll → 200

    const result = await pollDeferred({
      signedFetch: mockFetch,
      locationUrl: 'https://auth.example/pending/123',
      onClarification,
    })

    expect(onClarification).toHaveBeenCalledWith('How many widgets?')
    expect(mockFetch).toHaveBeenCalledTimes(3)
    // Verify the POST with clarification response
    expect(mockFetch).toHaveBeenNthCalledWith(2, 'https://auth.example/pending/123', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ clarification_response: '42 widgets' }),
    })
    expect(result.response.status).toBe(200)
  })

  it('handles 503 with backoff', async () => {
    const svc503 = new Response(null, { status: 503, headers: { 'Retry-After': '1' } })
    const done = new Response('ok', { status: 200 })
    mockFetch.mockResolvedValueOnce(svc503).mockResolvedValueOnce(done)

    const result = await pollDeferred({
      signedFetch: mockFetch,
      locationUrl: 'https://auth.example/pending/123',
    })

    expect(result.response.status).toBe(200)
    expect(mockFetch).toHaveBeenCalledTimes(2)
  })

  it('times out and throws', async () => {
    // Always return 202
    mockFetch.mockImplementation(async () =>
      new Response(null, { status: 202, headers: { 'Retry-After': '1' } }),
    )

    await expect(
      pollDeferred({
        signedFetch: mockFetch,
        locationUrl: 'https://auth.example/pending/123',
        maxPollDuration: 0, // immediate timeout
      }),
    ).rejects.toThrow('Polling timed out')
  })

  it('returns unexpected status as terminal', async () => {
    const response = new Response('teapot', { status: 418 })
    mockFetch.mockResolvedValueOnce(response)

    const result = await pollDeferred({
      signedFetch: mockFetch,
      locationUrl: 'https://auth.example/pending/123',
    })

    expect(result.response.status).toBe(418)
  })
})
