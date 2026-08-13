import { describe, it, expect, vi, beforeAll, beforeEach, afterEach, afterAll } from 'vitest'
import { readConfig, writeConfig, getAgentConfig, readCachedMetadata, evictCachedMetadata } from '@aauth/local-keys'
import type { AAuthConfig } from '@aauth/local-keys'
import { bootstrapWithPS } from './bootstrap-ps.js'

const PS_URL = 'https://ps.example'
const AGENT_URL = 'https://agent.example'

const validMetadata = {
  issuer: PS_URL,
  auth_token_endpoint: `${PS_URL}/aauth/token`,
  person_token_endpoint: `${PS_URL}/aauth/person`,
  jwks_uri: `${PS_URL}/.well-known/jwks.json`,
  interaction_endpoint: `${PS_URL}/aauth/interact`,
}

function mockMetadataResponse(body: unknown, status = 200): Response {
  return new Response(typeof body === 'string' ? body : JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

describe('bootstrapWithPS', () => {
  let originalConfig: AAuthConfig
  let mockFetch: ReturnType<typeof vi.fn>

  beforeAll(() => {
    originalConfig = readConfig()
  })

  afterAll(() => {
    writeConfig(originalConfig)
  })

  beforeEach(() => {
    writeConfig({ agents: {} })
    mockFetch = vi.fn()
    vi.stubGlobal('fetch', mockFetch)
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    // Drop the on-disk cache entry the bootstrap may have written (keyed by PS host).
    evictCachedMetadata('ps.example')
  })

  it('fetches metadata from the correct well-known URL', async () => {
    mockFetch.mockResolvedValueOnce(mockMetadataResponse(validMetadata))

    await bootstrapWithPS({ agentUrl: AGENT_URL, personServerUrl: PS_URL })

    expect(mockFetch).toHaveBeenCalledWith(`${PS_URL}/.well-known/aauth-person.json`)
  })

  it('writes agentId and personServerUrl to config on success', async () => {
    mockFetch.mockResolvedValueOnce(mockMetadataResponse(validMetadata))

    await bootstrapWithPS({ agentUrl: AGENT_URL, personServerUrl: PS_URL })

    const agentConfig = getAgentConfig(AGENT_URL)
    expect(agentConfig?.agentId).toBe('aauth:local@agent.example')
    expect(agentConfig?.personServerUrl).toBe(PS_URL)
  })

  it('caches the fetched PS metadata (by PS host) so fetch can skip the runtime fetch', async () => {
    mockFetch.mockResolvedValueOnce(mockMetadataResponse(validMetadata))

    await bootstrapWithPS({ agentUrl: AGENT_URL, personServerUrl: PS_URL })

    // The full fetched doc is cached verbatim, keyed by the PS host — not in config.
    expect(readCachedMetadata('ps.example')).toEqual(validMetadata)
    expect(getAgentConfig(AGENT_URL)).not.toHaveProperty('personServerMetadata')
  })

  it('uses the provided `local` value in agentId', async () => {
    mockFetch.mockResolvedValueOnce(mockMetadataResponse(validMetadata))

    await bootstrapWithPS({ agentUrl: AGENT_URL, personServerUrl: PS_URL, local: 'work' })

    expect(getAgentConfig(AGENT_URL)?.agentId).toBe('aauth:work@agent.example')
  })

  it('preserves existing key entries when writing the agent config', async () => {
    writeConfig({
      agents: {
        [AGENT_URL]: {
          keys: {
            'kid-123': {
              backend: 'yubikey-piv',
              algorithm: 'ES256',
              keyId: '9e',
              deviceLabel: 'yubikey-5c-0775',
            },
          },
        },
      },
    })
    mockFetch.mockResolvedValueOnce(mockMetadataResponse(validMetadata))

    await bootstrapWithPS({ agentUrl: AGENT_URL, personServerUrl: PS_URL })

    const agentConfig = getAgentConfig(AGENT_URL)
    expect(agentConfig?.keys['kid-123']).toBeDefined()
    expect(agentConfig?.personServerUrl).toBe(PS_URL)
  })

  it('throws when metadata endpoint returns non-OK', async () => {
    mockFetch.mockResolvedValueOnce(new Response('not found', { status: 404 }))

    await expect(
      bootstrapWithPS({ agentUrl: AGENT_URL, personServerUrl: PS_URL }),
    ).rejects.toThrow(/Failed to fetch PS metadata.*404/)
  })

  it('throws when metadata is missing issuer', async () => {
    const { issuer, ...rest } = validMetadata
    void issuer
    mockFetch.mockResolvedValueOnce(mockMetadataResponse(rest))

    await expect(
      bootstrapWithPS({ agentUrl: AGENT_URL, personServerUrl: PS_URL }),
    ).rejects.toThrow(/missing required field: issuer/)
  })

  it('throws when metadata is missing auth_token_endpoint', async () => {
    const { auth_token_endpoint, ...rest } = validMetadata
    void auth_token_endpoint
    mockFetch.mockResolvedValueOnce(mockMetadataResponse(rest))

    await expect(
      bootstrapWithPS({ agentUrl: AGENT_URL, personServerUrl: PS_URL }),
    ).rejects.toThrow(/missing required field: auth_token_endpoint/)
  })

  it('throws when metadata is missing person_token_endpoint, naming the field', async () => {
    const { person_token_endpoint, ...rest } = validMetadata
    void person_token_endpoint
    mockFetch.mockResolvedValueOnce(mockMetadataResponse(rest))

    await expect(
      bootstrapWithPS({ agentUrl: AGENT_URL, personServerUrl: PS_URL }),
    ).rejects.toThrow(/missing required field: person_token_endpoint/)
  })

  it('says why a missing person_token_endpoint is fatal, not deferred to first use', async () => {
    const { person_token_endpoint, ...rest } = validMetadata
    void person_token_endpoint
    mockFetch.mockResolvedValueOnce(mockMetadataResponse(rest))

    const error = await bootstrapWithPS({ agentUrl: AGENT_URL, personServerUrl: PS_URL })
      .then(() => null, (e: Error) => e)

    expect(error).toBeInstanceOf(Error)
    const message = (error as Error).message
    expect(message).toContain('person_token_endpoint')
    expect(message).toContain(PS_URL)
    expect(message).toContain(`${PS_URL}/.well-known/aauth-person.json`)
    expect(message).toMatch(/cannot issue person tokens/)
  })

  it('does not bind or cache anything when person_token_endpoint is missing', async () => {
    const { person_token_endpoint, ...rest } = validMetadata
    void person_token_endpoint
    mockFetch.mockResolvedValueOnce(mockMetadataResponse(rest))

    await expect(
      bootstrapWithPS({ agentUrl: AGENT_URL, personServerUrl: PS_URL }),
    ).rejects.toThrow()

    // Binding to a PS that cannot issue person tokens would fail at first use —
    // so nothing is written: no agent config, no cached metadata.
    expect(getAgentConfig(AGENT_URL)).toBeNull()
    expect(readCachedMetadata('ps.example')).toBeNull()
  })

  it('lists every missing required field at once (the -10 metadata a live PS still serves)', async () => {
    // What https://person.hello.coop publishes today: -10 field names, no person endpoint.
    mockFetch.mockResolvedValueOnce(
      mockMetadataResponse({
        issuer: PS_URL,
        token_endpoint: `${PS_URL}/aauth/token`,
        interaction_endpoint: `${PS_URL}/auth`,
        jwks_uri: `${PS_URL}/.well-known/jwks.json`,
      }),
    )

    await expect(
      bootstrapWithPS({ agentUrl: AGENT_URL, personServerUrl: PS_URL }),
    ).rejects.toThrow(/missing required fields: auth_token_endpoint, person_token_endpoint/)
  })

  it('explains the -10 → -11 rename when the PS still publishes token_endpoint', async () => {
    const { auth_token_endpoint, ...rest } = validMetadata
    mockFetch.mockResolvedValueOnce(
      mockMetadataResponse({ ...rest, token_endpoint: auth_token_endpoint }),
    )

    await expect(
      bootstrapWithPS({ agentUrl: AGENT_URL, personServerUrl: PS_URL }),
    ).rejects.toThrow(/auth_token_endpoint[\s\S]*token_endpoint/)
  })

  it('throws when metadata is missing jwks_uri', async () => {
    const { jwks_uri, ...rest } = validMetadata
    void jwks_uri
    mockFetch.mockResolvedValueOnce(mockMetadataResponse(rest))

    await expect(
      bootstrapWithPS({ agentUrl: AGENT_URL, personServerUrl: PS_URL }),
    ).rejects.toThrow(/missing required field: jwks_uri/)
  })

  it('throws when issuer does not match the PS URL', async () => {
    mockFetch.mockResolvedValueOnce(
      mockMetadataResponse({ ...validMetadata, issuer: 'https://imposter.example' }),
    )

    await expect(
      bootstrapWithPS({ agentUrl: AGENT_URL, personServerUrl: PS_URL }),
    ).rejects.toThrow(/issuer.*does not match URL/)
  })

  it('accepts trailing-slash differences between issuer and URL', async () => {
    mockFetch.mockResolvedValueOnce(
      mockMetadataResponse({ ...validMetadata, issuer: `${PS_URL}/` }),
    )

    await expect(
      bootstrapWithPS({ agentUrl: AGENT_URL, personServerUrl: PS_URL }),
    ).resolves.not.toThrow()
  })

  it('strips trailing slash from PS URL when constructing metadata URL', async () => {
    mockFetch.mockResolvedValueOnce(mockMetadataResponse(validMetadata))

    await bootstrapWithPS({ agentUrl: AGENT_URL, personServerUrl: `${PS_URL}/` })

    expect(mockFetch).toHaveBeenCalledWith(`${PS_URL}/.well-known/aauth-person.json`)
  })

  it('does NOT make a registration POST to the PS', async () => {
    mockFetch.mockResolvedValueOnce(mockMetadataResponse(validMetadata))

    await bootstrapWithPS({ agentUrl: AGENT_URL, personServerUrl: PS_URL })

    // Only the metadata GET should have been issued.
    expect(mockFetch).toHaveBeenCalledTimes(1)
  })
})
