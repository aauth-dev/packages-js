import { describe, it, expect, vi, beforeAll, beforeEach, afterEach, afterAll } from 'vitest'
import { readConfig, writeConfig, getAgentConfig } from '@aauth/local-keys'
import type { AAuthConfig } from '@aauth/local-keys'
import { bootstrapWithPS } from './bootstrap-ps.js'

const PS_URL = 'https://ps.example'
const AGENT_URL = 'https://agent.example'

const validMetadata = {
  issuer: PS_URL,
  token_endpoint: `${PS_URL}/aauth/token`,
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
    writeConfig({ agentProviders: {} })
    mockFetch = vi.fn()
    vi.stubGlobal('fetch', mockFetch)
  })

  afterEach(() => {
    vi.unstubAllGlobals()
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

  it('uses the provided `local` value in agentId', async () => {
    mockFetch.mockResolvedValueOnce(mockMetadataResponse(validMetadata))

    await bootstrapWithPS({ agentUrl: AGENT_URL, personServerUrl: PS_URL, local: 'work' })

    expect(getAgentConfig(AGENT_URL)?.agentId).toBe('aauth:work@agent.example')
  })

  it('preserves existing key entries when writing the agent config', async () => {
    writeConfig({
      agentProviders: {
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

  it('throws when metadata is missing token_endpoint', async () => {
    const { token_endpoint, ...rest } = validMetadata
    void token_endpoint
    mockFetch.mockResolvedValueOnce(mockMetadataResponse(rest))

    await expect(
      bootstrapWithPS({ agentUrl: AGENT_URL, personServerUrl: PS_URL }),
    ).rejects.toThrow(/missing required field: token_endpoint/)
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
