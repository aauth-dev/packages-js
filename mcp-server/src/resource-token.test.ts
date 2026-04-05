import { describe, it, expect, vi, beforeEach } from 'vitest'
import { createResourceToken } from './resource-token.js'

describe('createResourceToken', () => {
  const mockSign = vi.fn().mockResolvedValue('eyJ.signed.jwt')

  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('creates a resource token with required fields', async () => {
    const token = await createResourceToken({
      resource: 'https://resource.example',
      authServer: 'https://auth.example',
      agent: 'https://dickhardt.github.io',
      agentJkt: 'jkt_thumbprint_123',
    }, mockSign)

    expect(token).toBe('eyJ.signed.jwt')

    // Verify payload
    const [payload, header] = mockSign.mock.calls[0]
    expect(payload.iss).toBe('https://resource.example')
    expect(payload.dwk).toBe('aauth-resource.json')
    expect(payload.aud).toBe('https://auth.example')
    expect(payload.agent).toBe('https://dickhardt.github.io')
    expect(payload.agent_jkt).toBe('jkt_thumbprint_123')
    expect(payload.iat).toBeTypeOf('number')
    expect(payload.exp).toBeTypeOf('number')
    expect(payload.exp - payload.iat).toBe(300) // default lifetime
    expect(payload.scope).toBeUndefined()

    // Verify header
    expect(header.alg).toBe('EdDSA')
    expect(header.typ).toBe('aa-resource+jwt')
  })

  it('includes scope when provided', async () => {
    await createResourceToken({
      resource: 'https://resource.example',
      authServer: 'https://auth.example',
      agent: 'https://dickhardt.github.io',
      agentJkt: 'jkt_123',
      scope: 'files.read files.write',
    }, mockSign)

    const [payload] = mockSign.mock.calls[0]
    expect(payload.scope).toBe('files.read files.write')
  })

  it('uses custom lifetime', async () => {
    await createResourceToken({
      resource: 'https://resource.example',
      authServer: 'https://auth.example',
      agent: 'https://dickhardt.github.io',
      agentJkt: 'jkt_123',
      lifetime: 600,
    }, mockSign)

    const [payload] = mockSign.mock.calls[0]
    expect(payload.exp - payload.iat).toBe(600)
  })

  it('calls sign function with correct payload and header', async () => {
    const customSign = vi.fn().mockResolvedValue('custom.jwt.token')

    const token = await createResourceToken({
      resource: 'https://api.acme.com',
      authServer: 'https://auth.hello.coop',
      agent: 'https://agent.example',
      agentJkt: 'thumb',
      scope: 'logs:read',
      lifetime: 120,
    }, customSign)

    expect(customSign).toHaveBeenCalledOnce()
    expect(token).toBe('custom.jwt.token')

    const [payload, header] = customSign.mock.calls[0]
    expect(payload).toMatchObject({
      iss: 'https://api.acme.com',
      aud: 'https://auth.hello.coop',
      agent: 'https://agent.example',
      agent_jkt: 'thumb',
      scope: 'logs:read',
    })
    expect(header).toEqual({
      alg: 'EdDSA',
      typ: 'aa-resource+jwt',
    })
  })
})
