import { describe, it, expect, vi } from 'vitest'
import { createResourceToken, clampToMission, AAuthTokenError } from './index.js'
import type { SignFn, PersonTokenReference } from './index.js'
import { RESOURCE, PS, MISSION_S256 } from './testing.js'

/** Captures what the package hands to the signer, without signing anything. */
function capturingSign() {
  const captured: { payload?: Record<string, unknown>; header?: Record<string, unknown> } = {}
  const sign: SignFn = vi.fn(async (payload, header) => {
    captured.payload = payload
    captured.header = header
    return 'signed.jwt.value'
  })
  return { sign, captured }
}

const personToken: PersonTokenReference = {
  iss: PS,
  sub: '8f14e45fceea167a5a36dedd4bea2543',
  jti: 'pt-3ab910',
  mission_s256: MISSION_S256,
}

function base(over: Record<string, unknown> = {}) {
  return {
    resource: RESOURCE,
    audience: PS,
    personToken,
    agentJkt: 'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs',
    scope: 'notes.read notes.write',
    ...over,
  }
}

describe('createResourceToken', () => {
  it('signs with the fully-specified Ed25519 alg, never EdDSA', async () => {
    const { sign, captured } = capturingSign()
    await createResourceToken(base({ kid: 'resource-key-1' }), sign)

    expect(captured.header).toEqual({
      alg: 'Ed25519',
      typ: 'aa-resource+jwt',
      kid: 'resource-key-1',
    })
    expect(captured.header!.alg).not.toBe('EdDSA')
  })

  it('emits the -11 claim set', async () => {
    const { sign, captured } = capturingSign()
    const now = 1_741_824_000
    await createResourceToken(base({ now }), sign)
    const p = captured.payload!

    expect(p.iss).toBe(RESOURCE)
    expect(p.dwk).toBe('aauth-resource.json')
    expect(p.aud).toBe(PS)
    expect(typeof p.jti).toBe('string')
    expect(p.ps).toBe(PS)
    expect(p.sub).toBe('8f14e45fceea167a5a36dedd4bea2543')
    expect(p.person_token_jti).toBe('pt-3ab910')
    expect(p.agent_jkt).toBe('NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs')
    expect(p.scope).toBe('notes.read notes.write')
    expect(p.iat).toBe(now)
    expect(p.exp).toBe(now + 300)
  })

  it('carries none of the removed -10 claims', async () => {
    const { sign, captured } = capturingSign()
    await createResourceToken(base(), sign)
    const p = captured.payload!

    expect(p.agent).toBeUndefined()
    expect(p.mission).toBeUndefined()
    expect(p.approver).toBeUndefined()
  })

  it('copies mission_s256 from the person token unchanged', async () => {
    const { sign, captured } = capturingSign()
    await createResourceToken(base(), sign)
    expect(captured.payload!.mission_s256).toBe(MISSION_S256)
  })

  it('omits mission_s256 when the person token carried none', async () => {
    const { sign, captured } = capturingSign()
    await createResourceToken(
      base({ personToken: { iss: PS, sub: 'u1', jti: 'pt-2' } }),
      sign,
    )
    expect(captured.payload!.mission_s256).toBeUndefined()
  })

  it('copies tenant from the person token, and lets the resource override it', async () => {
    const { sign, captured } = capturingSign()
    await createResourceToken(
      base({ personToken: { ...personToken, tenant: 'acme' } }),
      sign,
    )
    expect(captured.payload!.tenant).toBe('acme')

    const second = capturingSign()
    await createResourceToken(
      base({ personToken: { ...personToken, tenant: 'acme' }, tenant: 'acme-eu' }),
      second.sign,
    )
    expect(second.captured.payload!.tenant).toBe('acme-eu')
  })

  it('adds the optional account, interaction and R3 claims', async () => {
    const { sign, captured } = capturingSign()
    await createResourceToken(
      base({
        account: 'dick@example.com',
        interaction: { url: 'https://resource.example/interact', code: 'A1B2-C3D4' },
        r3: { uri: 'https://resource.example/r3/abc', s256: 'aBcDeF' },
      }),
      sign,
    )
    const p = captured.payload!
    expect(p.account).toBe('dick@example.com')
    expect(p.interaction).toEqual({ url: 'https://resource.example/interact', code: 'A1B2-C3D4' })
    expect(p.r3_uri).toBe('https://resource.example/r3/abc')
    expect(p.r3_s256).toBe('aBcDeF')
  })

  it('rejects a half-specified R3 reference', async () => {
    const { sign } = capturingSign()
    await expect(
      createResourceToken(base({ r3: { uri: 'https://r.example/r3/a', s256: '' } }), sign),
    ).rejects.toThrow('REQUIRED together')
  })

  it('clamps exp to the mission expires_at', async () => {
    const { sign, captured } = capturingSign()
    const now = 1_741_824_000
    await createResourceToken(base({ now, missionExpiresAt: now + 60 }), sign)
    expect(captured.payload!.exp).toBe(now + 60)
  })

  it('does not extend exp when the mission outlives the token', async () => {
    const { sign, captured } = capturingSign()
    const now = 1_741_824_000
    await createResourceToken(base({ now, missionExpiresAt: now + 86_400 }), sign)
    expect(captured.payload!.exp).toBe(now + 300)
  })

  it('refuses to mint under an already-expired mission', async () => {
    const { sign } = capturingSign()
    const now = 1_741_824_000
    await expect(
      createResourceToken(base({ now, missionExpiresAt: now - 1 }), sign),
    ).rejects.toThrow('mission expires_at is in the past')
  })

  it('requires a person token', async () => {
    const { sign } = capturingSign()
    await expect(
      createResourceToken(base({ personToken: { iss: PS, sub: 'u1' } }), sign),
    ).rejects.toThrow('needs iss, sub and jti')
  })

  it('requires scope', async () => {
    const { sign } = capturingSign()
    await expect(createResourceToken(base({ scope: '' }), sign)).rejects.toThrow('scope is a REQUIRED')
  })

  it('rejects an iss or aud that is not a server identifier', async () => {
    const { sign } = capturingSign()
    await expect(createResourceToken(base({ resource: 'https://resource.example/' }), sign))
      .rejects.toThrow('iss must be a valid HTTPS server identifier')
    await expect(createResourceToken(base({ audience: 'http://ps.example' }), sign))
      .rejects.toThrow('aud must be a valid HTTPS server identifier')
  })

  it('reports errors as AAuthTokenError with a code', async () => {
    const { sign } = capturingSign()
    try {
      await createResourceToken(base({ scope: '' }), sign)
      expect.fail('should have thrown')
    } catch (err) {
      expect(err).toBeInstanceOf(AAuthTokenError)
      expect((err as AAuthTokenError).code).toBe('invalid_scope')
    }
  })
})

describe('clampToMission', () => {
  it('is a no-op without a mission', () => {
    expect(clampToMission(1000)).toBe(1000)
  })

  it('never extends', () => {
    expect(clampToMission(1000, 2000)).toBe(1000)
  })

  it('shortens to the mission', () => {
    expect(clampToMission(2000, 1000)).toBe(1000)
  })
})
