import { describe, it, expect } from 'vitest'
import * as protocol from './index.js'

describe('public surface', () => {
  it('exports exactly the contracted runtime surface', () => {
    expect(Object.keys(protocol).sort()).toEqual(
      [
        'DWK',
        'SIGNING_ALG',
        'TOKEN_TYP',
        'UnsupportedRequirementError',
        'buildCapabilitiesHeader',
        'buildRequirementHeader',
        'decodeJwtHeader',
        'decodeJwtPayload',
        'isCapability',
        'isKnownAccessMode',
        'isRequirementValue',
        'parseCapabilitiesHeader',
        'parseRequirementHeader',
        'planAccessMode',
      ].sort(),
    )
  })

  // AAuth-Mission and its IANA registration were removed in -11. A mission
  // reaches a resource only inside a PS-issued token, as the mission_s256 claim.
  it('exports no mission header helpers', () => {
    for (const name of ['buildMissionHeader', 'parseMissionHeader', 'AAuthMission']) {
      expect(protocol).not.toHaveProperty(name)
    }
  })

  // The package has one runtime dependency and it is deliberate: the RFC 8941
  // parser lives in @hellocoop/httpsig, which anything importing this package
  // pulls in anyway. What must not appear is a second one.
  it('depends on @hellocoop/httpsig and nothing else', async () => {
    const pkg = await import('../package.json', { with: { type: 'json' } })
    const deps = (pkg.default as Record<string, unknown>).dependencies as Record<string, string>
    expect(Object.keys(deps)).toEqual(['@hellocoop/httpsig'])
  })
})
