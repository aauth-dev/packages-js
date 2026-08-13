import { describe, it, expect } from 'vitest'
import { decodeJwtHeader, decodeJwtPayload } from './jwt.js'
import { TOKEN_TYP, DWK, SIGNING_ALG } from './constants.js'

function b64url(value: unknown): string {
  return Buffer.from(JSON.stringify(value), 'utf8').toString('base64url')
}

function makeJwt(header: unknown, payload: unknown): string {
  return `${b64url(header)}.${b64url(payload)}.c2ln`
}

const personToken = makeJwt(
  { alg: SIGNING_ALG, typ: TOKEN_TYP.person, kid: 'k1' },
  {
    iss: 'https://ps.example',
    dwk: DWK.person,
    aud: 'https://resource.example',
    sub: 'directed-subject',
    cnf: { jwk: { kty: 'OKP', crv: 'Ed25519', alg: SIGNING_ALG, x: 'xx' } },
    jti: 'j1',
    iat: 1_700_000_000,
    exp: 1_700_003_600,
  },
)

describe('decodeJwtHeader', () => {
  it('decodes the header', () => {
    expect(decodeJwtHeader(personToken)).toEqual({
      alg: 'Ed25519',
      typ: 'aa-person+jwt',
      kid: 'k1',
    })
  })

  it('handles base64url segments containing - and _', () => {
    const jwt = makeJwt({ typ: TOKEN_TYP.agent, x: '>>>???' }, { a: 1 })
    expect(decodeJwtHeader(jwt).x).toBe('>>>???')
  })
})

describe('decodeJwtPayload', () => {
  it('decodes the payload', () => {
    const payload = decodeJwtPayload(personToken)
    expect(payload.iss).toBe('https://ps.example')
    expect(payload.dwk).toBe('aauth-person.json')
    expect(payload.jti).toBe('j1')
  })

  it('decodes UTF-8 beyond ASCII', () => {
    expect(decodeJwtPayload(makeJwt({}, { name: 'Ünïcøde ✓' })).name).toBe('Ünïcøde ✓')
  })
})

describe('decoding failures', () => {
  it('throws when the token is not three segments', () => {
    expect(() => decodeJwtPayload('a.b')).toThrow(/3 dot-separated segments/)
    expect(() => decodeJwtHeader('not-a-jwt')).toThrow(/3 dot-separated segments/)
  })

  it('throws on an empty string', () => {
    expect(() => decodeJwtPayload('')).toThrow(/not a string/)
  })

  it('throws when a segment is not JSON', () => {
    const jwt = `${Buffer.from('not json', 'utf8').toString('base64url')}.${b64url({})}.sig`
    expect(() => decodeJwtHeader(jwt)).toThrow(/not valid JSON/)
  })

  it('throws when a segment is JSON but not an object', () => {
    expect(() => decodeJwtPayload(makeJwt({}, [1, 2, 3]))).toThrow(/not a JSON object/)
    expect(() => decodeJwtPayload(makeJwt({}, 'a string'))).toThrow(/not a JSON object/)
    expect(() => decodeJwtPayload(makeJwt({}, null))).toThrow(/not a JSON object/)
  })
})

describe('constants', () => {
  it('names the four token typ values', () => {
    expect(TOKEN_TYP).toEqual({
      agent: 'aa-agent+jwt',
      person: 'aa-person+jwt',
      resource: 'aa-resource+jwt',
      auth: 'aa-auth+jwt',
    })
  })

  it('names the four dwk documents', () => {
    expect(DWK).toEqual({
      agent: 'aauth-agent.json',
      person: 'aauth-person.json',
      resource: 'aauth-resource.json',
      access: 'aauth-access.json',
    })
  })

  it('uses the fully-specified RFC 9864 algorithm, not polymorphic EdDSA', () => {
    expect(SIGNING_ALG).toBe('Ed25519')
    expect(SIGNING_ALG).not.toBe('EdDSA')
  })
})
