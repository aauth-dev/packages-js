/**
 * Test helpers, shared by this package's test files. Not exported from the
 * package entry point (`index.ts`) and not part of the public API.
 */
import { generateKeyPair, exportJWK, SignJWT, calculateJwkThumbprint } from 'jose'
import type { JWK } from 'jose'
import { vi } from 'vitest'

export const RESOURCE = 'https://resource.example'
export const PS = 'https://ps.example'
export const AP = 'https://ap.example'

export interface TestKeys {
  /** Issuer key: signs JWTs, published in the issuer's JWKS. */
  issuerPrivate: CryptoKey
  issuerJwk: JWK
  /** Agent key: signs the HTTP request, carried in `cnf.jwk`. */
  agentJwk: JWK
  agentThumbprint: string
}

export async function createTestKeys(kid = 'issuer-1'): Promise<TestKeys> {
  const issuer = await generateKeyPair('Ed25519', { extractable: true })
  const issuerJwk = { ...(await exportJWK(issuer.publicKey)), alg: 'Ed25519', kid }

  const agent = await generateKeyPair('Ed25519', { extractable: true })
  const agentJwk = { ...(await exportJWK(agent.publicKey)), alg: 'Ed25519' }

  return {
    issuerPrivate: issuer.privateKey as CryptoKey,
    issuerJwk,
    agentJwk,
    agentThumbprint: await calculateJwkThumbprint(agentJwk, 'sha256'),
  }
}

export async function signTestJwt(
  key: CryptoKey,
  typ: string,
  claims: Record<string, unknown>,
  header: Record<string, unknown> = {},
): Promise<string> {
  const now = Math.floor(Date.now() / 1000)
  return new SignJWT({ iat: now, exp: now + 3600, ...claims })
    .setProtectedHeader({ alg: 'Ed25519', typ, kid: 'issuer-1', ...header } as never)
    .sign(key)
}

/** A fetch that serves `{iss}/.well-known/{dwk}` with an inline JWKS. */
export function mockJwksFetch(entries: Array<{ iss: string; dwk: string; keys: JWK[] }>) {
  return vi.fn(async (input: string) => {
    const url = input.toString()
    for (const e of entries) {
      if (url === `${e.iss}/.well-known/${e.dwk}`) {
        return new Response(JSON.stringify({ issuer: e.iss, jwks: { keys: e.keys } }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        })
      }
    }
    return new Response('Not Found', { status: 404 })
  })
}

/** A mission, present in every test that exercises mission plumbing. */
export const MISSION_S256 = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
