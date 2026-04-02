import {
  jwtVerify,
  createLocalJWKSet,
  calculateJwkThumbprint,
  decodeProtectedHeader,
  decodeJwt,
} from 'jose'
import type { JWK, JSONWebKeySet } from 'jose'

// --- Types ---

export interface VerifyTokenOptions {
  jwt: string                     // raw JWT (from httpsig result.jwt.raw)
  httpSignatureThumbprint: string // thumbprint of HTTP signing key (from httpsig result.thumbprint)
}

export interface VerifiedAgentToken {
  type: 'agent'
  iss: string
  dwk: string
  sub: string
  cnf: { jwk: JWK }
  iat: number
  exp: number
}

export interface VerifiedAuthToken {
  type: 'auth'
  iss: string
  dwk: string
  aud: string | string[]
  agent: string
  cnf: { jwk: JWK }
  sub?: string
  scope?: string
  tenant?: string
  iat: number
  exp: number
}

export type VerifiedToken = VerifiedAgentToken | VerifiedAuthToken

// --- Error class ---

export class AAuthTokenError extends Error {
  constructor(public code: string, message: string) {
    super(message)
  }
}

// --- Metadata cache ---

const metadataCache = new Map<string, { jwksUri: string; fetchedAt: number }>()
const METADATA_CACHE_TTL = 600_000 // 10 minutes

async function resolveJwksUri(iss: string, metadataPath: string): Promise<string> {
  const metadataUrl = `${iss}${metadataPath}`
  const cached = metadataCache.get(metadataUrl)
  if (cached && Date.now() - cached.fetchedAt < METADATA_CACHE_TTL) {
    return cached.jwksUri
  }

  const res = await fetch(metadataUrl)
  if (!res.ok) {
    throw new AAuthTokenError(
      'metadata_fetch_failed',
      `Failed to fetch metadata from ${metadataUrl}: ${res.status}`,
    )
  }

  const metadata = await res.json() as { jwks_uri?: string }
  if (!metadata.jwks_uri) {
    throw new AAuthTokenError(
      'metadata_fetch_failed',
      `No jwks_uri in metadata from ${metadataUrl}`,
    )
  }

  metadataCache.set(metadataUrl, { jwksUri: metadata.jwks_uri, fetchedAt: Date.now() })
  return metadata.jwks_uri
}

// Exposed for testing
export function clearMetadataCache(): void {
  metadataCache.clear()
}

// --- Main function ---

const CLOCK_SKEW = 60 // 60 seconds

export async function verifyToken(options: VerifyTokenOptions): Promise<VerifiedToken> {
  const { jwt: rawJwt, httpSignatureThumbprint } = options

  // 1. Decode header — check typ
  const header = decodeProtectedHeader(rawJwt)
  const typ = header.typ

  if (typ !== 'agent+jwt' && typ !== 'auth+jwt') {
    throw new AAuthTokenError(
      typ === 'agent+jwt' ? 'invalid_agent_token' : 'invalid_auth_token',
      `Unknown JWT typ: ${typ}`,
    )
  }

  const isAgent = typ === 'agent+jwt'
  const errorCode = isAgent ? 'invalid_agent_token' : 'invalid_auth_token'

  // 2. Decode and validate required claims
  const claims = decodeJwt(rawJwt)

  if (!claims.iss) {
    throw new AAuthTokenError(errorCode, 'Missing required claim: iss')
  }
  if (claims.iat === undefined) {
    throw new AAuthTokenError(errorCode, 'Missing required claim: iat')
  }
  if (claims.exp === undefined) {
    throw new AAuthTokenError(errorCode, 'Missing required claim: exp')
  }

  const dwk = (claims as Record<string, unknown>).dwk as string | undefined
  if (!dwk) {
    throw new AAuthTokenError(errorCode, 'Missing required claim: dwk')
  }

  const cnf = claims.cnf as { jwk?: JWK } | undefined
  if (!cnf?.jwk) {
    throw new AAuthTokenError(errorCode, 'Missing required claim: cnf.jwk')
  }

  if (isAgent) {
    if (!claims.sub) {
      throw new AAuthTokenError(errorCode, 'Missing required claim: sub')
    }
  } else {
    if (!claims.aud) {
      throw new AAuthTokenError(errorCode, 'Missing required claim: aud')
    }
    if (!(claims as Record<string, unknown>).agent) {
      throw new AAuthTokenError(errorCode, 'Missing required claim: agent')
    }
  }

  // 3. Check expiration
  const now = Math.floor(Date.now() / 1000)
  if (claims.exp < now - CLOCK_SKEW) {
    throw new AAuthTokenError(errorCode, 'Token has expired')
  }

  // 4. Key binding — cnf.jwk thumbprint must match httpSignatureThumbprint
  const cnfThumbprint = await calculateJwkThumbprint(cnf.jwk, 'sha256')
  if (cnfThumbprint !== httpSignatureThumbprint) {
    throw new AAuthTokenError(
      'key_binding_failed',
      'cnf.jwk thumbprint does not match HTTP signature key',
    )
  }

  // 5. Resolve JWKS URI from metadata using dwk claim
  const metadataPath = `/.well-known/${dwk}`

  const jwksUri = await resolveJwksUri(claims.iss, metadataPath)

  // 6. Fetch JWKS and verify JWT signature
  const jwksRes = await fetch(jwksUri)
  if (!jwksRes.ok) {
    throw new AAuthTokenError(
      errorCode,
      `Failed to fetch JWKS from ${jwksUri}: ${jwksRes.status}`,
    )
  }
  const jwksData = await jwksRes.json() as JSONWebKeySet

  try {
    const jwks = createLocalJWKSet(jwksData)
    await jwtVerify(rawJwt, jwks, {
      clockTolerance: CLOCK_SKEW,
    })
  } catch (err) {
    if (err instanceof AAuthTokenError) throw err
    throw new AAuthTokenError(
      errorCode,
      `JWT signature verification failed: ${(err as Error).message}`,
    )
  }

  // Build result
  if (isAgent) {
    return {
      type: 'agent',
      iss: claims.iss,
      dwk,
      sub: claims.sub as string,
      cnf: { jwk: cnf.jwk },
      iat: claims.iat as number,
      exp: claims.exp as number,
    }
  }

  const result: VerifiedAuthToken = {
    type: 'auth',
    iss: claims.iss,
    dwk,
    aud: claims.aud as string | string[],
    agent: (claims as Record<string, unknown>).agent as string,
    cnf: { jwk: cnf.jwk },
    iat: claims.iat as number,
    exp: claims.exp as number,
  }
  if (claims.sub) result.sub = claims.sub as string
  if ((claims as Record<string, unknown>).scope) {
    result.scope = (claims as Record<string, unknown>).scope as string
  }
  if ((claims as Record<string, unknown>).tenant) {
    result.tenant = (claims as Record<string, unknown>).tenant as string
  }

  return result
}
