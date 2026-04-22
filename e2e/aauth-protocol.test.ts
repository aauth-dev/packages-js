import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import {
  generateKeyPair,
  exportJWK,
  calculateJwkThumbprint,
} from 'jose'

// --- Mock wiring ---
// httpSigFetch replaces @hellocoop/httpsig.fetch so that
// mcp-agent's createSignedFetch/createAAuthFetch call our mock server harness.

const { mockHttpSigFetch } = vi.hoisted(() => ({
  mockHttpSigFetch: vi.fn(),
}))

vi.mock('@hellocoop/httpsig', () => ({
  fetch: mockHttpSigFetch,
}))

// MCP SDK mocks for ServerManager tests
const {
  mockConnect, mockListTools, mockCallTool, MockClient,
  mockTransportClose, MockStreamableHTTPClientTransport, mockCreateSignedFetch,
} = vi.hoisted(() => {
  const mockConnect = vi.fn().mockResolvedValue(undefined)
  const mockListTools = vi.fn()
  const mockCallTool = vi.fn()
  const MockClient = vi.fn().mockImplementation(() => ({
    connect: mockConnect,
    listTools: mockListTools,
    callTool: mockCallTool,
  }))
  const mockTransportClose = vi.fn().mockResolvedValue(undefined)
  const MockStreamableHTTPClientTransport = vi.fn().mockReturnValue({
    close: mockTransportClose,
  })
  const mockCreateSignedFetch = vi.fn().mockReturnValue(vi.fn())
  return {
    mockConnect, mockListTools, mockCallTool, MockClient,
    mockTransportClose, MockStreamableHTTPClientTransport, mockCreateSignedFetch,
  }
})

vi.mock('@modelcontextprotocol/sdk/client/index.js', () => ({
  Client: MockClient,
}))

vi.mock('@modelcontextprotocol/sdk/client/streamableHttp.js', () => ({
  StreamableHTTPClientTransport: MockStreamableHTTPClientTransport,
}))

// --- Imports (after mocks) ---

import {
  buildAAuthHeader,
  InteractionManager,
  verifyToken,
  clearMetadataCache,
} from '@aauth/mcp-server'
import type { VerifiedAgentToken, VerifiedAuthToken } from '@aauth/mcp-server'
import { parseAAuthHeader, createAAuthFetch } from '@aauth/mcp-agent'
import { ServerManager } from '@aauth/mcp-openclaw'

import {
  createTestKeys,
  createAgentJwt,
  createAuthJwt,
  createGetKeyMaterial,
  createMockServer,
} from './helpers.js'
import type { TestKeys } from './helpers.js'

// --- Constants ---

const AGENT_URL = 'https://agent.example'
const AGENT_ID = 'aauth:test@example.com'
const AUTH_SERVER_URL = 'https://auth.example'
const RESOURCE_URL = 'https://resource.example'
const INTERACTION_URL = 'https://auth.example/interact'

// =============================================================================
// Suite 1: AAuth-Requirement header round-trip
// =============================================================================

describe('AAuth-Requirement header round-trip (server builds → agent parses)', () => {
  it('round-trips auth-token challenge', () => {
    const header = buildAAuthHeader('auth-token', {
      resourceToken: 'rt_abc123',
    })
    const parsed = parseAAuthHeader(header)

    expect(parsed.requirement).toBe('auth-token')
    expect(parsed.resourceToken).toBe('rt_abc123')
  })

  it('round-trips interaction challenge', () => {
    const header = buildAAuthHeader('interaction', {
      url: 'https://auth.example/interact',
      code: 'CODE1234',
    })
    const parsed = parseAAuthHeader(header)

    expect(parsed.requirement).toBe('interaction')
    expect(parsed.url).toBe('https://auth.example/interact')
    expect(parsed.code).toBe('CODE1234')
  })

  it('round-trips approval level', () => {
    const header = buildAAuthHeader('approval')
    const parsed = parseAAuthHeader(header)
    expect(parsed.requirement).toBe('approval')
  })
})

// =============================================================================
// Suite 2: verifyToken with real tokens
// =============================================================================

describe('verifyToken with real tokens', () => {
  let keys: TestKeys
  const originalFetch = globalThis.fetch

  beforeEach(async () => {
    keys = await createTestKeys()
    clearMetadataCache()
  })

  afterEach(() => {
    globalThis.fetch = originalFetch
  })

  it('verifies a real agent+jwt → VerifiedAgentToken', async () => {
    const agentJwt = await createAgentJwt(keys, AGENT_URL, AGENT_ID)

    const server = createMockServer({
      keys,
      resourceUrl: RESOURCE_URL,
      authServerUrl: AUTH_SERVER_URL,
      agentUrl: AGENT_URL,
      sub: AGENT_ID,
    })
    globalThis.fetch = server.globalFetch as typeof fetch

    const result = await verifyToken({
      jwt: agentJwt,
      httpSignatureThumbprint: keys.agentEphemeral.thumbprint,
    })

    expect(result.type).toBe('agent')
    const agent = result as VerifiedAgentToken
    expect(agent.iss).toBe(AGENT_URL)
    expect(agent.dwk).toBe('aauth-agent.json')
    expect(agent.sub).toBe(AGENT_ID)
    expect(agent.cnf.jwk).toEqual(keys.agentEphemeral.pubJwk)
    expect(agent.iat).toBeTypeOf('number')
    expect(agent.exp).toBeTypeOf('number')
  })

  it('verifies a real auth+jwt → VerifiedAuthToken', async () => {
    const authJwt = await createAuthJwt(keys, {
      iss: AUTH_SERVER_URL,
      aud: RESOURCE_URL,
      agent: AGENT_URL,
      sub: 'user-456',
      scope: 'files.read',
    })

    const server = createMockServer({
      keys,
      resourceUrl: RESOURCE_URL,
      authServerUrl: AUTH_SERVER_URL,
      agentUrl: AGENT_URL,
      sub: AGENT_ID,
    })
    globalThis.fetch = server.globalFetch as typeof fetch

    const result = await verifyToken({
      jwt: authJwt,
      httpSignatureThumbprint: keys.agentEphemeral.thumbprint,
    })

    expect(result.type).toBe('auth')
    const auth = result as VerifiedAuthToken
    expect(auth.iss).toBe(AUTH_SERVER_URL)
    expect(auth.dwk).toBe('aauth-person.json')
    expect(auth.aud).toBe(RESOURCE_URL)
    expect(auth.agent).toBe(AGENT_URL)
    expect(auth.sub).toBe('user-456')
    expect(auth.scope).toBe('files.read')
  })

  it('throws key_binding_failed on thumbprint mismatch', async () => {
    const agentJwt = await createAgentJwt(keys, AGENT_URL, AGENT_ID)

    const wrongKey = await generateKeyPair('EdDSA', { crv: 'Ed25519' })
    const wrongPubJwk = await exportJWK(wrongKey.publicKey)
    const wrongThumbprint = await calculateJwkThumbprint(wrongPubJwk, 'sha256')

    const server = createMockServer({
      keys,
      resourceUrl: RESOURCE_URL,
      authServerUrl: AUTH_SERVER_URL,
      agentUrl: AGENT_URL,
      sub: AGENT_ID,
    })
    globalThis.fetch = server.globalFetch as typeof fetch

    await expect(
      verifyToken({ jwt: agentJwt, httpSignatureThumbprint: wrongThumbprint }),
    ).rejects.toThrow('cnf.jwk thumbprint does not match')
  })
})

// =============================================================================
// Suite 3: Full 401 challenge-response (direct grant)
// =============================================================================

describe('Full 401 challenge-response (direct grant)', () => {
  let keys: TestKeys
  const originalFetch = globalThis.fetch

  beforeEach(async () => {
    keys = await createTestKeys()
    clearMetadataCache()
    vi.clearAllMocks()
  })

  afterEach(() => {
    globalThis.fetch = originalFetch
  })

  it('agent request → 401 → exchangeToken → auth server creates auth+jwt → retry → 200', async () => {
    const agentJwt = await createAgentJwt(keys, AGENT_URL, AGENT_ID)
    const getKeyMaterial = createGetKeyMaterial(keys, agentJwt)

    const server = createMockServer({
      keys,
      resourceUrl: RESOURCE_URL,
      authServerUrl: AUTH_SERVER_URL,
      agentUrl: AGENT_URL,
      sub: AGENT_ID,
      requireAuthToken: true,
    })

    // Wire mocks
    mockHttpSigFetch.mockImplementation(server.httpSigFetch)
    globalThis.fetch = server.globalFetch as typeof fetch

    const aAuthFetch = createAAuthFetch({
      getKeyMaterial,
      authServerUrl: AUTH_SERVER_URL,
    })
    const result = await aAuthFetch(`${RESOURCE_URL}/api/data`)

    expect(result.status).toBe(200)
    const body = await result.json()
    expect(body.status).toBe('ok')
    expect(body.user).toBe('user-123')

    // httpSigFetch should have been called multiple times:
    // 1. initial request to resource (→ 401)
    // 2. metadata fetch to auth server
    // 3. token POST to auth server
    // 4. retry to resource with auth token (→ 200)
    expect(mockHttpSigFetch.mock.calls.length).toBeGreaterThanOrEqual(4)
  })

  it('second request reuses cached token, no re-exchange', async () => {
    const agentJwt = await createAgentJwt(keys, AGENT_URL, AGENT_ID)
    const getKeyMaterial = createGetKeyMaterial(keys, agentJwt)

    const server = createMockServer({
      keys,
      resourceUrl: RESOURCE_URL,
      authServerUrl: AUTH_SERVER_URL,
      agentUrl: AGENT_URL,
      sub: AGENT_ID,
      requireAuthToken: true,
    })

    mockHttpSigFetch.mockImplementation(server.httpSigFetch)
    globalThis.fetch = server.globalFetch as typeof fetch

    const aAuthFetch = createAAuthFetch({
      getKeyMaterial,
      authServerUrl: AUTH_SERVER_URL,
    })

    // First request — full challenge-response
    const result1 = await aAuthFetch(`${RESOURCE_URL}/api/data`)
    expect(result1.status).toBe(200)

    const callCountAfterFirst = mockHttpSigFetch.mock.calls.length

    // Second request — should reuse cached auth token
    const result2 = await aAuthFetch(`${RESOURCE_URL}/api/other`)
    expect(result2.status).toBe(200)

    // Second request should only need 1 call (the resource request with cached token)
    const callCountAfterSecond = mockHttpSigFetch.mock.calls.length
    expect(callCountAfterSecond - callCountAfterFirst).toBe(1)
  })

  it('justification and hints pass through to token endpoint body', async () => {
    const agentJwt = await createAgentJwt(keys, AGENT_URL, AGENT_ID)
    const getKeyMaterial = createGetKeyMaterial(keys, agentJwt)

    let capturedBody: Record<string, string> | undefined
    const server = createMockServer({
      keys,
      resourceUrl: RESOURCE_URL,
      authServerUrl: AUTH_SERVER_URL,
      agentUrl: AGENT_URL,
      sub: AGENT_ID,
      requireAuthToken: true,
      onTokenRequest: (body) => { capturedBody = body },
    })

    mockHttpSigFetch.mockImplementation(server.httpSigFetch)
    globalThis.fetch = server.globalFetch as typeof fetch

    const aAuthFetch = createAAuthFetch({
      getKeyMaterial,
      authServerUrl: AUTH_SERVER_URL,
      justification: 'read user files',
      loginHint: 'alice@acme.com',
      tenant: 'acme.com',
      domainHint: 'acme.com',
    })
    await aAuthFetch(`${RESOURCE_URL}/api/data`)

    expect(capturedBody).toBeDefined()
    expect(capturedBody!.resource_token).toBeDefined()
    expect(capturedBody!.justification).toBe('read user files')
    expect(capturedBody!.login_hint).toBe('alice@acme.com')
    expect(capturedBody!.tenant).toBe('acme.com')
    expect(capturedBody!.domain_hint).toBe('acme.com')
  })
})

// =============================================================================
// Suite 4: Deferred/interaction grant
// =============================================================================

describe('Deferred/interaction grant', () => {
  let keys: TestKeys
  const originalFetch = globalThis.fetch

  beforeEach(async () => {
    keys = await createTestKeys()
    clearMetadataCache()
    vi.clearAllMocks()
  })

  afterEach(() => {
    globalThis.fetch = originalFetch
  })

  it('token endpoint returns 202 → onInteraction receives url and code → resolve → poll gets 200 → retry succeeds', async () => {
    const agentJwt = await createAgentJwt(keys, AGENT_URL, AGENT_ID)
    const getKeyMaterial = createGetKeyMaterial(keys, agentJwt)

    const interactionManager = new InteractionManager({
      baseUrl: AUTH_SERVER_URL,
      interactionUrl: INTERACTION_URL,
    })
    const server = createMockServer({
      keys,
      resourceUrl: RESOURCE_URL,
      authServerUrl: AUTH_SERVER_URL,
      agentUrl: AGENT_URL,
      sub: AGENT_ID,
      requireAuthToken: true,
      deferredMode: true,
      interactionManager,
    })

    mockHttpSigFetch.mockImplementation(server.httpSigFetch)
    globalThis.fetch = server.globalFetch as typeof fetch

    let receivedUrl: string | undefined
    let receivedCode: string | undefined
    const onInteraction = (url: string, code: string) => {
      receivedUrl = url
      receivedCode = code

      // Simulate external resolution: resolve the pending request
      // after a short delay to allow the poll to start
      setTimeout(async () => {
        // Create an auth token for resolution
        const authJwt = await createAuthJwt(keys, {
          iss: AUTH_SERVER_URL,
          aud: RESOURCE_URL,
          agent: AGENT_URL,
          sub: 'user-deferred',
        })

        // Find calls to /pending/ to get the ID
        const pendingCalls = mockHttpSigFetch.mock.calls.filter(
          (call: unknown[]) => String(call[0]).includes('/pending/'),
        )
        if (pendingCalls.length > 0) {
          const pendingUrl = String(pendingCalls[0][0])
          const pendingId = pendingUrl.split('/pending/')[1]
          interactionManager.resolve(pendingId, { auth_token: authJwt, expires_in: 3600 })
        }
      }, 200)
    }

    const aAuthFetch = createAAuthFetch({
      getKeyMaterial,
      authServerUrl: AUTH_SERVER_URL,
      onInteraction,
    })

    const result = await aAuthFetch(`${RESOURCE_URL}/api/data`)

    expect(result.status).toBe(200)
    expect(receivedUrl).toBe(INTERACTION_URL)
    expect(receivedCode).toBeDefined()
    expect(receivedCode!.length).toBeGreaterThan(0)
  })

  it('InteractionManager createPending builds correct AAuth-Requirement header with url and code', () => {
    const manager = new InteractionManager({
      baseUrl: AUTH_SERVER_URL,
      interactionUrl: INTERACTION_URL,
    })
    const { headers, pending } = manager.createPending()

    expect(pending.code).toBeDefined()
    expect(pending.code.length).toBe(8)
    expect(headers.Location).toMatch(/\/pending\//)
    expect(headers['AAuth-Requirement']).toContain('requirement=interaction')
    expect(headers['AAuth-Requirement']).toContain(`url="${INTERACTION_URL}"`)
    expect(headers['AAuth-Requirement']).toContain(`code="${pending.code}"`)

    // The header round-trips through parse
    const parsed = parseAAuthHeader(headers['AAuth-Requirement'])
    expect(parsed.requirement).toBe('interaction')
    expect(parsed.url).toBe(INTERACTION_URL)
    expect(parsed.code).toBe(pending.code)
  })
})

// =============================================================================
// Suite 5: ServerManager with AAuth signing
// =============================================================================

describe('ServerManager with AAuth signing (mocked MCP SDK)', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockListTools.mockResolvedValue({
      tools: [{ name: 'read_file' }, { name: 'write_file' }],
    })
  })

  it('createSignedFetch called with getKeyMaterial → connectAll succeeds', async () => {
    const keys = await createTestKeys()
    const agentJwt = await createAgentJwt(keys, AGENT_URL, AGENT_ID)
    const getKeyMaterial = createGetKeyMaterial(keys, agentJwt)

    const manager = new ServerManager({
      servers: { myfiles: `${RESOURCE_URL}/mcp` },
      getKeyMaterial,
    })

    await manager.connectAll()

    // Verify MCP SDK was called correctly
    expect(MockStreamableHTTPClientTransport).toHaveBeenCalledOnce()
    const [url, opts] = MockStreamableHTTPClientTransport.mock.calls[0]
    expect(url).toBeInstanceOf(URL)
    expect(url.href).toBe(`${RESOURCE_URL}/mcp`)
    // The transport should have received a fetch function
    expect(opts.fetch).toBeTypeOf('function')

    expect(MockClient).toHaveBeenCalledWith({
      name: 'aauth-myfiles',
      version: '0.0.1',
    })
    expect(mockConnect).toHaveBeenCalledOnce()
    expect(mockListTools).toHaveBeenCalledOnce()
  })

  it('callTool routes to correct server with original tool name', async () => {
    const keys = await createTestKeys()
    const agentJwt = await createAgentJwt(keys, AGENT_URL, AGENT_ID)
    const getKeyMaterial = createGetKeyMaterial(keys, agentJwt)

    mockCallTool.mockResolvedValue({ content: [{ type: 'text', text: 'file data' }] })

    const manager = new ServerManager({
      servers: { myfiles: `${RESOURCE_URL}/mcp` },
      getKeyMaterial,
    })

    await manager.connectAll()

    const tools = manager.getTools()
    expect(tools).toContainEqual({
      prefixedName: 'myfiles_read_file',
      serverName: 'myfiles',
      originalName: 'read_file',
    })

    const result = await manager.callTool('myfiles_read_file', { path: '/test.txt' })
    expect(mockCallTool).toHaveBeenCalledWith({
      name: 'read_file',
      arguments: { path: '/test.txt' },
    })
    expect(result).toEqual({ content: [{ type: 'text', text: 'file data' }] })
  })
})
