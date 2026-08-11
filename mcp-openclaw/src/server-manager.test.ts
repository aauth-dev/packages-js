import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { UnsupportedRequirementError } from '@aauth/protocol'

const {
  mockConnect, mockListTools, mockCallTool, MockClient,
  mockTransportClose, MockStreamableHTTPClientTransport,
  mockCreateSignedFetch, mockGetPersonToken, signedRequests, responseQueue,
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

  // Every signed request made through a mocked createSignedFetch, with the key
  // material that would have gone into its Signature-Key header.
  const signedRequests: Array<{ url: string; signatureKey: unknown }> = []
  const responseQueue: Response[] = []
  const mockCreateSignedFetch = vi.fn((getKeyMaterial: () => Promise<{ signatureKey: unknown }>) =>
    vi.fn(async (url: string | URL) => {
      const { signatureKey } = await getKeyMaterial()
      signedRequests.push({ url: String(url), signatureKey })
      return responseQueue.shift() ?? new Response(null, { status: 200 })
    }),
  )
  const mockGetPersonToken = vi.fn()

  return {
    mockConnect, mockListTools, mockCallTool, MockClient,
    mockTransportClose, MockStreamableHTTPClientTransport,
    mockCreateSignedFetch, mockGetPersonToken, signedRequests, responseQueue,
  }
})

vi.mock('@modelcontextprotocol/sdk/client/index.js', () => ({
  Client: MockClient,
}))

vi.mock('@modelcontextprotocol/sdk/client/streamableHttp.js', () => ({
  StreamableHTTPClientTransport: MockStreamableHTTPClientTransport,
}))

vi.mock('@aauth/agent', () => ({
  createSignedFetch: mockCreateSignedFetch,
  getPersonToken: mockGetPersonToken,
}))

import { ServerManager } from './server-manager.js'

function b64u(value: object): string {
  return Buffer.from(JSON.stringify(value)).toString('base64url')
}

function jwt(payload: Record<string, unknown>): string {
  return `${b64u({ alg: 'Ed25519', typ: 'aa-agent+jwt' })}.${b64u(payload)}.sig`
}

const AGENT_TOKEN = jwt({ sub: 'aauth:openclaw@example.com', ps: 'https://ps.example' })
const PS_LESS_AGENT_TOKEN = jwt({ sub: 'aauth:openclaw@example.com' })
const PERSON_TOKEN = jwt({ aud: 'https://files.example.com' })

/** Key material getter for an agent token with the given payload. */
function keyMaterial(agentToken = AGENT_TOKEN) {
  return vi.fn().mockResolvedValue({
    signingKey: { kty: 'OKP', crv: 'Ed25519' },
    signatureKey: { type: 'jwt', jwt: agentToken },
  })
}

/** Stub the resource-metadata fetch with a declared `access_mode`. */
function stubResourceMetadata(accessMode?: string): void {
  vi.stubGlobal('fetch', vi.fn(async () => (
    accessMode === undefined
      ? new Response(null, { status: 404 })
      : new Response(JSON.stringify({ access_mode: accessMode }), { status: 200 })
  )))
}

/** The `fetch` the transport was constructed with, for the nth server. */
function transportFetch(index = 0): (url: string, init?: RequestInit) => Promise<Response> {
  return MockStreamableHTTPClientTransport.mock.calls[index][1].fetch
}

describe('ServerManager', () => {
  let getKeyMaterial: ReturnType<typeof keyMaterial>

  beforeEach(() => {
    vi.clearAllMocks()
    signedRequests.length = 0
    responseQueue.length = 0
    getKeyMaterial = keyMaterial()
    stubResourceMetadata()
    mockListTools.mockResolvedValue({
      tools: [{ name: 'read_file' }, { name: 'write_file' }],
    })
    mockGetPersonToken.mockResolvedValue({
      personToken: PERSON_TOKEN,
      expiresIn: 3600,
    })
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('connectAll creates transport and client per server', async () => {
    const manager = new ServerManager({
      servers: { myfiles: 'https://files.example.com/mcp' },
      getKeyMaterial,
    })

    await manager.connectAll()

    // The agent-token fetch (person server) is built from getKeyMaterial itself.
    expect(mockCreateSignedFetch).toHaveBeenCalledWith(getKeyMaterial)
    expect(MockStreamableHTTPClientTransport).toHaveBeenCalledOnce()
    const [url] = MockStreamableHTTPClientTransport.mock.calls[0]
    expect(url).toBeInstanceOf(URL)
    expect(url.href).toBe('https://files.example.com/mcp')
    expect(MockClient).toHaveBeenCalledWith({
      name: 'aauth-myfiles',
      version: '0.0.1',
    })
    expect(mockConnect).toHaveBeenCalledOnce()
    expect(mockListTools).toHaveBeenCalledOnce()
  })

  it('connects to multiple servers', async () => {
    const manager = new ServerManager({
      servers: {
        files: 'https://files.example.com/mcp',
        db: 'https://db.example.com/mcp',
      },
      getKeyMaterial,
    })

    await manager.connectAll()

    expect(MockStreamableHTTPClientTransport).toHaveBeenCalledTimes(2)
    expect(MockClient).toHaveBeenCalledTimes(2)
  })

  it('getTools returns tools prefixed with server name', async () => {
    const manager = new ServerManager({
      servers: { myfiles: 'https://files.example.com/mcp' },
      getKeyMaterial,
    })

    await manager.connectAll()
    const tools = manager.getTools()

    expect(tools).toEqual([
      { prefixedName: 'myfiles_read_file', serverName: 'myfiles', originalName: 'read_file' },
      { prefixedName: 'myfiles_write_file', serverName: 'myfiles', originalName: 'write_file' },
    ])
  })

  it('callTool routes to correct client with original name', async () => {
    mockCallTool.mockResolvedValue({ content: [{ type: 'text', text: 'data' }] })

    const manager = new ServerManager({
      servers: { myfiles: 'https://files.example.com/mcp' },
      getKeyMaterial,
    })

    await manager.connectAll()
    const result = await manager.callTool('myfiles_read_file', { path: '/test' })

    expect(mockCallTool).toHaveBeenCalledWith({
      name: 'read_file',
      arguments: { path: '/test' },
    })
    expect(result).toEqual({ content: [{ type: 'text', text: 'data' }] })
  })

  it('callTool throws for unknown tool', async () => {
    const manager = new ServerManager({
      servers: { myfiles: 'https://files.example.com/mcp' },
      getKeyMaterial,
    })

    await manager.connectAll()

    await expect(manager.callTool('unknown_tool', {})).rejects.toThrow(
      'Unknown tool: unknown_tool',
    )
  })

  it('shutdown closes all transports', async () => {
    const manager = new ServerManager({
      servers: {
        files: 'https://files.example.com/mcp',
        db: 'https://db.example.com/mcp',
      },
      getKeyMaterial,
    })

    await manager.connectAll()
    await manager.shutdown()

    expect(mockTransportClose).toHaveBeenCalledTimes(2)
  })

  describe('person token', () => {
    it('is not requested when the resource declares agent-token access', async () => {
      stubResourceMetadata('agent-token')
      const manager = new ServerManager({
        servers: { myfiles: 'https://files.example.com/mcp' },
        getKeyMaterial,
      })

      await manager.connectAll()
      await transportFetch()('https://files.example.com/mcp')

      expect(mockGetPersonToken).not.toHaveBeenCalled()
      expect(signedRequests.at(-1)?.signatureKey).toEqual({ type: 'jwt', jwt: AGENT_TOKEN })
    })

    it('is obtained up front when the resource declares person-token access', async () => {
      stubResourceMetadata('person-token')
      const manager = new ServerManager({
        servers: { myfiles: 'https://files.example.com/mcp' },
        getKeyMaterial,
        missionS256: 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
      })

      await manager.connectAll()

      expect(mockGetPersonToken).toHaveBeenCalledOnce()
      expect(mockGetPersonToken.mock.calls[0][0]).toMatchObject({
        // The PS comes from the agent token's `ps` claim, the resource is the
        // MCP server's origin — it becomes the person token's `aud`.
        personServerUrl: 'https://ps.example',
        resource: 'https://files.example.com',
        missionS256: 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
      })
    })

    it('is obtained up front when the resource declares auth-token access', async () => {
      stubResourceMetadata('auth-token')
      const manager = new ServerManager({
        servers: { myfiles: 'https://files.example.com/mcp' },
        getKeyMaterial,
      })

      await manager.connectAll()

      expect(mockGetPersonToken).toHaveBeenCalledOnce()
    })

    it('replaces the agent token in the signature key once held', async () => {
      stubResourceMetadata('person-token')
      const manager = new ServerManager({
        servers: { myfiles: 'https://files.example.com/mcp' },
        getKeyMaterial,
      })

      await manager.connectAll()
      await transportFetch()('https://files.example.com/mcp')

      expect(signedRequests.at(-1)?.signatureKey).toEqual({ type: 'jwt', jwt: PERSON_TOKEN })
    })

    it('uses the configured person server over the agent token ps claim', async () => {
      stubResourceMetadata('person-token')
      const manager = new ServerManager({
        servers: { myfiles: 'https://files.example.com/mcp' },
        getKeyMaterial,
        personServerUrl: 'https://other-ps.example',
      })

      await manager.connectAll()

      expect(mockGetPersonToken.mock.calls[0][0]).toMatchObject({
        personServerUrl: 'https://other-ps.example',
      })
    })

    it('caches PS metadata from the first request and reports it', async () => {
      // -11 renamed `token_endpoint` to `auth_token_endpoint` and added the
      // REQUIRED `person_token_endpoint`.
      const metadata = {
        auth_token_endpoint: 'https://ps.example/token',
        person_token_endpoint: 'https://ps.example/person',
      }
      const onPersonServerMetadata = vi.fn()
      mockGetPersonToken.mockImplementation(async (options: {
        onMetadata?: (m: typeof metadata) => void
      }) => {
        options.onMetadata?.(metadata)
        return { personToken: PERSON_TOKEN, expiresIn: 3600 }
      })
      stubResourceMetadata('person-token')

      const manager = new ServerManager({
        servers: { myfiles: 'https://files.example.com/mcp' },
        getKeyMaterial,
        onPersonServerMetadata,
      })

      await manager.connectAll()
      expect(onPersonServerMetadata).toHaveBeenCalledWith(metadata)
      expect(mockGetPersonToken.mock.calls[0][0].personServerMetadata).toBeUndefined()

      // A later person token request reuses the cached copy — no second
      // /.well-known fetch at the PS.
      responseQueue.push(
        new Response(null, {
          status: 401,
          headers: { 'AAuth-Requirement': 'requirement=person-token' },
        }),
        new Response('{}', { status: 200 }),
      )
      await transportFetch()('https://files.example.com/mcp')

      expect(mockGetPersonToken).toHaveBeenCalledTimes(2)
      expect(mockGetPersonToken.mock.calls[1][0].personServerMetadata).toEqual(metadata)
    })
  })

  describe('AAuth-Requirement challenges', () => {
    it('obtains a person token and retries on requirement=person-token', async () => {
      const manager = new ServerManager({
        servers: { myfiles: 'https://files.example.com/mcp' },
        getKeyMaterial,
      })
      await manager.connectAll()
      expect(mockGetPersonToken).not.toHaveBeenCalled()

      responseQueue.push(
        new Response(null, {
          status: 401,
          headers: { 'AAuth-Requirement': 'requirement=person-token' },
        }),
        new Response('{}', { status: 200 }),
      )

      const response = await transportFetch()('https://files.example.com/mcp', {
        method: 'POST',
        body: '{"jsonrpc":"2.0"}',
      })

      expect(response.status).toBe(200)
      expect(mockGetPersonToken).toHaveBeenCalledOnce()
      expect(mockGetPersonToken.mock.calls[0][0]).toMatchObject({
        resource: 'https://files.example.com',
      })
      // First attempt on the agent token, retry on the person token.
      expect(signedRequests.map((r) => r.signatureKey)).toEqual([
        { type: 'jwt', jwt: AGENT_TOKEN },
        { type: 'jwt', jwt: PERSON_TOKEN },
      ])
    })

    it('surfaces an unrecognized requirement as an error', async () => {
      const manager = new ServerManager({
        servers: { myfiles: 'https://files.example.com/mcp' },
        getKeyMaterial,
      })
      await manager.connectAll()

      responseQueue.push(
        new Response(null, {
          status: 401,
          headers: { 'AAuth-Requirement': 'requirement=quantum-token' },
        }),
      )

      await expect(
        transportFetch()('https://files.example.com/mcp'),
      ).rejects.toThrow(UnsupportedRequirementError)
      expect(mockGetPersonToken).not.toHaveBeenCalled()
    })

    it('passes through a 401 with no AAuth-Requirement header', async () => {
      const manager = new ServerManager({
        servers: { myfiles: 'https://files.example.com/mcp' },
        getKeyMaterial,
      })
      await manager.connectAll()

      responseQueue.push(new Response(null, { status: 401 }))

      const response = await transportFetch()('https://files.example.com/mcp')

      expect(response.status).toBe(401)
      expect(mockGetPersonToken).not.toHaveBeenCalled()
    })
  })

  describe('access mode planning', () => {
    it('skips a resource this agent cannot satisfy', async () => {
      stubResourceMetadata('auth-token')
      const manager = new ServerManager({
        servers: { myfiles: 'https://files.example.com/mcp' },
        getKeyMaterial: keyMaterial(PS_LESS_AGENT_TOKEN),
      })

      await manager.connectAll()

      expect(MockStreamableHTTPClientTransport).not.toHaveBeenCalled()
      expect(manager.getTools()).toEqual([])
      const [skipped] = manager.getSkippedServers()
      expect(skipped).toMatchObject({
        name: 'myfiles',
        url: 'https://files.example.com/mcp',
        mode: 'auth-token',
      })
      expect(skipped.reason).toBeTruthy()
    })

    it('connects when the resource declares a mode it does not recognize', async () => {
      stubResourceMetadata('some-future-mode')
      const manager = new ServerManager({
        servers: { myfiles: 'https://files.example.com/mcp' },
        getKeyMaterial,
      })

      await manager.connectAll()

      expect(manager.getSkippedServers()).toEqual([])
      expect(MockStreamableHTTPClientTransport).toHaveBeenCalledOnce()
      expect(mockGetPersonToken).not.toHaveBeenCalled()
    })

    it('connects when the resource publishes no metadata', async () => {
      const manager = new ServerManager({
        servers: { myfiles: 'https://files.example.com/mcp' },
        getKeyMaterial,
      })

      await manager.connectAll()

      expect(manager.getSkippedServers()).toEqual([])
      expect(MockStreamableHTTPClientTransport).toHaveBeenCalledOnce()
    })
  })
})
