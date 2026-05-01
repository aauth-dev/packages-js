import { describe, it, expect, vi, beforeEach } from 'vitest'

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
  return { mockConnect, mockListTools, mockCallTool, MockClient, mockTransportClose, MockStreamableHTTPClientTransport, mockCreateSignedFetch }
})

vi.mock('@modelcontextprotocol/sdk/client/index.js', () => ({
  Client: MockClient,
}))

vi.mock('@modelcontextprotocol/sdk/client/streamableHttp.js', () => ({
  StreamableHTTPClientTransport: MockStreamableHTTPClientTransport,
}))

vi.mock('@aauth/mcp-agent', () => ({
  createSignedFetch: mockCreateSignedFetch,
}))

import { ServerManager } from './server-manager.js'

describe('ServerManager', () => {
  const getKeyMaterial = vi.fn()

  beforeEach(() => {
    vi.clearAllMocks()
    mockListTools.mockResolvedValue({
      tools: [
        {
          name: 'read_file',
          description: 'Read a file',
          inputSchema: { type: 'object', properties: { path: { type: 'string' } } },
        },
        { name: 'write_file' },
      ],
    })
  })

  it('connectAll creates transport and client per server', async () => {
    const manager = new ServerManager({
      servers: { myfiles: 'https://files.example.com/mcp' },
      getKeyMaterial,
    })

    await manager.connectAll()

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
      {
        prefixedName: 'myfiles_read_file',
        serverName: 'myfiles',
        originalName: 'read_file',
        description: 'Read a file',
        inputSchema: { type: 'object', properties: { path: { type: 'string' } } },
      },
      {
        prefixedName: 'myfiles_write_file',
        serverName: 'myfiles',
        originalName: 'write_file',
        description: undefined,
        inputSchema: undefined,
      },
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
})
