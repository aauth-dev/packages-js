import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { parseArgs } from './args.js'

describe('parseArgs', () => {
  const originalEnv = { ...process.env }
  const mockExit = vi.spyOn(process, 'exit').mockImplementation(() => {
    throw new Error('process.exit called')
  })

  beforeEach(() => {
    vi.clearAllMocks()
    delete process.env.AAUTH_AGENT_URL
    delete process.env.AAUTH_DELEGATE
    delete process.env.AAUTH_TOKEN_LIFETIME
  })

  afterEach(() => {
    process.env = { ...originalEnv }
  })

  it('parses server-url and --agent-url', () => {
    const result = parseArgs([
      'node', 'cli.js',
      'https://example.com/mcp',
      '--agent-url', 'https://agent.example.com',
    ])

    expect(result).toEqual({
      serverUrl: 'https://example.com/mcp',
      agentUrl: 'https://agent.example.com',
      delegate: undefined,
      tokenLifetime: undefined,
    })
  })

  it('parses all options', () => {
    const result = parseArgs([
      'node', 'cli.js',
      'https://example.com/mcp',
      '--agent-url', 'https://agent.example.com',
      '--delegate', 'claude',
      '--token-lifetime', '7200',
    ])

    expect(result).toEqual({
      serverUrl: 'https://example.com/mcp',
      agentUrl: 'https://agent.example.com',
      delegate: 'claude',
      tokenLifetime: 7200,
    })
  })

  it('falls back to AAUTH_AGENT_URL env var', () => {
    process.env.AAUTH_AGENT_URL = 'https://env-agent.example.com'

    const result = parseArgs([
      'node', 'cli.js',
      'https://example.com/mcp',
    ])

    expect(result.agentUrl).toBe('https://env-agent.example.com')
  })

  it('falls back to AAUTH_DELEGATE env var', () => {
    process.env.AAUTH_AGENT_URL = 'https://agent.example.com'
    process.env.AAUTH_DELEGATE = 'env-delegate'

    const result = parseArgs([
      'node', 'cli.js',
      'https://example.com/mcp',
    ])

    expect(result.delegate).toBe('env-delegate')
  })

  it('falls back to AAUTH_TOKEN_LIFETIME env var', () => {
    process.env.AAUTH_AGENT_URL = 'https://agent.example.com'
    process.env.AAUTH_TOKEN_LIFETIME = '1800'

    const result = parseArgs([
      'node', 'cli.js',
      'https://example.com/mcp',
    ])

    expect(result.tokenLifetime).toBe(1800)
  })

  it('CLI --agent-url overrides env var', () => {
    process.env.AAUTH_AGENT_URL = 'https://env.example.com'

    const result = parseArgs([
      'node', 'cli.js',
      'https://example.com/mcp',
      '--agent-url', 'https://cli.example.com',
    ])

    expect(result.agentUrl).toBe('https://cli.example.com')
  })

  it('exits on missing server-url', () => {
    expect(() => parseArgs(['node', 'cli.js'])).toThrow('process.exit called')
    expect(mockExit).toHaveBeenCalledWith(1)
  })

  it('exits when server-url starts with --', () => {
    expect(() => parseArgs(['node', 'cli.js', '--agent-url', 'https://a.com'])).toThrow('process.exit called')
    expect(mockExit).toHaveBeenCalledWith(1)
  })

  it('allows missing agent-url (resolved from config at runtime)', () => {
    const result = parseArgs([
      'node', 'cli.js',
      'https://example.com/mcp',
    ])
    expect(result.serverUrl).toBe('https://example.com/mcp')
    expect(result.agentUrl).toBeUndefined()
  })

  it('exits on non-numeric token-lifetime', () => {
    expect(() => parseArgs([
      'node', 'cli.js',
      'https://example.com/mcp',
      '--agent-url', 'https://agent.example.com',
      '--token-lifetime', 'abc',
    ])).toThrow('process.exit called')
    expect(mockExit).toHaveBeenCalledWith(1)
  })
})
