import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'

// Mock the network-touching handlers so we test dispatch only (no consent/HTTP).
vi.mock('./handlers.js', () => ({
  resolvePersonServer: vi.fn(() => 'https://ps.example'),
  buildGetKeyMaterial: vi.fn(() => async () => ({})),
  buildRequestInit: vi.fn(() => ({ method: 'GET', headers: new Headers() })),
  handleAuthorize: vi.fn(async () => {}),
  handlePreAuthed: vi.fn(async () => {}),
  handleAgentOnly: vi.fn(async () => {}),
  handleFullFlow: vi.fn(async () => {}),
}))

// Mock only stdin reading; keep a simple real-ish merge.
vi.mock('./json-input.js', () => ({
  readJsonInput: vi.fn(async () => ({ url: 'https://from-json.example' })),
  mergeJsonInput: (args: Record<string, unknown>, json: Record<string, unknown>) => ({ ...args, ...json }),
}))

import { run } from './cli.js'
import {
  handleAuthorize,
  handlePreAuthed,
  handleAgentOnly,
  handleFullFlow,
} from './handlers.js'
import { readJsonInput } from './json-input.js'

// --- harness ---

let out: string[]
let err: string[]
const origLog = console.log
const origErr = console.error
const origArgv = process.argv

function setArgv(...cliArgs: string[]) {
  process.argv = ['node', '/x/cli.js', ...cliArgs]
}

beforeEach(() => {
  vi.clearAllMocks()
  out = []
  err = []
  console.log = (...a: unknown[]) => out.push(a.join(' '))
  console.error = (...a: unknown[]) => err.push(a.join(' '))
  process.exitCode = undefined
})

afterEach(() => {
  console.log = origLog
  console.error = origErr
  process.argv = origArgv
  process.exitCode = undefined
})

const noHandlerCalled = () => {
  expect(handleFullFlow).not.toHaveBeenCalled()
  expect(handleAgentOnly).not.toHaveBeenCalled()
  expect(handlePreAuthed).not.toHaveBeenCalled()
  expect(handleAuthorize).not.toHaveBeenCalled()
}

describe('cli dispatch', () => {
  it('--version prints the version and runs no handler', async () => {
    setArgv('--version')
    await run()
    expect(out.join('\n')).toMatch(/^\d+\.\d+\.\d+$/m)
    noHandlerCalled()
  })

  it('bare invocation prints top-level help', async () => {
    setArgv()
    await run()
    expect(out.join('\n')).toContain('DESCRIPTION')
    expect(out.join('\n')).toContain('USAGE')
    noHandlerCalled()
  })

  it('--help prints top-level help', async () => {
    setArgv('--help')
    await run()
    expect(out.join('\n')).toContain('DESCRIPTION')
    noHandlerCalled()
  })

  it('skill prints the one guide and folds in the protocol spec URL', async () => {
    setArgv('skill')
    await run()
    const md = out.join('\n')
    expect(md).toContain('@aauth/fetch')
    expect(md).toContain('## AAuth protocol spec')
    expect(md).toContain('draft-hardt-oauth-aauth-protocol.md')
    noHandlerCalled()
  })

  it('skill ignores any extra name (single guide, no selection)', async () => {
    setArgv('skill', 'anything')
    await run()
    expect(out.join('\n')).toContain('@aauth/fetch')
    expect(process.exitCode).toBeUndefined()
    noHandlerCalled()
  })

  it('skill --help prints the skill command help', async () => {
    setArgv('skill', '--help')
    await run()
    expect(out.join('\n').toLowerCase()).toContain('skill')
    noHandlerCalled()
  })

  it('bare <url> dispatches to the full flow', async () => {
    setArgv('https://api.example')
    await run()
    expect(handleFullFlow).toHaveBeenCalledOnce()
    expect((handleFullFlow as ReturnType<typeof vi.fn>).mock.calls[0][0]).toMatchObject({ url: 'https://api.example' })
    expect(handleAgentOnly).not.toHaveBeenCalled()
    expect(handlePreAuthed).not.toHaveBeenCalled()
  })

  it('--agent-only dispatches to agent-only mode', async () => {
    setArgv('--agent-only', 'https://api.example')
    await run()
    expect(handleAgentOnly).toHaveBeenCalledOnce()
    expect(handleFullFlow).not.toHaveBeenCalled()
  })

  it('--auth-token + --signing-key dispatches to pre-authed mode', async () => {
    setArgv('--auth-token', 'eyJ.tok', '--signing-key', '{"kty":"OKP"}', 'https://api.example')
    await run()
    expect(handlePreAuthed).toHaveBeenCalledOnce()
    expect(handleFullFlow).not.toHaveBeenCalled()
    expect(handleAgentOnly).not.toHaveBeenCalled()
  })

  it('authorize <url> dispatches to handleAuthorize', async () => {
    setArgv('authorize', 'https://api.example/authorize')
    await run()
    expect(handleAuthorize).toHaveBeenCalledOnce()
    expect((handleAuthorize as ReturnType<typeof vi.fn>).mock.calls[0][0]).toMatchObject({ url: 'https://api.example/authorize' })
  })

  it('authorize with no url prints its help and exits 1', async () => {
    setArgv('authorize')
    await run()
    expect(process.exitCode).toBe(1)
    expect(handleAuthorize).not.toHaveBeenCalled()
  })

  it('authorize --help prints its help without erroring', async () => {
    setArgv('authorize', '--help')
    await run()
    expect(process.exitCode).toBeUndefined()
    expect(handleAuthorize).not.toHaveBeenCalled()
  })

  it('--json reads stdin and dispatches with the merged url', async () => {
    setArgv('--json')
    await run()
    expect(readJsonInput).toHaveBeenCalledOnce()
    expect(handleFullFlow).toHaveBeenCalledOnce()
    expect((handleFullFlow as ReturnType<typeof vi.fn>).mock.calls[0][0]).toMatchObject({ url: 'https://from-json.example' })
  })
})
