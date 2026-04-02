import { describe, it, expect, vi, beforeEach } from 'vitest'
import { InteractionManager } from './interaction.js'

describe('InteractionManager', () => {
  let manager: InteractionManager

  beforeEach(() => {
    manager = new InteractionManager({
      baseUrl: 'https://resource.example',
      interactionUrl: 'https://resource.example/interact',
    })
  })

  it('creates a pending request with headers', () => {
    const { headers, pending } = manager.createPending()

    expect(pending.id).toBeTruthy()
    expect(pending.code).toHaveLength(8)
    expect(pending.createdAt).toBeGreaterThan(0)
    expect(pending.promise).toBeInstanceOf(Promise)

    expect(headers.Location).toMatch(/^https:\/\/resource\.example\/pending\/[a-f0-9]+$/)
    expect(headers['Retry-After']).toBe('0')
    expect(headers['Cache-Control']).toBe('no-store')
    expect(headers['AAuth-Requirement']).toContain('requirement=interaction')
    expect(headers['AAuth-Requirement']).toContain('url="https://resource.example/interact"')
    expect(headers['AAuth-Requirement']).toContain(`code="${pending.code}"`)
  })

  it('generates unique IDs and codes', () => {
    const a = manager.createPending()
    const b = manager.createPending()

    expect(a.pending.id).not.toBe(b.pending.id)
    // Codes could theoretically collide but very unlikely
  })

  it('looks up pending by ID', () => {
    const { pending } = manager.createPending()
    const found = manager.getPending(pending.id)
    expect(found).toBe(pending)
  })

  it('returns undefined for unknown ID', () => {
    expect(manager.getPending('nonexistent')).toBeUndefined()
  })

  it('resolves a pending request', async () => {
    const { pending } = manager.createPending()
    manager.resolve(pending.id, { auth_token: 'tok' })

    const result = await pending.promise
    expect(result).toEqual({ auth_token: 'tok' })
    expect(manager.size).toBe(0)
  })

  it('rejects a pending request', async () => {
    const { pending } = manager.createPending()
    manager.reject(pending.id, 'User denied')

    await expect(pending.promise).rejects.toThrow('User denied')
    expect(manager.size).toBe(0)
  })

  it('throws on resolve with unknown ID', () => {
    expect(() => manager.resolve('fake', {})).toThrow('No pending request')
  })

  it('throws on reject with unknown ID', () => {
    expect(() => manager.reject('fake', 'err')).toThrow('No pending request')
  })

  it('cleans up expired pending requests', async () => {
    const shortManager = new InteractionManager({
      baseUrl: 'https://resource.example',
      interactionUrl: 'https://resource.example/interact',
      ttl: 0, // expire immediately
    })

    const { pending } = shortManager.createPending()
    expect(shortManager.size).toBe(1)

    // Wait a tick so Date.now() advances past creation
    await new Promise((r) => setTimeout(r, 10))

    shortManager.cleanup()
    expect(shortManager.size).toBe(0)

    await expect(pending.promise).rejects.toThrow('expired')
  })

  it('uses custom pendingPath', () => {
    const custom = new InteractionManager({
      baseUrl: 'https://resource.example',
      interactionUrl: 'https://resource.example/interact',
      pendingPath: '/api/pending',
    })

    const { headers } = custom.createPending()
    expect(headers.Location).toContain('/api/pending/')
  })

  it('uses custom code length', () => {
    const custom = new InteractionManager({
      baseUrl: 'https://resource.example',
      interactionUrl: 'https://resource.example/interact',
      codeLength: 12,
    })

    const { pending } = custom.createPending()
    expect(pending.code).toHaveLength(12)
  })

  it('strips trailing slash from baseUrl', () => {
    const custom = new InteractionManager({
      baseUrl: 'https://resource.example/',
      interactionUrl: 'https://resource.example/interact',
    })

    const { headers } = custom.createPending()
    // Should not have double slash between host and path (https:// is fine)
    const path = headers.Location.replace('https://', '')
    expect(path).not.toContain('//')
    expect(headers.Location).toMatch(/^https:\/\/resource\.example\/pending\//)
  })
})
