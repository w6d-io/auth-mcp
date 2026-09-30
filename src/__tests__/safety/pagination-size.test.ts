import { describe, expect, it } from 'vitest'
import { decodeCursor, encodeCursor, paginate } from '../../safety/pagination.js'
import { capSize } from '../../safety/size.js'

describe('paginate', () => {
  const all = Array.from({ length: 120 }, (_, i) => i)

  it('pages with an opaque cursor', () => {
    const p1 = paginate(all, { query: 'q' })
    expect(p1.items).toHaveLength(50)
    expect(p1.total).toBe(120)
    const p2 = paginate(all, { query: 'q', cursor: p1.nextCursor!, limit: 100 })
    expect(p2.items[0]).toBe(50)
    expect(p2.items).toHaveLength(70)
    expect(p2.nextCursor).toBeNull()
  })

  it('caps the limit at 100', () => expect(paginate(all, { query: 'q', limit: 1000 }).items).toHaveLength(100))

  it('refuses a cursor issued for another query, or forged', () => {
    const c = encodeCursor(50, 'list_sites')
    expect(decodeCursor(c, 'list_sites')).toBe(50)
    expect(() => decodeCursor(c, 'list_groups')).toThrow(/cursor/)
    expect(() => decodeCursor('not-a-cursor', 'q')).toThrow(/cursor/)
    expect(() => decodeCursor(Buffer.from('{"o":-5,"q":"x"}').toString('base64url'), 'q')).toThrow(/cursor/)
    expect(() => decodeCursor('x'.repeat(300), 'q')).toThrow(/cursor/)
  })
})

describe('capSize', () => {
  it('passes small data through', () => expect(capSize({ a: 1 }, 100)).toEqual({ data: { a: 1 }, truncated: false }))

  it('shrinks data.items from the end and flags it', () => {
    const data = { items: Array.from({ length: 1000 }, (_, i) => ({ i, pad: 'x'.repeat(50) })), total: 1000 }
    const out = capSize(data, 4096)
    expect(out.truncated).toBe(true)
    expect(Buffer.byteLength(JSON.stringify(out.data))).toBeLessThanOrEqual(4096)
    expect((out.data as typeof data).items[0].i).toBe(0)
    expect((out.data as typeof data).total).toBe(1000)
  })

  it('cuts long strings when there is no list', () => {
    const out = capSize({ template: 'y'.repeat(100_000) }, 1024)
    expect(out.truncated).toBe(true)
    expect(Buffer.byteLength(JSON.stringify(out.data))).toBeLessThanOrEqual(1024)
  })

  it('gives up to null rather than exceed', () => {
    const wide = Object.fromEntries(Array.from({ length: 5000 }, (_, i) => [`k${i}`, i]))
    expect(capSize(wide, 512)).toEqual({ data: null, truncated: true })
  })
})
