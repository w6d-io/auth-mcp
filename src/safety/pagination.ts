import { createHash } from 'node:crypto'
import { toolError } from './errors.js'

/**
 * Opaque cursors for lists jinbe returns whole (sites, groups, versions): an offset bound to the
 * query it was issued for, so a cursor from one list cannot be replayed against another. Not a
 * secret — tampering yields at worst another page of what the caller could list anyway.
 */

export const DEFAULT_LIMIT = 50
export const MAX_LIMIT = 100

interface CursorBody {
  o: number
  q: string
}

const queryHash = (query: string) => createHash('sha256').update(query).digest('base64url').slice(0, 16)

export function encodeCursor(offset: number, query: string): string {
  return Buffer.from(JSON.stringify({ o: offset, q: queryHash(query) } satisfies CursorBody)).toString('base64url')
}

export function decodeCursor(cursor: string | undefined, query: string): number {
  if (!cursor) return 0
  if (cursor.length > 256) throw toolError('invalid_cursor', 'Not a cursor this server issued')
  try {
    const body = JSON.parse(Buffer.from(cursor, 'base64url').toString('utf8')) as CursorBody
    if (!Number.isInteger(body.o) || body.o < 0 || body.o > 1_000_000 || body.q !== queryHash(query)) throw new Error('mismatch')
    return body.o
  } catch {
    throw toolError('invalid_cursor', 'Not a cursor this server issued for this query')
  }
}

export interface Page<T> {
  items: T[]
  total: number
  nextCursor: string | null
}

export function paginate<T>(all: readonly T[], opts: { limit?: number; cursor?: string; query: string }): Page<T> {
  const limit = Math.min(Math.max(1, opts.limit ?? DEFAULT_LIMIT), MAX_LIMIT)
  const offset = decodeCursor(opts.cursor, opts.query)
  const items = all.slice(offset, offset + limit)
  const next = offset + limit < all.length ? encodeCursor(offset + limit, opts.query) : null
  return { items, total: all.length, nextCursor: next }
}
