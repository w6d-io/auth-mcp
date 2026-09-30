/**
 * Responses are capped (64 KB by default) and say so with `truncated: true` rather than failing or
 * silently dropping (plan §4). Lists shrink from the end; anything else has its long strings cut.
 */

const bytes = (v: unknown) => Buffer.byteLength(JSON.stringify(v) ?? '', 'utf8')

function shortenStrings(value: unknown, cap: number): unknown {
  if (typeof value === 'string') return value.length > cap ? `${value.slice(0, cap)}…` : value
  if (Array.isArray(value)) return value.map((v) => shortenStrings(v, cap))
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, shortenStrings(v, cap)]))
  }
  return value
}

/** Fit `data` in `limit` bytes. The array to shrink is `data` itself or `data.items`. */
export function capSize(data: unknown, limit: number): { data: unknown; truncated: boolean } {
  if (bytes(data) <= limit) return { data, truncated: false }

  const list = Array.isArray(data)
    ? { get: () => data as unknown[], set: (xs: unknown[]) => xs as unknown }
    : data && typeof data === 'object' && Array.isArray((data as { items?: unknown }).items)
      ? { get: () => (data as { items: unknown[] }).items, set: (xs: unknown[]) => ({ ...(data as object), items: xs }) }
      : null

  if (list) {
    const all = list.get()
    let lo = 0
    let hi = all.length
    while (lo < hi) {
      const mid = Math.ceil((lo + hi) / 2)
      if (bytes(list.set(all.slice(0, mid))) <= limit) lo = mid
      else hi = mid - 1
    }
    if (lo > 0) return { data: list.set(all.slice(0, lo)), truncated: true }
  }

  for (const cap of [500, 120]) {
    const shorter = shortenStrings(data, cap)
    if (bytes(shorter) <= limit) return { data: shorter, truncated: true }
  }
  return { data: null, truncated: true }
}
