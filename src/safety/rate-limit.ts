/**
 * Per (subject, client) budgets (plan §5): 60 reads/min and 10 writes/min by default. A sliding
 * window over the last minute, in memory; the store is an interface so a Redis one can replace it
 * when auth-mcp runs more than one replica (each replica otherwise grants the full budget).
 */

export type Bucket = 'read' | 'write'

export interface RateLimitDecision {
  allowed: boolean
  remaining: number
  retryAfterSec: number
}

export interface RateLimiter {
  take(key: string, bucket: Bucket): RateLimitDecision
}

export class SlidingWindowRateLimiter implements RateLimiter {
  private readonly hits = new Map<string, number[]>()

  constructor(
    private readonly limits: Record<Bucket, number>,
    private readonly windowMs = 60_000,
    private readonly now: () => number = Date.now,
    private readonly maxKeys = 50_000
  ) {}

  take(key: string, bucket: Bucket): RateLimitDecision {
    const limit = this.limits[bucket]
    const id = `${bucket}\0${key}`
    const t = this.now()
    const since = t - this.windowMs
    const recent = (this.hits.get(id) ?? []).filter((at) => at > since)
    if (recent.length >= limit) {
      this.hits.set(id, recent)
      const retryAfterSec = Math.max(1, Math.ceil((recent[0] + this.windowMs - t) / 1000))
      return { allowed: false, remaining: 0, retryAfterSec }
    }
    recent.push(t)
    if (!this.hits.has(id) && this.hits.size >= this.maxKeys) this.sweep(since)
    this.hits.set(id, recent)
    return { allowed: true, remaining: limit - recent.length, retryAfterSec: 0 }
  }

  private sweep(since: number): void {
    for (const [id, times] of this.hits) {
      if (times.every((at) => at <= since)) this.hits.delete(id)
    }
    // Still full: drop the oldest keys rather than grow without bound.
    while (this.hits.size >= this.maxKeys) this.hits.delete(this.hits.keys().next().value as string)
  }
}

/** The budget key: the human and the client, so one runaway client does not starve the user's others. */
export const rateKey = (subject: string, clientId: string) => `${subject}\0${clientId}`
