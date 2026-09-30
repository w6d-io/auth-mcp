import { describe, expect, it } from 'vitest'
import { SlidingWindowRateLimiter, rateKey } from '../../safety/rate-limit.js'

describe('SlidingWindowRateLimiter', () => {
  it('allows the budget per minute, then refuses with a Retry-After', () => {
    let now = 0
    const rl = new SlidingWindowRateLimiter({ read: 3, write: 1 }, 60_000, () => now)
    const key = rateKey('user-1', 'client-1')
    expect([1, 2, 3].map(() => rl.take(key, 'read').allowed)).toEqual([true, true, true])
    now = 10_000
    const refused = rl.take(key, 'read')
    expect(refused).toEqual({ allowed: false, remaining: 0, retryAfterSec: 50 })
    now = 60_001
    expect(rl.take(key, 'read').allowed).toBe(true)
  })

  it('keeps reads and writes, users and clients apart', () => {
    const rl = new SlidingWindowRateLimiter({ read: 1, write: 1 })
    expect(rl.take(rateKey('u', 'c'), 'read').allowed).toBe(true)
    expect(rl.take(rateKey('u', 'c'), 'write').allowed).toBe(true)
    expect(rl.take(rateKey('u', 'c2'), 'read').allowed).toBe(true)
    expect(rl.take(rateKey('u2', 'c'), 'read').allowed).toBe(true)
    expect(rl.take(rateKey('u', 'c'), 'read').allowed).toBe(false)
  })

  it('stays bounded in memory', () => {
    const rl = new SlidingWindowRateLimiter({ read: 5, write: 5 }, 60_000, Date.now, 100)
    for (let i = 0; i < 1000; i++) rl.take(`k${i}`, 'read')
    expect((rl as unknown as { hits: Map<string, number[]> }).hits.size).toBeLessThanOrEqual(100)
  })
})
