/**
 * Keys revoked through this replica (revoke_my_key). jinbe is the authority — a revoked key's tokens
 * stop at its next introspection — but auth-mcp caches the key's exchanged token (up to 10 minutes)
 * and the verified principal (TOKEN_CACHE_TTL_MS), and answers some tools locally, so without this a
 * revoked key kept working here until those caches ran out. Listeners drop the cache entries; the set
 * refuses the key at once on this replica. Other replicas fall back on their cache TTL.
 */
export class KeyRevocations {
  private readonly revoked = new Map<string, number>()
  private readonly listeners: Array<(keyId: string) => void> = []

  constructor(
    /** Longer than any token a key can have been exchanged for. */
    private readonly ttlMs = 60 * 60 * 1000,
    private readonly maxEntries = 10_000,
    private readonly now: () => number = Date.now
  ) {}

  onRevoke(listener: (keyId: string) => void): void {
    this.listeners.push(listener)
  }

  revoke(keyId: string): void {
    if (this.revoked.size >= this.maxEntries) this.revoked.delete(this.revoked.keys().next().value as string)
    this.revoked.set(keyId, this.now() + this.ttlMs)
    for (const listener of this.listeners) listener(keyId)
  }

  isRevoked(keyId: string | null | undefined): boolean {
    if (!keyId) return false
    const until = this.revoked.get(keyId)
    if (until === undefined) return false
    if (until > this.now()) return true
    this.revoked.delete(keyId)
    return false
  }
}
