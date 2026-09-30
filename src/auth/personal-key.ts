import { AuthError, mcpDisabledFrom } from './types.js'
import { sha256 } from './bearer.js'
import type { ActorTokenSource } from './actor-token.js'

/**
 * Personal MCP keys (`stk_mcp_<client_id>.<secret>`) are Hydra client_credentials clients owned by a
 * user. The key never reaches jinbe: it is exchanged for a 10-minute access token, cached per key
 * until shortly before expiry, and that token goes through the same verifier as an OAuth token — so
 * introspection, scopes and audit are identical for both.
 */
export interface KeyExchanger {
  exchange(keyId: string, secret: string): Promise<{ accessToken: string; expiresIn: number }>
}

type Fetch = typeof fetch

interface TokenResponse {
  access_token?: unknown
  expires_in?: unknown
}

function tokenFrom(body: TokenResponse): { accessToken: string; expiresIn: number } {
  if (typeof body.access_token !== 'string' || !body.access_token) throw new AuthError('invalid_key', 'No token was issued')
  const expiresIn = typeof body.expires_in === 'number' && body.expires_in > 0 ? body.expires_in : 600
  return { accessToken: body.access_token, expiresIn }
}

/**
 * Directly at Hydra public `/oauth2/token`. Hydra grants only the scopes REQUESTED, so this needs the
 * key's scope set up front (`requestScopes`); without jinbe telling us, it asks for `mcp` alone, which
 * is enough for get_my_identity and nothing else. Use JinbeKeyExchanger in environments where jinbe has it.
 */
export class HydraClientCredentialsExchanger implements KeyExchanger {
  constructor(
    private readonly publicUrl: string,
    private readonly resource: string,
    private readonly requestScopes: readonly string[] = ['mcp'],
    private readonly fetchImpl: Fetch = fetch
  ) {}

  async exchange(keyId: string, secret: string) {
    const basic = Buffer.from(`${encodeURIComponent(keyId)}:${encodeURIComponent(secret)}`).toString('base64')
    let res: Response
    try {
      res = await this.fetchImpl(new URL('/oauth2/token', this.publicUrl), {
        method: 'POST',
        headers: {
          authorization: `Basic ${basic}`,
          'content-type': 'application/x-www-form-urlencoded',
          accept: 'application/json',
        },
        body: new URLSearchParams({
          grant_type: 'client_credentials',
          scope: this.requestScopes.join(' '),
          audience: this.resource,
        }).toString(),
        signal: AbortSignal.timeout(5000),
      })
    } catch {
      throw new AuthError('verifier_unavailable', 'The authorization server did not answer')
    }
    if (res.status === 400 || res.status === 401) throw new AuthError('invalid_key', 'The personal key was refused')
    if (!res.ok) throw new AuthError('verifier_unavailable', `Token exchange failed (${res.status})`)
    return tokenFrom((await res.json()) as TokenResponse)
  }
}

/**
 * jinbe does the exchange (proposed W2 contract, NOT IN JINBE YET):
 *   POST /api/mcp/personal-keys/exchange   Authorization: Bearer stk_mcp_…   X-Actor-Token: <SA token>
 *   200 → { access_token, expires_in }   401 → unknown, expired or revoked
 *   403 {error: 'mcp_disabled'} → an administrator turned MCP off, or limited it to other groups
 * jinbe knows the key's metadata (subject, scopes or "all my permissions", expiry), re-intersects the
 * scopes with the holder's CURRENT rights on every call, and records last_used_at. A key is not bound
 * to an organisation.
 */
export class JinbeKeyExchanger implements KeyExchanger {
  constructor(
    private readonly jinbeUrl: string,
    private readonly actor: ActorTokenSource,
    private readonly fetchImpl: Fetch = fetch
  ) {}

  async exchange(keyId: string, secret: string) {
    let res: Response
    try {
      res = await this.fetchImpl(new URL('/api/mcp/personal-keys/exchange', this.jinbeUrl), {
        method: 'POST',
        headers: {
          authorization: `Bearer stk_mcp_${keyId}.${secret}`,
          'x-actor-token': await this.actor.get(),
          accept: 'application/json',
        },
        signal: AbortSignal.timeout(5000),
      })
    } catch {
      throw new AuthError('verifier_unavailable', 'jinbe did not answer')
    }
    const off = await mcpDisabledFrom(res)
    if (off) throw off
    if (res.status === 401 || res.status === 403 || res.status === 404) throw new AuthError('invalid_key', 'The personal key was refused')
    if (!res.ok) throw new AuthError('verifier_unavailable', `Token exchange failed (${res.status})`)
    return tokenFrom((await res.json()) as TokenResponse)
  }
}

/** Caches one access token per key (keyed by sha256 of the whole key) until 30 s before it expires. */
export class CachingKeyExchanger implements KeyExchanger {
  private readonly cache = new Map<string, { keyId: string; accessToken: string; expiresIn: number; until: number }>()

  constructor(
    private readonly inner: KeyExchanger,
    private readonly maxEntries = 10_000,
    private readonly now: () => number = Date.now
  ) {}

  async exchange(keyId: string, secret: string) {
    const key = sha256(`${keyId}.${secret}`)
    const t = this.now()
    const hit = this.cache.get(key)
    if (hit && hit.until > t) return { accessToken: hit.accessToken, expiresIn: Math.floor((hit.until - t) / 1000) }
    if (hit) this.cache.delete(key)
    const out = await this.inner.exchange(keyId, secret)
    if (this.cache.size >= this.maxEntries) this.cache.delete(this.cache.keys().next().value as string)
    this.cache.set(key, { keyId, ...out, until: t + Math.max(0, out.expiresIn - 30) * 1000 })
    return out
  }

  /** Drop every cached token of a key (revoked): the next use exchanges again, and is refused. */
  forgetKey(keyId: string): void {
    for (const [k, v] of this.cache) if (v.keyId === keyId) this.cache.delete(k)
  }
}
