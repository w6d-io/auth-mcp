import { AuthError, mcpDisabledFrom, type Principal } from './types.js'
import { MCP_SCOPE, parseScopeString, usableScopes } from './scopes.js'
import { sha256 } from './bearer.js'
import type { ActorTokenSource } from './actor-token.js'

/**
 * Turns an access token into a Principal, or refuses it. Two real implementations, one seam:
 *
 *   HydraIntrospectionVerifier — RFC 7662 at hydra-admin. Works today, but needs auth-mcp → hydra-admin
 *     in the NetworkPolicy, and hydra-admin is also where clients are minted.
 *   JinbeTokenInfoVerifier — asks jinbe (`POST /api/mcp/token-info`, with the actor token), which
 *     introspects on our behalf. Keeps hydra-admin closed to everything but jinbe. NOT IN JINBE YET.
 *
 * Both apply the same claim rules (principalFromClaims), so the choice is about the network, not the
 * semantics.
 */
export interface TokenVerifier {
  verify(token: string): Promise<Principal>
}

/** The introspection claims auth-mcp reads (RFC 7662 + Hydra's `ext`, set by the consent app / token hook). */
export interface IntrospectionClaims {
  active?: boolean
  scope?: string
  client_id?: string
  sub?: string
  exp?: number
  aud?: string[] | string
  token_use?: string
  ext?: {
    org?: unknown
    email?: unknown
    kind?: unknown
    subject?: unknown
    key_id?: unknown
    key_expires_at?: unknown
    all_permissions?: unknown
    key_step_up_at?: unknown
    key_step_up_actions?: unknown
  }
}

const ORG_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/
const SUBJECT = /^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$/

/**
 * The claim rules: active, access token, our audience, a human subject, `mcp` scope. No organisation is
 * required: `ext.org`, when present and well-formed, is kept for information only.
 */
export function principalFromClaims(
  claims: IntrospectionClaims,
  opts: { resource: string; token: string; now?: number }
): Principal {
  const now = opts.now ?? Math.floor(Date.now() / 1000)
  if (claims.active !== true) throw new AuthError('invalid_token', 'The token is not active')
  if (claims.token_use && claims.token_use !== 'access_token') throw new AuthError('invalid_token', 'Not an access token')
  if (typeof claims.exp !== 'number' || claims.exp <= now) throw new AuthError('invalid_token', 'The token has expired')

  const aud = Array.isArray(claims.aud) ? claims.aud : claims.aud ? [claims.aud] : []
  if (!aud.includes(opts.resource)) throw new AuthError('wrong_audience', 'The token was not issued for this server')

  const ext = claims.ext ?? {}
  const org = typeof ext.org === 'string' && ORG_ID.test(ext.org) ? ext.org : null

  const personal = ext.kind === 'personal'
  const subject = personal ? ext.subject : claims.sub
  if (typeof subject !== 'string' || !SUBJECT.test(subject)) throw new AuthError('invalid_token', 'The token names no user')
  if (personal) {
    // Keys expire at most 30 days after creation (owner decision); jinbe enforces it at creation, this
    // refuses a token minted from a key that has since expired but whose client still exists.
    if (typeof ext.key_expires_at !== 'number' || ext.key_expires_at <= now) {
      throw new AuthError('invalid_key', 'The personal key has expired')
    }
  }

  const scopes = usableScopes(parseScopeString(claims.scope))
  if (!scopes.includes(MCP_SCOPE)) throw new AuthError('invalid_token', 'The token does not carry the mcp scope')
  if (typeof claims.client_id !== 'string' || !claims.client_id) throw new AuthError('invalid_token', 'The token names no client')

  return {
    subject,
    email: typeof ext.email === 'string' ? ext.email : null,
    org,
    scopes,
    clientId: claims.client_id,
    kind: personal ? 'personal' : 'oauth',
    keyId: personal ? (typeof ext.key_id === 'string' ? ext.key_id : claims.client_id) : null,
    expiresAt: claims.exp,
    tokenHash: sha256(opts.token),
    ...(personal ? stepUpClaims(ext) : {}),
  }
}

/** A personal key's step-up facts, only when jinbe reports them (an absent field stays absent: unknown). */
function stepUpClaims(ext: NonNullable<IntrospectionClaims['ext']>): Pick<Principal, 'stepUpAt' | 'stepUpActions'> {
  const out: Pick<Principal, 'stepUpAt' | 'stepUpActions'> = {}
  const at = ext.key_step_up_at
  // ISO string, or epoch seconds like the other ext times.
  if (typeof at === 'string' && Number.isFinite(Date.parse(at))) out.stepUpAt = new Date(Date.parse(at)).toISOString()
  else if (typeof at === 'number' && Number.isFinite(at)) out.stepUpAt = new Date(at * 1000).toISOString()
  else if (at === null) out.stepUpAt = null
  if (typeof ext.key_step_up_actions === 'boolean') out.stepUpActions = ext.key_step_up_actions
  return out
}

type Fetch = typeof fetch

export class HydraIntrospectionVerifier implements TokenVerifier {
  constructor(
    private readonly adminUrl: string,
    private readonly resource: string,
    private readonly fetchImpl: Fetch = fetch
  ) {}

  async verify(token: string): Promise<Principal> {
    let res: Response
    try {
      res = await this.fetchImpl(new URL('/admin/oauth2/introspect', this.adminUrl), {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
        body: new URLSearchParams({ token }).toString(),
        signal: AbortSignal.timeout(5000),
      })
    } catch {
      throw new AuthError('verifier_unavailable', 'The authorization server did not answer')
    }
    if (!res.ok) throw new AuthError('verifier_unavailable', `Introspection failed (${res.status})`)
    return principalFromClaims((await res.json()) as IntrospectionClaims, { resource: this.resource, token })
  }
}

/**
 * jinbe introspects for us. Contract proposed to jinbe (W1):
 *   POST /api/mcp/token-info   Authorization: Bearer <token>   X-Actor-Token: <SA token>
 *   200 → IntrospectionClaims (only the fields above), 401 → not active.
 */
export class JinbeTokenInfoVerifier implements TokenVerifier {
  constructor(
    private readonly jinbeUrl: string,
    private readonly resource: string,
    private readonly actor: ActorTokenSource,
    private readonly fetchImpl: Fetch = fetch
  ) {}

  async verify(token: string): Promise<Principal> {
    let res: Response
    try {
      res = await this.fetchImpl(new URL('/api/mcp/token-info', this.jinbeUrl), {
        method: 'POST',
        headers: { authorization: `Bearer ${token}`, 'x-actor-token': await this.actor.get(), accept: 'application/json' },
        signal: AbortSignal.timeout(5000),
      })
    } catch {
      throw new AuthError('verifier_unavailable', 'jinbe did not answer')
    }
    const off = await mcpDisabledFrom(res)
    if (off) throw off
    if (res.status === 401 || res.status === 403) throw new AuthError('invalid_token', 'The token is not active')
    if (!res.ok) throw new AuthError('verifier_unavailable', `Token info failed (${res.status})`)
    return principalFromClaims((await res.json()) as IntrospectionClaims, { resource: this.resource, token })
  }
}

/** A fixed principal for local development against a jinbe running with DEV_BYPASS_AUTH. */
export class DevVerifier implements TokenVerifier {
  constructor(private readonly principal: Omit<Principal, 'tokenHash' | 'expiresAt'>) {}

  async verify(token: string): Promise<Principal> {
    return { ...this.principal, tokenHash: sha256(token), expiresAt: Math.floor(Date.now() / 1000) + 600 }
  }
}

/**
 * Positive answers cached for at most `ttlMs` and never past the token's own expiry; refusals are not
 * cached (a revoked token then fails within ttlMs, which matches the edge's introspection cache).
 */
export class CachingVerifier implements TokenVerifier {
  private readonly cache = new Map<string, { principal: Principal; until: number }>()

  constructor(
    private readonly inner: TokenVerifier,
    private readonly ttlMs: number,
    private readonly maxEntries = 10_000,
    private readonly now: () => number = Date.now
  ) {}

  async verify(token: string): Promise<Principal> {
    const key = sha256(token)
    const hit = this.cache.get(key)
    const t = this.now()
    if (hit && hit.until > t) return hit.principal
    if (hit) this.cache.delete(key)
    const principal = await this.inner.verify(token)
    if (this.cache.size >= this.maxEntries) this.cache.delete(this.cache.keys().next().value as string)
    this.cache.set(key, { principal, until: Math.min(t + this.ttlMs, principal.expiresAt * 1000) })
    return principal
  }

  clear(): void {
    this.cache.clear()
  }

  /** Drop the cached principals of a key's tokens (revoked). */
  forgetKey(keyId: string): void {
    for (const [k, v] of this.cache) if (v.principal.keyId === keyId) this.cache.delete(k)
  }
}
