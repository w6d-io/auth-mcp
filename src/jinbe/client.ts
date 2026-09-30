import { randomUUID } from 'node:crypto'
import type { AuthenticatedPrincipal } from '../auth/types.js'
import type { ActorTokenSource } from '../auth/actor-token.js'
import { fromJinbe, toolError } from '../safety/errors.js'

/**
 * The only way auth-mcp talks to jinbe. Every request carries TWO credentials (plan §2, actor-token
 * pattern — Hydra has no RFC 8693 exchange):
 *   Authorization: Bearer <the user's MCP-audience token>   — WHO, and within which scopes
 *   X-Actor-Token: <auth-mcp's projected SA token>          — that it comes through auth-mcp
 * plus X-Audit-Context (via=mcp, client_id, tool, key_id) so jinbe's audit line can say how the call
 * arrived. That header is advisory: jinbe must take client_id/key_id from introspection, never from it.
 *
 * No credential of auth-mcp's own ever authorises anything: without the user's token there is no call.
 */

export interface CallContext {
  principal: AuthenticatedPrincipal
  tool: string
  requestId?: string
}

export interface RequestOptions {
  query?: Record<string, string | number | boolean | string[] | undefined>
  body?: unknown
  headers?: Record<string, string>
  /** Longer than the default for a call known to be slow (verify_site probes routes in series). */
  timeoutMs?: number
}

export interface WriteOptions {
  body?: unknown
  /** Sent as `Idempotency-Key`: jinbe replays the first answer to a retry with the same key. */
  idempotencyKey?: string
  headers?: Record<string, string>
}

export interface JinbeResponse<T> {
  status: number
  body: T
  headers: Headers
}

type Fetch = typeof fetch

const MAX_RESPONSE_BYTES = 5 * 1024 * 1024
const HEADER_VALUE = /^[A-Za-z0-9._:@/-]{1,128}$/
export const IDEMPOTENCY_KEY = /^[A-Za-z0-9_-]{8,64}$/

/**
 * The one DELETE auth-mcp ever sends: revoking one of the holder's own keys. Owner rule: nothing else
 * is deleted through MCP (jinbe's delegation gate refuses it too; this is the second line).
 */
const DELETABLE = /^\/api\/me\/api-keys\/[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/

export function auditContext(ctx: CallContext): string {
  const parts: Array<[string, string | null]> = [
    ['via', 'mcp'],
    ['client_id', ctx.principal.clientId],
    ['tool', ctx.tool],
    ['key_id', ctx.principal.keyId],
  ]
  return parts
    .filter((p): p is [string, string] => typeof p[1] === 'string' && HEADER_VALUE.test(p[1]))
    .map(([k, v]) => `${k}=${v}`)
    .join('; ')
}

export class JinbeClient {
  constructor(
    private readonly baseUrl: string,
    private readonly actor: ActorTokenSource,
    private readonly timeoutMs: number,
    private readonly fetchImpl: Fetch = fetch
  ) {}

  async request<T>(ctx: CallContext, method: string, path: string, opts: RequestOptions = {}): Promise<JinbeResponse<T>> {
    if (!path.startsWith('/api/')) throw new Error(`jinbe path must start with /api/: ${path}`)
    if (method.toUpperCase() === 'DELETE' && !DELETABLE.test(path)) {
      throw toolError('never_via_mcp', 'Nothing is deleted through MCP: do it in the console')
    }
    const url = new URL(path, this.baseUrl)
    // A `..` or `.` segment from a value would move the call to another route: refused, never resolved.
    if (url.pathname !== path) throw toolError('invalid_request', 'Invalid path')
    for (const [k, v] of Object.entries(opts.query ?? {})) {
      if (v === undefined) continue
      for (const item of Array.isArray(v) ? v : [v]) url.searchParams.append(k, String(item))
    }

    let actorToken: string
    try {
      actorToken = await this.actor.get()
    } catch {
      throw toolError('upstream_unavailable', 'auth-mcp cannot prove its identity to the platform right now', { retryable: true })
    }

    const headers: Record<string, string> = {
      accept: 'application/json',
      authorization: `Bearer ${ctx.principal.accessToken}`,
      'x-actor-token': actorToken,
      'x-audit-context': auditContext(ctx),
      'x-request-id': ctx.requestId ?? randomUUID(),
      'user-agent': 'auth-mcp/0.1',
      ...(opts.headers ?? {}),
    }
    if (opts.body !== undefined) headers['content-type'] = 'application/json'

    let res: Response
    try {
      res = await this.fetchImpl(url, {
        method,
        headers,
        body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
        signal: AbortSignal.timeout(opts.timeoutMs ?? this.timeoutMs),
        redirect: 'error',
      })
    } catch {
      throw toolError('upstream_unavailable', 'The platform API did not answer', { retryable: true })
    }

    const body = await readJson(res)
    if (!res.ok) throw fromJinbe(res.status, body, res.headers.get('retry-after'))
    return { status: res.status, body: body as T, headers: res.headers }
  }

  async get<T>(ctx: CallContext, path: string, query?: RequestOptions['query']): Promise<T> {
    return (await this.request<T>(ctx, 'GET', path, { query })).body
  }

  async post<T>(ctx: CallContext, path: string, body: unknown): Promise<T> {
    return (await this.request<T>(ctx, 'POST', path, { body })).body
  }

  /**
   * A write (POST / PUT / PATCH / DELETE). POST, PUT and PATCH always carry an Idempotency-Key — the
   * caller's, or a fresh one — so a retried call changes things once.
   */
  async write<T>(ctx: CallContext, method: 'POST' | 'PUT' | 'PATCH' | 'DELETE', path: string, opts: WriteOptions = {}): Promise<JinbeResponse<T>> {
    const headers: Record<string, string> = { ...(opts.headers ?? {}) }
    if (method !== 'DELETE') {
      const key = opts.idempotencyKey ?? randomUUID()
      if (!IDEMPOTENCY_KEY.test(key)) throw toolError('invalid_request', 'idempotencyKey must be 8-64 letters, digits, - or _')
      headers['idempotency-key'] = key
    }
    return this.request<T>(ctx, method, path, { body: opts.body, headers })
  }
}

async function readJson(res: Response): Promise<unknown> {
  const length = Number(res.headers.get('content-length') ?? '0')
  if (length > MAX_RESPONSE_BYTES) throw toolError('upstream_unavailable', 'The platform answer is too large', { status: res.status })
  const text = await res.text()
  if (text.length > MAX_RESPONSE_BYTES) throw toolError('upstream_unavailable', 'The platform answer is too large', { status: res.status })
  if (!text) return null
  try {
    return JSON.parse(text)
  } catch {
    // A non-JSON body (an ingress error page) is not passed on: it is not ours to show.
    return null
  }
}

/** Path segment encoding for values already validated against a name pattern. */
export const seg = (value: string) => encodeURIComponent(value)
