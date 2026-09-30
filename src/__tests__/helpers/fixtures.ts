import { pino } from 'pino'
import { withAccessToken, type AuthenticatedPrincipal, type Principal } from '../../auth/types.js'
import { StaticActorTokenSource } from '../../auth/actor-token.js'
import { JinbeClient } from '../../jinbe/client.js'
import { KillSwitches } from '../../safety/kill-switch.js'
import { SlidingWindowRateLimiter } from '../../safety/rate-limit.js'
import type { ToolDeps } from '../../mcp/registry.js'

export const ORG = '11111111-1111-4111-8111-111111111111'
export const OTHER_ORG = '22222222-2222-4222-8222-222222222222'
export const ACCESS_TOKEN = 'ory_at_useraccesstoken0123456789abcdef'
export const ACTOR_TOKEN = 'actor-sa-token-value'
export const JINBE = 'http://jinbe.test:3000'

export function principal(overrides: Partial<Principal> = {}): AuthenticatedPrincipal {
  return withAccessToken(
    {
      subject: 'user-1',
      email: 'alice@example.com',
      org: null,
      scopes: ['mcp', 'sites:read', 'sites:write', 'groups:read', 'access:read', 'access:check', 'users:read', 'audit:read', 'org.members:read'],
      clientId: 'client-claude',
      kind: 'oauth',
      keyId: null,
      expiresAt: Math.floor(Date.now() / 1000) + 600,
      tokenHash: 'hash',
      ...overrides,
    },
    ACCESS_TOKEN
  )
}

export interface Recorded {
  method: string
  url: URL
  headers: Record<string, string>
  body: unknown
}

export type Route = (req: Recorded) => { status?: number; body?: unknown; headers?: Record<string, string> }

/** A fake jinbe: routes keyed by "METHOD /path" (no query). Unknown routes answer 404. */
export function mockJinbe(routes: Record<string, Route | object>) {
  const calls: Recorded[] = []
  const fetchImpl = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(String(input))
    const headers = Object.fromEntries(Object.entries((init?.headers ?? {}) as Record<string, string>).map(([k, v]) => [k.toLowerCase(), v]))
    const rec: Recorded = { method: init?.method ?? 'GET', url, headers, body: init?.body ? JSON.parse(String(init.body)) : undefined }
    calls.push(rec)
    const route = routes[`${rec.method} ${url.pathname}`]
    const out = typeof route === 'function' ? (route as Route)(rec) : route ? { status: 200, body: route } : { status: 404, body: { error: 'not_found', message: 'No such route' } }
    return new Response(out.body === undefined ? null : JSON.stringify(out.body), {
      status: out.status ?? 200,
      headers: { 'content-type': 'application/json', ...(out.headers ?? {}) },
    })
  }) as typeof fetch
  return { fetchImpl, calls }
}

export const silentLogger = pino({ level: 'silent' })

export function deps(fetchImpl: typeof fetch, overrides: Partial<ToolDeps> = {}): ToolDeps {
  return {
    jinbe: new JinbeClient(JINBE, new StaticActorTokenSource(ACTOR_TOKEN), 2000, fetchImpl),
    killSwitches: new KillSwitches({ enabled: true, readOnly: false }, null),
    rateLimiter: new SlidingWindowRateLimiter({ read: 1000, write: 1000 }),
    logger: silentLogger,
    responseLimitBytes: 65536,
    exposeUnwired: true,
    ...overrides,
  }
}

/** The structuredContent of a tool result. */
export const sc = (r: { structuredContent?: unknown }) => r.structuredContent as Record<string, any>
export const text = (r: { content: unknown }) => (r.content as Array<{ text: string }>)[0].text
