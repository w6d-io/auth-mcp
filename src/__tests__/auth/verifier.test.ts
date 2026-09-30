import { describe, expect, it, vi } from 'vitest'
import {
  CachingVerifier,
  HydraIntrospectionVerifier,
  JinbeTokenInfoVerifier,
  principalFromClaims,
  type IntrospectionClaims,
  type TokenVerifier,
} from '../../auth/verifier.js'
import { AuthError } from '../../auth/types.js'
import { StaticActorTokenSource } from '../../auth/actor-token.js'
import { ORG } from '../helpers/fixtures.js'

const RESOURCE = 'https://mcp.test/mcp'
const NOW = 1_800_000_000
const TOKEN = 'ory_at_sometoken0123456789'

const claims = (over: Partial<IntrospectionClaims> = {}): IntrospectionClaims => ({
  active: true,
  scope: 'mcp admin:read',
  client_id: 'client-1',
  sub: 'user-1',
  exp: NOW + 600,
  aud: [RESOURCE],
  token_use: 'access_token',
  ext: { org: ORG, email: 'a@example.com' },
  ...over,
})

const code = (fn: () => unknown) => {
  try {
    fn()
  } catch (err) {
    return (err as AuthError).code
  }
  return 'no error'
}

describe('principalFromClaims', () => {
  const opts = { resource: RESOURCE, token: TOKEN, now: NOW }

  it('builds a principal from an OAuth token', () => {
    const p = principalFromClaims(claims(), opts)
    expect(p).toMatchObject({ subject: 'user-1', org: ORG, scopes: ['mcp', 'admin:read'], clientId: 'client-1', kind: 'oauth', keyId: null })
    expect(p.tokenHash).toMatch(/^[0-9a-f]{64}$/)
    expect(JSON.stringify(p)).not.toContain(TOKEN)
  })

  it('refuses an inactive token', () => expect(code(() => principalFromClaims(claims({ active: false }), opts))).toBe('invalid_token'))
  it('refuses an expired token', () => expect(code(() => principalFromClaims(claims({ exp: NOW }), opts))).toBe('invalid_token'))
  it('refuses a refresh token', () => expect(code(() => principalFromClaims(claims({ token_use: 'refresh_token' }), opts))).toBe('invalid_token'))
  it('refuses a token for another audience (a jinbe-audience token replayed here)', () => {
    expect(code(() => principalFromClaims(claims({ aud: ['jinbe'] }), opts))).toBe('wrong_audience')
    expect(code(() => principalFromClaims(claims({ aud: undefined }), opts))).toBe('wrong_audience')
  })
  it('accepts a token bound to no org (personal keys are not org-bound); a malformed org is dropped', () => {
    expect(principalFromClaims(claims({ ext: {} }), opts).org).toBeNull()
    expect(principalFromClaims(claims({ ext: { org: ['a', 'b'] } }), opts).org).toBeNull()
    expect(principalFromClaims(claims({ ext: { org: ORG } }), opts).org).toBe(ORG)
  })
  it('accepts a personal key token without an org', () => {
    const p = principalFromClaims(
      claims({ sub: 'key-client', client_id: 'key-client', ext: { kind: 'personal', subject: 'user-9', key_expires_at: NOW + 3600, all_permissions: true } }),
      opts
    )
    expect(p).toMatchObject({ subject: 'user-9', org: null, kind: 'personal', keyId: 'key-client' })
  })
  it('refuses a token without the mcp scope', () => expect(code(() => principalFromClaims(claims({ scope: 'admin:read' }), opts))).toBe('invalid_token'))
  it('drops wildcard scopes', () => expect(principalFromClaims(claims({ scope: 'mcp * admin:read' }), opts).scopes).toEqual(['mcp', 'admin:read']))

  it('takes a personal key token subject from ext.subject, not sub (= the client)', () => {
    const p = principalFromClaims(
      claims({ sub: 'key-client', client_id: 'key-client', ext: { org: ORG, kind: 'personal', subject: 'user-9', key_expires_at: NOW + 3600 } }),
      opts
    )
    expect(p).toMatchObject({ subject: 'user-9', kind: 'personal', keyId: 'key-client' })
  })
  it('refuses a personal token whose key has expired, or that says nothing about expiry', () => {
    const ext = { org: ORG, kind: 'personal', subject: 'user-9' }
    expect(code(() => principalFromClaims(claims({ ext: { ...ext, key_expires_at: NOW - 1 } }), opts))).toBe('invalid_key')
    expect(code(() => principalFromClaims(claims({ ext }), opts))).toBe('invalid_key')
  })
  it('refuses a personal token that names no user', () => {
    expect(code(() => principalFromClaims(claims({ ext: { org: ORG, kind: 'personal', key_expires_at: NOW + 60 } }), opts))).toBe('invalid_token')
  })
})

describe('HydraIntrospectionVerifier', () => {
  it('introspects at hydra-admin with the token in the form body', async () => {
    const fetchImpl = vi.fn(async (_url: unknown, init?: RequestInit) => {
      expect(String(init?.body)).toBe(`token=${TOKEN}`)
      return new Response(JSON.stringify(claims({ exp: Math.floor(Date.now() / 1000) + 600 })), { status: 200 })
    })
    const v = new HydraIntrospectionVerifier('http://hydra-admin:4445', RESOURCE, fetchImpl as never)
    expect((await v.verify(TOKEN)).subject).toBe('user-1')
    expect(String(fetchImpl.mock.calls[0][0])).toBe('http://hydra-admin:4445/admin/oauth2/introspect')
  })
  it('maps an unreachable server to verifier_unavailable', async () => {
    const v = new HydraIntrospectionVerifier('http://hydra-admin:4445', RESOURCE, (async () => { throw new Error('ECONNREFUSED') }) as never)
    await expect(v.verify(TOKEN)).rejects.toMatchObject({ code: 'verifier_unavailable' })
  })
})

describe('JinbeTokenInfoVerifier', () => {
  it('sends the token and the actor token', async () => {
    const fetchImpl = vi.fn(async (_url: unknown, init?: RequestInit) => {
      const h = init?.headers as Record<string, string>
      expect(h.authorization).toBe(`Bearer ${TOKEN}`)
      expect(h['x-actor-token']).toBe('sa')
      return new Response(JSON.stringify(claims({ exp: Math.floor(Date.now() / 1000) + 600 })), { status: 200 })
    })
    const v = new JinbeTokenInfoVerifier('http://jinbe:3000', RESOURCE, new StaticActorTokenSource('sa'), fetchImpl as never)
    expect((await v.verify(TOKEN)).org).toBe(ORG)
  })
  it('maps 401 to invalid_token', async () => {
    const v = new JinbeTokenInfoVerifier('http://jinbe:3000', RESOURCE, new StaticActorTokenSource('sa'), (async () => new Response('', { status: 401 })) as never)
    await expect(v.verify(TOKEN)).rejects.toMatchObject({ code: 'invalid_token' })
  })
})

describe('JinbeTokenInfoVerifier — turned off by an administrator', () => {
  it('maps 403 mcp_disabled to mcp_disabled, and a bare 403 still to invalid_token', async () => {
    const off = new JinbeTokenInfoVerifier('http://jinbe:3000', RESOURCE, new StaticActorTokenSource('sa'),
      (async () => new Response(JSON.stringify({ error: 'mcp_disabled', reason: 'disabled' }), { status: 403 })) as never)
    await expect(off.verify(TOKEN)).rejects.toMatchObject({ code: 'mcp_disabled', message: 'MCP access is turned off by an administrator' })
    const bare = new JinbeTokenInfoVerifier('http://jinbe:3000', RESOURCE, new StaticActorTokenSource('sa'),
      (async () => new Response(JSON.stringify({ error: 'Forbidden' }), { status: 403 })) as never)
    await expect(bare.verify(TOKEN)).rejects.toMatchObject({ code: 'invalid_token' })
  })
  it("maps group_not_allowed (the person's groups may not use MCP) to its own message", async () => {
    const off = new JinbeTokenInfoVerifier('http://jinbe:3000', RESOURCE, new StaticActorTokenSource('sa'),
      (async () => new Response(JSON.stringify({ error: 'mcp_disabled', reason: 'group_not_allowed' }), { status: 403 })) as never)
    await expect(off.verify(TOKEN)).rejects.toMatchObject({ code: 'mcp_disabled', message: 'MCP access is not enabled for your groups by an administrator' })
  })
})

describe('CachingVerifier', () => {
  it('caches positives for the ttl, never past the token expiry, and never caches refusals', async () => {
    let now = 1_000_000
    let calls = 0
    let fail = false
    const inner: TokenVerifier = {
      verify: async () => {
        calls++
        if (fail) throw new AuthError('invalid_token', 'revoked')
        return principalFromClaims(claims({ exp: Math.floor(now / 1000) + 20 }), { resource: RESOURCE, token: TOKEN, now: Math.floor(now / 1000) })
      },
    }
    const v = new CachingVerifier(inner, 30_000, 10, () => now)
    await v.verify(TOKEN)
    await v.verify(TOKEN)
    expect(calls).toBe(1)
    now += 21_000 // past the token's own exp (20 s), inside the 30 s ttl
    fail = true
    await expect(v.verify(TOKEN)).rejects.toMatchObject({ code: 'invalid_token' })
    await expect(v.verify(TOKEN)).rejects.toMatchObject({ code: 'invalid_token' })
    expect(calls).toBe(3)
  })
})
