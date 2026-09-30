import { describe, expect, it } from 'vitest'
import { JinbeClient, auditContext } from '../../jinbe/client.js'
import { StaticActorTokenSource, type ActorTokenSource } from '../../auth/actor-token.js'
import { ToolError } from '../../safety/errors.js'
import { ACCESS_TOKEN, ACTOR_TOKEN, JINBE, mockJinbe, principal } from '../helpers/fixtures.js'

const ctx = (over = {}) => ({ principal: principal(over), tool: 'list_sites', requestId: 'req-1' })

describe('JinbeClient', () => {
  it('sends the user token, the actor token and the audit context — and nothing of its own', async () => {
    const jinbe = mockJinbe({ 'GET /api/admin/sites': [] })
    const client = new JinbeClient(JINBE, new StaticActorTokenSource(ACTOR_TOKEN), 1000, jinbe.fetchImpl)
    await client.get(ctx(), '/api/admin/sites', { q: 'a b', many: ['x', 'y'], skip: undefined })
    const call = jinbe.calls[0]
    expect(call.headers.authorization).toBe(`Bearer ${ACCESS_TOKEN}`)
    expect(call.headers['x-actor-token']).toBe(ACTOR_TOKEN)
    expect(call.headers['x-audit-context']).toBe('via=mcp; client_id=client-claude; tool=list_sites')
    expect(call.headers['x-request-id']).toBe('req-1')
    expect(call.headers.cookie).toBeUndefined()
    expect(call.url.searchParams.get('q')).toBe('a b')
    expect(call.url.searchParams.getAll('many')).toEqual(['x', 'y'])
    expect(call.url.searchParams.has('skip')).toBe(false)
  })

  it('adds key_id for personal keys and drops values that could inject into the header', () => {
    expect(auditContext(ctx({ kind: 'personal', keyId: 'key-1' }))).toBe('via=mcp; client_id=client-claude; tool=list_sites; key_id=key-1')
    expect(auditContext(ctx({ clientId: 'evil; via=browser' }))).toBe('via=mcp; tool=list_sites')
  })

  it('refuses a path outside /api/', async () => {
    const client = new JinbeClient(JINBE, new StaticActorTokenSource(ACTOR_TOKEN), 1000, mockJinbe({}).fetchImpl)
    await expect(client.get(ctx(), 'http://evil.example/steal')).rejects.toThrow(/\/api\//)
  })

  it('maps jinbe errors to tool errors', async () => {
    const jinbe = mockJinbe({ 'GET /api/admin/sites': () => ({ status: 503, body: { error: 'policy_unavailable', message: 'OPA down' } }) })
    const client = new JinbeClient(JINBE, new StaticActorTokenSource(ACTOR_TOKEN), 1000, jinbe.fetchImpl)
    await expect(client.get(ctx(), '/api/admin/sites')).rejects.toMatchObject({ body: { code: 'retry_later', retryable: true } })
  })

  it('does not pass on a non-JSON error page', async () => {
    const fetchImpl = (async () => new Response('<html>ingress 403</html>', { status: 403 })) as typeof fetch
    const client = new JinbeClient(JINBE, new StaticActorTokenSource(ACTOR_TOKEN), 1000, fetchImpl)
    const err = await client.get(ctx(), '/api/admin/sites').catch((e) => e as ToolError)
    expect(err.body.code).toBe('forbidden')
    expect(JSON.stringify(err.body)).not.toContain('html')
  })

  it('network failure → upstream_unavailable, retryable', async () => {
    const client = new JinbeClient(JINBE, new StaticActorTokenSource(ACTOR_TOKEN), 1000, (async () => { throw new TypeError('fetch failed') }) as never)
    await expect(client.get(ctx(), '/api/admin/sites')).rejects.toMatchObject({ body: { code: 'upstream_unavailable', retryable: true } })
  })

  it('no actor token → no call at all', async () => {
    const jinbe = mockJinbe({ 'GET /api/admin/sites': [] })
    const broken: ActorTokenSource = { get: async () => { throw new Error('no file') } }
    const client = new JinbeClient(JINBE, broken, 1000, jinbe.fetchImpl)
    await expect(client.get(ctx(), '/api/admin/sites')).rejects.toMatchObject({ body: { code: 'upstream_unavailable' } })
    expect(jinbe.calls).toHaveLength(0)
  })

  it('refuses an oversized answer', async () => {
    const fetchImpl = (async () => new Response('[]', { status: 200, headers: { 'content-length': String(50 * 1024 * 1024) } })) as typeof fetch
    const client = new JinbeClient(JINBE, new StaticActorTokenSource(ACTOR_TOKEN), 1000, fetchImpl)
    await expect(client.get(ctx(), '/api/admin/sites')).rejects.toMatchObject({ body: { code: 'upstream_unavailable' } })
  })
})
