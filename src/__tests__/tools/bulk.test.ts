import { describe, expect, it } from 'vitest'
import { execute } from '../../mcp/registry.js'
import { BULK_OPS, BULK_SPEC, executeBulk, getBulkJob, planBulk } from '../../mcp/tools/bulk.js'
import { deps, mockJinbe, principal, sc } from '../helpers/fixtures.js'

const B = '/api/admin/bulk'
const key = principal({ scopes: ['mcp', 'sites:write', 'users:verify', 'users:create', 'groups.members:write'] })
const HASH = 'a'.repeat(64)
const plan = (op: string) => ({
  planId: '6f1d2c3b-4a59-4e6f-8a7b-9c0d1e2f3a4b', planHash: HASH, op, expiresAt: 't',
  counts: { ok: 1, skip: 1, refused: 0, not_found: 0 }, items: [{ index: 0, outcome: { status: 'ok', action: 'send' } }, { index: 1, outcome: { status: 'skip', reason: 'already_verified' } }], warnings: [],
})

describe('plan_bulk', () => {
  it('posts to the op route, with params only when given', async () => {
    const jinbe = mockJinbe({ [`POST ${B}/users.verification/plan`]: plan('users.verification') })
    const r = await execute(planBulk, { op: 'users.verification', items: [{ user: 'a@example.com' }, { user: 'u-2' }] }, key, deps(jinbe.fetchImpl))
    expect(jinbe.calls[0].body).toEqual({ items: [{ user: 'a@example.com' }, { user: 'u-2' }] })
    expect(jinbe.calls[0].headers['idempotency-key']).toBeDefined()
    expect(sc(r).data).toMatchObject({ planHash: HASH, op: 'users.verification', counts: { ok: 1, skip: 1 }, warnings: [] })
  })

  it('maps routes in bulk into a site draft (sites.routes.upsert, params {site})', async () => {
    const jinbe = mockJinbe({ [`POST ${B}/sites.routes.upsert/plan`]: plan('sites.routes.upsert') })
    const routes = [{ id: 'list', methods: ['GET'], path: '/api/items', gate: 'api', access: { kind: 'permission', permission: 'billing:read' } }]
    await execute(planBulk, { op: 'sites.routes.upsert', items: routes, params: { site: 'billing' } }, key, deps(jinbe.fetchImpl))
    expect(jinbe.calls[0].body).toEqual({ items: routes, params: { site: 'billing' } })
  })

  it('checks items and params against the op before any call', async () => {
    const jinbe = mockJinbe({})
    for (const args of [
      { op: 'users.invite', items: [{ email: 'not-an-email' }] },
      { op: 'groups.members.add', items: [{ user: 'a@example.com' }] },
      { op: 'sites.routes.upsert', items: [{ id: 'x', methods: ['GET'], path: '/x', gate: 'api', access: { kind: 'public' } }] },
      { op: 'users.verification', items: [{ user: 'a' }], params: { force: true } },
    ]) {
      const r = await execute(planBulk, args, key, deps(jinbe.fetchImpl))
      expect(sc(r).error.code, args.op).toBe('invalid_request')
    }
    expect(jinbe.calls).toHaveLength(0)
  })

  it('offers only the four ops, none removing anything, each with its own permission', async () => {
    expect([...BULK_OPS]).toEqual(['sites.routes.upsert', 'users.invite', 'users.verification', 'groups.members.add'])
    expect(Object.fromEntries(BULK_OPS.map((o) => [o, BULK_SPEC[o].permission]))).toEqual({
      'sites.routes.upsert': 'sites:write', 'users.invite': 'users:create', 'users.verification': 'users:verify', 'groups.members.add': 'groups.members:write',
    })
    const jinbe = mockJinbe({})
    for (const op of ['users.create', 'org.members.add', 'org.members.remove', 'groups.members.remove', 'users.delete']) {
      expect(sc(await execute(planBulk, { op, items: [{ user: 'a' }] }, key, deps(jinbe.fetchImpl))).error.code).toBe('invalid_request')
    }
    const tooMany = await execute(planBulk, { op: 'users.verification', items: Array.from({ length: 201 }, (_, i) => ({ user: `u${i}` })) }, key, deps(jinbe.fetchImpl))
    expect(sc(tooMany).error.code).toBe('invalid_request')
    expect(jinbe.calls).toHaveLength(0)
  })
})

describe('execute_bulk and get_bulk_job', () => {
  const job = { id: 'job-00001-aaaa', op: 'users.invite', state: 'running', total: 2, counts: { done: 0 }, items: [{ index: 0, status: 'pending' }], createdAt: 't', updatedAt: 't' }

  it('runs the plan on the op route and follows the job', async () => {
    const jinbe = mockJinbe({
      [`POST ${B}/users.invite/execute`]: () => ({ status: 202, body: job }),
      [`GET ${B}/jobs/job-00001-aaaa`]: { ...job, state: 'done', items: [{ index: 0, status: 'done', action: 'created' }] },
    })
    const d = deps(jinbe.fetchImpl)
    const r = await execute(executeBulk, { op: 'users.invite', planId: '6f1d2c3b-4a59-4e6f-8a7b-9c0d1e2f3a4b', planHash: HASH }, key, d)
    expect(jinbe.calls[0].body).toEqual({ planId: '6f1d2c3b-4a59-4e6f-8a7b-9c0d1e2f3a4b', planHash: HASH })
    expect(sc(r).data).toEqual({ jobId: 'job-00001-aaaa', op: 'users.invite', state: 'running', total: 2, counts: { done: 0 } })
    const j = await execute(getBulkJob, { jobId: 'job-00001-aaaa' }, key, d)
    expect(sc(j).data).toMatchObject({ state: 'done', items: [{ index: 0, status: 'done', action: 'created' }] })
  })

  it('plan_changed is a conflict carrying the new plan; plan_not_found; a key budget 429 is retryable', async () => {
    const args = { op: 'users.invite', planId: '6f1d2c3b-4a59-4e6f-8a7b-9c0d1e2f3a4b', planHash: HASH }
    const changed = mockJinbe({ [`POST ${B}/users.invite/execute`]: () => ({ status: 409, body: { error: 'plan_changed', message: 'Plan again', plan: plan('users.invite') } }) })
    const c = await execute(executeBulk, args, key, deps(changed.fetchImpl))
    expect(sc(c).error).toMatchObject({ code: 'conflict', upstream: 'plan_changed' })
    expect(sc(c).error.details.plan.planHash).toBe(HASH)
    const gone = mockJinbe({ [`POST ${B}/users.invite/execute`]: () => ({ status: 404, body: { error: 'plan_not_found', message: 'expired' } }) })
    expect(sc(await execute(executeBulk, args, key, deps(gone.fetchImpl))).error.code).toBe('not_found')
    const busy = mockJinbe({ [`POST ${B}/users.invite/execute`]: () => ({ status: 429, body: { error: 'rate_limited', message: 'Too many writes', retryAfter: 42 } }) })
    expect(sc(await execute(executeBulk, args, key, deps(busy.fetchImpl))).error).toMatchObject({ code: 'rate_limited', retryable: true, retryAfterSec: 42 })
  })
})
