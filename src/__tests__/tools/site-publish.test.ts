import { describe, expect, it } from 'vitest'
import { execute } from '../../mcp/registry.js'
import { pauseSite, publishSite, requestSiteApply, resumeSite, rollbackSite } from '../../mcp/tools/site-publish.js'
import { deps, mockJinbe, principal, sc } from '../helpers/fixtures.js'

const S = '/api/admin/sites'
const publisher = principal({ scopes: ['mcp', 'sites:write', 'sites:apply'], kind: 'personal', keyId: 'key-1' })
const applyRecord = {
  id: 'apply-1', site: 'billing', version: 4, by: 'alice@example.com', startedAt: 't', state: 'running',
  previous: { version: 3, rules: ['r'] }, stages: [{ name: 'saved', state: 'done', at: 't' }],
}
const saved = { site: {}, version: 4, etag: 'e4', status: 'live', savedAt: 't', savedBy: 's', applied: null }

describe('publish_site', () => {
  it('applies the latest saved version by default, without who or the previous state', async () => {
    const jinbe = mockJinbe({ [`GET ${S}/billing`]: saved, [`POST ${S}/billing/apply`]: applyRecord })
    const r = await execute(publishSite, { name: 'billing' }, publisher, deps(jinbe.fetchImpl))
    const post = jinbe.calls.find((c) => c.method === 'POST')!
    expect(post.body).toEqual({ version: 4 })
    expect(post.headers['idempotency-key']).toBeDefined()
    expect(sc(r).data).toEqual({ id: 'apply-1', site: 'billing', version: 4, startedAt: 't', state: 'running', stages: [{ name: 'saved', state: 'done' }] })
  })

  it('production: use_apply_request points at request_site_apply', async () => {
    const jinbe = mockJinbe({
      [`POST ${S}/billing/apply`]: () => ({
        status: 403,
        body: { error: 'Forbidden', code: 'delegation_refused', message: 'This credential acts for a user…', reason: 'delegation_refused:use_apply_request' },
      }),
    })
    const r = await execute(publishSite, { name: 'billing', version: 4 }, publisher, deps(jinbe.fetchImpl))
    expect(sc(r).error).toMatchObject({ code: 'use_apply_request', retryable: false })
    expect(sc(r).error.message).toContain('request_site_apply')
  })

  it('a key without protected actions: create a new key with protected actions allowed', async () => {
    const jinbe = mockJinbe({
      [`POST ${S}/billing/apply`]: () => ({ status: 422, body: { error: 'step_up_unavailable', message: 'This action requires a second factor proven in a browser session.' } }),
    })
    const r = await execute(publishSite, { name: 'billing', version: 4 }, publisher, deps(jinbe.fetchImpl))
    expect(sc(r).error.code).toBe('protected_actions_off')
    expect(sc(r).error.message).toMatch(/create a new key with protected actions allowed/)
    expect(sc(r).error.message).not.toMatch(/browser/)
  })

  it('needs sites:apply: sites:write alone does not list or run it', async () => {
    const jinbe = mockJinbe({})
    const r = await execute(publishSite, { name: 'billing', version: 4 }, principal({ scopes: ['mcp', 'sites:write'] }), deps(jinbe.fetchImpl))
    expect(sc(r).error.code).toBe('insufficient_scope')
    expect(jinbe.calls).toHaveLength(0)
  })
})

describe('publish gate', () => {
  it('sends acknowledge; unconfirmed_findings comes back with the unresolved findings', async () => {
    const findings = [{ code: 'public_catch_all', level: 'confirm', message: 'Every path is public', fix: 'Deny the catch-all' }]
    const jinbe = mockJinbe({ [`POST ${S}/billing/apply`]: () => ({ status: 422, body: { error: 'unconfirmed_findings', message: 'Not published: 1 finding to acknowledge', findings } }) })
    const r = await execute(publishSite, { name: 'billing', version: 4, acknowledge: ['public_route'] }, publisher, deps(jinbe.fetchImpl))
    expect(jinbe.calls[0].body).toEqual({ version: 4, acknowledge: ['public_route'] })
    expect(sc(r).error).toMatchObject({ code: 'unconfirmed_findings', retryable: false })
    expect(sc(r).error.details.findings).toEqual(findings)
    expect(sc(r).error.hint).toMatch(/acknowledge/)
  })

  it('refuses a malformed code or more than 32 before any call', async () => {
    const jinbe = mockJinbe({})
    for (const acknowledge of [['Public-Route'], Array.from({ length: 33 }, (_, i) => `c${i}`)]) {
      expect(sc(await execute(publishSite, { name: 'billing', version: 4, acknowledge }, publisher, deps(jinbe.fetchImpl))).error.code).toBe('invalid_request')
    }
    expect(jinbe.calls).toHaveLength(0)
  })
})

describe('request_site_apply', () => {
  it('creates an apply request and says a person approves it', async () => {
    const jinbe = mockJinbe({
      [`POST ${S}/billing/requests`]: { id: 'req-1', site: 'billing', version: 4, etag: 'e4', requestedBy: 'alice@example.com', requestedAt: 't', state: 'pending', risk: { level: 'low' }, needsSecondApprover: true },
    })
    const r = await execute(requestSiteApply, { name: 'billing', version: 4, note: 'ship it' }, principal({ scopes: ['mcp', 'sites:write'] }), deps(jinbe.fetchImpl))
    expect(jinbe.calls[0].body).toEqual({ version: 4, note: 'ship it' })
    expect(sc(r).data).toMatchObject({ id: 'req-1', state: 'pending', needsSecondApprover: true })
    expect(JSON.stringify(sc(r))).not.toContain('alice@example.com')
    expect(sc(r).notes[0]).toMatch(/cannot approve/)
  })

  it('a version that is not the saved one is a conflict', async () => {
    const jinbe = mockJinbe({ [`POST ${S}/billing/requests`]: () => ({ status: 409, body: { error: 'version_mismatch', message: 'Version 5 is the saved one' } }) })
    const r = await execute(requestSiteApply, { name: 'billing', version: 4 }, principal({ scopes: ['mcp', 'sites:write'] }), deps(jinbe.fetchImpl))
    expect(sc(r).error.code).toBe('conflict')
  })
})

describe('pause, resume, rollback', () => {
  it('call their jinbe routes with an idempotency key', async () => {
    const jinbe = mockJinbe({
      [`POST ${S}/billing/pause`]: applyRecord,
      [`POST ${S}/billing/resume`]: applyRecord,
      [`POST ${S}/billing/rollback`]: applyRecord,
    })
    const d = deps(jinbe.fetchImpl)
    for (const [tool, args] of [
      [pauseSite, { name: 'billing' }],
      [resumeSite, { name: 'billing' }],
      [rollbackSite, { name: 'billing', toVersion: 2, note: 'bad deploy' }],
    ] as const) {
      const r = await execute(tool, args, publisher, d)
      expect(r.isError, tool.name).toBeUndefined()
    }
    expect(jinbe.calls.map((c) => c.url.pathname)).toEqual([`${S}/billing/pause`, `${S}/billing/resume`, `${S}/billing/rollback`])
    expect(jinbe.calls[2].body).toEqual({ toVersion: 2, note: 'bad deploy' })
    expect(jinbe.calls.every((c) => c.headers['idempotency-key'])).toBe(true)
  })

  it('are flagged destructive and protected', () => {
    for (const t of [publishSite, pauseSite, resumeSite, rollbackSite]) {
      expect(t.destructive, t.name).toBe(true)
      expect(t.protectedAction, t.name).toBe(true)
    }
  })
})
