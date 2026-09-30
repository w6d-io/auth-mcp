import { describe, expect, it } from 'vitest'
import { execute } from '../../mcp/registry.js'
import { explainAccess, findUsers, getUserAccess } from '../../mcp/tools/access.js'
import { getAuditEvent, searchAudit } from '../../mcp/tools/audit.js'
import { getMyIdentity } from '../../mcp/tools/identity.js'
import { ORG, deps, mockJinbe, principal, sc } from '../helpers/fixtures.js'

describe('access tools', () => {
  it('explain_access posts to the access checker', async () => {
    const answer = { allow: false, reason: 'forbidden', app: 'payroll', owners: ['payroll'], matchingRules: [], groups: [], roles: [], permissions: [], superAdmin: false }
    const jinbe = mockJinbe({ 'POST /api/admin/rbac/access-check': answer })
    const args = { email: 'bob@example.com', method: 'DELETE', path: '/api/pay/1' }
    const r = await execute(explainAccess, args, principal(), deps(jinbe.fetchImpl))
    expect(sc(r).data).toEqual(answer)
    expect(jinbe.calls[0].body).toEqual({ ...args, aal: 'aal1' })
    expect(sc(r).notes).toBeUndefined()
  })

  it('explain_access: needs_2fa at aal1 says it would be allowed at aal2 and who requires the second factor', async () => {
    const answer = {
      allow: false, reason: 'needs_2fa', app: 'echo-mfa', owners: ['echo-mfa'], matchingRules: [], groups: ['super_admins'], roles: [], permissions: ['*'], superAdmin: true,
      aal: 'aal1', stepUp: { requiredAal: 'aal2', allowedAtAal2: true, requiredBy: ['site'] },
    }
    const jinbe = mockJinbe({ 'POST /api/admin/rbac/access-check': answer })
    const r = await execute(explainAccess, { email: 'root@example.com', method: 'GET', path: '/' }, principal(), deps(jinbe.fetchImpl))
    expect(sc(r).notes).toEqual([expect.stringMatching(/^Would be allowed at aal2 \(second factor\): this site requires a second factor for everyone\. The only failing condition is the sign-in level/)])
  })

  it('explain_access: from an older jinbe (reason only) the note is still given; refused at aal2 too says so', async () => {
    const base = { allow: false, reason: 'needs_2fa', app: 'x', owners: ['x'], matchingRules: [], groups: [], roles: [], permissions: [], superAdmin: false }
    const old = await execute(explainAccess, { email: 'a@example.com', method: 'GET', path: '/' }, principal(), deps(mockJinbe({ 'POST /api/admin/rbac/access-check': base }).fetchImpl))
    expect(sc(old).notes[0]).toMatch(/^Would be allowed at aal2/)
    const both = { ...base, stepUp: { requiredAal: 'aal2', allowedAtAal2: false, requiredBy: ['platform_group'] } }
    const r = await execute(explainAccess, { email: 'a@example.com', method: 'GET', path: '/' }, principal(), deps(mockJinbe({ 'POST /api/admin/rbac/access-check': both }).fetchImpl))
    expect(sc(r).notes[0]).toMatch(/still refused at aal2/)
  })

  it('explain_access: asked at aal2, the level is passed and no step-up note is added', async () => {
    const answer = { allow: true, reason: 'ok', app: 'x', owners: ['x'], matchingRules: [], groups: [], roles: [], permissions: [], superAdmin: true, aal: 'aal2' }
    const jinbe = mockJinbe({ 'POST /api/admin/rbac/access-check': answer })
    const r = await execute(explainAccess, { email: 'a@example.com', method: 'GET', path: '/', aal: 'aal2' }, principal(), deps(jinbe.fetchImpl))
    expect(jinbe.calls[0].body).toMatchObject({ aal: 'aal2' })
    expect(sc(r).notes).toBeUndefined()
  })

  it('get_user_access', async () => {
    const access = { site: { groups: ['g'], byService: { payroll: ['r'] } }, orgs: [{ orgId: ORG, name: 'Acme', admin: true, grants: [] }] }
    const r = await execute(getUserAccess, { userId: 'u-1' }, principal(), deps(mockJinbe({ 'GET /api/admin/users/u-1/access': access }).fetchImpl))
    expect(sc(r).data).toEqual(access)
  })

  it('find_users keeps only the documented fields', async () => {
    const jinbe = mockJinbe({
      'GET /api/admin/users/lookup': { match: 'prefix', data: [{ id: 'u1', email: 'a@x.test', name: 'A', active: true, groups: [], organizations: [ORG], mfa: true, traits: { phone: '1' }, recovery: 'x' }] },
    })
    const r = await execute(findUsers, { query: 'a@', limit: 5 }, principal(), deps(jinbe.fetchImpl))
    expect(sc(r).data.items).toEqual([{ id: 'u1', email: 'a@x.test', name: 'A', active: true, groups: [], organizations: [ORG], mfa: true }])
    expect(jinbe.calls[0].url.searchParams.get('q')).toBe('a@')
    expect(jinbe.calls[0].url.searchParams.get('limit')).toBe('5')
  })

  it('find_users needs users:read', async () => {
    const r = await execute(findUsers, { query: 'a' }, principal({ scopes: ['mcp', 'sites:read'] }), deps(mockJinbe({}).fetchImpl))
    expect(sc(r).error.code).toBe('insufficient_scope')
  })
})

describe('audit tools', () => {
  const page = { events: [{ event_id: 'e1', event: 'site.updated', actor: { type: 'user', id: 'u1', session_id_hash: 'hmac-sha256:00' } }], nextCursor: 'jinbe-cursor', scope: {}, range: { from: 'a', to: 'b' }, truncated: false }

  it('search_audit sends no org unless asked, and defaults to the last 24 hours', async () => {
    const jinbe = mockJinbe({ 'GET /api/audit/events': page })
    const r = await execute(searchAudit, { event: ['sites.*'], result: 'denied' }, principal(), deps(jinbe.fetchImpl))
    const q = jinbe.calls[0].url.searchParams
    expect(q.has('org')).toBe(false)
    expect(q.getAll('event')).toEqual(['sites.*'])
    expect(Date.parse(q.get('to')!) - Date.parse(q.get('from')!)).toBe(86_400_000)
    expect(sc(r).nextCursor).toBe('jinbe-cursor')
    expect(sc(r).data.items[0].actor.session_id_hash).toBe('hmac-sha256:00')
  })

  it('an org argument narrows the search (jinbe decides whether it is readable); a non-uuid is refused', async () => {
    const jinbe = mockJinbe({ 'GET /api/audit/events': page })
    await execute(searchAudit, { org: ORG }, principal(), deps(jinbe.fetchImpl))
    expect(jinbe.calls[0].url.searchParams.getAll('org')).toEqual([ORG])
    const r = await execute(searchAudit, { org: 'someone-else' } as never, principal(), deps(jinbe.fetchImpl))
    expect(r.isError).toBe(true)
    expect(jinbe.calls).toHaveLength(1)
  })

  it('maps org_out_of_scope', async () => {
    const jinbe = mockJinbe({ 'GET /api/audit/events': () => ({ status: 403, body: { error: 'org_out_of_scope', message: 'You can only see audit events for organisations you administer.' } }) })
    const r = await execute(searchAudit, {}, principal(), deps(jinbe.fetchImpl))
    expect(sc(r).error).toMatchObject({ code: 'org_out_of_scope', retryable: false })
  })

  it('get_audit_event', async () => {
    const id = '0b7f7c2e-6a6c-4a55-9d4e-2f5b8f7e9a10'
    const r = await execute(getAuditEvent, { eventId: id }, principal(), deps(mockJinbe({ [`GET /api/audit/events/${id}`]: { event_id: id } }).fetchImpl))
    expect(sc(r).data.event_id).toBe(id)
  })
})

describe('get_my_identity', () => {
  it('answers from the token; its only jinbe call is the second-factor read, and it survives that failing', async () => {
    const jinbe = mockJinbe({})
    const r = await execute(getMyIdentity, {}, principal({ scopes: ['mcp', 'admin:read'] }), deps(jinbe.fetchImpl))
    expect(sc(r).data).toMatchObject({ subject: 'user-1', org: null, scopes: ['mcp', 'admin:read'], readOnly: true, credentialType: 'oauth', secondFactor: { available: false } })
    expect(jinbe.calls.map((c) => `${c.method} ${c.url.pathname}`)).toEqual(['GET /api/me/permissions'])
    expect(JSON.stringify(r)).not.toContain('ory_at_')
  })

  it('which of my actions need a second factor, and what this connection can do about each', async () => {
    const jinbe = mockJinbe({
      'GET /api/me/permissions': {
        groups: ['ops'], roles: [], permissions: ['sites:apply', 'users:reset_second_factor'],
        secondFactor: { required: true, requiredBecause: ['ops'], enrolled: true, methods: ['totp'], currentAal: 'aal2', factorAgeMin: 3, stepUpFresh: true, stepUpPermissions: ['sites:apply', 'users:reset_second_factor'] },
      },
    })
    const p = principal({ scopes: ['mcp', 'sites:apply'], kind: 'personal', keyId: 'k', stepUpActions: false })
    const r = await execute(getMyIdentity, {}, p, deps(jinbe.fetchImpl))
    const sf = sc(r).data.secondFactor
    expect(sf.signIn).toEqual({ required: true, requiredBecause: ['ops'], enrolled: true, methods: ['totp'] })
    expect(sf.actionsNeedingIt).toEqual([
      { permission: 'sites:apply', tools: ['publish_site', 'pause_site', 'resume_site', 'rollback_site'], thisConnection: 'key_created_without' },
      { permission: 'users:reset_second_factor', tools: [], thisConnection: 'console_only' },
    ])
  })

  it('a personal key without email or expiry still answers (no internal_error)', async () => {
    const p = principal({ kind: 'personal', keyId: 'key-1', email: null, expiresAt: undefined as unknown as number })
    const r = await execute(getMyIdentity, {}, p, deps(mockJinbe({}).fetchImpl))
    expect(r.isError).toBeFalsy()
    expect(sc(r).data).toMatchObject({ credentialType: 'personal_key', keyId: 'key-1', email: null, tokenExpiresAt: null })
  })
})
