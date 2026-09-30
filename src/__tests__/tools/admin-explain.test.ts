import { describe, expect, it } from 'vitest'
import { execute } from '../../mcp/registry.js'
import { explainAdminAccess } from '../../mcp/tools/admin-explain.js'
import { getUserAccess } from '../../mcp/tools/access.js'
import { getSite } from '../../mcp/tools/sites.js'
import { fromJinbe } from '../../safety/errors.js'
import { deps, mockJinbe, principal, sc } from '../helpers/fixtures.js'

const explained = {
  subject: { id: 'user-1', email: 'alice@example.com', via: 'delegated', client: true, scopes: ['mcp', 'org.members:read'] },
  route: { method: 'GET', path: '/api/organizations/o1/users', pattern: '/api/organizations/:organizationId/users', params: { organizationId: 'o1' } },
  verdict: { status: 403, allowed: false, code: 'step_up_unavailable', reason: 'needs_2fa' },
  decidedBy: 'requireServiceAdmin',
  steps: [{ step: 'opa', verdict: 'refuse', input: { method: 'GET' }, detail: { allow: false, reason: 'needs_2fa', explain: { available: false, note: 'rbac.explain not deployed' } } }],
  disagreements: [{ kind: 'roster_redis_vs_opa', between: ['redis', 'opa'], detail: 'alice@example.com is on the roster in jinbe but not in the policy data.' }],
}

describe('explain_admin_access', () => {
  it('any connection may explain its own call; the answer passes through with readable notes', async () => {
    const jinbe = mockJinbe({ 'POST /api/admin/rbac/explain-route': explained })
    const r = await execute(explainAdminAccess, { method: 'GET', path: '/api/organizations/o1/users' }, principal({ scopes: ['mcp'] }), deps(jinbe.fetchImpl))
    expect(jinbe.calls[0].body).toEqual({ method: 'GET', path: '/api/organizations/o1/users' })
    expect(jinbe.calls[0].headers['idempotency-key']).toBeUndefined()
    expect(sc(r).data.decidedBy).toBe('requireServiceAdmin')
    const notes = sc(r).notes.join(' ')
    expect(notes).toMatch(/Refused by requireServiceAdmin \(step_up_unavailable\)/)
    expect(notes).toMatch(/cannot stand in/)
    expect(notes).toMatch(/Disagreement \(roster_redis_vs_opa\): alice@example.com is on the roster/)
    expect(notes).toMatch(/not deployed yet/)
  })

  it('only jinbe paths; asking about someone else without access:check is jinbe\'s permission_required', async () => {
    const none = mockJinbe({})
    expect(sc(await execute(explainAdminAccess, { method: 'GET', path: '/metrics' }, principal(), deps(none.fetchImpl))).error.code).toBe('invalid_request')
    expect(none.calls).toHaveLength(0)
    const refused = mockJinbe({ 'POST /api/admin/rbac/explain-route': () => ({ status: 403, body: { error: 'Forbidden', code: 'permission_required', permission: 'access:check', grantedBy: ['security'], hint: 'Ask an administrator to add you to one of: security.' } }) })
    const r = await execute(explainAdminAccess, { method: 'GET', path: '/api/admin/users', subject: 'bob@example.com' }, principal(), deps(refused.fetchImpl))
    expect(sc(r).error).toMatchObject({ code: 'forbidden', details: { permission: 'access:check', grantedBy: ['security'] } })
  })
})

describe('admin-explain fields elsewhere', () => {
  it('get_user_access says why a rostered person is not an org admin to the policy', async () => {
    const jinbe = mockJinbe({ 'GET /api/admin/users/u-1/access': { site: { groups: [], byService: {} }, orgs: [{ orgId: 'o1', name: 'Acme', admin: false, rostered: true, why: 'email_case_mismatch', grants: [] }] } })
    const r = await execute(getUserAccess, { userId: 'u-1' }, principal(), deps(jinbe.fetchImpl))
    expect(sc(r).notes[0]).toMatch(/Acme: on the organisation's admin roster but not an admin to the policy \(the roster spells their email with a different case\)/)
  })

  it('get_site carries resolvedGates (explicit vs default per field)', async () => {
    const resolvedGates = [{ gate: 'billing-api', handlers: [{ kind: 'authenticator', handler: 'oauth2_introspection', enabled: true, config: { cache: { ttl: '30s' } }, fields: { 'cache.ttl': 'default' } }] }]
    const jinbe = mockJinbe({ 'GET /api/admin/sites/billing': { site: {}, version: 1, etag: 'e', status: 'live', savedAt: 't', savedBy: 'x', applied: null, resolvedGates } })
    expect(sc(await execute(getSite, { name: 'billing' }, principal(), deps(jinbe.fetchImpl))).data.resolvedGates).toEqual(resolvedGates)
  })

  it('requireServiceAdmin refusals: route_not_published → not_found, needs_2fa → needs_2fa, with grantedBy', () => {
    expect(fromJinbe(403, { error: 'Forbidden', code: 'route_not_published', reason: 'not_found' }).body.code).toBe('not_found')
    const e = fromJinbe(403, { error: 'Forbidden', code: 'needs_2fa', reason: 'needs_2fa', permission: 'org.members:read', grantedBy: ['org-admins'], hint: 'Prove a second factor.', stepUp: { requiredAal: 'aal2' } })
    expect(e.body).toMatchObject({ code: 'needs_2fa', hint: 'Prove a second factor.', details: { permission: 'org.members:read', grantedBy: ['org-admins'], stepUp: { requiredAal: 'aal2' } } })
  })
})
