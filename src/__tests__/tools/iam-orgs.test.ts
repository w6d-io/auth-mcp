import { describe, expect, it } from 'vitest'
import { execute } from '../../mcp/registry.js'
import { getMyPermissions, getPermissionCatalog, listGroups, listRoles, listServices } from '../../mcp/tools/iam.js'
import { getOrg, listOrgMemberRoles, listOrgs, listOrgUsers } from '../../mcp/tools/orgs.js'
import { ORG, OTHER_ORG, deps, mockJinbe, principal, sc } from '../helpers/fixtures.js'

describe('IAM read tools', () => {
  it('list_groups filters and paginates', async () => {
    const groups = [{ name: 'payroll_admins', services: { payroll: ['admin'] } }, { name: 'viewers', services: { payroll: ['read'] } }]
    const r = await execute(listGroups, { query: 'pay' }, principal(), deps(mockJinbe({ 'GET /api/admin/rbac/groups': { groups } }).fetchImpl))
    expect(sc(r).data).toEqual({ items: [groups[0]], total: 1 })
  })

  it('list_services', async () => {
    const r = await execute(listServices, {}, principal(), deps(mockJinbe({ 'GET /api/admin/rbac/services': { services: [{ name: 'payroll' }] } }).fetchImpl))
    expect(sc(r).data.items).toEqual([{ name: 'payroll' }])
  })

  it('list_roles and get_permission_catalog hit the service paths', async () => {
    const jinbe = mockJinbe({
      'GET /api/admin/rbac/services/payroll/roles': { service: 'payroll', roles: [{ name: 'admin', permissions: ['payroll:write'] }] },
      'GET /api/admin/rbac/services/payroll/permissions': { service: 'payroll', permissions: ['payroll:read', 'payroll:write'] },
    })
    const d = deps(jinbe.fetchImpl)
    expect(sc(await execute(listRoles, { service: 'payroll' }, principal(), d)).data.roles[0].name).toBe('admin')
    expect(sc(await execute(getPermissionCatalog, { service: 'payroll' }, principal(), d)).data.permissions).toHaveLength(2)
  })

  it('get_my_permissions works with the baseline scope alone', async () => {
    const jinbe = mockJinbe({ 'GET /api/me/permissions': { subject: 'user-1', groups: ['g'], roles: ['r'], permissions: ['admin:read'], actions: { invite: false } } })
    const r = await execute(getMyPermissions, {}, principal({ scopes: ['mcp'] }), deps(jinbe.fetchImpl))
    expect(sc(r).data).toEqual({ groups: ['g'], roles: ['r'], permissions: ['admin:read'], actions: { invite: false } })
  })
})

describe('organisation tools name their org; jinbe decides', () => {
  it('list_orgs lists the orgs you belong to, with what you may do in each', async () => {
    const jinbe = mockJinbe({
      'GET /api/me/organizations': { organizations: [ORG, OTHER_ORG], names: { [ORG]: 'Acme' } },
      'GET /api/me/permissions': { groups: [], roles: [], permissions: [], orgPermissions: { [ORG]: ['org.members:read'], 'ffffffff-0000-4000-8000-000000000000': ['org.members:read'] } },
    })
    const r = await execute(listOrgs, {}, principal(), deps(jinbe.fetchImpl))
    expect(sc(r).data.items).toEqual([
      { id: ORG, name: 'Acme', permissions: ['org.members:read'] },
      { id: OTHER_ORG, name: null, permissions: [] },
    ])
    expect(jinbe.calls.find((c) => c.url.pathname === '/api/me/permissions')?.url.searchParams.get('orgLimit')).toBe('1000')
  })

  it('list_orgs still lists the orgs when the permissions are not reported', async () => {
    const jinbe = mockJinbe({ 'GET /api/me/organizations': { organizations: [ORG], names: {} } })
    const r = await execute(listOrgs, {}, principal(), deps(jinbe.fetchImpl))
    expect(sc(r).data.items).toEqual([{ id: ORG, name: null, permissions: null }])
  })

  it('list_orgs: an org past the last page of permissions is unknown, not empty', async () => {
    const [low, high] = [ORG, OTHER_ORG].sort()
    const jinbe = mockJinbe({
      'GET /api/me/organizations': { organizations: [low, high] },
      'GET /api/me/permissions': { groups: [], roles: [], permissions: [], orgPermissions: {}, orgPermissionsPage: { total: 2000, next: low } },
    })
    const r = await execute(listOrgs, {}, principal(), deps(jinbe.fetchImpl))
    expect(sc(r).data.items.map((i: { permissions: unknown }) => i.permissions)).toEqual([[], null])
  })

  it('get_org as a member: the org roles and which you may assign, no platform view without orgs:read', async () => {
    const jinbe = mockJinbe({
      'GET /api/me/organizations': { organizations: [ORG], names: { [ORG]: 'Acme' } },
      [`GET /api/organizations/${ORG}/roles`]: { roles: [{ role: 'jinbe:viewer', permissions: ['org.members:read'], assignable: true }, { role: 'jinbe:owner', permissions: ['org.members:write'], assignable: false }] },
    })
    const r = await execute(getOrg, { org: ORG }, principal(), deps(jinbe.fetchImpl))
    expect(sc(r).data).toEqual({
      id: ORG,
      name: 'Acme',
      member: true,
      platform: null,
      roles: [
        { role: 'jinbe:viewer', permissions: ['org.members:read'], assignable: true },
        { role: 'jinbe:owner', permissions: ['org.members:write'], assignable: false },
      ],
    })
    expect(jinbe.calls.map((c) => c.url.pathname)).not.toContain(`/api/admin/organizations/${ORG}`)
  })

  it('get_org with orgs:read: owners and sites from the platform, even for an org you do not belong to', async () => {
    const jinbe = mockJinbe({
      'GET /api/me/organizations': { organizations: [] },
      [`GET /api/admin/organizations/${OTHER_ORG}`]: { id: OTHER_ORG, name: 'Globex', tenant: 'globex', applications: [], owners: ['u-1'], sites: ['jinbe', 'shop'] },
      [`GET /api/organizations/${OTHER_ORG}/roles`]: () => ({ status: 403, body: { error: 'Forbidden', message: 'Not allowed' } }),
    })
    const r = await execute(getOrg, { org: OTHER_ORG }, principal({ scopes: ['mcp', 'orgs:read', 'org.members:read'] }), deps(jinbe.fetchImpl))
    expect(sc(r).data).toMatchObject({ name: 'Globex', member: false, platform: { tenant: 'globex', owners: ['u-1'], sites: ['jinbe', 'shop'] }, roles: null })
    expect(sc(r).notes.join(' ')).toMatch(/org\.members:read/)
  })

  it('get_org: an organisation that does not exist is not_found', async () => {
    const jinbe = mockJinbe({
      'GET /api/me/organizations': { organizations: [] },
      [`GET /api/admin/organizations/${ORG}`]: () => ({ status: 404, body: { error: 'organisation_not_found', message: 'No organisation' } }),
      [`GET /api/organizations/${ORG}/roles`]: { roles: [] },
    })
    const r = await execute(getOrg, { org: ORG }, principal({ scopes: ['mcp', 'orgs:read', 'org.members:read'] }), deps(jinbe.fetchImpl))
    expect(sc(r).error).toMatchObject({ code: 'not_found' })
  })

  it('get_org: refused everywhere is a forbidden', async () => {
    const jinbe = mockJinbe({
      'GET /api/me/organizations': { organizations: [] },
      [`GET /api/organizations/${OTHER_ORG}/roles`]: () => ({ status: 403, body: { error: 'Forbidden', message: 'Not allowed' } }),
    })
    const r = await execute(getOrg, { org: OTHER_ORG }, principal(), deps(jinbe.fetchImpl))
    expect(sc(r).error).toMatchObject({ code: 'forbidden' })
  })

  it('list_org_users returns id, email, name, state only — no traits, no credentials', async () => {
    const jinbe = mockJinbe({
      [`GET /api/organizations/${ORG}/users`]: {
        data: [
          { id: 'u1', state: 'active', traits: { email: 'a@acme.test', name: { first: 'Ada', last: 'L' }, phone: '+33 6' }, credentials: { password: { hashed: 'x' } }, metadata_admin: { x: 1 } },
          { id: 'u2', traits: { email: 'b@acme.test', name: 'Bob' } },
        ],
      },
    })
    const r = await execute(listOrgUsers, { org: ORG, email: 'a@acme.test' }, principal(), deps(jinbe.fetchImpl))
    expect(sc(r).data.items).toEqual([
      { id: 'u1', email: 'a@acme.test', name: 'Ada L', state: 'active' },
      { id: 'u2', email: 'b@acme.test', name: 'Bob', state: null },
    ])
    expect(jinbe.calls[0].url.searchParams.get('credentials_identifier')).toBe('a@acme.test')
    expect(JSON.stringify(r)).not.toContain('+33')
  })

  it('list_org_member_roles: the org roles each member holds', async () => {
    const jinbe = mockJinbe({
      [`GET /api/organizations/${ORG}/users`]: { data: [{ id: 'u1', traits: { email: 'a@acme.test' }, roles: ['jinbe:owner'] }, { id: 'u2', traits: { email: 'b@acme.test' } }] },
    })
    const r = await execute(listOrgMemberRoles, { org: ORG }, principal(), deps(jinbe.fetchImpl))
    expect(sc(r).data.items).toEqual([
      { id: 'u1', email: 'a@acme.test', roles: ['jinbe:owner'] },
      { id: 'u2', email: 'b@acme.test', roles: [] },
    ])
  })

  it('list_org_member_roles with userId: that member\'s roles and direct grants here', async () => {
    const USER = '0f0e0d0c-0b0a-4908-8706-050403020100'
    const jinbe = mockJinbe({
      [`GET /api/organizations/${ORG}/users/${USER}/roles`]: { id: USER, roles: ['jinbe:viewer'] },
      [`GET /api/organizations/${ORG}/users/${USER}/grants`]: {
        id: USER, email: 'a@acme.test',
        grants: [{ id: 'g1', scope: ORG, app: 'shop', kind: 'role', name: 'editor', expiresAt: '2026-12-01T00:00:00Z', grantedBy: 'boss@acme.test', grantedAt: 't', active: true }],
      },
    })
    const r = await execute(listOrgMemberRoles, { org: ORG, userId: USER }, principal({ scopes: ['mcp', 'org.members:read'] }), deps(jinbe.fetchImpl))
    expect(sc(r).data.items).toEqual([{
      id: USER, email: 'a@acme.test', roles: ['jinbe:viewer'],
      directGrants: [{ id: 'g1', app: 'shop', kind: 'role', name: 'editor', active: true, expiresAt: '2026-12-01T00:00:00Z', grantedBy: 'boss@acme.test', reason: null }],
    }])
  })

  it('another org is just another argument: jinbe refusing it is a forbidden', async () => {
    const jinbe = mockJinbe({ [`GET /api/organizations/${OTHER_ORG}/users`]: () => ({ status: 403, body: { error: 'Forbidden', message: 'Not allowed' } }) })
    const r = await execute(listOrgMemberRoles, { org: OTHER_ORG }, principal(), deps(jinbe.fetchImpl))
    expect(sc(r).error).toMatchObject({ code: 'forbidden' })
    expect(jinbe.calls[0].url.pathname).toBe(`/api/organizations/${OTHER_ORG}/users`)
  })

  it('an org tool without an org is refused before jinbe is called', async () => {
    const jinbe = mockJinbe({})
    const r = await execute(listOrgUsers, {} as never, principal(), deps(jinbe.fetchImpl))
    expect(r.isError).toBe(true)
    expect(jinbe.calls).toHaveLength(0)
  })
})

describe('second factor in the IAM reads (jinbe wave19)', () => {
  it('get_second_factor_map passes the one-read map through', async () => {
    const { getSecondFactorMap } = await import('../../mcp/tools/iam.js')
    const map = { rules: [], groups: { ops: { required: true } }, permissions: null, unavailable: ['permissions'] }
    const r = await execute(getSecondFactorMap, {}, principal({ scopes: ['mcp', 'groups:read'] }), deps(mockJinbe({ 'GET /api/admin/rbac/second-factor-map': map }).fetchImpl))
    expect(sc(r).data).toEqual(map)
  })

  it('jinbe roles carry stepUpPermissions, jinbe permissions their stepUpRule', async () => {
    const { listRoles, getPermissionCatalog } = await import('../../mcp/tools/iam.js')
    const jinbe = mockJinbe({
      'GET /api/admin/rbac/services/jinbe/roles': { service: 'jinbe', roles: [{ name: 'ops', permissions: ['sites:read', 'sites:apply'] }] },
      'GET /api/admin/rbac/services/jinbe/permissions': ['sites:read', 'sites:apply'],
      'GET /api/catalog': { permissions: [{ name: 'sites:apply', stepUpRule: { required: true, maxAgeMin: 15, viaPersonalKey: { maxAgeDays: 30 }, fourEyes: 'prod' } }, { name: 'sites:read', stepUpRule: { required: false, maxAgeMin: null, viaPersonalKey: null, fourEyes: false } }] },
    })
    const roles = await execute(listRoles, { service: 'jinbe' }, principal(), deps(jinbe.fetchImpl))
    expect(sc(roles).data.roles[0].stepUpPermissions).toEqual(['sites:apply'])
    const cat = await execute(getPermissionCatalog, { service: 'jinbe' }, principal(), deps(jinbe.fetchImpl))
    expect(sc(cat).data.stepUpRules['sites:apply']).toMatchObject({ required: true, maxAgeMin: 15, fourEyes: 'prod' })
  })
})
