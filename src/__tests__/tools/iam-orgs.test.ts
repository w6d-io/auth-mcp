import { describe, expect, it } from 'vitest'
import { execute } from '../../mcp/registry.js'
import { getMyPermissions, getPermissionCatalog, listGroups, listRoles, listServices } from '../../mcp/tools/iam.js'
import { getOrg, listOrgGrants, listOrgs, listOrgUsers } from '../../mcp/tools/orgs.js'
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
  it('list_orgs lists the ids the org tools take', async () => {
    const jinbe = mockJinbe({ 'GET /api/me/organizations': { organizations: [ORG, OTHER_ORG], names: { [ORG]: 'Acme' } } })
    const r = await execute(listOrgs, {}, principal(), deps(jinbe.fetchImpl))
    expect(sc(r).data.items).toEqual([
      { id: ORG, name: 'Acme' },
      { id: OTHER_ORG, name: null },
    ])
  })

  it('get_org reads assignable groups of the named org', async () => {
    const jinbe = mockJinbe({
      'GET /api/me/organizations': { organizations: [ORG], names: { [ORG]: 'Acme' } },
      [`GET /api/organizations/${ORG}/assignable-groups`]: { groups: [{ name: 'acme-payroll', roles: { payroll: ['user'] } }] },
    })
    const r = await execute(getOrg, { org: ORG }, principal(), deps(jinbe.fetchImpl))
    expect(sc(r).data).toEqual({ id: ORG, name: 'Acme', assignableGroups: [{ name: 'acme-payroll', roles: { payroll: ['user'] } }] })
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

  it('list_org_grants', async () => {
    const jinbe = mockJinbe({ [`GET /api/organizations/${ORG}/grants`]: { grants: { 'a@acme.test': ['acme-payroll'] } } })
    const r = await execute(listOrgGrants, { org: ORG }, principal(), deps(jinbe.fetchImpl))
    expect(sc(r).data.items).toEqual([{ member: 'a@acme.test', groups: ['acme-payroll'] }])
  })

  it('an org admin key (org.members:read only) reaches the org tools', async () => {
    const jinbe = mockJinbe({ [`GET /api/organizations/${ORG}/grants`]: { grants: {} } })
    const r = await execute(listOrgGrants, { org: ORG }, principal({ scopes: ['mcp', 'org.members:read'] }), deps(jinbe.fetchImpl))
    expect(r.isError).toBeUndefined()
  })

  it('another org is just another argument: jinbe refusing it is a forbidden', async () => {
    const jinbe = mockJinbe({ [`GET /api/organizations/${OTHER_ORG}/grants`]: () => ({ status: 403, body: { error: 'Forbidden', message: 'Not allowed' } }) })
    const r = await execute(listOrgGrants, { org: OTHER_ORG }, principal(), deps(jinbe.fetchImpl))
    expect(sc(r).error).toMatchObject({ code: 'forbidden' })
    expect(jinbe.calls[0].url.pathname).toBe(`/api/organizations/${OTHER_ORG}/grants`)
  })

  it('an org tool without an org is refused before jinbe is called', async () => {
    const jinbe = mockJinbe({})
    const r = await execute(listOrgUsers, {} as never, principal(), deps(jinbe.fetchImpl))
    expect(r.isError).toBe(true)
    expect(jinbe.calls).toHaveLength(0)
  })
})
