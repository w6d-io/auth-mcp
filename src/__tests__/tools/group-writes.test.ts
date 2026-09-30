import { describe, expect, it } from 'vitest'
import { execute } from '../../mcp/registry.js'
import { createGroup, setSiteRoles, updateGroup } from '../../mcp/tools/group-writes.js'
import { writeTools } from '../../mcp/tools/index.js'
import { PROTECTED } from '../../mcp/permissions.js'
import { deps, mockJinbe, principal, sc } from '../helpers/fixtures.js'

const R = '/api/admin/rbac'
const admin = principal({ scopes: ['mcp', 'groups:write'], kind: 'personal', keyId: 'key-1' })

describe('create_group', () => {
  it('posts the group with an idempotency key', async () => {
    const jinbe = mockJinbe({ [`POST ${R}/groups`]: () => ({ status: 201, body: { success: true } }) })
    const r = await execute(createGroup, { name: 'billing_support', services: { billing: ['viewer'] } }, admin, deps(jinbe.fetchImpl))
    expect(jinbe.calls[0].body).toEqual({ name: 'billing_support', services: { billing: ['viewer'] } })
    expect(jinbe.calls[0].headers['idempotency-key']).toBeDefined()
    expect(sc(r).data).toEqual({ name: 'billing_support', services: { billing: ['viewer'] }, created: true })
  })

  it('refuses a bad name locally; a taken one is a conflict', async () => {
    const none = mockJinbe({})
    expect(sc(await execute(createGroup, { name: 'Billing-Support', services: {} }, admin, deps(none.fetchImpl))).error.code).toBe('invalid_request')
    expect(none.calls).toHaveLength(0)
    const taken = mockJinbe({ [`POST ${R}/groups`]: () => ({ status: 409, body: { error: 'conflict', message: 'exists' } }) })
    expect(sc(await execute(createGroup, { name: 'billing_support', services: {} }, admin, deps(taken.fetchImpl))).error.code).toBe('conflict')
  })
})

describe('update_group', () => {
  const groups = { groups: [{ name: 'billing_support', services: { billing: ['viewer'], shop: ['viewer'] } }] }

  it('merges by default and replaces on request, returning before and after', async () => {
    const jinbe = mockJinbe({ [`GET ${R}/groups`]: groups, [`PUT ${R}/groups/billing_support`]: { success: true } })
    const d = deps(jinbe.fetchImpl)
    const m = await execute(updateGroup, { name: 'billing_support', services: { billing: ['editor'] } }, admin, d)
    expect(jinbe.calls[1].body).toEqual({ services: { billing: ['editor'], shop: ['viewer'] } })
    expect(sc(m).data.before).toEqual({ billing: ['viewer'], shop: ['viewer'] })
    await execute(updateGroup, { name: 'billing_support', services: { billing: ['editor'] }, mode: 'replace' }, admin, d)
    expect(jinbe.calls[3].body).toEqual({ services: { billing: ['editor'] } })
  })

  it('an unknown group is not_found, nothing written', async () => {
    const jinbe = mockJinbe({ [`GET ${R}/groups`]: groups })
    expect(sc(await execute(updateGroup, { name: 'ghost', services: {} }, admin, deps(jinbe.fetchImpl))).error.code).toBe('not_found')
    expect(jinbe.calls.map((c) => c.method)).toEqual(['GET'])
  })
})

describe('set_site_roles', () => {
  it('replaces the roles, returning before and after; no bare * accepted', async () => {
    const jinbe = mockJinbe({ [`GET ${R}/services/billing/roles`]: { service: 'billing', roles: [{ name: 'viewer' }] }, [`PUT ${R}/services/billing/roles`]: { success: true } })
    const roles = { viewer: ['billing:read'], editor: ['billing:read', 'billing:write'] }
    const r = await execute(setSiteRoles, { service: 'billing', roles }, admin, deps(jinbe.fetchImpl))
    expect(jinbe.calls[1].body).toEqual({ roles })
    expect(sc(r).data).toMatchObject({ before: [{ name: 'viewer' }], after: roles })
    const star = mockJinbe({})
    expect(sc(await execute(setSiteRoles, { service: 'billing', roles: { admin: ['*'] } }, admin, deps(star.fetchImpl))).error.code).toBe('invalid_request')
    expect(star.calls).toHaveLength(0)
  })

  it('a key without protected actions is told to create one', async () => {
    const jinbe = mockJinbe({ [`GET ${R}/services/billing/roles`]: { roles: [] }, [`PUT ${R}/services/billing/roles`]: () => ({ status: 422, body: { error: 'step_up_unavailable' } }) })
    const r = await execute(setSiteRoles, { service: 'billing', roles: { viewer: ['billing:read'] } }, admin, deps(jinbe.fetchImpl))
    expect(sc(r).error.code).toBe('protected_actions_off')
  })
})

describe('protected flags match jinbe KEY_STEP_UP_PERMISSIONS', () => {
  it('a tool is protected exactly when its catalogue permission is', () => {
    for (const t of writeTools) {
      if (t.name === 'plan_bulk' || t.name === 'execute_bulk') continue
      expect(!!t.protectedAction, t.name).toBe(PROTECTED.has(t.scopes[0]))
    }
  })
  it('no group tool deletes', () => {
    expect(writeTools.map((t) => t.name).filter((n) => /delete|remove/.test(n))).toEqual([])
  })
})
