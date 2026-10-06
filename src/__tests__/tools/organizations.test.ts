import { describe, expect, it } from 'vitest'
import { execute } from '../../mcp/registry.js'
import { buildGate, expertGate, isExpertGate, ORG_GATE, PASS, presetGate, WHO } from '../../mcp/gate-presets.js'
import { buildSite, organizationTemplate, TEMPLATE_IDS, withOrganizations } from '../../mcp/site-templates.js'
import { lintSite } from '../../mcp/site-lint.js'
import { CATALOG_NEVER, P } from '../../mcp/permissions.js'
import { createSite } from '../../mcp/tools/site-writes.js'
import { setSiteOrganizations } from '../../mcp/tools/site-onboarding.js'
import { setSiteSignUp } from '../../mcp/tools/site-signup.js'
import { inviteToOrg, listOrgInvitations } from '../../mcp/tools/orgs.js'
import { allTools } from '../../mcp/tools/index.js'
import { ORG, OTHER_ORG, deps, mockJinbe, principal, sc } from '../helpers/fixtures.js'

const S = '/api/admin/sites'
const NOT_FOUND = () => ({ status: 404, body: { error: 'not_found' } })
const dev = principal({ scopes: ['mcp', 'sites:read', 'sites:write'] })
const basics = { name: 'billing', displayName: 'Billing', host: 'billing.example.com', service: 'billing', namespace: 'billing', port: 8080 }

/** jinbe sites/presets.ts ORG_GATE, as it serialises. */
const JINBE_ORG_GATE = {
  id: 'organization',
  label: 'Organization members and API keys',
  authenticators: [{ handler: 'cookie_session' }, { handler: 'oauth2_introspection' }],
  authorizer: 'policy',
  mutators: [{ handler: 'header' }],
  errors: 'api',
}

describe('organization presets (jinbe sites/presets.ts)', () => {
  it('people-and-org-keys and the organization gate are jinbe\'s, and a preset gate', () => {
    expect(WHO['people-and-org-keys']).toEqual([{ handler: 'cookie_session' }, { handler: 'oauth2_introspection' }])
    expect(JSON.stringify(ORG_GATE)).toBe(JSON.stringify(JINBE_ORG_GATE))
    expect(isExpertGate(ORG_GATE)).toBe(false)
  })

  it('no preset admits tokens without the policy: tokens + everyone is refused, nobody and policy are not', () => {
    const tokenWho = Object.entries(WHO).filter(([, hs]) => hs.some((h) => h.handler === 'oauth2_introspection')).map(([w]) => w)
    expect(tokenWho.sort()).toEqual(['machines', 'people-and-org-keys', 'signed-in-or-tokens', 'tokens'])
    for (const who of Object.keys(WHO)) {
      for (const pass of Object.keys(PASS)) {
        const r = presetGate.safeParse({ id: 'g', label: 'G', who, pass })
        expect(r.success, `${who}/${pass}`).toBe(!(tokenWho.includes(who) && pass === 'everyone'))
        if (r.success) expect(lintSite({ gates: [buildGate(r.data)] }).some((f) => f.code === 'tokens_need_policy'), `${who}/${pass}`).toBe(false)
      }
    }
  })

  it('an expert gate admitting tokens must use the policy (or deny)', () => {
    const base = { id: 'x', label: 'X', mutators: [{ handler: 'header' }], errors: 'api', reason: 'custom' }
    expect(expertGate.safeParse({ ...base, authenticators: [{ handler: 'oauth2_introspection' }], authorizer: { handler: 'allow' } }).success).toBe(false)
    expect(expertGate.safeParse({ ...base, authenticators: [{ handler: 'oauth2_introspection' }], authorizer: { handler: 'deny' } }).success).toBe(true)
    expect(expertGate.safeParse({ ...base, authenticators: [{ handler: 'cookie_session' }], authorizer: { handler: 'allow' } }).success).toBe(true)
  })

  it('no template, with or without organizations, produces a gate jinbe refuses (tokens_need_policy)', () => {
    for (const t of TEMPLATE_IDS) {
      for (const site of [buildSite(t, basics), withOrganizations(buildSite(t, basics)).site]) {
        expect(lintSite(site).filter((f) => f.code === 'tokens_need_policy' || f.code === 'organizations_off'), t).toEqual([])
      }
    }
  })
})

describe('the organization template (jinbe sites/organizations.ts organizationTemplate)', () => {
  it('is jinbe\'s: switch, gate, org route under the prefix, default org roles', () => {
    const t = organizationTemplate('billing', '/pay')
    expect(t.organizations).toEqual({ enabled: true, ownerRole: 'admin' })
    expect(t.gate).toEqual(JINBE_ORG_GATE)
    expect(t.route).toEqual({
      id: 'org', methods: ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE'], path: '/pay/orgs/:orgId/:any*', gate: 'organization',
      access: { kind: 'permission', permission: 'billing:use' }, orgParam: 'orgId', source: 'template',
    })
    expect(t.orgGrantable).toEqual({ 'billing-admin': { label: 'Admins', roles: ['admin'] }, 'billing-member': { label: 'Members', roles: ['user'] } })
    expect(organizationTemplate('billing').route.path).toBe('/orgs/:orgId/:any*')
  })

  it('adds to a site and keeps what is there: owner role, org roles, a route on the same path', () => {
    const site = buildSite('web-api', basics)
    const on = withOrganizations(site)
    expect(on.problems).toEqual([])
    expect(on.site.organizations).toEqual({ enabled: true, ownerRole: 'admin' })
    expect((on.site.gates as Array<{ id: string }>).map((g) => g.id)).toEqual(['public', 'browser', 'api', 'organization'])
    expect(on.added).toContain('route org (/orgs/:orgId/:any*)')

    const again = withOrganizations(on.site)
    expect(again.added).toEqual([])
    expect(JSON.stringify(again.site)).toBe(JSON.stringify(on.site))

    const custom = {
      ...site,
      organizations: { enabled: false, ownerRole: 'owner' },
      groups: { platform: {}, orgGrantable: { 'billing-owner': { label: 'Owners', roles: ['admin'] }, 'billing-member': { label: 'Mine', roles: ['viewer'] } } },
      routes: { items: [{ id: 'tenants', path: '/orgs/:orgId/:any*' }], catchAll: {} },
    }
    const kept = withOrganizations(custom)
    expect(kept.site.organizations).toEqual({ enabled: true, ownerRole: 'owner' })
    expect((kept.site.groups as any).orgGrantable['billing-member']).toEqual({ label: 'Mine', roles: ['viewer'] })
    expect((kept.site.routes as any).items).toHaveLength(1)
    expect(kept.kept).toContain('route tenants (/orgs/:orgId/:any*)')
  })

  it('says what jinbe would refuse: org roles mapping to missing site roles', () => {
    const r = withOrganizations({ ...buildSite('app', basics), roles: 'readonly' })
    expect(r.problems.join(' ')).toMatch(/admin, user/)
  })
})

describe('the site lint says early what jinbe refuses', () => {
  it('tokens_need_policy, high, first among a gate\'s findings', () => {
    const gate = { id: 'api', authenticators: [{ handler: 'oauth2_introspection' }], authorizer: { handler: 'allow' }, mutators: [{ handler: 'header' }], errors: 'api' }
    const f = lintSite({ gates: [gate] })
    expect(f[0]).toMatchObject({ code: 'tokens_need_policy', level: 'high', path: 'gates[0].authorizer' })
    expect(lintSite({ gates: [{ ...gate, authorizer: { handler: 'deny' } }] }).some((x) => x.code === 'tokens_need_policy')).toBe(false)
  })

  it('organizations_off: org routes, org roles, served orgs or org sign-up without the switch', () => {
    const site = buildSite('app', basics)
    expect(lintSite(site).some((f) => f.code === 'organizations_off')).toBe(false)
    const off = { ...site, routes: { items: [{ id: 'o', path: '/orgs/:orgId', orgParam: 'orgId' }] }, orgs: [ORG], signUp: { orgs: 'personal' } }
    expect(lintSite(off).find((f) => f.code === 'organizations_off')?.message).toMatch(/orgParam.*orgs.*signUp/)
    expect(lintSite({ ...off, organizations: { enabled: true } }).some((f) => f.code === 'organizations_off')).toBe(false)
  })
})

describe('create_site: upstream.path and organizations', () => {
  it('stores upstream.path and turns organizations on with the template', async () => {
    const jinbe = mockJinbe({ [`GET ${S}/billing`]: NOT_FOUND, [`GET ${S}/billing/draft`]: NOT_FOUND, [`PUT ${S}/billing/draft`]: { baseVersion: 0 } })
    const r = await execute(
      createSite,
      { name: 'billing', displayName: 'Billing', template: 'api', host: 'billing.example.com', upstream: { service: 'billing', namespace: 'billing', port: 8080, path: '/api/external' }, organizations: true },
      dev,
      deps(jinbe.fetchImpl)
    )
    expect(r.isError).toBeUndefined()
    const put = (jinbe.calls.find((c) => c.method === 'PUT')!.body as { site: any }).site
    expect(put.upstream).toEqual({ service: 'billing', namespace: 'billing', port: 8080, path: '/api/external' })
    expect(put.organizations).toEqual({ enabled: true, ownerRole: 'admin' })
    expect(put.routes.items.map((x: any) => x.id)).toContain('org')
    expect(sc(r).data.organizations.problems).toEqual([])
  })

  it('refuses a templated or trailing-slash upstream path locally', async () => {
    const jinbe = mockJinbe({})
    for (const path of ['/api/:id', '/api/', 'api']) {
      const r = await execute(createSite, { name: 'billing', displayName: 'B', host: 'b.example.com', upstream: { service: 'b', namespace: 'b', port: 80, path } }, dev, deps(jinbe.fetchImpl))
      expect(sc(r).error.code, path).toBe('invalid_request')
    }
    expect(jinbe.calls).toHaveLength(0)
  })

  it('refuses a preset gate admitting tokens with pass everyone, before any call', async () => {
    const jinbe = mockJinbe({})
    const r = await execute(
      createSite,
      { name: 'billing', displayName: 'B', host: 'b.example.com', upstream: { service: 'b', namespace: 'b', port: 80 }, gates: [{ id: 'api', label: 'API', who: 'machines', pass: 'everyone' }] },
      dev,
      deps(jinbe.fetchImpl)
    )
    expect(sc(r).error.code).toBe('invalid_request')
    expect(jinbe.calls).toHaveLength(0)
  })
})

describe('set_site_organizations', () => {
  const draft = () => ({ site: buildSite('web-api', basics), baseVersion: 2, etag: 'd1' })

  it('applies the template to the draft with If-Match, adds served organizations, and lints', async () => {
    const jinbe = mockJinbe({ [`GET ${S}/billing/draft`]: draft(), [`GET ${S}/billing`]: NOT_FOUND, [`PUT ${S}/billing/draft`]: { baseVersion: 2, etag: 'd2' } })
    const r = await execute(setSiteOrganizations, { name: 'billing', serve: [ORG, OTHER_ORG] }, dev, deps(jinbe.fetchImpl))
    expect(r.isError).toBeUndefined()
    const put = jinbe.calls.find((c) => c.method === 'PUT')!
    expect(put.headers['if-match']).toBe('"d1"')
    const site = (put.body as { site: any }).site
    expect(site.organizations).toEqual({ enabled: true, ownerRole: 'admin' })
    expect(site.orgs).toEqual([ORG, OTHER_ORG])
    expect(site.groups.orgGrantable).toHaveProperty('billing-admin')
    expect(sc(r).data.lint.findings.some((f: { code: string }) => f.code === 'organizations_off' || f.code === 'tokens_need_policy')).toBe(false)
    expect(sc(r).notes.join(' ')).toMatch(/invite_to_org/)
  })

  it('refuses when there is nothing to add, without writing', async () => {
    const on = withOrganizations(buildSite('web-api', basics)).site
    const jinbe = mockJinbe({ [`GET ${S}/billing/draft`]: { site: { ...on, orgs: [ORG] }, baseVersion: 2 }, [`GET ${S}/billing`]: NOT_FOUND })
    const r = await execute(setSiteOrganizations, { name: 'billing', serve: [ORG] }, dev, deps(jinbe.fetchImpl))
    expect(sc(r).error.code).toBe('invalid_request')
    expect(jinbe.calls.some((c) => c.method === 'PUT')).toBe(false)
  })
})

describe('set_site_signup without organizations', () => {
  it('defaults the sign-up organization to none while organizations are off', async () => {
    const jinbe = mockJinbe({ [`GET ${S}/billing/draft`]: { site: buildSite('app', basics), baseVersion: 1 }, [`GET ${S}/billing`]: NOT_FOUND, [`PUT ${S}/billing/draft`]: { baseVersion: 1 } })
    const r = await execute(setSiteSignUp, { name: 'billing', mode: 'closed' }, dev, deps(jinbe.fetchImpl))
    expect(sc(r).data.signUp.orgs).toBe('none')
  })
})

describe('organisation invitations', () => {
  const inviter = principal({ scopes: ['mcp', 'org.members:read', 'org.members:write'] })

  it('invite_to_org exists because org.members:write is delegable; nothing removes, revokes or creates keys', () => {
    expect(CATALOG_NEVER.has(P.ORG_MEMBERS_WRITE)).toBe(false)
    expect(CATALOG_NEVER.has('orgs.keys:write')).toBe(true)
    expect(allTools.find((t) => t.name === 'invite_to_org')?.scopes).toEqual(['org.members:write'])
    const orgWrites = allTools.filter((t) => t.write && t.scopes.some((s) => s.startsWith('org.') || s.startsWith('orgs')))
    expect(orgWrites.map((t) => t.name)).toEqual(['invite_to_org'])
    for (const t of allTools) for (const s of t.scopes) expect(CATALOG_NEVER.has(s), `${t.name}: ${s}`).toBe(false)
  })

  it('posts {email, roles} and returns neither the token nor the link', async () => {
    const jinbe = mockJinbe({
      [`POST /api/organizations/${ORG}/invitations`]: () => ({
        status: 201,
        body: { invitation: { id: 'i1', org: ORG, email: 'dave@example.com', roles: ['billing:member'], invitedBy: { id: 'user-1', email: 'alice@example.com' } }, token: 'raw-invitation-token-value', link: 'https://kuma.example.com/#/invite?token=raw-invitation-token-value' },
      }),
    })
    const r = await execute(inviteToOrg, { org: ORG, email: 'Dave@Example.com', roles: ['billing:member'] }, inviter, deps(jinbe.fetchImpl))
    expect(r.isError).toBeUndefined()
    expect(jinbe.calls[0].body).toEqual({ email: 'dave@example.com', roles: ['billing:member'] })
    expect(jinbe.calls[0].headers['idempotency-key']).toBeTruthy()
    expect(sc(r).data.invitation).toEqual({ id: 'i1', email: 'dave@example.com', roles: ['billing:member'], byPlatform: false, createdAt: null, expiresAt: null })
    expect(sc(r).data).not.toHaveProperty('link')
    expect(JSON.stringify(sc(r))).not.toContain('raw-invitation-token-value')
    expect(sc(r).notes.join(' ')).toMatch(/account page/)
    expect(JSON.stringify(sc(r))).not.toContain('alice@example.com')
  })

  it('refuses inviting the key holder, and a malformed role, before any call', async () => {
    const jinbe = mockJinbe({})
    expect(sc(await execute(inviteToOrg, { org: ORG, email: 'alice@example.com' }, inviter, deps(jinbe.fetchImpl))).error.code).toBe('self_target_refused')
    expect(sc(await execute(inviteToOrg, { org: ORG, email: 'bob@example.com', roles: ['admin'] }, inviter, deps(jinbe.fetchImpl))).error.code).toBe('invalid_request')
    expect(jinbe.calls).toHaveLength(0)
  })

  it('list_org_invitations shows pending invitations without tokens or the inviter', async () => {
    const jinbe = mockJinbe({
      [`GET /api/organizations/${ORG}/invitations`]: { invitations: [{ id: 'i1', org: ORG, email: 'dave@example.com', roles: [], invitedBy: { id: 'u', email: 'alice@example.com' }, byPlatform: true, expiresAt: 'x' }] },
    })
    const r = await execute(listOrgInvitations, { org: ORG }, inviter, deps(jinbe.fetchImpl))
    expect(sc(r).data.items).toEqual([{ id: 'i1', email: 'dave@example.com', roles: [], byPlatform: true, createdAt: null, expiresAt: 'x' }])
    expect(JSON.stringify(sc(r))).not.toContain('alice@example.com')
  })
})
