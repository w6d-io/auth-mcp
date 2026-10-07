import { describe, expect, it } from 'vitest'
import { execute } from '../../mcp/registry.js'
import { backendPath, lintNames, namesOf, rolesFromRoutes, siblingNameFindings, siteRoles } from '../../mcp/site-names.js'
import { checkSiteDraft, findSitesForService } from '../../mcp/tools/sites.js'
import { setSiteAccess } from '../../mcp/tools/site-onboarding.js'
import { planSiteChangeText, onboardSiteText } from '../../mcp/prompts.js'
import { BEFORE_YOU_BUILD, NAMING_CONVENTION } from '../../mcp/guide.js'
import { SERVER_INSTRUCTIONS } from '../../mcp/server.js'
import { deps, mockJinbe, principal, sc } from '../helpers/fixtures.js'

// Same names for the same thing: one backend (earning-service) once got the template roles on one site,
// `partner` on another and a group `earnings-tech` saying nothing — what reuse, the convention and the
// name lints are for.

const S = '/api/admin/sites'
const NOT_FOUND = () => ({ status: 404, body: { error: 'not_found' } })
const dev = principal({ scopes: ['mcp', 'sites:read', 'sites:write', 'groups:read'] })
const tmpl = (n: string) => ({
  admin: [`${n}:create`, `${n}:delete`, `${n}:execute`, `${n}:list`, `${n}:read`, `${n}:update`, 'earnings.external:read'],
  editor: [`${n}:list`, `${n}:read`, `${n}:create`, `${n}:update`],
  viewer: [`${n}:list`, `${n}:read`],
  user: [`${n}:list`, `${n}:read`, `${n}:use`],
})
// `earnings` as it stood on auth-dev: template roles kept over routes asking other permissions.
const earnings = () => ({
  name: 'earnings',
  upstream: { service: 'earning-service', namespace: 'stairling', port: 80 },
  routes: {
    items: [
      { id: 'days', methods: ['GET'], path: '/api/external/earnings/days', gate: 'organization', access: { kind: 'permission', permission: 'earnings.external:read' } },
      { id: 'last-activity', methods: ['GET'], path: '/api/earnings/persons/:personId/last-activity', gate: 'organization', access: { kind: 'permission', permission: 'earnings.last-activity:read' } },
    ],
    catchAll: { gate: 'organization', access: { kind: 'deny' } },
  },
  roles: { ...tmpl('earnings'), 'last-activity-reader': ['earnings.last-activity:read'] },
  groups: { platform: { 'earnings-tech': ['last-activity-reader'] }, orgGrantable: { 'earnings-admin': { label: 'Admin', roles: ['admin'] }, 'earnings-member': { label: 'Member', roles: ['user'] } } },
  organizations: { enabled: true, ownerRole: 'admin' },
})
// `stairfleet`: the same backend behind a rewrite, with the access named for the job.
const stairfleet = () => ({
  name: 'stairfleet',
  upstream: { service: 'earning-service', namespace: 'stairling', port: 80, stripPath: '/api/v1', path: '/api/external' },
  routes: { items: [{ id: 'earnings-days', methods: ['GET'], path: '/api/v1/earnings/days', gate: 'organization', access: { kind: 'permission', permission: 'earnings.external:read' } }], catchAll: { gate: 'organization', access: { kind: 'deny' } } },
  roles: { partner: ['earnings.external:read'] },
  groups: { platform: {}, orgGrantable: { 'stairfleet-partner': { label: 'Partner', roles: ['partner'] } } },
  organizations: { enabled: true, ownerRole: 'partner' },
})
const codes = (site: Record<string, unknown>) => lintNames(site).map((f) => f.code)

describe('lintNames', () => {
  it('flags the template roles left over routes asking other permissions, and a group not named for what it gives', () => {
    const f = lintNames(earnings())
    expect(f.map((x) => x.code)).toEqual(['template_roles_unused', 'group_name_pattern'])
    expect(f[0]).toMatchObject({ level: 'low', path: 'roles' })
    expect(f[0].message).toMatch(/admin, editor, viewer, user carry earnings:create.*no route asks.*from-routes/)
    expect(f[1].message).toMatch(/'earnings-tech' gives last-activity-reader.*'earnings-last-activity-readers'/)
  })

  it('a site named for the job has no finding; the template org groups (<site>-admin, <site>-member) pass', () => {
    expect(codes(stairfleet())).toEqual([])
    const named = { ...earnings(), roles: { partner: ['earnings.external:read'], 'activity-reader': ['earnings.last-activity:read'] }, groups: { platform: { 'earnings-activity-readers': ['activity-reader'] }, orgGrantable: { 'earnings-partner': { roles: ['partner'] } } }, organizations: { enabled: true, ownerRole: 'partner' } }
    expect(codes(named)).toEqual([])
  })

  it('flags a role carrying permissions no route asks, never a wildcard', () => {
    const site = { ...stairfleet(), roles: { partner: ['earnings.external:read', 'earnings.payouts:write', 'earnings:*'] } }
    const f = lintNames(site)
    expect(f.map((x) => x.code)).toEqual(['role_permission_unused'])
    expect(f[0].message).toMatch(/'partner' carries earnings\.payouts:write/)
    expect(f[0].message).not.toMatch(/earnings:\*/)
  })

  it('flags a route permission no role carries: medium without organizations, low (org keys still reach it) with them', () => {
    const off = { ...stairfleet(), roles: { viewer: ['other:read'] }, organizations: { enabled: false }, groups: {} }
    expect(lintNames(off).find((x) => x.code === 'route_permission_unheld')).toMatchObject({ level: 'medium' })
    const on = { ...stairfleet(), roles: { viewer: ['other:read'] } }
    const f = lintNames(on).find((x) => x.code === 'route_permission_unheld')!
    expect(f.level).toBe('low')
    expect(f.message).toMatch(/only organization API keys/)
    // A wildcard role reaches it.
    expect(codes({ ...stairfleet(), roles: { partner: ['earnings.external:*'] } })).not.toContain('route_permission_unheld')
  })

  it('a preset is expanded as jinbe does: standard over routes asking its own verbs is fine, over others is left over', () => {
    const mine = { name: 'payroll', routes: { items: [{ methods: ['GET'], path: '/x', access: { kind: 'permission', permission: 'payroll:read' } }] }, roles: 'standard' }
    expect(codes(mine)).toEqual([])
    expect(siteRoles(mine).admin).toContain('payroll:read')
    const other = { ...mine, routes: { items: [{ methods: ['GET'], path: '/x', access: { kind: 'permission', permission: 'payroll.slips:read' } }] } }
    expect(codes(other)).toEqual(['template_roles_unused'])
  })

  it('leaves a shared platform group (not <site>-…) to its own name, and checks org groups as <site>-<role>', () => {
    const site = { ...stairfleet(), groups: { platform: { devs: ['partner'] }, orgGrantable: { 'stairfleet-readers': { roles: ['partner'] } } } }
    const f = lintNames(site)
    expect(f.map((x) => x.code)).toEqual(['group_name_pattern'])
    expect(f[0].message).toMatch(/'stairfleet-partner' \(<site>-<role>\)/)
  })
})

describe('names across sibling sites', () => {
  it('maps a site path to the backend path (strip_path removed, upstream.path prepended)', () => {
    expect(backendPath(stairfleet(), '/api/v1/earnings/days')).toBe('/api/external/earnings/days')
    expect(backendPath(earnings(), '/api/external/earnings/days')).toBe('/api/external/earnings/days')
  })

  it('a route reaching a backend path a sibling protects with another permission is flagged with the sibling name', () => {
    const draft = { ...earnings(), routes: { items: [{ id: 'd', methods: ['GET'], path: '/api/external/earnings/days', access: { kind: 'permission', permission: 'earnings.days:read' } }] } }
    const f = siblingNameFindings(draft, [{ name: 'stairfleet', site: stairfleet() }])
    expect(f).toHaveLength(1)
    expect(f[0]).toMatchObject({ code: 'name_differs_from_sibling', level: 'medium' })
    expect(f[0].message).toMatch(/'stairfleet' already protects with earnings\.external:read; this site asks earnings\.days:read/)
    expect(siblingNameFindings(earnings(), [{ name: 'stairfleet', site: stairfleet() }])).toEqual([])
  })

  it('namesOf lists each permission with the backend paths asking it, the roles and the groups', () => {
    const n = namesOf([{ name: 'earnings', site: earnings() }, { name: 'stairfleet', site: stairfleet() }])
    expect(n.permissions.find((p) => p.permission === 'earnings.external:read')!.routes).toEqual([
      { site: 'earnings', method: 'GET', path: '/api/external/earnings/days', backend: '/api/external/earnings/days' },
      { site: 'stairfleet', method: 'GET', path: '/api/v1/earnings/days', backend: '/api/external/earnings/days' },
    ])
    expect(n.roles).toContainEqual({ site: 'stairfleet', role: 'partner', permissions: ['earnings.external:read'] })
    expect(n.groups).toContainEqual({ site: 'earnings', kind: 'platform', group: 'earnings-tech', roles: ['last-activity-reader'] })
    expect(n.groups).toContainEqual({ site: 'stairfleet', kind: 'organization', group: 'stairfleet-partner', roles: ['partner'] })
  })

  it('rolesFromRoutes makes one role per permission the routes ask, named from it', () => {
    expect(rolesFromRoutes(earnings())).toEqual({ 'external-reader': ['earnings.external:read'], 'last-activity-reader': ['earnings.last-activity:read'] })
  })
})

describe('the tools', () => {
  const summary = (name: string, host: string) => ({ name, displayName: name, host, status: 'live', version: 1, appliedVersion: 1, appliedAt: null, appliedBy: null, orgs: 0, protection: null })
  const world = () => ({
    [`GET ${S}`]: [summary('earnings', 'earnings.example.com'), summary('stairfleet', 'stairfleet.example.com')],
    [`GET ${S}/earnings`]: { site: earnings(), version: 5, etag: 'e', status: 'live' },
    [`GET ${S}/stairfleet`]: { site: stairfleet(), version: 1, etag: 'e', status: 'live' },
    [`POST ${S}/preview`]: { checks: [], risk: { flags: [] }, words: [] },
  })

  it('find_sites_for_service carries the names in use and says to reuse them', async () => {
    const r = await execute(findSitesForService, { service: 'earning-service', namespace: 'stairling' }, dev, deps(mockJinbe(world()).fetchImpl))
    expect(sc(r).data.names.permissions.map((p: { permission: string }) => p.permission)).toEqual(['earnings.external:read', 'earnings.last-activity:read'])
    expect(sc(r).notes.join(' ')).toMatch(/Reuse these names.*<site>-<role>s/)
  })

  it('check_site_draft flags a route naming a sibling backend operation differently', async () => {
    const draft = { ...earnings(), name: 'earnings-v2', routes: { items: [{ id: 'd', methods: ['GET'], path: '/api/external/earnings/days', gate: 'organization', access: { kind: 'permission', permission: 'earnings.days:read' } }], catchAll: { gate: 'organization', access: { kind: 'deny' } } } }
    const r = await execute(checkSiteDraft, { site: draft }, dev, deps(mockJinbe(world()).fetchImpl))
    const f = sc(r).data.lint.findings.filter((x: { code: string }) => x.code === 'name_differs_from_sibling')
    expect(f.length).toBeGreaterThan(0)
    expect(f[0].message).toMatch(/earnings\.external:read/)
  })

  it("set_site_access roles 'from-routes' writes one role per route permission, and refuses when no route asks one", async () => {
    const draft = { site: { ...earnings(), name: 'billing' }, baseVersion: 1 }
    const j = mockJinbe({ [`GET ${S}/billing/draft`]: draft, [`GET ${S}/billing`]: NOT_FOUND, [`PUT ${S}/billing/draft`]: (req) => ({ body: { baseVersion: (req.body as any).baseVersion, updatedAt: 'now' } }) })
    const r = await execute(setSiteAccess, { name: 'billing', roles: 'from-routes' }, dev, deps(j.fetchImpl))
    expect((j.calls.find((c) => c.method === 'PUT')!.body as any).site.roles).toEqual({ 'external-reader': ['earnings.external:read'], 'last-activity-reader': ['earnings.last-activity:read'] })
    expect(sc(r).notes[0]).toMatch(/Rename each for the job/)
    const empty = { site: { name: 'billing', routes: { items: [], catchAll: { access: { kind: 'deny' } } } }, baseVersion: 1 }
    const j2 = mockJinbe({ [`GET ${S}/billing/draft`]: empty, [`GET ${S}/billing`]: NOT_FOUND })
    const r2 = await execute(setSiteAccess, { name: 'billing', roles: 'from-routes' }, dev, deps(j2.fetchImpl))
    expect(sc(r2).error.code).toBe('invalid_request')
    expect(j2.calls.some((c) => c.method === 'PUT')).toBe(false)
  })
})

describe('the convention, said once and everywhere an assistant reads', () => {
  it('guide, intake, onboarding and the instructions carry it', () => {
    const guide = BEFORE_YOU_BUILD.join('\n')
    expect(NAMING_CONVENTION.join(' ')).toMatch(/resource\[\.sub\]:verb.*named for the job.*<site>-<role>s.*<site>-<role>/)
    expect(guide).toMatch(/Same names for the same thing/)
    expect(guide).toMatch(/template_roles_unused.*name_differs_from_sibling/)
    expect(planSiteChangeText({})).toMatch(/read `names`.*reuse them/)
    expect(planSiteChangeText({})).toMatch(/which names are reused from which sibling/)
    expect(onboardSiteText({})).toMatch(/reuse its names/)
    expect(onboardSiteText({})).toMatch(/from-routes/)
    expect(SERVER_INSTRUCTIONS).toMatch(/Keep names: reuse the permissions, roles and groups already used for that Service/)
  })
})
