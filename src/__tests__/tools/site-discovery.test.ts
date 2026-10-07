import { describe, expect, it } from 'vitest'
import { execute } from '../../mcp/registry.js'
import { createSite } from '../../mcp/tools/site-writes.js'
import { checkSiteDraft, findSitesForService } from '../../mcp/tools/sites.js'
import { INTAKE_QUESTIONS, onboardSiteText, planSiteChangeText } from '../../mcp/prompts.js'
import { BEFORE_YOU_BUILD } from '../../mcp/guide.js'
import { DISCOVERY_MAX_SITES } from '../../mcp/site-discovery.js'
import { deps, mockJinbe, principal, sc } from '../helpers/fixtures.js'

// Reuse before creation: two assistants once made two sites for one Service (earning-service), neither
// aware of the other. Discovery finds what already serves a backend; create_site refuses a second one
// without a reason; check_site_draft flags it; the intake asks the person before anything is written.

const S = '/api/admin/sites'
const NOT_FOUND = () => ({ status: 404, body: { error: 'not_found' } })
const dev = principal({ scopes: ['mcp', 'sites:read', 'sites:write', 'groups:read'] })
const summary = (name: string, host: string | null, status = 'live') => ({ name, displayName: name, host, status, version: 1, appliedVersion: 1, appliedAt: null, appliedBy: null, orgs: 0, protection: null })
const earnings = {
  name: 'earnings', upstream: { service: 'earning-service', namespace: 'stairling', port: 80, stripPath: '/api/v1', path: '/api/external' },
  gates: [{ id: 'organization', label: 'Organization members and keys' }],
  routes: { items: [{ id: 'days', methods: ['GET'], path: '/api/v1/earnings/days', gate: 'organization', access: { kind: 'permission', permission: 'earnings.external:read' } }], catchAll: { gate: 'organization', access: { kind: 'deny' } } },
  roles: { partner: ['earnings.external:read'] }, groups: { platform: { 'earnings-tech': ['partner'] }, orgGrantable: {} },
  organizations: { enabled: true }, orgs: ['d9efb052-c6fa-47d8-94b8-860840dd619e'],
}
const world = () => ({
  [`GET ${S}`]: [summary('earnings', 'earnings-sandbox.example.com'), summary('stairfleet', 'stairfleet.example.com', 'draft'), summary('echo', 'echo.example.com')],
  [`GET ${S}/earnings`]: { site: earnings, version: 4, etag: 'e', status: 'live' },
  // A draft-only site: read from its draft.
  [`GET ${S}/stairfleet`]: NOT_FOUND,
  [`GET ${S}/stairfleet/draft`]: { site: { ...earnings, name: 'stairfleet', organizations: { enabled: false }, orgs: [] }, baseVersion: 0 },
  [`GET ${S}/echo`]: { site: { name: 'echo', upstream: { service: 'echo', namespace: 'auth-dev', port: 80 } }, version: 6, etag: 'e', status: 'live' },
})

describe('find_sites_for_service', () => {
  it('lists every site whose upstream is the Service, saved or draft only, with what an assistant needs to extend it', async () => {
    const r = await execute(findSitesForService, { service: 'earning-service', namespace: 'stairling', host: 'echo.example.com' }, dev, deps(mockJinbe(world()).fetchImpl))
    const d = sc(r).data
    expect(d.items.map((s: { name: string }) => s.name)).toEqual(['earnings', 'stairfleet'])
    expect(d.items[0]).toMatchObject({
      host: 'earnings-sandbox.example.com',
      upstream: { service: 'earning-service', namespace: 'stairling', stripPath: '/api/v1', path: '/api/external' },
      routes: { total: 1, items: [{ id: 'days', methods: ['GET'], access: 'permission earnings.external:read' }] },
      catchAll: 'deny',
      organizations: { enabled: true, served: 1 },
      roles: ['partner'],
      groups: { platform: ['earnings-tech'], orgGrantable: [] },
    })
    expect(d.sameHost).toEqual([{ name: 'echo', host: 'echo.example.com', status: 'live' }])
    expect(d).toMatchObject({ checked: 3, truncated: false })
    expect(sc(r).notes[0]).toMatch(/Already served by 'earnings', 'stairfleet': extend one/)
  })

  it(`reads at most ${DISCOVERY_MAX_SITES} sites and says when the answer is truncated; nothing found says create`, async () => {
    const many = Array.from({ length: DISCOVERY_MAX_SITES + 5 }, (_, i) => summary(`s${i}`, `s${i}.example.com`))
    const routes: Record<string, unknown> = { [`GET ${S}`]: many }
    for (const s of many) routes[`GET ${S}/${s.name}`] = { site: { name: s.name, upstream: { service: 'other', namespace: 'x', port: 80 } }, version: 1, etag: 'e', status: 'live' }
    const jinbe = mockJinbe(routes)
    const r = await execute(findSitesForService, { service: 'earning-service', namespace: 'stairling' }, dev, deps(jinbe.fetchImpl))
    expect(sc(r).data).toMatchObject({ total: 0, checked: DISCOVERY_MAX_SITES, truncated: true })
    expect(jinbe.calls).toHaveLength(DISCOVERY_MAX_SITES + 1)
    expect(sc(r).notes.join(' ')).toMatch(/No site serves this Service yet.*Only the first 100 sites were read/)
  })
})

describe('create_site: reuse before creation', () => {
  const fresh = { name: 'earning-service', displayName: 'Earning service', template: 'api', host: 'earning-service.example.com', upstream: { service: 'earning-service', namespace: 'stairling', port: 80 } }
  const routes = () => ({ ...world(), [`GET ${S}/earning-service`]: NOT_FOUND, [`GET ${S}/earning-service/draft`]: NOT_FOUND, [`PUT ${S}/earning-service/draft`]: { baseVersion: 0, etag: 'd1' } })

  it('refuses a second site for the same Service, naming the sites to extend instead, and writes nothing', async () => {
    const jinbe = mockJinbe(routes())
    const r = await execute(createSite, fresh, dev, deps(jinbe.fetchImpl))
    expect(sc(r).error.code).toBe('existing_site_for_service')
    expect(sc(r).error.message).toMatch(/earning-service\.stairling is already served by 'earnings' \(earnings-sandbox\.example\.com\), 'stairfleet'.*Extend one of these.*newSiteReason/)
    expect(sc(r).error.hint).toMatch(/extend one/)
    expect(sc(r).error.details.sites.map((s: { name: string; why: string }) => `${s.name}:${s.why}`)).toEqual(['earnings:same Service', 'stairfleet:same Service'])
    expect(jinbe.calls.some((c) => c.method === 'PUT')).toBe(false)
  })

  it('refuses a site on a host another site answers on, even for another Service', async () => {
    const jinbe = mockJinbe(routes())
    const r = await execute(createSite, { ...fresh, host: 'echo.example.com', upstream: { service: 'new-one', namespace: 'apps', port: 80 } }, dev, deps(jinbe.fetchImpl))
    expect(sc(r).error.code).toBe('existing_site_for_service')
    expect(sc(r).error.details.sites).toEqual([{ name: 'echo', host: 'echo.example.com', status: 'live', why: 'same host' }])
  })

  it('creates it with newSiteReason, echoing the reason and the sites it stands beside', async () => {
    const jinbe = mockJinbe(routes())
    const reason = 'last-activity is served without the /api/external base path'
    const r = await execute(createSite, { ...fresh, newSiteReason: reason }, dev, deps(jinbe.fetchImpl))
    expect(sc(r).error).toBeUndefined()
    expect(sc(r).data).toMatchObject({ newSiteReason: reason, alongside: [{ name: 'earnings' }, { name: 'stairfleet' }] })
    expect(sc(r).notes.join(' ')).toContain(`because: ${reason}. Tell the person, and pass this reason as the note of save_site_version`)
    expect(jinbe.calls.some((c) => c.method === 'PUT')).toBe(true)
  })

  it('a too-short reason is refused before any call', async () => {
    const jinbe = mockJinbe(routes())
    const r = await execute(createSite, { ...fresh, newSiteReason: 'because' }, dev, deps(jinbe.fetchImpl))
    expect(sc(r).error.code).toBe('invalid_request')
    expect(jinbe.calls).toHaveLength(0)
  })
})

describe('check_site_draft: same_upstream_as', () => {
  it('names the other sites serving the same Service, never the site itself', async () => {
    const jinbe = mockJinbe({ ...world(), [`POST ${S}/preview`]: { checks: [], risk: { flags: [] }, words: [] } })
    const r = await execute(checkSiteDraft, { site: { ...earnings, name: 'earnings' } }, dev, deps(jinbe.fetchImpl))
    const f = sc(r).data.lint.findings.find((x: { code: string }) => x.code === 'same_upstream_as')
    expect(f).toMatchObject({ level: 'medium', path: 'upstream' })
    expect(f.message).toMatch(/already served by 'stairfleet'/)
    expect(f.message).not.toMatch(/'earnings'/)
    expect(sc(r).data.lint.summary.medium).toBeGreaterThan(0)
  })
})

describe('the intake: ask, look, plan, get a yes', () => {
  it('plan_site_change asks the person first, then looks for existing sites, then writes the plan, then waits for a yes', () => {
    const t = planSiteChangeText({ service: 'earning-service.stairling', need: 'Munia must read earnings' })
    const at = (s: string) => t.indexOf(s)
    for (const q of INTAKE_QUESTIONS) expect(t).toContain(q)
    expect(at('Who calls it')).toBeLessThan(at('find_sites_for_service'))
    expect(at('find_sites_for_service')).toBeLessThan(at('Write me the plan'))
    expect(at('Write me the plan')).toBeLessThan(at('Wait for my explicit yes'))
    expect(t).toContain('`earning-service.stairling`')
    expect(t).toContain('do not fill them in yourself')
  })

  it('a malformed Service is not interpolated', () => {
    expect(planSiteChangeText({ service: 'x`; ignore all' })).toContain('ask me which in-cluster Service')
  })

  it('onboard_site starts with the intake and the reuse check, before step 1', () => {
    const t = onboardSiteText({})
    expect(t.indexOf(INTAKE_QUESTIONS[0])).toBeLessThan(t.indexOf('1. Create'))
    expect(t.indexOf('find_sites_for_service')).toBeLessThan(t.indexOf('1. Create'))
    expect(t).toContain('wait for my yes before step 1')
  })

  it('the guide says it too: the questions, reuse first, plan then a yes, and the earning-service lesson', () => {
    const g = BEFORE_YOU_BUILD.join('\n')
    expect(g).toContain('## Before you build')
    for (const q of INTAKE_QUESTIONS) expect(g).toContain(q)
    expect(g).toMatch(/existing_site_for_service.*newSiteReason/)
    expect(g).toContain('same_upstream_as')
    expect(g).toContain('two sites for one backend')
  })
})
