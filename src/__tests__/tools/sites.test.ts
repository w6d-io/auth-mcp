import { describe, expect, it } from 'vitest'
import { execute } from '../../mcp/registry.js'
import { blastRadius, checkSiteDraft, getPlatform, getSite, listSites, matchRequest, renderTemplate, siteVersions } from '../../mcp/tools/sites.js'
import { deps, mockJinbe, principal, sc } from '../helpers/fixtures.js'

const summary = (name: string, status = 'live') => ({
  name, displayName: name.toUpperCase(), host: `${name}.example.com`, status, version: 2, appliedVersion: 2,
  appliedAt: '2026-09-01T00:00:00Z', appliedBy: 'root@example.com', orgs: 1, protection: null,
  draft: { by: 'bob@example.com', at: '2026-09-02T00:00:00Z' },
})

describe('list_sites', () => {
  const sites = [summary('alpha'), summary('beta', 'draft'), summary('gamma', 'paused')]

  it('lists sites without the emails of who applied or drafted', async () => {
    const jinbe = mockJinbe({ 'GET /api/admin/sites': sites })
    const r = await execute(listSites, {}, principal(), deps(jinbe.fetchImpl))
    expect(r.isError).toBeUndefined()
    const data = sc(r).data
    expect(data.total).toBe(3)
    expect(data.items[0]).toMatchObject({ name: 'alpha', status: 'live', draftAt: '2026-09-02T00:00:00Z' })
    expect(JSON.stringify(r)).not.toContain('@example.com')
    expect(sc(r).untrusted).toBe(true)
    expect(sc(r).source).toBe('jinbe:/api/admin/sites')
  })

  it('filters by status and query and paginates', async () => {
    const many = Array.from({ length: 130 }, (_, i) => summary(`s${String(i).padStart(3, '0')}`))
    const jinbe = mockJinbe({ 'GET /api/admin/sites': many })
    const d = deps(jinbe.fetchImpl)
    const p1 = await execute(listSites, { limit: 100 }, principal(), d)
    expect(sc(p1).data.items).toHaveLength(100)
    const p2 = await execute(listSites, { limit: 100, cursor: sc(p1).nextCursor }, principal(), d)
    expect(sc(p2).data.items).toHaveLength(30)
    expect(sc(p2).nextCursor).toBeNull()
    const q = await execute(listSites, { status: 'live', query: 's12' }, principal(), d)
    expect(sc(q).data.total).toBe(10)
  })

  it('a cursor from another query is refused', async () => {
    const many = Array.from({ length: 60 }, (_, i) => summary(`s${i}x`))
    const d = deps(mockJinbe({ 'GET /api/admin/sites': many }).fetchImpl)
    const p1 = await execute(listSites, {}, principal(), d)
    const r = await execute(listSites, { status: 'live', cursor: sc(p1).nextCursor }, principal(), d)
    expect(sc(r).error.code).toBe('invalid_cursor')
  })
})

describe('get_site', () => {
  it('returns the intent, etag and applied state without emails', async () => {
    const jinbe = mockJinbe({
      'GET /api/admin/sites/payroll': {
        site: { name: 'payroll', displayName: 'Payroll' }, version: 4, etag: 'abc', status: 'live',
        savedAt: '2026-09-01T00:00:00Z', savedBy: 'x@example.com', applied: { version: 3, at: '2026-09-01T00:00:00Z', by: 'y@example.com', rules: ['r1', 'r2'] },
      },
    })
    const r = await execute(getSite, { name: 'payroll' }, principal(), deps(jinbe.fetchImpl))
    expect(sc(r).data).toMatchObject({ version: 4, etag: 'abc', applied: { version: 3, rules: 2 } })
    expect(JSON.stringify(r)).not.toContain('@example.com')
  })

  it('maps a 404', async () => {
    const r = await execute(getSite, { name: 'nope' }, principal(), deps(mockJinbe({}).fetchImpl))
    expect(r.isError).toBe(true)
    expect(sc(r).error.code).toBe('not_found')
  })
})

describe('site_versions, blast_radius, get_platform', () => {
  it('lists versions without who saved them', async () => {
    const jinbe = mockJinbe({ 'GET /api/admin/sites/payroll/versions': [{ version: 1, by: 'a@example.com', savedAt: 't', note: 'n' }] })
    const r = await execute(siteVersions, { name: 'payroll' }, principal(), deps(jinbe.fetchImpl))
    expect(sc(r).data.items).toEqual([{ version: 1, savedAt: 't', note: 'n' }])
  })

  it('returns the blast radius', async () => {
    const br = { groups: ['payroll-admins'], orgGrantableGroups: [], orgs: [{ id: 'o', grants: 2 }], rules: 3, routes: 5, people: null, apiKeys: null, requests24h: null }
    const r = await execute(blastRadius, { name: 'payroll' }, principal(), deps(mockJinbe({ 'GET /api/admin/sites/payroll/blast-radius': br }).fetchImpl))
    expect(sc(r).data).toEqual(br)
  })

  it('returns the platform view', async () => {
    const r = await execute(getPlatform, {}, principal(), deps(mockJinbe({ 'GET /api/admin/sites/platform': { env: 'dev', fourEyes: 'off' } }).fetchImpl))
    expect(sc(r).data).toEqual({ env: 'dev', fourEyes: 'off' })
  })
})

describe('check_site_draft', () => {
  const site = {
    name: 'payroll', displayName: 'Payroll', address: { host: 'payroll.example.com' },
    upstream: { service: 'payroll', namespace: 'payroll', port: 80 },
    gates: [{ id: 'main', label: 'Main', authenticators: [{ handler: 'cookie_session' }], authorizer: 'policy', mutators: [{ handler: 'header' }], errors: 'website' }],
    routes: { items: [{ id: 'w', methods: ['POST'], path: '/api/pay', gate: 'main', access: { kind: 'public' } }], catchAll: { gate: 'main', access: { kind: 'deny' } } },
    roles: 'standard', groups: { platform: {}, orgGrantable: {} }, orgs: [],
  }

  it('lints locally and runs the platform preview when the key carries sites:write', async () => {
    const jinbe = mockJinbe({ 'POST /api/admin/sites/preview': { artefacts: { rules: ['big'] }, checks: [{ level: 'warn', code: 'rule_overlap', message: 'overlaps' }], risk: { flags: [] }, words: [] } })
    const r = await execute(checkSiteDraft, { site }, principal(), deps(jinbe.fetchImpl))
    const data = sc(r).data
    expect(data.lint.findings.map((f: { code: string }) => f.code)).toContain('public_write_route')
    expect(data.lint.summary.high).toBeGreaterThan(0)
    expect(data.preview.checks[0].code).toBe('rule_overlap')
    expect(data.preview.artefacts).toBeUndefined()
    expect(jinbe.calls[0].body).toEqual({ site })
  })

  it('without sites:write: lint only, and no call to jinbe', async () => {
    const jinbe = mockJinbe({})
    const r = await execute(checkSiteDraft, { site }, principal({ scopes: ['mcp', 'sites:read'] }), deps(jinbe.fetchImpl))
    expect(sc(r).data.preview).toBeNull()
    expect(sc(r).notes[0]).toMatch(/sites:write/)
    expect(jinbe.calls).toHaveLength(0)
  })

  it('a preview refusal is reported inside the result, the lint still returned', async () => {
    const jinbe = mockJinbe({ 'POST /api/admin/sites/preview': () => ({ status: 400, body: { error: 'invalid_request', message: 'The request is not valid', issues: [{ path: ['site', 'gates'] }] } }) })
    const r = await execute(checkSiteDraft, { site: { name: 'x' } }, principal(), deps(jinbe.fetchImpl))
    expect(r.isError).toBeUndefined()
    expect(sc(r).data.preview.error.code).toBe('invalid_request')
    expect(sc(r).data.preview.error.details.issues).toHaveLength(1)
    expect(sc(r).notes[0]).toMatch(/^Partial result: the lint above is complete/)
    expect(sc(r).notes[0]).not.toMatch(/Retry/)
  })

  it('a throttled cluster: lint returned, preview marked retryable, partial-result note says retry', async () => {
    const jinbe = mockJinbe({
      'POST /api/admin/sites/preview': () => ({
        status: 503,
        headers: { 'retry-after': '2' },
        body: { error: 'kubernetes_rate_limited', message: 'The Kubernetes API is temporarily rate-limiting requests, nothing was changed; retry in a few seconds (list zones: 429)' },
      }),
    })
    const r = await execute(checkSiteDraft, { site }, principal(), deps(jinbe.fetchImpl))
    expect(r.isError).toBeUndefined()
    expect(sc(r).data.lint.findings.length).toBeGreaterThan(0)
    expect(sc(r).data.preview.error).toMatchObject({ code: 'rate_limited', retryable: true })
    expect(sc(r).notes[0]).toMatch(/Partial result.*rate_limited.*Retry check_site_draft shortly/)
  })
})

describe('match_request, render_template', () => {
  it('forwards the dry run', async () => {
    const jinbe = mockJinbe({ 'POST /api/admin/sites/match': { rule: 'payroll-main', route: 'w' } })
    const r = await execute(matchRequest, { method: 'GET', url: 'https://payroll.example.com/x', against: 'live' }, principal(), deps(jinbe.fetchImpl))
    expect(sc(r).data).toEqual({ rule: 'payroll-main', route: 'w' })
  })

  it('redacts a rendered template that carries a secret', async () => {
    const jinbe = mockJinbe({ 'POST /api/admin/sites/render': { output: 'Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123' } })
    const r = await execute(
      renderTemplate,
      { template: '{{ print .Extra.token }}', kind: 'header', sample: { method: 'GET', url: 'https://a.example.com/' } },
      principal(),
      deps(jinbe.fetchImpl)
    )
    expect(sc(r).data.output).toBe('Authorization: Bearer [REDACTED]')
  })

  it('both need sites:read', async () => {
    const r = await execute(matchRequest, { method: 'GET', url: 'https://a.example.com/', against: 'live' }, principal({ scopes: ['mcp', 'users:read'] }), deps(mockJinbe({}).fetchImpl))
    expect(sc(r).error.code).toBe('insufficient_scope')
  })
})
