import { describe, expect, it } from 'vitest'
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { execute, isVisible, registerTools } from '../../mcp/registry.js'
import { allTools, readTools, stubTools, writeTools } from '../../mcp/tools/index.js'
import { simulateGrant } from '../../mcp/tools/drafts.js'
import { saveSiteDraft } from '../../mcp/tools/site-writes.js'
import { listSites } from '../../mcp/tools/sites.js'
import { KillSwitches } from '../../safety/kill-switch.js'
import { SlidingWindowRateLimiter } from '../../safety/rate-limit.js'
import { ORG, deps, mockJinbe, principal, sc } from '../helpers/fixtures.js'

describe('tool catalogue', () => {
  it('names are unique and every tool declares scopes and a static description', () => {
    const names = allTools.map((t) => t.name)
    expect(new Set(names).size).toBe(names.length)
    for (const t of allTools) {
      expect(t.scopes.length).toBeGreaterThan(0)
      expect(t.description.length).toBeGreaterThan(20)
    }
  })
  it('names are verb_noun, never a bare word the edge WAF reads as a shell command (CRS 932260 blocked "whoami")', () => {
    for (const t of allTools) expect(t.name).toMatch(/^[a-z]+(_[a-z]+)+$/)
  })
  it('every read tool is wired and not a write; every write-wave tool is wired; every stub is unwired', () => {
    expect(readTools.every((t) => t.wired !== false && !t.write)).toBe(true)
    expect(writeTools.every((t) => t.wired !== false)).toBe(true)
    expect(stubTools.every((t) => t.wired === false)).toBe(true)
  })

  it('the change-request stubs are gone: writes are direct, group and role definitions never', () => {
    const names = allTools.map((t) => t.name)
    for (const gone of ['propose_group_change', 'propose_role_change', 'request_site_publish', 'rollback_request', 'get_change_request']) {
      expect(names).not.toContain(gone)
    }
  })
})

describe('visibility (UX pre-filter)', () => {
  const d = deps(mockJinbe({}).fetchImpl)

  it('lists only what the scopes carry', () => {
    const server = new McpServer({ name: 't', version: '0' })
    const names = registerTools(server, readTools, principal({ scopes: ['mcp'] }), d)
    expect(names.sort()).toEqual(['get_my_identity', 'get_my_permissions', 'list_orgs'])
  })

  it('hides unwired stubs unless exposed, and writes in read-only mode', () => {
    const readOnly = deps(mockJinbe({}).fetchImpl, { killSwitches: new KillSwitches({ enabled: true, readOnly: true }, null) })
    expect(isVisible(saveSiteDraft, principal(), readOnly)).toBe(false)
    expect(isVisible(saveSiteDraft, principal(), deps(mockJinbe({}).fetchImpl, { exposeUnwired: false }))).toBe(true)
    expect(isVisible(simulateGrant, principal(), deps(mockJinbe({}).fetchImpl, { exposeUnwired: false }))).toBe(false)
    expect(isVisible(saveSiteDraft, principal(), d)).toBe(true)
  })
})

describe('execute: refusals come before any jinbe call', () => {
  it('kill switch per user', async () => {
    const jinbe = mockJinbe({ 'GET /api/admin/sites': [] })
    const ks = new KillSwitches({ enabled: true, readOnly: false }, () => JSON.stringify({ disabledUsers: ['user-1'] }))
    const r = await execute(listSites, {}, principal(), deps(jinbe.fetchImpl, { killSwitches: ks }))
    expect(sc(r).error.code).toBe('mcp_disabled')
    expect(jinbe.calls).toHaveLength(0)
  })

  it('read-only refuses writes even if listed earlier', async () => {
    const ks = new KillSwitches({ enabled: true, readOnly: true }, null)
    const r = await execute(saveSiteDraft, { name: 'payroll', site: {} }, principal(), deps(mockJinbe({}).fetchImpl, { killSwitches: ks }))
    expect(sc(r).error.code).toBe('read_only')
  })

  it('rate limit answers rate_limited with retryAfterSec', async () => {
    const d = deps(mockJinbe({ 'GET /api/admin/sites': [] }).fetchImpl, { rateLimiter: new SlidingWindowRateLimiter({ read: 1, write: 1 }) })
    await execute(listSites, {}, principal(), d)
    const r = await execute(listSites, {}, principal(), d)
    expect(sc(r).error).toMatchObject({ code: 'rate_limited', retryable: true })
    expect(sc(r).error.retryAfterSec).toBeGreaterThan(0)
  })

  it('an unexpected exception becomes internal_error without leaking its message', async () => {
    const d = deps((async () => new Response('[1,2', { status: 200 })) as never)
    const r = await execute(listSites, {}, principal(), d)
    expect(sc(r).error).toEqual({ code: 'internal_error', message: 'Internal error', retryable: false })
  })
})

describe('stubs', () => {
  it('refuse with not_wired and never call jinbe', async () => {
    const jinbe = mockJinbe({})
    const r = await execute(simulateGrant, { userId: 'u-2', addGroups: ['g'] }, principal(), deps(jinbe.fetchImpl))
    expect(sc(r).error.code).toBe('not_wired')
    expect(jinbe.calls).toHaveLength(0)
  })
})
