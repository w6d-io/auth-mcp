import { describe, expect, it } from 'vitest'
import { execute } from '../../mcp/registry.js'
import { extendSiteTtl, listDeletionRequests, requestSiteDeletion } from '../../mcp/tools/site-lifecycle.js'
import { createSite, saveSiteVersion } from '../../mcp/tools/site-writes.js'
import { getSite } from '../../mcp/tools/sites.js'
import { allTools } from '../../mcp/tools/index.js'
import { deps, mockJinbe, principal, sc } from '../helpers/fixtures.js'

const S = '/api/admin/sites'
const dev = principal({ scopes: ['mcp', 'sites:read', 'sites:write'] })
const eph = { ttlSec: 43200, expiresAt: '2026-10-01T00:00:00Z', remainingSec: 43000, expired: false, setBy: 'alice@example.com' }

describe('ephemeral sites', () => {
  it('save_site_version sends ephemeral {ttl} (and null to make it permanent)', async () => {
    const jinbe = mockJinbe({ [`GET ${S}/tmp-demo`]: () => ({ status: 404, body: { error: 'not_found' } }), [`PUT ${S}/tmp-demo`]: { name: 'tmp-demo', version: 1, etag: 'e1', ephemeral: eph } })
    const r = await execute(saveSiteVersion, { name: 'tmp-demo', site: { name: 'tmp-demo' }, ephemeral: { ttl: '12h' } }, dev, deps(jinbe.fetchImpl))
    expect(jinbe.calls.find((c) => c.method === 'PUT')!.body).toEqual({ site: { name: 'tmp-demo' }, ephemeral: { ttl: '12h' } })
    expect(sc(r).data.ephemeral).toMatchObject({ ttlSec: 43200 })
    expect(JSON.stringify(sc(r))).not.toContain('alice@example.com')
  })

  it('refuses a TTL outside 1 hour to 7 days, or malformed, before any call', async () => {
    const jinbe = mockJinbe({})
    for (const ttl of [60, 604801, '8d', '30m', '12x', 'soon']) {
      const r = await execute(extendSiteTtl, { name: 'tmp-demo', ttl }, dev, deps(jinbe.fetchImpl))
      expect(sc(r).error.code, String(ttl)).toBe('invalid_request')
    }
    expect(jinbe.calls).toHaveLength(0)
  })

  it('create_site records the request and says it starts at the first save', async () => {
    const jinbe = mockJinbe({ [`GET ${S}/tmp-demo`]: () => ({ status: 404, body: { error: 'not_found' } }), [`GET ${S}/tmp-demo/draft`]: () => ({ status: 404, body: { error: 'not_found' } }), [`PUT ${S}/tmp-demo/draft`]: { baseVersion: 0 } })
    const r = await execute(createSite, { name: 'tmp-demo', displayName: 'Demo', host: 'tmp-demo.example.com', upstream: { service: 'd', namespace: 'd', port: 80 }, ephemeral: { ttl: '3d' } }, dev, deps(jinbe.fetchImpl))
    expect(sc(r).data.ephemeral.requested).toEqual({ ttl: '3d' })
    expect(sc(r).notes.join(' ')).toMatch(/save_site_version.*paused \(not deleted\)/)
  })

  it('extend_site_ttl posts {} by default; an expired site stays paused and the note says how to resume', async () => {
    const jinbe = mockJinbe({ [`POST ${S}/tmp-demo/ttl`]: { name: 'tmp-demo', state: 'paused', ephemeral: { ...eph, expired: true } } })
    const r = await execute(extendSiteTtl, { name: 'tmp-demo' }, dev, deps(jinbe.fetchImpl))
    expect(jinbe.calls[0].body).toEqual({})
    expect(jinbe.calls[0].headers['idempotency-key']).toBeDefined()
    expect(sc(r).data).toMatchObject({ state: 'paused', ephemeral: { expired: true } })
    expect(sc(r).notes[0]).toMatch(/resume_site/)
    const permanent = mockJinbe({ [`POST ${S}/tmp-demo/ttl`]: () => ({ status: 409, body: { error: 'not_ephemeral', message: 'not ephemeral' } }) })
    expect(sc(await execute(extendSiteTtl, { name: 'tmp-demo', ttl: 7200 }, dev, deps(permanent.fetchImpl))).error).toMatchObject({ code: 'conflict', upstream: 'not_ephemeral' })
  })

  it('get_site shows the expiry without who set it', async () => {
    const jinbe = mockJinbe({ [`GET ${S}/tmp-demo`]: { site: {}, version: 1, etag: 'e', status: 'live', savedAt: 't', savedBy: 'x', applied: null, ephemeral: eph } })
    const r = await execute(getSite, { name: 'tmp-demo' }, dev, deps(jinbe.fetchImpl))
    expect(sc(r).data.ephemeral).toEqual({ ttlSec: 43200, expiresAt: '2026-10-01T00:00:00Z', remainingSec: 43000, expired: false })
  })
})

describe('deletion requests', () => {
  it('request_site_deletion creates a request a person approves; nothing is deleted', async () => {
    const jinbe = mockJinbe({ [`POST ${S}/tmp-demo/deletion-requests`]: () => ({ status: 201, body: { id: 'dr-1', site: 'tmp-demo', reason: 'retired', requestedBy: 'alice@example.com', requesterId: 'u-1', requestedAt: 't', state: 'pending' } }) })
    const r = await execute(requestSiteDeletion, { name: 'tmp-demo', reason: 'retired' }, dev, deps(jinbe.fetchImpl))
    expect(jinbe.calls.map((c) => c.method)).toEqual(['POST'])
    expect(sc(r).data).toEqual({ id: 'dr-1', site: 'tmp-demo', state: 'pending', requestedAt: 't', reason: 'retired' })
    expect(sc(r).notes[0]).toMatch(/other than you.*cannot approve/)
  })

  it('one open request per site: conflict', async () => {
    const jinbe = mockJinbe({ [`POST ${S}/tmp-demo/deletion-requests`]: () => ({ status: 409, body: { error: 'deletion_request_pending', message: 'already' } }) })
    expect(sc(await execute(requestSiteDeletion, { name: 'tmp-demo' }, dev, deps(jinbe.fetchImpl))).error).toMatchObject({ code: 'conflict', upstream: 'deletion_request_pending' })
  })

  it('lists requests without who asked or decided', async () => {
    const jinbe = mockJinbe({ [`GET ${S}/deletion-requests`]: [{ id: 'dr-1', site: 'a', state: 'pending', requestedBy: 'x@example.com', requesterId: 'u', decidedBy: null }] })
    const r = await execute(listDeletionRequests, { state: 'pending' }, dev, deps(jinbe.fetchImpl))
    expect(jinbe.calls[0].url.searchParams.get('state')).toBe('pending')
    expect(sc(r).data.items).toEqual([{ id: 'dr-1', site: 'a', state: 'pending' }])
  })

  it('there is no tool to approve, reject or delete', () => {
    expect(allTools.map((t) => t.name).filter((n) => /approve|reject|^delete/.test(n))).toEqual([])
  })
})
