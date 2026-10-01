import { describe, expect, it } from 'vitest'
import { execute } from '../../mcp/registry.js'
import { refreshSecondFactor } from '../../mcp/tools/step-up.js'
import { publishSite } from '../../mcp/tools/site-publish.js'
import { canI } from '../../mcp/tools/index.js'
import { deps, mockJinbe, principal, sc } from '../helpers/fixtures.js'

const LINK = { url: 'https://kuma.example.com/#/mcp/step-up/r-1', expiresAt: '2026-10-01T12:10:00Z' }
const old = new Date(Date.now() - 40 * 86400e3).toISOString()
const expiredKey = principal({ scopes: ['mcp', 'sites:read', 'sites:apply'], kind: 'personal', keyId: 'k', stepUpActions: true, stepUpAt: old })
const stepUpRefusal = (keyReason: string) => () => ({
  status: 422,
  body: { error: 'step_up_unavailable', message: 'needs a browser', hint: 'create a new key', permission: 'sites:apply', secondFactor: { rule: 'step_up', requiredAal: 'aal2', keyReason } },
})

describe('refresh_second_factor', () => {
  it('returns the link and what to do with it', async () => {
    const jinbe = mockJinbe({ 'POST /api/me/mcp/step-up-requests': () => ({ status: 201, body: LINK }) })
    const r = await execute(refreshSecondFactor, {}, expiredKey, deps(jinbe.fetchImpl))
    expect(sc(r).data).toEqual(LINK)
    expect(sc(r).notes[0]).toBe('Open this link and confirm with your second factor, then tell me to try again.')
    expect(sc(r).notes[1]).toMatch(/afresh/)
    expect(jinbe.calls[0].body).toBeUndefined()
    expect(jinbe.calls[0].headers['idempotency-key']).toBeDefined()
  })

  it('refuses to show a link that is not https', async () => {
    const jinbe = mockJinbe({ 'POST /api/me/mcp/step-up-requests': () => ({ status: 201, body: { url: 'javascript:alert(1)' } }) })
    expect(sc(await execute(refreshSecondFactor, {}, expiredKey, deps(jinbe.fetchImpl))).error.code).toBe('upstream_unavailable')
  })

  it('a connection created without protected actions is told a refresh will not turn them on', async () => {
    const jinbe = mockJinbe({ 'POST /api/me/mcp/step-up-requests': () => ({ status: 201, body: LINK }) })
    const r = await execute(refreshSecondFactor, {}, principal({ kind: 'personal', keyId: 'k', stepUpActions: false }), deps(jinbe.fetchImpl))
    expect(sc(r).notes.join(' ')).toMatch(/does not turn them on/)
  })
})

describe('a refused protected action carries the link when a refresh fixes it', () => {
  it('key_step_up_expired: the link is in details and the hint', async () => {
    const jinbe = mockJinbe({ 'POST /api/admin/sites/billing/apply': stepUpRefusal('key_step_up_expired'), 'POST /api/me/mcp/step-up-requests': () => ({ status: 201, body: LINK }) })
    const r = await execute(publishSite, { name: 'billing', version: 2 }, expiredKey, deps(jinbe.fetchImpl))
    expect(sc(r).error.code).toBe('protected_actions_off')
    expect(sc(r).error.details.stepUpLink).toEqual(LINK)
    expect(sc(r).error.hint).toBe(`Open this link and confirm with your second factor, then tell me to try again. ${LINK.url} (valid until ${LINK.expiresAt})`)
  })

  it('no link for step_up_actions_off, for a console-only action, or when the key was made without them', async () => {
    for (const [p, reason] of [[expiredKey, 'step_up_actions_off'], [expiredKey, 'not_allowed_here'], [principal({ ...expiredKey, stepUpActions: false } as never), 'key_step_up_expired']] as const) {
      const jinbe = mockJinbe({ 'POST /api/admin/sites/billing/apply': stepUpRefusal(reason), 'POST /api/me/mcp/step-up-requests': () => ({ status: 201, body: LINK }) })
      const r = await execute(publishSite, { name: 'billing', version: 2 }, p, deps(jinbe.fetchImpl))
      expect(sc(r).error.details?.stepUpLink, reason).toBeUndefined()
      expect(jinbe.calls.some((c) => c.url.pathname.endsWith('step-up-requests')), reason).toBe(false)
    }
  })

  it('a link that cannot be made leaves the refusal as it was', async () => {
    const jinbe = mockJinbe({ 'POST /api/admin/sites/billing/apply': stepUpRefusal('no_key_step_up') })
    const r = await execute(publishSite, { name: 'billing', version: 2 }, expiredKey, deps(jinbe.fetchImpl))
    expect(sc(r).error.code).toBe('protected_actions_off')
    expect(sc(r).error.details.stepUpLink).toBeUndefined()
  })

  it('an OAuth sign-in past its 12 h window gets the link too', async () => {
    const oauth = principal({ scopes: ['mcp', 'sites:apply'], kind: 'oauth', stepUpActions: true, stepUpUntil: new Date(Date.now() - 1000).toISOString() })
    const jinbe = mockJinbe({ 'POST /api/admin/sites/billing/apply': () => ({ status: 422, body: { error: 'step_up_unavailable' } }), 'POST /api/me/mcp/step-up-requests': () => ({ status: 201, body: LINK }) })
    const r = await execute(publishSite, { name: 'billing', version: 2 }, oauth, deps(jinbe.fetchImpl))
    expect(sc(r).error.details.stepUpLink).toEqual(LINK)
  })
})

describe('can_i suggests the refresh (and creates nothing itself)', () => {
  it('proof expired → suggest refresh_second_factor, no jinbe write', async () => {
    const jinbe = mockJinbe({})
    const r = await execute(canI, { tool: 'publish_site' }, expiredKey, deps(jinbe.fetchImpl))
    expect(sc(r).data).toMatchObject({ wouldRefuseBecause: 'protected_actions_off', suggest: { tool: 'refresh_second_factor' } })
    expect(jinbe.calls.filter((c) => c.method !== 'GET')).toHaveLength(0)
  })
})

describe('step-up link API refusals (jinbe wave20/step-up-refresh)', () => {
  it('409 protected_actions_not_allowed relays jinbe\'s message under protected_actions_off', async () => {
    const jinbe = mockJinbe({ 'POST /api/me/mcp/step-up-requests': () => ({ status: 409, body: { error: 'protected_actions_not_allowed', message: 'This sign-in was consented without protected actions: reconnect and tick them.' } }) })
    const r = await execute(refreshSecondFactor, {}, expiredKey, deps(jinbe.fetchImpl))
    expect(sc(r).error).toMatchObject({ code: 'protected_actions_off', message: 'This sign-in was consented without protected actions: reconnect and tick them.', upstream: 'protected_actions_not_allowed' })
  })

  it('429: reuse the last link', async () => {
    const jinbe = mockJinbe({ 'POST /api/me/mcp/step-up-requests': () => ({ status: 429, body: { error: 'rate_limited' }, headers: { 'retry-after': '120' } }) })
    const r = await execute(refreshSecondFactor, {}, expiredKey, deps(jinbe.fetchImpl))
    expect(sc(r).error).toMatchObject({ code: 'rate_limited', retryAfterSec: 120 })
    expect(sc(r).error.hint).toMatch(/use the last link/)
  })

  it('403 protected_actions_off (admin switch) keeps jinbe\'s message', async () => {
    const jinbe = mockJinbe({ 'POST /api/me/mcp/step-up-requests': () => ({ status: 403, body: { error: 'protected_actions_off', message: 'An administrator turned protected actions off for assistants.' } }) })
    const r = await execute(refreshSecondFactor, {}, expiredKey, deps(jinbe.fetchImpl))
    expect(sc(r).error).toMatchObject({ code: 'protected_actions_off', message: 'An administrator turned protected actions off for assistants.' })
  })
})

describe('re-verify once before refusing for an old proof (no 30 s lag after a refresh)', () => {
  const fresh = principal({ ...expiredKey, stepUpAt: new Date().toISOString() } as never)

  it('jinbe refused on the stale view; re-verified fresh: the call runs again once and succeeds', async () => {
    let applies = 0
    const jinbe = mockJinbe({
      'POST /api/admin/sites/billing/apply': (req) => (++applies === 1 ? stepUpRefusal('key_step_up_expired')() : { body: { id: 'a-1', state: 'running', key: req.headers['idempotency-key'] } }),
    })
    let reverified = 0
    const d = deps(jinbe.fetchImpl, { reverify: async () => (reverified++, fresh) })
    const r = await execute(publishSite, { name: 'billing', version: 2, idempotencyKey: 'publish-0001' }, expiredKey, d)
    expect(r.isError).toBeUndefined()
    expect(reverified).toBe(1)
    expect(applies).toBe(2)
    // jinbe recorded the refusal under the caller's key: the retry uses a key derived from it.
    expect(jinbe.calls.map((c) => c.headers['idempotency-key'])).toEqual(['publish-0001', 'publish-0001-r1'])
  })

  it('still stale after re-verifying: one re-verify, no second run, the refusal (with its link) stands', async () => {
    let applies = 0
    const jinbe = mockJinbe({ 'POST /api/admin/sites/billing/apply': () => (applies++, stepUpRefusal('key_step_up_expired')()), 'POST /api/me/mcp/step-up-requests': () => ({ status: 201, body: LINK }) })
    let reverified = 0
    const r = await execute(publishSite, { name: 'billing', version: 2 }, expiredKey, deps(jinbe.fetchImpl, { reverify: async (p) => (reverified++, p) }))
    expect(sc(r).error.code).toBe('protected_actions_off')
    expect(sc(r).error.details.stepUpLink).toEqual(LINK)
    expect([reverified, applies]).toEqual([1, 1])
  })

  it('not for refusals a refresh cannot fix, and never when re-verifying fails', async () => {
    let reverified = 0
    const jinbe = mockJinbe({ 'POST /api/admin/sites/billing/apply': stepUpRefusal('step_up_actions_off') })
    await execute(publishSite, { name: 'billing', version: 2 }, expiredKey, deps(jinbe.fetchImpl, { reverify: async () => (reverified++, fresh) }))
    expect(reverified).toBe(0)
    const broken = mockJinbe({ 'POST /api/admin/sites/billing/apply': stepUpRefusal('no_key_step_up') })
    const r = await execute(publishSite, { name: 'billing', version: 2 }, expiredKey, deps(broken.fetchImpl, { reverify: async () => { throw new Error('jinbe down') } }))
    expect(sc(r).error.code).toBe('protected_actions_off')
  })

  it('can_i and get_my_identity see the refreshed proof at once', async () => {
    const jinbe = mockJinbe({})
    const d = deps(jinbe.fetchImpl, { reverify: async () => fresh })
    expect(sc(await execute(canI, { tool: 'publish_site' }, expiredKey, d)).data).toMatchObject({ protectedActionsAllowed: true })
    const { getMyIdentity } = await import('../../mcp/tools/identity.js')
    expect(sc(await execute(getMyIdentity, {}, expiredKey, d)).data.protectedActions.allowed).toBe(true)
  })
})
