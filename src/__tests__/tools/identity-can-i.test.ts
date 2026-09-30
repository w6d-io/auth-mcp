import { describe, expect, it } from 'vitest'
import { execute } from '../../mcp/registry.js'
import { getMyIdentity } from '../../mcp/tools/identity.js'
import { canI } from '../../mcp/tools/index.js'
import { protectedActionsOf, KEY_STEP_UP_MAX_AGE_MS } from '../../auth/protected-actions.js'
import { principalFromClaims } from '../../auth/verifier.js'
import { KillSwitches } from '../../safety/kill-switch.js'
import { deps, mockJinbe, principal, sc } from '../helpers/fixtures.js'

const DAY = 24 * 3600 * 1000
const recent = new Date(Date.now() - 2 * DAY).toISOString()
const old = new Date(Date.now() - 31 * DAY).toISOString()
const key = (over: object = {}) =>
  principal({ scopes: ['mcp', 'sites:read', 'sites:write', 'sites:apply', 'users:recovery'], kind: 'personal', keyId: 'key-1', stepUpAt: recent, stepUpActions: true, ...over })

describe('protectedActionsOf (the twin of jinbe keyStepUpVerdict)', () => {
  it.each([
    ['a fresh key with protected actions', { kind: 'personal', stepUpAt: recent, stepUpActions: true }, true, undefined],
    ['created with protected actions off', { kind: 'personal', stepUpAt: recent, stepUpActions: false }, false, 'key_created_without'],
    ['on, but no factor proven at creation', { kind: 'personal', stepUpActions: true }, false, 'key_created_without'],
    ['proof older than 30 days', { kind: 'personal', stepUpAt: old, stepUpActions: true }, false, 'proof_expired'],
    ['an OAuth sign-in jinbe says nothing about', { kind: 'oauth' }, false, 'unknown'],
    ['an OAuth sign-in within jinbe\'s 12 h window', { kind: 'oauth', stepUpActions: true, stepUpAt: recent, stepUpUntil: new Date(Date.now() + 3600e3).toISOString() }, true, undefined],
    ['an OAuth sign-in past the window', { kind: 'oauth', stepUpActions: true, stepUpAt: recent, stepUpUntil: new Date(Date.now() - 60e3).toISOString() }, false, 'proof_expired'],
    ['an OAuth consent without protected actions', { kind: 'oauth', stepUpActions: false }, false, 'consent_without'],
    ['a jinbe that does not report it', { kind: 'personal' }, false, 'unknown'],
  ] as const)('%s', (_label, p, allowed, reason) => {
    const out = protectedActionsOf(p as never)
    expect(out.allowed).toBe(allowed)
    expect(out.reason).toBe(reason)
    expect(out.covers).toEqual(['sites:apply', 'users:update_email', 'groups.members:write', 'groups:write'])
  })

  it('validUntil is the proof time plus 30 days', () => {
    expect(protectedActionsOf({ kind: 'personal', stepUpAt: recent, stepUpActions: true }).validUntil).toBe(new Date(Date.parse(recent) + KEY_STEP_UP_MAX_AGE_MS).toISOString())
  })

  it('token-info claims are carried into the principal (ISO or epoch seconds)', () => {
    const now = Math.floor(Date.now() / 1000)
    const base = { active: true, scope: 'mcp', client_id: 'key-1', sub: 'key-1', exp: now + 600, aud: 'https://mcp.test/mcp' }
    const ext = { kind: 'personal', subject: 'user-1', key_id: 'key-1', key_expires_at: now + 1000 }
    const iso = principalFromClaims({ ...base, ext: { ...ext, key_step_up_at: recent, key_step_up_actions: false } }, { resource: 'https://mcp.test/mcp', token: 't' })
    expect(iso).toMatchObject({ stepUpAt: recent, stepUpActions: false })
    const epoch = principalFromClaims({ ...base, ext: { ...ext, key_step_up_at: now } }, { resource: 'https://mcp.test/mcp', token: 't' })
    expect(epoch.stepUpAt).toBe(new Date(now * 1000).toISOString())
    const none = principalFromClaims({ ...base, ext }, { resource: 'https://mcp.test/mcp', token: 't' })
    expect('stepUpAt' in none || 'stepUpActions' in none).toBe(false)
  })
})

describe('get_my_identity', () => {
  it('reports protectedActions and readOnly from the scopes', async () => {
    const r = await execute(getMyIdentity, {}, key(), deps(mockJinbe({}).fetchImpl))
    expect(sc(r).data.protectedActions).toMatchObject({ allowed: true, validUntil: expect.any(String) })
    expect(sc(r).data.readOnly).toBe(false)
  })

  it('readOnly follows MCP read-only mode too', async () => {
    const ro = deps(mockJinbe({}).fetchImpl, { killSwitches: new KillSwitches({ enabled: true, readOnly: true }, null) })
    const r = await execute(getMyIdentity, {}, key(), ro)
    expect(sc(r).data.readOnly).toBe(true)
  })
})

describe('can_i: no side effects, the refusal it would get', () => {
  const ask = async (p: ReturnType<typeof key>, tool: string, args?: object, jinbe = mockJinbe({ 'GET /api/admin/sites/platform': { production: false } }), d = deps(jinbe.fetchImpl)) => {
    const r = await execute(canI, { tool, ...(args ? { arguments: args } : {}) }, p, d)
    return { data: sc(r).data, notes: sc(r).notes as string[] | undefined, jinbe }
  }

  const gateJinbe = (publish: object, findings: object[] = []) =>
    mockJinbe({
      'GET /api/admin/sites/platform': { production: false },
      'GET /api/admin/sites/billing': { site: { name: 'billing' }, version: 2 },
      'POST /api/admin/sites/preview': { checks: [], risk: { flags: [] }, words: [], findings, publish },
    })

  it('allowed: reads production and previews the saved site (compute only), nothing else', async () => {
    const { data, notes, jinbe } = await ask(key(), 'publish_site', { name: 'billing', version: 2, acknowledge: ['public_route'] }, gateJinbe({ blocked: false, acknowledge: ['public_route'] }))
    expect(data).toMatchObject({ tool: 'publish_site', allowed: true, needs: [], protectedAction: true, protectedActionsAllowed: true })
    expect(jinbe.calls.map((c) => `${c.method} ${c.url.pathname}`)).toEqual(['GET /api/admin/sites/platform', 'GET /api/admin/sites/billing', 'POST /api/admin/sites/preview'])
    expect(notes?.join(' ')).toMatch(/passes with acknowledge \[public_route\]/)
  })

  it('the publish gate: missing acknowledgements, or error findings to fix', async () => {
    const missing = await ask(key(), 'publish_site', { name: 'billing' }, gateJinbe({ blocked: false, acknowledge: ['public_route', 'gate_not_preset'] }))
    expect(missing.data).toMatchObject({ allowed: false, wouldRefuseBecause: 'unconfirmed_findings', acknowledgeMissing: ['public_route', 'gate_not_preset'] })
    const blocked = await ask(key(), 'request_site_apply', { name: 'billing' }, gateJinbe({ blocked: true, acknowledge: [] }, [{ code: 'gate_without_authenticator', level: 'error', message: 'm', fix: 'add one' }]))
    expect(blocked.data).toMatchObject({ allowed: false, wouldRefuseBecause: 'unconfirmed_findings', errors: [{ code: 'gate_without_authenticator', fix: 'add one' }] })
  })

  it('production: use_apply_request, pointing at request_site_apply', async () => {
    const { data } = await ask(key(), 'publish_site', undefined, mockJinbe({ 'GET /api/admin/sites/platform': { production: true } }))
    expect(data).toMatchObject({ allowed: false, wouldRefuseBecause: 'use_apply_request', instead: 'request_site_apply' })
  })

  it.each([
    ['protected_actions_off', key({ stepUpActions: false }), 'publish_site', undefined],
    ['insufficient_scope', key({ scopes: ['mcp', 'sites:read'] }), 'save_site_draft', undefined],
    ['self_target_refused', key(), 'send_recovery_email', { userId: 'user-1' }],
    ['invalid_request', key(), 'get_site', { name: '../x' }],
    ['unknown_tool', key(), 'delete_site', undefined],
  ] as const)('%s', async (code, p, tool, args) => {
    const { data, jinbe } = await ask(p, tool, args)
    expect(data.allowed).toBe(false)
    expect(data.wouldRefuseBecause).toBe(code)
    expect(jinbe.calls).toHaveLength(0)
  })

  it('names the missing permissions and why protected actions are off', async () => {
    const { data } = await ask(key({ scopes: ['mcp'] }), 'publish_site')
    expect(data).toMatchObject({ needs: ['sites:apply'], wouldRefuseBecause: 'insufficient_scope' })
    const expired = await ask(key({ stepUpAt: old }), 'change_user_email')
    expect(expired.data).toMatchObject({ protectedActionsAllowed: false, protectedActionsReason: 'proof_expired' })
  })

  it('insufficient_scope names the groups granting the missing permission, when the key can read them', async () => {
    const jinbe = mockJinbe({
      'GET /api/admin/rbac/groups': { groups: [{ name: 'super_admins', services: { global: ['admin'] } }, { name: 'ops', services: { jinbe: ['ops'] } }, { name: 'devs', services: { jinbe: ['dev'] } }] },
      'GET /api/admin/rbac/services/jinbe/roles': { roles: [{ name: 'ops', permissions: ['sites:read', 'sites:apply'] }, { name: 'dev', permissions: ['sites:write'] }] },
      'GET /api/admin/rbac/services/global/roles': { roles: [{ name: 'admin', permissions: ['*'] }] },
    })
    const reader = key({ scopes: ['mcp', 'sites:read', 'groups:read'] })
    const { data } = await ask(reader, 'publish_site', undefined, jinbe)
    expect(data).toMatchObject({ wouldRefuseBecause: 'insufficient_scope', needs: ['sites:apply'], grantedBy: ['ops', 'super_admins'] })
    expect(data.hint).toMatch(/one of ops, super_admins/)
    expect(jinbe.calls.every((c) => c.method === 'GET')).toBe(true)
  })

  it('read-only mode: every write would be refused read_only', async () => {
    const ro = deps(mockJinbe({}).fetchImpl, { killSwitches: new KillSwitches({ enabled: true, readOnly: true }, null) })
    const { data } = await ask(key(), 'save_site_draft', undefined, undefined, ro)
    expect(data.wouldRefuseBecause).toBe('read_only')
  })

  it('is a read tool any connection sees, and never writes', async () => {
    expect(canI.write).toBeFalsy()
    const { jinbe } = await ask(key(), 'send_recovery_email', { userId: '0f0e0d0c-0b0a-4908-8706-050403020100' })
    expect(jinbe.calls.every((c) => c.method === 'GET')).toBe(true)
  })
})
