import { describe, expect, it } from 'vitest'
import { authorizationServerMetadataUrl, checkIssuer } from '../../auth/issuer-check.js'
import { principalFromClaims } from '../../auth/verifier.js'
import { protectedActionsOf, REAUTH_GUIDANCE } from '../../auth/protected-actions.js'
import { metadataUrl, protectedResourceMetadata } from '../../app.js'
import { execute } from '../../mcp/registry.js'
import { getMyIdentity } from '../../mcp/tools/identity.js'
import { deps, mockJinbe, principal, sc } from '../helpers/fixtures.js'

const RESOURCE = 'https://mcp.authdev.dev.example.com/mcp'
const ISSUER = 'https://hydra.authdev.dev.example.com/'
const now = Math.floor(Date.now() / 1000)
const claims = (ext: Record<string, unknown>) => ({
  active: true, token_use: 'access_token', scope: 'mcp offline_access sites:read', client_id: 'dcr-client-1', sub: 'user-1', exp: now + 900, aud: [RESOURCE], ext,
})

describe('OAuth principal from token-info', () => {
  it('reads the consent facts: kind oauth, 2FA time, protected actions, window, sign-in end, client name, mode', () => {
    const p = principalFromClaims(
      claims({ kind: 'oauth', email: 'a@x.test', scope_mode: 'chosen', step_up_at: new Date((now - 60) * 1000).toISOString(), step_up_actions: true, step_up_until: new Date((now + 12 * 3600) * 1000).toISOString(), granted_at: now - 60, grant_expires_at: now + 30 * 86400, client_name: 'Claude Code' }),
      { resource: RESOURCE, token: 't' }
    )
    expect(p).toMatchObject({ kind: 'oauth', subject: 'user-1', clientId: 'dcr-client-1', keyId: null, stepUpActions: true, scopeMode: 'chosen', clientName: 'Claude Code' })
    expect(Date.parse(p.stepUpUntil!)).toBe((now + 12 * 3600) * 1000)
    expect(protectedActionsOf(p)).toMatchObject({ allowed: true })
  })

  it('ISO times work too; absent facts stay absent (unknown, never guessed); malformed ones are dropped', () => {
    const iso = principalFromClaims(claims({ kind: 'oauth', step_up_until: new Date((now + 60) * 1000).toISOString() }), { resource: RESOURCE, token: 't' })
    expect(iso.stepUpUntil).toBe(new Date((now + 60) * 1000).toISOString())
    const off = principalFromClaims(claims({ kind: 'oauth', step_up_actions: true }), { resource: RESOURCE, token: 't' })
    expect(protectedActionsOf(off)).toMatchObject({ allowed: false, reason: 'disabled_by_admin' })
    const bare = principalFromClaims(claims({ kind: 'oauth' }), { resource: RESOURCE, token: 't' })
    expect(bare.stepUpUntil).toBeUndefined()
    expect(protectedActionsOf(bare)).toMatchObject({ allowed: false, reason: 'unknown' })
    const bad = principalFromClaims(claims({ kind: 'oauth', step_up_until: 'soon', step_up_actions: 'yes', scope_mode: 'everything' }), { resource: RESOURCE, token: 't' })
    expect(bad).not.toHaveProperty('stepUpUntil')
    expect(bad).not.toHaveProperty('stepUpActions')
    expect(bad).not.toHaveProperty('scopeMode')
  })

  it('past the 12 h window or without the consent box: not allowed, with how to get them back', () => {
    const expired = protectedActionsOf({ kind: 'oauth', stepUpActions: true, stepUpUntil: new Date(Date.now() - 1000).toISOString() })
    expect(expired).toMatchObject({ allowed: false, reason: 'proof_expired', guidance: REAUTH_GUIDANCE })
    expect(protectedActionsOf({ kind: 'oauth', stepUpActions: false })).toMatchObject({ reason: 'consent_without', guidance: REAUTH_GUIDANCE })
  })
})

describe('get_my_identity for a browser sign-in', () => {
  it('says oauth, the client, the mode and when the sign-in ends, and protected actions with guidance', async () => {
    const p = principal({ kind: 'oauth', clientName: 'Claude Code', scopeMode: 'all', grantExpiresAt: '2026-10-30T00:00:00.000Z', stepUpActions: true, stepUpUntil: new Date(Date.now() - 1000).toISOString() })
    const r = await execute(getMyIdentity, {}, p, deps(mockJinbe({}).fetchImpl))
    expect(sc(r).data).toMatchObject({ credentialType: 'oauth', signIn: { client: 'Claude Code', permissions: 'all', expiresAt: '2026-10-30T00:00:00.000Z' } })
    expect(sc(r).data.protectedActions).toMatchObject({ allowed: false, reason: 'proof_expired', guidance: REAUTH_GUIDANCE })
  })
})

describe('discovery (what Claude Code follows)', () => {
  it('the 401 metadata URL and the metadata itself', () => {
    expect(metadataUrl(RESOURCE)).toBe('https://mcp.authdev.dev.example.com/.well-known/oauth-protected-resource/mcp')
    const prm = protectedResourceMetadata({ MCP_RESOURCE: RESOURCE, HYDRA_ISSUER: ISSUER, MCP_ALLOWED_ORIGINS: [], MCP_BODY_LIMIT_BYTES: 1 })
    expect(prm.resource).toBe(RESOURCE)
    expect(prm.authorization_servers).toEqual([ISSUER])
    expect(prm.scopes_supported).toContain('offline_access')
  })

  it('RFC 8414 metadata URL keeps no double slash for an issuer with a trailing slash', () => {
    expect(authorizationServerMetadataUrl(ISSUER)).toBe('https://hydra.authdev.dev.example.com/.well-known/oauth-authorization-server')
    expect(authorizationServerMetadataUrl('https://as.example.com/tenant/')).toBe('https://as.example.com/.well-known/oauth-authorization-server/tenant')
  })

  it('the startup check: byte-equal issuer, or which problem', async () => {
    const answer = (status: number, body: unknown) => (async () => new Response(JSON.stringify(body), { status })) as typeof fetch
    expect(await checkIssuer(ISSUER, answer(200, { issuer: ISSUER }))).toMatchObject({ ok: true })
    expect(await checkIssuer(ISSUER, answer(200, { issuer: ISSUER.slice(0, -1) }))).toMatchObject({ ok: false, problem: 'mismatch', found: ISSUER.slice(0, -1) })
    expect(await checkIssuer(ISSUER, answer(404, {}))).toMatchObject({ ok: false, problem: 'not_found' })
    expect(await checkIssuer(ISSUER, (async () => { throw new Error('down') }) as never)).toMatchObject({ ok: false, problem: 'unreachable' })
  })
})

describe('token-info refusals the person can act on', () => {
  it('grant_expired says to sign in again', async () => {
    const { JinbeTokenInfoVerifier } = await import('../../auth/verifier.js')
    const { StaticActorTokenSource } = await import('../../auth/actor-token.js')
    const v = new JinbeTokenInfoVerifier('http://jinbe.test', RESOURCE, new StaticActorTokenSource('a'), (async () =>
      new Response(JSON.stringify({ error: 'invalid_token', message: 'Refused', reason: 'grant_expired' }), { status: 401 })) as never)
    await expect(v.verify('ory_at_x')).rejects.toMatchObject({ code: 'invalid_token', message: expect.stringMatching(/sign in again/) })
  })
})
