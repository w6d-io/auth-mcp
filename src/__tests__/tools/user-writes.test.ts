import { describe, expect, it } from 'vitest'
import { execute } from '../../mcp/registry.js'
import {
  addUserToGroups, changeUserEmail, inviteUser, resendVerificationEmail, revokeMyKey, sendLoginLink, sendRecoveryEmail,
} from '../../mcp/tools/user-writes.js'
import { deps, mockJinbe, principal, sc } from '../helpers/fixtures.js'

const U = '/api/admin/users'
const BOB = '0f0e0d0c-0b0a-4908-8706-050403020100'
const desk = principal({
  scopes: ['mcp', 'users:create', 'users:recovery', 'users:send_login_link', 'users:verify', 'users:update_email', 'groups.members:write'],
  kind: 'personal',
  keyId: 'key-1',
})

describe('invite_user', () => {
  it('creates the user with an invitation, and passes optional groups to the grant gate', async () => {
    const jinbe = mockJinbe({ [`POST ${U}`]: () => ({ status: 201, body: { id: BOB, state: 'active', traits: { email: 'bob@example.com', name: 'Bob' }, metadata_admin: { x: 1 } } }) })
    const r = await execute(inviteUser, { email: 'bob@example.com', name: 'Bob' }, desk, deps(jinbe.fetchImpl))
    expect(jinbe.calls[0].body).toEqual({ email: 'bob@example.com', name: 'Bob', sendInvite: true })
    expect(jinbe.calls[0].headers['idempotency-key']).toBeDefined()
    expect(sc(r).data).toEqual({ id: BOB, email: 'bob@example.com', name: 'Bob', state: 'active', invited: true, groups: [] })
    await execute(inviteUser, { email: 'bob@example.com', groups: ['support'], sendInvite: false }, desk, deps(jinbe.fetchImpl))
    expect(jinbe.calls[1].body).toEqual({ email: 'bob@example.com', groups: ['support'], sendInvite: false })
  })

  it('a taken address maps to conflict', async () => {
    const jinbe = mockJinbe({ [`POST ${U}`]: () => ({ status: 409, body: { error: 'conflict', message: 'exists' } }) })
    const r = await execute(inviteUser, { email: 'bob@example.com' }, desk, deps(jinbe.fetchImpl))
    expect(sc(r).error.code).toBe('conflict')
  })
})

describe('recovery, login link, verification', () => {
  it('send and never return a link', async () => {
    const jinbe = mockJinbe({
      [`POST ${U}/${BOB}/recovery-email`]: () => ({ status: 204 }),
      [`POST ${U}/${BOB}/login-link`]: { sent: true, expiresAt: '2026-10-01T00:00:00Z' },
      [`POST ${U}/${BOB}/verification`]: () => ({ status: 202, body: { sent: true } }),
    })
    const d = deps(jinbe.fetchImpl)
    expect(sc(await execute(sendRecoveryEmail, { userId: BOB }, desk, d)).data).toEqual({ userId: BOB, sent: true })
    expect(sc(await execute(sendLoginLink, { userId: BOB, returnTo: 'https://billing.example.com/' }, desk, d)).data).toEqual({ userId: BOB, sent: true, expiresAt: '2026-10-01T00:00:00Z' })
    expect(sc(await execute(resendVerificationEmail, { userId: BOB }, desk, d)).data).toEqual({ userId: BOB, sent: true })
    expect(jinbe.calls[1].body).toEqual({ return_to: 'https://billing.example.com/' })
  })

  it.each([
    [409, 'already_verified', 'conflict'],
    [422, 'unknown_address', 'invalid_request'],
    [409, 'verification_link_unavailable', 'conflict'],
  ])('verification %i %s → %s', async (status, error, code) => {
    const jinbe = mockJinbe({ [`POST ${U}/${BOB}/verification`]: () => ({ status, body: { error, message: 'no' } }) })
    const r = await execute(resendVerificationEmail, { userId: BOB, address: 'bob@example.com' }, desk, deps(jinbe.fetchImpl))
    expect(sc(r).error).toMatchObject({ code, upstream: error })
    expect(jinbe.calls[0].body).toEqual({ address: 'bob@example.com' })
  })

  it('a verification rate limit carries retryAfterSec', async () => {
    const jinbe = mockJinbe({ [`POST ${U}/${BOB}/verification`]: () => ({ status: 429, body: { error: 'rate_limited' }, headers: { 'retry-after': '600' } }) })
    const r = await execute(resendVerificationEmail, { userId: BOB }, desk, deps(jinbe.fetchImpl))
    expect(sc(r).error).toMatchObject({ code: 'rate_limited', retryable: true, retryAfterSec: 600 })
  })

  it('the new endpoints are marked as needing jinbe wave17', () => {
    expect(resendVerificationEmail.requiresJinbe).toBe('wave17/mcp-endpoints')
    expect(changeUserEmail.requiresJinbe).toBe('wave17/mcp-endpoints')
  })
})

describe('change_user_email', () => {
  it('posts only the new address and returns the verification and notice state', async () => {
    const jinbe = mockJinbe({
      [`POST ${U}/${BOB}/email`]: { id: BOB, email: 'bob@new.example.com', verified: false, verificationSent: false, verificationError: 'courier down', oldAddressNotice: { delivered: false, recorded: true, channel: 'audit' } },
    })
    const r = await execute(changeUserEmail, { userId: BOB, newEmail: 'bob@new.example.com' }, desk, deps(jinbe.fetchImpl))
    expect(jinbe.calls[0].body).toEqual({ email: 'bob@new.example.com' })
    expect(sc(r).data).toEqual({
      userId: BOB, email: 'bob@new.example.com', verified: false, verificationSent: false, verificationError: 'courier down',
      oldAddressNotice: { delivered: false, recorded: true, channel: 'audit' },
    })
    expect(sc(r).notes[0]).toMatch(/resend_verification_email/)
  })

  it.each([
    [409, 'address_unavailable', 'conflict'],
    [403, 'own_address', 'self_target_refused'],
    [403, 'outranked', 'forbidden'],
    [400, 'address_unchanged', 'invalid_request'],
    [404, 'not_found', 'not_found'],
  ])('%i %s → %s', async (status, error, code) => {
    const jinbe = mockJinbe({ [`POST ${U}/${BOB}/email`]: () => ({ status, body: { error, message: 'no' } }) })
    const r = await execute(changeUserEmail, { userId: BOB, newEmail: 'bob@new.example.com' }, desk, deps(jinbe.fetchImpl))
    expect(sc(r).error.code).toBe(code)
  })

  it('a key without protected actions gets the key message', async () => {
    const jinbe = mockJinbe({ [`POST ${U}/${BOB}/email`]: () => ({ status: 422, body: { error: 'reauth_required', message: 'Re-verify two-factor authentication' } }) })
    const r = await execute(changeUserEmail, { userId: BOB, newEmail: 'bob@new.example.com' }, desk, deps(jinbe.fetchImpl))
    expect(sc(r).error.code).toBe('protected_actions_off')
    expect(sc(r).error.hint).toMatch(/create a new key with protected actions allowed.*Re-authenticate/)
  })

  it('never your own account, by id or email, and jinbe is not called', async () => {
    const jinbe = mockJinbe({})
    for (const userId of ['user-1']) {
      const r = await execute(changeUserEmail, { userId, newEmail: 'me@evil.example.com' }, desk, deps(jinbe.fetchImpl))
      expect(sc(r).error.code).toBe('self_target_refused')
    }
    const g = await execute(addUserToGroups, { email: 'ALICE@example.com', groups: ['super_admin'] }, desk, deps(jinbe.fetchImpl))
    expect(sc(g).error.code).toBe('self_target_refused')
    expect(jinbe.calls).toHaveLength(0)
  })
})

describe('add_user_to_groups', () => {
  it('PUTs the union of held and new groups: it can only add', async () => {
    const jinbe = mockJinbe({
      [`GET ${U}/bob%40example.com/groups`]: { email: 'bob@example.com', groups: ['users', 'billing-viewers'], availableGroups: [] },
      [`PUT ${U}/bob%40example.com/groups`]: (req) => ({ body: { groups: (req.body as any).groups } }),
    })
    const r = await execute(addUserToGroups, { email: 'bob@example.com', groups: ['support', 'users'] }, desk, deps(jinbe.fetchImpl))
    const put = jinbe.calls.find((c) => c.method === 'PUT')!
    expect(put.body).toEqual({ groups: ['users', 'billing-viewers', 'support'] })
    expect(put.headers['idempotency-key']).toBeDefined()
    expect(sc(r).data).toMatchObject({ status: 'added', added: ['support'], already_member: ['users'], changed: true })
  })

  it('writes nothing when every group is already held, or when the current groups cannot be read', async () => {
    const held = mockJinbe({ [`GET ${U}/bob%40example.com/groups`]: { groups: ['support'] } })
    const r = await execute(addUserToGroups, { email: 'bob@example.com', groups: ['support'] }, desk, deps(held.fetchImpl))
    expect(sc(r).data).toMatchObject({ status: 'unchanged', changed: false, added: [], already_member: ['support'] })
    expect(sc(r).notes[0]).toMatch(/nothing was written/)
    expect(held.calls.map((c) => c.method)).toEqual(['GET'])
    const broken = mockJinbe({ [`GET ${U}/bob%40example.com/groups`]: { weird: true } })
    const b = await execute(addUserToGroups, { email: 'bob@example.com', groups: ['support'] }, desk, deps(broken.fetchImpl))
    expect(sc(b).error.code).toBe('upstream_unavailable')
    expect(broken.calls.map((c) => c.method)).toEqual(['GET'])
  })

  it('jinbe refusing the route to a key (delegation_ineligible) → never through MCP', async () => {
    const jinbe = mockJinbe({
      [`GET ${U}/bob%40example.com/groups`]: { groups: [] },
      [`PUT ${U}/bob%40example.com/groups`]: () => ({ status: 403, body: { error: 'Forbidden', code: 'delegation_refused', reason: 'delegation_ineligible:groups.members:revoke' } }),
    })
    const r = await execute(addUserToGroups, { email: 'bob@example.com', groups: ['support'] }, desk, deps(jinbe.fetchImpl))
    expect(sc(r).error).toMatchObject({ code: 'never_via_mcp', upstream: 'delegation_ineligible:groups.members:revoke' })
    expect(sc(r).error.message).toBe('This action is never allowed through MCP: do it in the console')
  })
})

describe('revoke_my_key', () => {
  it('revokes this connection\'s key by default: the one DELETE MCP sends', async () => {
    const jinbe = mockJinbe({ 'DELETE /api/me/api-keys/key-1': () => ({ status: 204 }) })
    const r = await execute(revokeMyKey, {}, desk, deps(jinbe.fetchImpl))
    expect(sc(r).data).toEqual({ keyId: 'key-1', revoked: true, thisConnection: true })
    expect(jinbe.calls[0].method).toBe('DELETE')
    expect(jinbe.calls[0].headers['idempotency-key']).toBeUndefined()
  })

  it('needs a key id on an OAuth connection, and a well-formed one', async () => {
    const jinbe = mockJinbe({})
    expect(sc(await execute(revokeMyKey, {}, principal(), deps(jinbe.fetchImpl))).error.code).toBe('invalid_request')
    expect(sc(await execute(revokeMyKey, { keyId: '../users/x' }, desk, deps(jinbe.fetchImpl))).error.code).toBe('invalid_request')
    expect(sc(await execute(revokeMyKey, { keyId: '..' }, desk, deps(jinbe.fetchImpl))).error.code).toBe('invalid_request')
    expect(jinbe.calls).toHaveLength(0)
  })
})
