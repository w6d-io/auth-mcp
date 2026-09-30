import { describe, expect, it } from 'vitest'
import { fromJinbe } from '../../safety/errors.js'

describe('fromJinbe', () => {
  it.each([
    [401, { error: 'Unauthorized', message: 'Authentication required' }, 'unauthenticated', false],
    [403, { error: 'Forbidden', message: 'Admin or superadmin access required' }, 'forbidden', false],
    [403, { error: 'org_out_of_scope', message: 'You can only see audit events for organisations you administer.' }, 'org_out_of_scope', false],
    [422, { error: 'reauth_required', message: 'recent 2FA', stepUp: { requiredAal: 'aal2', maxAgeMinutes: 15 } }, 'protected_actions_off', false],
    [422, { error: 'second_factor_required', message: 'enrol' }, 'second_factor_required', false],
    [422, { error: 'step_up_unavailable', message: 'browser only' }, 'protected_actions_off', false],
    [409, { error: 'approval_required', message: 'four eyes' }, 'needs_human_approval', false],
    [403, { error: 'second_approver_required', message: 'another super admin' }, 'needs_human_approval', false],
    [503, { error: 'organisation_directory_unavailable', message: 'down' }, 'organisation_directory_unavailable', true],
    [503, { error: 'policy_unavailable', message: 'OPA' }, 'retry_later', true],
    [503, { error: 'audit_store_unavailable' }, 'upstream_unavailable', true],
    [400, { error: 'invalid_spec', message: 'bad openapi' }, 'invalid_spec', false],
    [422, { error: 'invalid_site', message: 'This version cannot be saved', checks: [{ level: 'error', code: 'x', message: 'y' }] }, 'invalid_spec', false],
    [409, { error: 'version_mismatch', message: 'stale' }, 'conflict', false],
    [409, { error: 'conflict', message: 'etag' }, 'conflict', false],
    [404, { error: 'not_found', message: 'Site not found: x' }, 'not_found', false],
    [429, { error: 'Too Many Requests' }, 'rate_limited', true],
    [502, { error: 'Bad Gateway', message: 'OPA did not answer' }, 'upstream_unavailable', true],
    [504, null, 'upstream_unavailable', true],
    [500, { error: 'internal_error', message: 'Internal error' }, 'internal_error', false],
    [400, { error: 'Validation failed', details: [{ path: 'q', message: 'required' }] }, 'invalid_request', false],
    [422, { error: 'gate_without_authenticator', message: 'a gate needs an authenticator', checks: [{ level: 'error', code: 'gate_without_authenticator', path: 'gates.0.authenticators' }] }, 'invalid_spec', false],
    [422, { error: 'unconfirmed_findings', message: 'Not published', findings: [] }, 'unconfirmed_findings', false],
    [429, { error: 'verify_rate_limited' }, 'rate_limited', true],
  ])('%i %j → %s', (status, body, code, retryable) => {
    const e = fromJinbe(status, body)
    expect(e.body.code).toBe(code)
    expect(e.body.retryable).toBe(retryable)
    expect(e.body.status).toBe(status)
    expect(e.body.hint === undefined || typeof e.body.hint === 'string').toBe(true)
  })

  it('keeps the upstream code when it differs', () => {
    expect(fromJinbe(422, { error: 'step_up_unavailable' }).body.upstream).toBe('step_up_unavailable')
    expect(fromJinbe(422, { error: 'reauth_required' }).body.upstream).toBe('reauth_required')
  })

  it('passes validation checks and step-up details on', () => {
    expect(fromJinbe(422, { error: 'invalid_site', checks: [1] }).body.details).toEqual({ checks: [1] })
    expect(fromJinbe(422, { error: 'reauth_required', stepUp: { requiredAal: 'aal2' } }).body.details).toEqual({ stepUp: { requiredAal: 'aal2' } })
  })

  it('reads Retry-After', () => expect(fromJinbe(429, {}, '12').body.retryAfterSec).toBe(12))

  it('a Kubernetes API 429 is a retryable rate limit, not an outage', () => {
    const e = fromJinbe(503, { error: 'kubernetes_rate_limited', message: 'The Kubernetes API is temporarily rate-limiting requests, nothing was changed; retry in a few seconds (list zones: 429)' }, '2')
    expect(e.body).toMatchObject({ code: 'rate_limited', retryable: true, retryAfterSec: 2, upstream: 'kubernetes_rate_limited' })
    expect(e.body.message).toContain('temporarily rate-limiting')
    // jinbe before kubernetes_rate_limited: the same 429 reported as kubernetes_unavailable
    const old = fromJinbe(503, { error: 'kubernetes_unavailable', message: 'The Kubernetes API is unavailable, nothing was changed (list zones: 429)' })
    expect(old.body).toMatchObject({ code: 'rate_limited', retryable: true })
    expect(old.body.message).toMatch(/temporarily rate-limited.*retry/)
    expect(fromJinbe(503, { error: 'kubernetes_unavailable', message: 'The Kubernetes API is unavailable, nothing was changed (list zones: 500)' }).body.code).toBe('upstream_unavailable')
  })

  it('sanitises and redacts an echoed message', () => {
    const e = fromJinbe(400, { error: 'invalid_request', message: `bad ${'x'.repeat(1000)} Bearer abcdefghijklmnopqrstuvwxyz` })
    expect(e.body.message.length).toBeLessThan(340)
    const e2 = fromJinbe(400, { error: 'invalid_request', message: 'token ory_at_abcdefghijklmnopqrstu leaked' })
    expect(e2.body.message).toContain('[REDACTED]')
  })

  it('ignores a non-code error string (HTML, prose)', () => {
    expect(fromJinbe(403, { error: '<b>Forbidden</b>' }).body.upstream).toBeUndefined()
  })
})

describe('grant guard refusals (jinbe permission-refusal.ts)', () => {
  const facts = { permission: 'users:update_email', grantedBy: ['security', 'super_admins'], hint: 'Ask an administrator to add you to one of: security, super_admins.' }

  it('permission_required (code, not error): forbidden with permission, grantedBy and the hint', () => {
    const e = fromJinbe(403, { error: 'Forbidden', code: 'permission_required', message: 'This needs users:update_email.', ...facts })
    expect(e.body).toMatchObject({ code: 'forbidden', upstream: 'permission_required', retryable: false, hint: facts.hint })
    expect(e.body.details).toEqual({ permission: 'users:update_email', grantedBy: ['security', 'super_admins'] })
  })

  it('grant_exceeds_own and staff_group_super_admin_only get their own codes, not retryable, with missing', () => {
    const over = fromJinbe(403, { error: 'grant_exceeds_own', code: 'grant_exceeds_own', message: 'grants what you do not hold', missing: ['billing:write'], missingByScope: { billing: ['billing:write'] }, grantedBy: ['billing_admins'], hint: 'Ask …', blockingGroup: 'g' })
    expect(over.body).toMatchObject({ code: 'grant_exceeds_own', retryable: false, hint: 'Ask …' })
    expect(over.body.details).toMatchObject({ missing: ['billing:write'], missingByScope: { billing: ['billing:write'] }, grantedBy: ['billing_admins'], blockingGroup: 'g' })
    const staff = fromJinbe(403, { error: 'staff_group_super_admin_only', message: 'Only a super admin may', permission: '*', grantedBy: [], hint: 'No group grants this on its own; ask a super admin.' })
    expect(staff.body).toMatchObject({ code: 'staff_group_super_admin_only', retryable: false, hint: 'No group grants this on its own; ask a super admin.' })
  })

  it('privilege_escalation_blocked (422) is a forbidden carrying its facts', () => {
    const e = fromJinbe(422, { error: 'privilege_escalation_blocked', message: 'blocked', permission: 'groups:write', grantedBy: ['super_admins'] })
    expect(e.body).toMatchObject({ code: 'forbidden', upstream: 'privilege_escalation_blocked', details: { permission: 'groups:write', grantedBy: ['super_admins'] } })
  })

  it('a delegated scope_missing keeps its message and carries jinbe\'s hint and grantedBy', () => {
    const e = fromJinbe(403, { error: 'Forbidden', code: 'insufficient_scope', reason: 'scope_missing:sites:apply', permission: 'sites:apply', grantedBy: ['ops'], hint: 'This credential does not carry sites:apply: use a key that carries it.' })
    expect(e.body).toMatchObject({ code: 'insufficient_scope', message: 'Your key lacks sites:apply', hint: 'This credential does not carry sites:apply: use a key that carries it.' })
    expect(e.body.details).toEqual({ permission: 'sites:apply', grantedBy: ['ops'] })
  })

  it('a hostile hint is sanitised and redacted; codes outside the hinted set keep ours', () => {
    const e = fromJinbe(403, { error: 'Forbidden', code: 'permission_required', hint: `Ask ${'‮'}admin Bearer abcdefghijklmnopqrstuvwxyz0123` })
    expect(e.body.hint).not.toContain('‮')
    expect(e.body.hint).toContain('[REDACTED]')
    expect(fromJinbe(409, { error: 'conflict', hint: 'jinbe says' }).body.hint).not.toBe('jinbe says')
  })
})

describe('second-factor refusals (jinbe wave19 2FA visibility)', () => {
  const refusal = (keyReason: string) => ({
    error: 'step_up_unavailable', message: 'needs a browser', hint: `jinbe hint for ${keyReason}`, permission: 'sites:apply',
    secondFactor: { rule: 'step_up', requiredAal: 'aal2', maxAgeMin: 15, keyReason },
  })

  it.each([
    ['key_step_up_expired', 'protected_actions_off', /older than 30 days/],
    ['no_key_step_up', 'protected_actions_off', /no second-factor proof/],
    ['step_up_actions_off', 'protected_actions_off', /protected actions off/],
    ['not_allowed_here', 'needs_2fa', /do it in the console/],
    ['not_personal_key', 'needs_2fa', /do it in the console/],
  ])('%s → %s', (keyReason, code, message) => {
    const e = fromJinbe(422, refusal(keyReason))
    expect(e.body.code).toBe(code)
    expect(e.body.message).toMatch(message)
    expect(e.body.hint).toBe(`jinbe hint for ${keyReason}`)
    expect(e.body.details).toMatchObject({ permission: 'sites:apply', secondFactor: { rule: 'step_up', keyReason } })
    expect(e.body.retryable).toBe(false)
  })

  it('a sign-in rule refusal keeps its rule and groups', () => {
    const e = fromJinbe(422, { error: 'second_factor_required', message: 'enrol', hint: 'Set up two-step sign-in', secondFactor: { rule: 'group_sign_in', requiredAal: 'aal2', requiredBecause: ['ops'] } })
    expect(e.body).toMatchObject({ code: 'second_factor_required', hint: 'Set up two-step sign-in', details: { secondFactor: { rule: 'group_sign_in', requiredBecause: ['ops'] } } })
  })
})
