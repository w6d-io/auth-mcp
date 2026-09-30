import { describe, expect, it } from 'vitest'
import { KillSwitches } from '../../safety/kill-switch.js'
import { principal, ORG } from '../helpers/fixtures.js'

const on = { enabled: true, readOnly: false }

describe('KillSwitches', () => {
  it('env off switches everything off, whatever the file says', () => {
    const k = new KillSwitches({ enabled: false, readOnly: false }, () => JSON.stringify({ enabled: true }))
    expect(k.current().enabled).toBe(false)
    expect(k.check(principal())).toEqual({ refused: true, reason: 'disabled' })
  })

  it('the file can switch off and to read-only, never back on', () => {
    expect(new KillSwitches(on, () => '{"enabled":false}').current().enabled).toBe(false)
    expect(new KillSwitches(on, () => '{"readOnly":true}').current().readOnly).toBe(true)
    expect(new KillSwitches({ enabled: true, readOnly: true }, () => '{"readOnly":false}').current().readOnly).toBe(true)
  })

  it('refuses per org (tokens naming one), user, client, key, and personal keys per org', () => {
    const file = {
      disabledOrgs: ['org-x'],
      disabledUsers: ['user-x'],
      disabledClients: ['client-x'],
      disabledKeys: ['key-x'],
      personalKeysDisabledOrgs: [ORG],
    }
    const k = new KillSwitches(on, () => JSON.stringify(file))
    expect(k.check(principal({ org: 'org-x' }))).toEqual({ refused: true, reason: 'org' })
    expect(k.check(principal({ subject: 'user-x' }))).toEqual({ refused: true, reason: 'user' })
    expect(k.check(principal({ clientId: 'client-x' }))).toEqual({ refused: true, reason: 'client' })
    expect(k.check(principal({ kind: 'personal', keyId: 'key-x', org: 'org-y' }))).toEqual({ refused: true, reason: 'key' })
    expect(k.check(principal({ kind: 'personal', keyId: 'key-y', org: ORG }))).toEqual({ refused: true, reason: 'personal_keys' })
    expect(k.check(principal())).toEqual({ refused: false })
    // Tokens are not org-bound: no org, no org switch applies.
    expect(k.check(principal({ kind: 'personal', keyId: 'key-y', org: null }))).toEqual({ refused: false })
  })

  it('a malformed file fails closed', () => {
    const errors: unknown[] = []
    const k = new KillSwitches(on, () => '{"enabled": tru', 10_000, Date.now, (e) => errors.push(e))
    expect(k.current()).toMatchObject({ enabled: false, readOnly: true })
    expect(errors).toHaveLength(1)
    expect(new KillSwitches(on, () => '{"unknownField": 1}').current().enabled).toBe(false)
  })

  it('re-reads the file after the ttl (a flip applies within 10 s)', () => {
    let now = 0
    let content = '{}'
    const k = new KillSwitches(on, () => content, 10_000, () => now)
    expect(k.current().enabled).toBe(true)
    content = '{"enabled":false}'
    now = 9_999
    expect(k.current().enabled).toBe(true)
    now = 10_000
    expect(k.current().enabled).toBe(false)
  })

  it('no file: env values', () => {
    expect(new KillSwitches(on, null).current()).toMatchObject({ enabled: true, readOnly: false })
    expect(new KillSwitches(on, () => null).current().enabled).toBe(true)
  })
})
