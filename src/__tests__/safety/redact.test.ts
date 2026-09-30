import { describe, expect, it } from 'vitest'
import { REDACTED, containsSecret, isSecretKey, redact, redactString } from '../../safety/redact.js'

describe('redactString', () => {
  it.each([
    ['personal key', 'use stk_mcp_3f9c2a1e-0b4d-4c6e-9a8b-7d5e4f3a2b1c.Zx9_kL2-mN4pQ6rS8tU0vW1y now'],
    ['ory access token', 'token ory_at_Qm9vYmFyLmJhei5xdXgu0123456789'],
    ['ory session token', 'ory_st_abcdefghijklmnop'],
    ['jwt', 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlLXZhbHVl'],
    ['pem', '-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----'],
    ['bearer header', 'Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123'],
    ['aws key', 'AKIAIOSFODNN7EXAMPLE'],
    ['vault ref', 'vault:secret/data/auth/kratos#webhook'],
    ['vault token', 'hvs.CAESIJlWh0-abcdefghijklmnopqrst'],
    ['github token', 'ghp_abcdefghijklmnopqrstuvwxyz0123456789'],
  ])('removes a %s', (_name, input) => {
    const out = redactString(input)
    expect(out).toContain(REDACTED)
    expect(containsSecret(out)).toBe(false)
  })

  it('removes credentials from URLs but keeps the host', () => {
    expect(redactString('postgres://admin:hunter2@db.internal:5432/app')).toBe(`postgres://${REDACTED}@db.internal:5432/app`)
  })

  it('leaves ordinary text alone', () => {
    const s = 'Site payroll on payroll.example.com, version 3, route /api/:id'
    expect(redactString(s)).toBe(s)
  })

  it('handles a truncated PEM block (no END line)', () => {
    expect(redactString('x -----BEGIN RSA PRIVATE KEY-----\nMIIabc')).toBe(`x ${REDACTED}`)
  })
})

describe('redact (deep)', () => {
  it('replaces values under secret-named keys whatever they look like', () => {
    const out = redact({
      name: 'site',
      config: { client_secret: 'plain', password: 'p', apiKey: 'k', sessionId: 's', headers: { Authorization: 'x' } },
      list: [{ token: 't' }],
    })
    expect(out).toEqual({
      name: 'site',
      config: { client_secret: REDACTED, password: REDACTED, apiKey: REDACTED, sessionId: REDACTED, headers: { Authorization: REDACTED } },
      list: [{ token: REDACTED }],
    })
  })

  it('keeps allow-listed look-alikes and empty values', () => {
    expect(redact({ tokenHash: 'abc', token_type: 'bearer', nextCursor: 'c', password: '' })).toEqual({ tokenHash: 'abc', token_type: 'bearer', nextCursor: 'c', password: '' })
  })

  it('does not follow cycles', () => {
    const a: Record<string, unknown> = { x: 1 }
    a.self = a
    expect(redact(a)).toEqual({ x: 1, self: REDACTED })
  })

  it('does not mutate its input', () => {
    const input = { password: 'p' }
    redact(input)
    expect(input.password).toBe('p')
  })

  it('knows secret keys', () => {
    for (const k of ['secret', 'client_secret', 'x-actor-token', 'refresh_token', 'privateKey', 'webhookSecret', 'set-cookie']) expect(isSecretKey(k)).toBe(true)
    for (const k of ['name', 'secretive_name_field_count', 'passwordless', 'tokenHash', 'session_id_hash']) expect(isSecretKey(k)).toBe(false)
  })
})
