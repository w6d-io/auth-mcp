import { describe, expect, it } from 'vitest'
import { covers, hasAnyScope, hasScope, isWriteScope, parseScopeString, usableScopes } from '../../auth/scopes.js'

describe('covers (twin of jinbe authorization-resolution.covers)', () => {
  it('equal permissions', () => expect(covers('admin:read', 'admin:read')).toBe(true))
  it('dotted ancestor, same verb', () => expect(covers('admin:write', 'admin.membership:write')).toBe(true))
  it('different verb', () => expect(covers('admin:read', 'admin:write')).toBe(false))
  it('a string prefix is not an ancestor', () => expect(covers('admin.member:write', 'admin.membership:write')).toBe(false))
  it('a child does not cover its parent', () => expect(covers('admin.membership:write', 'admin:write')).toBe(false))
})

describe('usableScopes', () => {
  it('drops wildcards and junk: a delegated token never carries super-admin by wildcard', () => {
    expect(usableScopes(['mcp', '*', 'admin:*', 'sites:apply', 'offline_access', 'DROP TABLE', 'x'])).toEqual(['mcp', 'sites:apply', 'offline_access'])
  })
})

describe('hasScope / hasAnyScope', () => {
  const scopes = ['mcp', 'admin:read']
  it('requires the mcp baseline for anything', () => {
    expect(hasScope(['admin:read'], 'admin:read')).toBe(false)
    expect(hasScope(['admin:read'], 'mcp')).toBe(false)
  })
  it('grants the baseline', () => expect(hasScope(scopes, 'mcp')).toBe(true))
  it('grants a held permission', () => expect(hasScope(scopes, 'admin:read')).toBe(true))
  it('refuses a scope beyond the token', () => expect(hasScope(scopes, 'admin:write')).toBe(false))
  it('does not treat * as covering anything', () => expect(hasScope(['mcp', '*'], 'admin:read')).toBe(false))
  it('offline_access covers nothing', () => expect(hasScope(['mcp', 'offline_access'], 'offline_access:read')).toBe(false))
  it('any-of', () => {
    expect(hasAnyScope(scopes, ['org:manage_users', 'admin:read'])).toBe(true)
    expect(hasAnyScope(scopes, ['org:manage_users'])).toBe(false)
    expect(hasAnyScope(scopes, [])).toBe(false)
  })
})

describe('helpers', () => {
  it('parses a scope string', () => expect(parseScopeString(' mcp  admin:read mcp ')).toEqual(['mcp', 'admin:read']))
  it('knows write verbs', () => {
    expect(isWriteScope('admin:read')).toBe(false)
    expect(isWriteScope('admin:write')).toBe(true)
    expect(isWriteScope('sessions:revoke')).toBe(true)
    expect(isWriteScope('mcp')).toBe(false)
  })
})
