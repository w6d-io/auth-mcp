import { describe, expect, it } from 'vitest'
import { parseAuthorization, parsePersonalKey } from '../../auth/bearer.js'

const KEY_ID = '3f9c2a1e-0b4d-4c6e-9a8b-7d5e4f3a2b1c'
const SECRET = 'Zx9_kL2-mN4pQ6rS8tU0vW1yA3bC5dE7'

describe('parseAuthorization', () => {
  it('reads a bearer access token', () => {
    expect(parseAuthorization('Bearer ory_at_abcdefghijklmnop.qrstu')).toEqual({ kind: 'token', token: 'ory_at_abcdefghijklmnop.qrstu' })
  })

  it('is case-insensitive on the scheme', () => {
    expect(parseAuthorization('bearer ory_at_abcdefghijklmnop')?.kind).toBe('token')
  })

  it('reads a personal key without forwarding it as a token', () => {
    expect(parseAuthorization(`Bearer stk_mcp_${KEY_ID}.${SECRET}`)).toMatchObject({ kind: 'personal_key', keyId: KEY_ID, secret: SECRET })
  })

  it.each([
    [undefined],
    [''],
    ['Basic dXNlcjpwYXNz'],
    ['Bearer'],
    ['Bearer short'],
    ['Bearer two tokens'],
    ['Bearer <script>alert(1)</script>0000000'],
    [['Bearer a', 'Bearer b']],
  ])('refuses %j', (header) => {
    expect(parseAuthorization(header as never)).toBeNull()
  })

  it('refuses a malformed personal key rather than treating it as an opaque token', () => {
    expect(parseAuthorization('Bearer stk_mcp_nodot000000000000000000000000')).toBeNull()
    expect(parseAuthorization(`Bearer stk_mcp_${KEY_ID}.short`)).toBeNull()
    expect(parseAuthorization(`Bearer stk_mcp_bad id.${SECRET}`)).toBeNull()
  })
})

describe('parsePersonalKey', () => {
  it('splits on the first dot only', () => {
    expect(parsePersonalKey(`stk_mcp_${KEY_ID}.${SECRET}.more`)).toMatchObject({ keyId: KEY_ID, secret: `${SECRET}.more` })
  })
  it('refuses another prefix', () => {
    expect(parsePersonalKey(`stk_api_${KEY_ID}.${SECRET}`)).toBeNull()
  })
})
