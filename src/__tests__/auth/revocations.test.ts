import { describe, expect, it } from 'vitest'
import { KeyRevocations } from '../../auth/revocations.js'
import { CachingKeyExchanger, type KeyExchanger } from '../../auth/personal-key.js'
import { CachingVerifier, type TokenVerifier } from '../../auth/verifier.js'
import { Authenticator } from '../../auth/authenticator.js'
import type { Principal } from '../../auth/types.js'
import { execute } from '../../mcp/registry.js'
import { revokeMyKey } from '../../mcp/tools/user-writes.js'
import { deps, mockJinbe, principal as toolPrincipal, sc } from '../helpers/fixtures.js'

const KEY_ID = '3f9c2a1e-0b4d-4c6e-9a8b-7d5e4f3a2b1c'
const SECRET = 'Zx9_kL2-mN4pQ6rS8tU0vW1yA3bC5dE7'
const KEY = `stk_mcp_${KEY_ID}.${SECRET}`
const principal: Principal = {
  subject: 'user-1', email: null, org: null, scopes: ['mcp'], clientId: KEY_ID, kind: 'personal', keyId: KEY_ID,
  expiresAt: Math.floor(Date.now() / 1000) + 600, tokenHash: 'h',
}

/** The production wiring (server.ts): caches in front of an exchanger and verifier that always say yes. */
function wired() {
  let exchanges = 0
  let verifies = 0
  const inner: KeyExchanger = { exchange: async () => ({ accessToken: `ory_at_minted${++exchanges}xxxxxxxx`, expiresIn: 600 }) }
  const verifier: TokenVerifier = { verify: async () => (verifies++, principal) }
  const keys = new CachingKeyExchanger(inner)
  const tokens = new CachingVerifier(verifier, 60_000)
  const revocations = new KeyRevocations()
  revocations.onRevoke((keyId) => {
    keys.forgetKey(keyId)
    tokens.forgetKey(keyId)
  })
  return { auth: new Authenticator(tokens, keys, revocations), revocations, counts: () => ({ exchanges, verifies }) }
}

describe('a revoked key stops at once on this replica', () => {
  it('the key is refused although its token is still cached, and the caches are dropped', async () => {
    const w = wired()
    await w.auth.authenticate(`Bearer ${KEY}`)
    await w.auth.authenticate(`Bearer ${KEY}`)
    expect(w.counts()).toEqual({ exchanges: 1, verifies: 1 })
    w.revocations.revoke(KEY_ID)
    await expect(w.auth.authenticate(`Bearer ${KEY}`)).rejects.toMatchObject({ code: 'invalid_key' })
    await expect(w.auth.authenticate('Bearer ory_at_minted1xxxxxxxx')).rejects.toMatchObject({ code: 'invalid_token' })
  })

  it('expires from the list after its ttl (jinbe has refused the key long before)', () => {
    let t = 0
    const r = new KeyRevocations(1000, 10, () => t)
    r.revoke('k')
    expect(r.isRevoked('k')).toBe(true)
    t = 1001
    expect(r.isRevoked('k')).toBe(false)
    expect(r.isRevoked(null)).toBe(false)
  })

  it('revoke_my_key sends the DELETE, then records the revocation', async () => {
    const revocations = new KeyRevocations()
    const jinbe = mockJinbe({ [`DELETE /api/me/api-keys/${KEY_ID}`]: () => ({ status: 204 }) })
    const me = toolPrincipal({ kind: 'personal', keyId: KEY_ID })
    const r = await execute(revokeMyKey, {}, me, deps(jinbe.fetchImpl, { revocations }))
    expect(sc(r).data.revoked).toBe(true)
    expect(jinbe.calls.map((c) => `${c.method} ${c.url.pathname}`)).toEqual([`DELETE /api/me/api-keys/${KEY_ID}`])
    expect(revocations.isRevoked(KEY_ID)).toBe(true)
  })

  it('a refused revoke records nothing', async () => {
    const revocations = new KeyRevocations()
    const jinbe = mockJinbe({ [`DELETE /api/me/api-keys/${KEY_ID}`]: () => ({ status: 404, body: { error: 'not_found' } }) })
    const r = await execute(revokeMyKey, {}, toolPrincipal({ kind: 'personal', keyId: KEY_ID }), deps(jinbe.fetchImpl, { revocations }))
    expect(sc(r).error.code).toBe('not_found')
    expect(revocations.isRevoked(KEY_ID)).toBe(false)
  })
})
