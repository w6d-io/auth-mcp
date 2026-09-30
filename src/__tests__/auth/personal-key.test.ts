import { describe, expect, it, vi } from 'vitest'
import { CachingKeyExchanger, HydraClientCredentialsExchanger, JinbeKeyExchanger, type KeyExchanger } from '../../auth/personal-key.js'
import { Authenticator } from '../../auth/authenticator.js'
import { StaticActorTokenSource } from '../../auth/actor-token.js'
import type { TokenVerifier } from '../../auth/verifier.js'
import type { Principal } from '../../auth/types.js'
import { ORG } from '../helpers/fixtures.js'

const KEY_ID = '3f9c2a1e-0b4d-4c6e-9a8b-7d5e4f3a2b1c'
const SECRET = 'Zx9_kL2-mN4pQ6rS8tU0vW1yA3bC5dE7'
const KEY = `stk_mcp_${KEY_ID}.${SECRET}`

const principal = (over: Partial<Principal> = {}): Principal => ({
  subject: 'user-1', email: null, org: ORG, scopes: ['mcp'], clientId: KEY_ID, kind: 'personal', keyId: KEY_ID,
  expiresAt: Math.floor(Date.now() / 1000) + 600, tokenHash: 'h', ...over,
})

describe('HydraClientCredentialsExchanger', () => {
  it('uses client_credentials with basic auth and the MCP audience', async () => {
    const fetchImpl = vi.fn(async (_url: unknown, init?: RequestInit) => {
      const h = init?.headers as Record<string, string>
      expect(h.authorization).toBe(`Basic ${Buffer.from(`${KEY_ID}:${SECRET}`).toString('base64')}`)
      const body = new URLSearchParams(String(init?.body))
      expect(body.get('grant_type')).toBe('client_credentials')
      expect(body.get('audience')).toBe('https://mcp.test/mcp')
      expect(body.get('scope')).toBe('mcp')
      return new Response(JSON.stringify({ access_token: 'ory_at_minted0123456789', expires_in: 600 }), { status: 200 })
    })
    const ex = new HydraClientCredentialsExchanger('http://hydra-public:4444', 'https://mcp.test/mcp', ['mcp'], fetchImpl as never)
    expect(await ex.exchange(KEY_ID, SECRET)).toEqual({ accessToken: 'ory_at_minted0123456789', expiresIn: 600 })
    expect(String(fetchImpl.mock.calls[0][0])).toBe('http://hydra-public:4444/oauth2/token')
  })
  it('maps a refused key to invalid_key', async () => {
    const ex = new HydraClientCredentialsExchanger('http://h', 'https://mcp.test/mcp', ['mcp'], (async () => new Response('{}', { status: 401 })) as never)
    await expect(ex.exchange(KEY_ID, SECRET)).rejects.toMatchObject({ code: 'invalid_key' })
  })
})

describe('JinbeKeyExchanger', () => {
  it('presents the key and the actor token to jinbe', async () => {
    const fetchImpl = vi.fn(async (url: unknown, init?: RequestInit) => {
      expect(String(url)).toBe('http://jinbe:3000/api/mcp/personal-keys/exchange')
      const h = init?.headers as Record<string, string>
      expect(h.authorization).toBe(`Bearer ${KEY}`)
      expect(h['x-actor-token']).toBe('sa')
      return new Response(JSON.stringify({ access_token: 'ory_at_x0123456789abcdef', expires_in: 600 }), { status: 200 })
    })
    const ex = new JinbeKeyExchanger('http://jinbe:3000', new StaticActorTokenSource('sa'), fetchImpl as never)
    expect((await ex.exchange(KEY_ID, SECRET)).accessToken).toBe('ory_at_x0123456789abcdef')
  })
  it('maps 403 (org forbids personal keys) to invalid_key', async () => {
    const ex = new JinbeKeyExchanger('http://jinbe:3000', new StaticActorTokenSource('sa'), (async () => new Response('', { status: 403 })) as never)
    await expect(ex.exchange(KEY_ID, SECRET)).rejects.toMatchObject({ code: 'invalid_key' })
  })
})

describe('JinbeKeyExchanger — turned off by an administrator', () => {
  const off = (reason: string) => (async () => new Response(JSON.stringify({ error: 'mcp_disabled', reason }), { status: 403 })) as never
  it('maps 403 mcp_disabled to a clear mcp_disabled error', async () => {
    const ex = new JinbeKeyExchanger('http://jinbe:3000', new StaticActorTokenSource('sa'), off('disabled'))
    await expect(ex.exchange(KEY_ID, SECRET)).rejects.toMatchObject({ code: 'mcp_disabled', message: 'MCP access is turned off by an administrator' })
  })
  it('names the organization when it is outside the administrator scope', async () => {
    const ex = new JinbeKeyExchanger('http://jinbe:3000', new StaticActorTokenSource('sa'), off('org_not_allowed'))
    await expect(ex.exchange(KEY_ID, SECRET)).rejects.toMatchObject({ code: 'mcp_disabled', message: 'MCP access is turned off for this organization by an administrator' })
  })
  it("says so when the holder's groups may not use MCP", async () => {
    const ex = new JinbeKeyExchanger('http://jinbe:3000', new StaticActorTokenSource('sa'), off('group_not_allowed'))
    await expect(ex.exchange(KEY_ID, SECRET)).rejects.toMatchObject({ code: 'mcp_disabled', message: 'MCP access is not enabled for your groups by an administrator' })
  })
})

describe('CachingKeyExchanger', () => {
  it('reuses a token until 30 s before it expires', async () => {
    let now = 0
    const inner: KeyExchanger = { exchange: vi.fn(async () => ({ accessToken: 'ory_at_cached000000000', expiresIn: 600 })) }
    const ex = new CachingKeyExchanger(inner, 10, () => now)
    await ex.exchange(KEY_ID, SECRET)
    now = 560_000
    await ex.exchange(KEY_ID, SECRET)
    expect(inner.exchange).toHaveBeenCalledTimes(1)
    now = 571_000
    await ex.exchange(KEY_ID, SECRET)
    expect(inner.exchange).toHaveBeenCalledTimes(2)
  })
  it('does not share a token between two secrets of the same key id', async () => {
    const inner: KeyExchanger = { exchange: vi.fn(async () => ({ accessToken: 'ory_at_cached000000000', expiresIn: 600 })) }
    const ex = new CachingKeyExchanger(inner)
    await ex.exchange(KEY_ID, SECRET)
    await ex.exchange(KEY_ID, `${SECRET}x`)
    expect(inner.exchange).toHaveBeenCalledTimes(2)
  })
})

describe('Authenticator', () => {
  const keys: KeyExchanger = { exchange: async () => ({ accessToken: 'ory_at_fromkey0000000000', expiresIn: 600 }) }

  it('verifies an OAuth token and attaches it non-enumerably', async () => {
    const verifier: TokenVerifier = { verify: async () => principal({ kind: 'oauth', keyId: null, clientId: 'c' }) }
    const p = await new Authenticator(verifier, keys).authenticate('Bearer ory_at_oauthtoken000000000')
    expect(p.accessToken).toBe('ory_at_oauthtoken000000000')
    expect(Object.keys(p)).not.toContain('accessToken')
    expect(JSON.stringify(p)).not.toContain('ory_at_')
  })

  it('exchanges a personal key and presents the minted token, never the key', async () => {
    const verify = vi.fn(async () => principal())
    const p = await new Authenticator({ verify }, keys).authenticate(`Bearer ${KEY}`)
    expect(verify).toHaveBeenCalledWith('ory_at_fromkey0000000000')
    expect(p.accessToken).toBe('ory_at_fromkey0000000000')
  })

  it('refuses a key whose minted token belongs to another key', async () => {
    const verifier: TokenVerifier = { verify: async () => principal({ keyId: 'another-key-id-000' }) }
    await expect(new Authenticator(verifier, keys).authenticate(`Bearer ${KEY}`)).rejects.toMatchObject({ code: 'invalid_key' })
  })

  it('refuses a key whose token is not a personal one', async () => {
    const verifier: TokenVerifier = { verify: async () => principal({ kind: 'oauth' }) }
    await expect(new Authenticator(verifier, keys).authenticate(`Bearer ${KEY}`)).rejects.toMatchObject({ code: 'invalid_key' })
  })

  it('says missing_token without a header and invalid_token with a malformed one', async () => {
    const a = new Authenticator({ verify: async () => principal() }, keys)
    await expect(a.authenticate(undefined)).rejects.toMatchObject({ code: 'missing_token' })
    await expect(a.authenticate('Basic abc')).rejects.toMatchObject({ code: 'invalid_token' })
  })
})
