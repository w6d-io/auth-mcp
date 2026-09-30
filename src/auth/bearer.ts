import { createHash } from 'node:crypto'

/**
 * What an `Authorization` header can carry here:
 *   - an OAuth access token from Hydra (opaque, `ory_at_…`), obtained by the MCP client through
 *     authorization code + PKCE;
 *   - a personal MCP key `stk_mcp_<client_id>.<secret>`, for clients that only take a static header.
 *     It is never forwarded: auth-mcp exchanges it for a 10-minute Hydra token (personal-key.ts).
 *
 * Parsing is strict and total: anything else is "no credential", which answers 401.
 */

export type Credential =
  | { kind: 'token'; token: string }
  | { kind: 'personal_key'; keyId: string; secret: string; raw: string }

export const PERSONAL_KEY_PREFIX = 'stk_mcp_'

// RFC 6750 b64token, bounded. Hydra opaque tokens are ~90 chars; 4 KB leaves room for JWTs, which
// are then refused by the verifier (wrong audience / not active) rather than here.
const TOKEN68 = /^[A-Za-z0-9\-._~+/]{16,4096}=*$/
// Hydra client ids are UUIDs by default; accept a conservative id alphabet.
const KEY_ID = /^[A-Za-z0-9][A-Za-z0-9-]{7,63}$/
const KEY_SECRET = /^[A-Za-z0-9_\-~.]{24,256}$/

export function parseAuthorization(header: string | string[] | undefined): Credential | null {
  if (typeof header !== 'string') return null
  const match = /^Bearer[ ]+(\S+)[ ]*$/i.exec(header)
  if (!match) return null
  const value = match[1]
  if (value.startsWith(PERSONAL_KEY_PREFIX)) return parsePersonalKey(value)
  return TOKEN68.test(value) ? { kind: 'token', token: value } : null
}

export function parsePersonalKey(value: string): Credential | null {
  if (!value.startsWith(PERSONAL_KEY_PREFIX)) return null
  const body = value.slice(PERSONAL_KEY_PREFIX.length)
  const dot = body.indexOf('.')
  if (dot <= 0) return null
  const keyId = body.slice(0, dot)
  const secret = body.slice(dot + 1)
  if (!KEY_ID.test(keyId) || !KEY_SECRET.test(secret)) return null
  return { kind: 'personal_key', keyId, secret, raw: value }
}

export const sha256 = (value: string) => createHash('sha256').update(value).digest('hex')
