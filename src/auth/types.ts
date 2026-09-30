/**
 * Who a call is made for. Built only from a verified token (introspection or jinbe token-info), never
 * from a header the client sets. The raw token rides along so the jinbe client can present it; it is
 * a non-enumerable property so a log line or JSON.stringify of a principal never carries it.
 */
export interface Principal {
  /** Kratos identity id of the human the token acts for. */
  subject: string
  email: string | null
  /**
   * `ext.org` when the token carries one — informational only (logs, get_my_identity). Tokens are not bound to
   * an organisation: an org tool names its org, and jinbe decides whether this person may act there.
   */
  org: string | null
  /** Granted scopes: `mcp` baseline, `offline_access`, and jinbe catalogue permissions (`sites:read`, …). */
  scopes: string[]
  /** The OAuth client (MCP client registration or personal-key client). */
  clientId: string
  kind: 'oauth' | 'personal'
  /** Personal keys only: the key's id (the Hydra client id), for audit and revocation. */
  keyId: string | null
  /**
   * When the second factor behind this connection was proven (ISO), and whether protected actions were
   * allowed: at key creation for a personal key (`ext.key_step_up_at` / `key_step_up_actions`), at
   * consent for an OAuth sign-in (`ext.second_factor_at` / `step_up_actions`). Undefined when jinbe
   * does not report them (older jinbe): never guessed.
   */
  stepUpAt?: string | null
  stepUpActions?: boolean
  /** OAuth: until when protected actions stand, as jinbe computes it (12 h after the consent 2FA). */
  stepUpUntil?: string | null
  /** OAuth: the sign-in's absolute end (30 days at most), after which the client must sign in again. */
  grantExpiresAt?: string | null
  /** OAuth: the registered client's name (somebody else's text: sanitised on output). */
  clientName?: string | null
  /** OAuth: consent gave all the person's permissions, or a chosen subset. */
  scopeMode?: 'all' | 'chosen'
  /** Access-token expiry (epoch seconds). */
  expiresAt: number
  /** sha256 of the access token, for cache keys and correlation; never the token itself. */
  tokenHash: string
}

export interface AuthenticatedPrincipal extends Principal {
  readonly accessToken: string
}

export function withAccessToken(principal: Principal, accessToken: string): AuthenticatedPrincipal {
  const out = { ...principal } as AuthenticatedPrincipal
  Object.defineProperty(out, 'accessToken', { value: accessToken, enumerable: false, writable: false })
  return out
}

/** Why a request carries no usable principal; the HTTP layer turns it into a 401. */
export class AuthError extends Error {
  constructor(
    readonly code: 'missing_token' | 'invalid_token' | 'invalid_key' | 'wrong_audience' | 'verifier_unavailable' | 'mcp_disabled',
    message: string
  ) {
    super(message)
    this.name = 'AuthError'
  }
}

export const MCP_OFF_MESSAGE = 'MCP access is turned off by an administrator'
const MCP_ORG_OFF_MESSAGE = 'MCP access is turned off for this organization by an administrator'
const MCP_GROUP_OFF_MESSAGE = 'MCP access is not enabled for your groups by an administrator'
const MCP_OAUTH_OFF_MESSAGE = 'Browser sign-in is turned off by an administrator: connect with a personal key instead'

const OFF_MESSAGES: Record<string, string> = {
  org_not_allowed: MCP_ORG_OFF_MESSAGE,
  group_not_allowed: MCP_GROUP_OFF_MESSAGE,
  // Settings → AI assistants: browser sign-in off while MCP stays on (personal keys keep working).
  oauth_disabled: MCP_OAUTH_OFF_MESSAGE,
}

/**
 * jinbe's 403 `{error: 'mcp_disabled', reason}` (token-info, key exchange): an administrator turned MCP
 * off (Settings → AI assistants), or limited it to groups this person is not in (`group_not_allowed`;
 * `org_not_allowed` from older jinbe versions). Not a bad credential — the
 * HTTP layer answers 403, not 401, so a client does not start an OAuth dance that cannot help.
 */
export async function mcpDisabledFrom(res: Response): Promise<AuthError | null> {
  if (res.status !== 403) return null
  let body: { error?: unknown; reason?: unknown }
  try {
    body = (await res.clone().json()) as { error?: unknown; reason?: unknown }
  } catch {
    return null
  }
  if (body?.error !== 'mcp_disabled') return null
  const reason = typeof body.reason === 'string' ? body.reason : ''
  return new AuthError('mcp_disabled', OFF_MESSAGES[reason] ?? MCP_OFF_MESSAGE)
}
