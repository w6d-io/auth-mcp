import type { AuthenticatedPrincipal } from '../auth/types.js'
import type { CallContext, JinbeClient } from '../jinbe/client.js'
import { protectedActionsOf } from '../auth/protected-actions.js'
import { ToolError, type ToolErrorBody } from '../safety/errors.js'

/**
 * A link that lets the person refresh the second factor behind THIS connection, in the browser
 * (jinbe POST /api/me/mcp/step-up-requests): they open it, prove their second factor, and the
 * connection's protected actions stand again. The link is for the connection's own holder, short-lived,
 * and jinbe — not auth-mcp — decides who may confirm it.
 */

export interface StepUpLink {
  url: string
  expiresAt: string | null
}

export const STEP_UP_PATH = '/api/me/mcp/step-up-requests'
export const STEP_UP_NOTE = 'Open this link and confirm with your second factor, then tell me to try again.'
/** jinbe drops its cache at once; auth-mcp's own token cache may hold the old proof for up to 30 s. */
export const STEP_UP_LAG = 'If it is still refused right after, wait up to 30 seconds and try again.'

/** Only an https link is shown: it comes from jinbe, but a person clicks it. */
function linkOf(body: unknown): StepUpLink | null {
  const b = (body ?? {}) as { url?: unknown; expiresAt?: unknown }
  if (typeof b.url !== 'string' || b.url.length > 2048) return null
  let u: URL
  try {
    u = new URL(b.url)
  } catch {
    return null
  }
  if (u.protocol !== 'https:' || u.username || u.password) return null
  return { url: u.toString(), expiresAt: typeof b.expiresAt === 'string' ? b.expiresAt : null }
}

/**
 * Create a link (no body: jinbe binds it to this user and this client); throws the tool error jinbe
 * answered with — 409 protected_actions_not_allowed for a connection made without protected actions,
 * 429 past 5 links per 10 minutes.
 */
export async function createStepUpLink(jinbe: JinbeClient, call: CallContext): Promise<StepUpLink> {
  const res = await jinbe.write<unknown>(call, 'POST', STEP_UP_PATH)
  const link = linkOf(res.body)
  if (!link) throw new ToolError({ code: 'upstream_unavailable', message: 'The platform did not return a usable link', retryable: true })
  return link
}

/** jinbe's key reasons a fresh second factor fixes (the action itself may stand on one). */
const REFRESHABLE_KEY_REASONS = new Set(['key_step_up_expired', 'no_key_step_up'])

/**
 * Whether a refusal is one a refreshed second factor fixes: protected actions were allowed (at key
 * creation or consent) but the proof is too old or missing. Never for a connection created without
 * them, nor for an action no connection may do.
 */
export function refreshable(body: ToolErrorBody, principal: AuthenticatedPrincipal): boolean {
  if (body.code !== 'protected_actions_off') return false
  if (principal.stepUpActions !== true) return false
  const keyReason = (body.details as { secondFactor?: { keyReason?: unknown } } | undefined)?.secondFactor?.keyReason
  if (typeof keyReason === 'string') return REFRESHABLE_KEY_REASONS.has(keyReason)
  const reason = protectedActionsOf(principal).reason
  return reason === 'proof_expired' || reason === 'key_created_without'
}

/**
 * The refusal with a link in it, when a refreshed second factor fixes it: details.stepUpLink and a hint
 * the client can show at once. Best effort — a link that cannot be made leaves the refusal as it was.
 */
export async function withStepUpLink(body: ToolErrorBody, principal: AuthenticatedPrincipal, jinbe: JinbeClient, call: CallContext): Promise<ToolErrorBody> {
  if (!refreshable(body, principal)) return body
  try {
    const link = await createStepUpLink(jinbe, { ...call, tool: 'refresh_second_factor' })
    const details = { ...((body.details as object | undefined) ?? {}), stepUpLink: link }
    return { ...body, details, hint: `${STEP_UP_NOTE} ${link.url}${link.expiresAt ? ` (valid until ${link.expiresAt})` : ''}` }
  } catch (err) {
    if (err instanceof ToolError) return body
    throw err
  }
}
