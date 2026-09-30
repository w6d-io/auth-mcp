import { z } from 'zod'
import type { ToolContext } from '../registry.js'
import { toolError } from '../../safety/errors.js'
import { IDEMPOTENCY_KEY } from '../../jinbe/client.js'
import { IDENTITY_ID, SITE_NAME } from '../../safety/untrusted.js'

/**
 * What every write tool shares. Owner rules (2026-09-29), enforced by jinbe's delegation gate and
 * repeated here where a local refusal is cheap:
 *   - a key does what its holder can do, directly (no change requests);
 *   - never a delete (revoking a key is the one exception), never zones, the gateway, sign-in or MCP
 *     settings, second-factor resets, key creation, approvals, the policy bundle or audit exports;
 *   - protected actions (publish, change an email, add to groups, edit groups and roles) only with a
 *     key created with protected actions allowed;
 *   - in production, a key requests a publish rather than applying it.
 * Every write sends an Idempotency-Key: the caller's, or a fresh one per call.
 */

export const SITES = '/api/admin/sites'
export const USERS = '/api/admin/users'

export const siteName = z.string().regex(SITE_NAME, 'a site name: lowercase letters, digits and dashes, 2-40 characters')
export const userId = z.string().regex(IDENTITY_ID, 'an identity id (see find_users)').describe('The identity id (find_users)')
export const idempotencyKey = z
  .string()
  .regex(IDEMPOTENCY_KEY)
  .optional()
  .describe('Optional. Retrying with the same key applies the change once; omitted, each call gets a new key')
export const note = z.string().max(280).optional().describe('A short note kept with the version or request')
export const intent = z.record(z.unknown()).describe('A Site intent (the object get_site returns under data.site)')

/** No self-change (a key cannot touch its own holder's account or groups): refused here as well as in jinbe. */
export function refuseSelfTarget(user: string, ctx: ToolContext): void {
  const self = [ctx.principal.subject, ctx.principal.email].filter((x): x is string => !!x).map((x) => x.toLowerCase())
  if (self.includes(user.trim().toLowerCase())) {
    throw toolError('self_target_refused', "A key cannot change its own holder's account or groups; ask another administrator")
  }
}

/** A value jinbe returned that should be an object, or an empty one. */
export const obj = (v: unknown): Record<string, unknown> => (v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : {})

/** Drop fields naming who did something (emails): minimal PII in results. */
export function withoutActors<T extends Record<string, unknown>>(v: T): Partial<T> {
  const out: Record<string, unknown> = {}
  for (const [k, val] of Object.entries(v)) {
    if (/^(by|updatedBy|savedBy|requestedBy|approvedBy|rejectedBy|appliedBy|importedBy)$/.test(k)) continue
    out[k] = val
  }
  return out as Partial<T>
}

/** Whether a jinbe call failed with not_found (a new site, no draft). */
export const isNotFound = (err: unknown) => (err as { body?: { code?: string } } | null)?.body?.code === 'not_found'
