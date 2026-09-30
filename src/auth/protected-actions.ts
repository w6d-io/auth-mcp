import type { Principal } from './types.js'

/**
 * Whether this connection may do PROTECTED actions, the twin of jinbe middleware/delegated-step-up.ts
 * (keyStepUpVerdict): a personal key stands on the second factor its holder proved when creating it,
 * for 30 days, unless it was created with protected actions off. Computed from what token-info reports;
 * jinbe still decides each call.
 */

/** jinbe KEY_STEP_UP_PERMISSIONS. */
export const PROTECTED_PERMISSIONS = ['sites:apply', 'users:update_email', 'groups.members:write', 'groups:write'] as const
export const KEY_STEP_UP_MAX_AGE_MS = 30 * 24 * 3600 * 1000

export type ProtectedReason = 'key_created_without' | 'proof_expired' | 'not_a_personal_key' | 'unknown'

export interface ProtectedActions {
  allowed: boolean
  reason?: ProtectedReason
  /** When the key's second-factor proof stops standing in (allowed, or expired at). */
  validUntil?: string
  covers: string[]
}

export function protectedActionsOf(p: Pick<Principal, 'kind' | 'keyStepUpAt' | 'keyStepUpActions'>, now = Date.now()): ProtectedActions {
  const covers = [...PROTECTED_PERMISSIONS]
  if (p.kind !== 'personal') return { allowed: false, reason: 'not_a_personal_key', covers }
  if (p.keyStepUpActions === false) return { allowed: false, reason: 'key_created_without', covers }
  // Neither field reported: a jinbe older than token-info's key_step_up_* claims. Not guessed.
  if (p.keyStepUpActions === undefined && p.keyStepUpAt === undefined) return { allowed: false, reason: 'unknown', covers }
  const at = p.keyStepUpAt ? Date.parse(p.keyStepUpAt) : NaN
  // Protected actions on, but no factor proven at creation: nothing to stand in (jinbe no_key_step_up).
  if (!Number.isFinite(at)) return { allowed: false, reason: 'key_created_without', covers }
  const validUntil = new Date(at + KEY_STEP_UP_MAX_AGE_MS).toISOString()
  if (now - at > KEY_STEP_UP_MAX_AGE_MS) return { allowed: false, reason: 'proof_expired', validUntil, covers }
  return { allowed: true, validUntil, covers }
}
