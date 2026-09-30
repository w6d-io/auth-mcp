import type { Principal } from './types.js'

/**
 * Whether this connection may do PROTECTED actions, the twin of jinbe middleware/delegated-step-up.ts
 * (keyStepUpVerdict): a personal key stands on the second factor its holder proved when creating it,
 * for 30 days, unless it was created with protected actions off; an OAuth sign-in on the second factor
 * proven at consent, for 12 hours (owner decision D1), if "allow protected actions" was ticked — jinbe
 * computes that window (`step_up_until`), auth-mcp keeps no constant of its own for it. Computed from
 * what token-info reports; jinbe still decides each call.
 */

/** jinbe KEY_STEP_UP_PERMISSIONS. */
export const PROTECTED_PERMISSIONS = ['sites:apply', 'users:update_email', 'groups.members:write', 'groups:write'] as const
export const KEY_STEP_UP_MAX_AGE_MS = 30 * 24 * 3600 * 1000

export type ProtectedReason = 'key_created_without' | 'consent_without' | 'proof_expired' | 'disabled_by_admin' | 'not_a_personal_key' | 'unknown'

export interface ProtectedActions {
  allowed: boolean
  reason?: ProtectedReason
  /** When the key's second-factor proof stops standing in (allowed, or expired at). */
  validUntil?: string
  /** What to do to get them (e.g. sign in again), when not allowed. */
  guidance?: string
  covers: string[]
}

/** How an OAuth connection gets protected actions back: sign in again (browser, second factor, consent). */
export const REAUTH_GUIDANCE =
  'Sign in again: in Claude Code, /mcp → example → Re-authenticate (browser, second factor, then tick "Allow protected actions" on the consent screen).'

type Facts = Pick<Principal, 'kind' | 'stepUpAt' | 'stepUpActions' | 'stepUpUntil'>

function forKey(p: Facts, now: number, covers: string[]): ProtectedActions {
  if (p.stepUpActions === false) {
    return { allowed: false, reason: 'key_created_without', guidance: 'Create a new key with protected actions allowed.', covers }
  }
  // Neither field reported: a jinbe older than token-info's key_step_up_* claims. Not guessed.
  if (p.stepUpActions === undefined && p.stepUpAt === undefined) return { allowed: false, reason: 'unknown', covers }
  const at = p.stepUpAt ? Date.parse(p.stepUpAt) : NaN
  // Protected actions on, but no factor proven at creation: nothing to stand in (jinbe no_key_step_up).
  if (!Number.isFinite(at)) return { allowed: false, reason: 'key_created_without', guidance: 'Create a new key with protected actions allowed.', covers }
  const validUntil = new Date(at + KEY_STEP_UP_MAX_AGE_MS).toISOString()
  if (now - at > KEY_STEP_UP_MAX_AGE_MS) {
    return { allowed: false, reason: 'proof_expired', validUntil, guidance: 'The key is older than 30 days for protected actions: create a new key with protected actions allowed.', covers }
  }
  return { allowed: true, validUntil, covers }
}

function forOAuth(p: Facts, now: number, covers: string[]): ProtectedActions {
  if (p.stepUpActions === false) return { allowed: false, reason: 'consent_without', guidance: REAUTH_GUIDANCE, covers }
  // Not reported at all: a jinbe older than the OAuth consent facts. Not guessed.
  if (p.stepUpActions === undefined) return { allowed: false, reason: 'unknown', covers }
  const until = p.stepUpUntil ? Date.parse(p.stepUpUntil) : NaN
  // Ticked at consent, but jinbe sends no step_up_until: an administrator turned protected actions off
  // for browser sign-ins, or no second-factor time was recorded at consent.
  if (!Number.isFinite(until)) {
    return {
      allowed: false,
      reason: 'disabled_by_admin',
      guidance: `Not available on this sign-in: an administrator turned protected actions off for browser sign-ins, or no second factor was recorded. ${REAUTH_GUIDANCE} If it stays off, do them in the console.`,
      covers,
    }
  }
  const validUntil = new Date(until).toISOString()
  if (until <= now) return { allowed: false, reason: 'proof_expired', validUntil, guidance: REAUTH_GUIDANCE, covers }
  return { allowed: true, validUntil, covers }
}

export function protectedActionsOf(p: Facts, now = Date.now()): ProtectedActions {
  const covers = [...PROTECTED_PERMISSIONS]
  if (p.kind === 'personal') return forKey(p, now, covers)
  if (p.kind === 'oauth') return forOAuth(p, now, covers)
  return { allowed: false, reason: 'not_a_personal_key', covers }
}
