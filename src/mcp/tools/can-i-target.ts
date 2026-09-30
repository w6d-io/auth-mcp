import type { ToolContext } from '../registry.js'
import { P } from '../permissions.js'
import { hasScope } from '../../auth/scopes.js'
import { ToolError } from '../../safety/errors.js'
import type { UserLookup } from '../../jinbe/types.js'

/**
 * can_i's per-target second-factor rule for group adds: a group whose "Members must use 2FA" switch
 * is on refuses a person who has not enrolled a second factor (jinbe user-groups.service: 422
 * mfa_required, rule enrol_before_joining). Predicted from two kinds of read: the groups' switches
 * (GET /rbac/groups, groups:read) and each target's enrolment (GET /users/lookup `mfa`, users:read).
 * At most MAX_TARGETS people are looked up; beyond that, the plan itself answers per item.
 */

const MAX_TARGETS = 20

interface Target {
  user: string
  groups: string[]
}

export type TargetVerdict = { refuse: Record<string, unknown> } | { notes: string[] }

function targetsOf(tool: string, args: Record<string, unknown> | undefined): Target[] {
  if (!args) return []
  const groups = (v: unknown) => (Array.isArray(v) ? v.map(String) : [])
  if (tool === 'add_user_to_groups' && typeof args.email === 'string') return [{ user: args.email, groups: groups(args.groups) }]
  if (tool === 'plan_bulk' && args.op === 'groups.members.add' && Array.isArray(args.items)) {
    return args.items
      .map((i) => i as Record<string, unknown>)
      .filter((i) => typeof i?.user === 'string')
      .map((i) => ({ user: i.user as string, groups: groups(i.groups) }))
  }
  return []
}

/** Which of `names` require their members to use 2FA; null when the switches cannot be read. */
async function requiringGroups(ctx: ToolContext, names: string[]): Promise<Set<string> | null> {
  const { groups } = await ctx.jinbe.get<{ groups?: Array<{ name: string; secondFactor?: { required?: boolean } | null }> }>(ctx.call, '/api/admin/rbac/groups')
  if (!Array.isArray(groups)) return null
  return new Set(groups.filter((g) => names.includes(g.name) && g.secondFactor?.required === true).map((g) => g.name))
}

/** Whether a person has enrolled a second factor: true/false, or null when not known. */
async function enrolled(ctx: ToolContext, user: string): Promise<boolean | null> {
  const r = await ctx.jinbe.get<UserLookup>(ctx.call, '/api/admin/users/lookup', { q: user, limit: 5 })
  const hit = (r.data ?? []).find((u) => u.id === user || u.email?.toLowerCase() === user.toLowerCase())
  return typeof hit?.mfa === 'boolean' ? hit.mfa : null
}

export async function targetSecondFactorRule(ctx: ToolContext, tool: string, args: Record<string, unknown> | undefined): Promise<TargetVerdict> {
  const targets = targetsOf(tool, args)
  if (!targets.length) return { notes: tool === 'add_user_to_groups' ? ['Pass the arguments (email, groups) to check the groups\' 2FA requirement for that person.'] : [] }
  if (!hasScope(ctx.principal.scopes, P.GROUPS_READ) || !hasScope(ctx.principal.scopes, P.USERS_READ)) {
    return { notes: ["Without groups:read and users:read this cannot tell whether a group requires its members to use 2FA and whether the person has set it up."] }
  }
  try {
    const requiring = await requiringGroups(ctx, [...new Set(targets.flatMap((t) => t.groups))])
    if (!requiring) return { notes: ['Could not read which groups require their members to use 2FA.'] }
    if (!requiring.size) return { notes: ['None of these groups requires its members to use 2FA.'] }
    const checked = targets.filter((t) => t.groups.some((g) => requiring.has(g))).slice(0, MAX_TARGETS)
    const blockers: Array<{ user: string; groups: string[] }> = []
    const unknown: string[] = []
    for (const t of checked) {
      const e = await enrolled(ctx, t.user)
      if (e === false) blockers.push({ user: t.user, groups: t.groups.filter((g) => requiring.has(g)) })
      else if (e === null) unknown.push(t.user)
    }
    const notes = [
      ...(unknown.length ? [`Not known whether ${unknown.join(', ')} set up 2FA: the platform checks when adding.`] : []),
      ...(targets.length > MAX_TARGETS ? [`Only the first ${MAX_TARGETS} people were checked; the plan reports the others.`] : []),
    ]
    if (blockers.length) {
      return {
        refuse: {
          wouldRefuseBecause: 'mfa_required',
          secondFactor: { rule: 'enrol_before_joining', requiredAal: 'aal2' },
          blocked: blockers,
          hint: `${blockers.map((b) => `${b.user}: ${b.groups.join(', ')} ${b.groups.length > 1 ? 'require' : 'requires'} its members to use 2FA`).join('; ')}. They must set up two-step sign-in (Settings → Authenticator app) before being added.`,
          ...(notes.length ? { notes } : {}),
        },
      }
    }
    return { notes: [`${[...requiring].join(', ')} ${requiring.size > 1 ? 'require' : 'requires'} its members to use 2FA; the people checked have set it up.`, ...notes] }
  } catch (err) {
    if (!(err instanceof ToolError)) throw err
    return { notes: ["Could not check the groups' 2FA requirement: the platform checks when adding."] }
  }
}
