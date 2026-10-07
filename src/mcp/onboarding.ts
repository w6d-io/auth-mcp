/**
 * Guided secure site onboarding: the one path every site tool points along, so a client never has to
 * guess the next step. Server-authored text only (no data interpolated but validated names).
 *
 *   1 create        create_site (template, gates by preset)
 *   2 access        set_site_access (roles, which groups get which role, second factor),
 *                   create_group / add_user_to_groups for the people
 *   3 check         check_site_draft: lint + the platform's security findings
 *   4 save          save_site_version
 *   5 publish       publish_site, acknowledging each finding that needs confirming
 *                   (request_site_apply in production)
 *   6 verify        verify_site, then report to the person
 */

export type Step = 'create' | 'access' | 'check' | 'save' | 'publish' | 'verify'

const NEXT: Record<Step, string> = {
  create: 'Step 2/6, design access: set_site_access (roles, which groups get which role, second factor on writes), create_group for a missing group, add_user_to_groups for the people. Then check_site_draft.',
  access: 'Step 3/6: check_site_draft on the draft. Fix high findings; show the person every finding marked confirm.',
  check: 'Step 4/6: save_site_version once no high finding is left.',
  save: 'Step 5/6: can_i publish_site, then publish_site with acknowledge listing each confirm finding the person accepted (request_site_apply in production).',
  publish: 'Step 6/6: verify_site, then report to the person: what is live, who can reach it, and any finding they acknowledged.',
  verify: 'Done: report to the person what verify_site found. A failed check means fix, save and publish again.',
}

export const nextStep = (step: Step) => NEXT[step]

/** kuma's standard platform groups and the role each gets on a new site (kuma lib/sites/templates.ts). */
export const STANDARD_GROUPS: Record<string, string> = { admins: 'admin', devs: 'editor', viewers: 'viewer' }

const ROLES_OF: Record<string, string[]> = {
  standard: ['admin', 'editor', 'viewer'],
  readonly: ['viewer'],
  operator: ['admin', 'operator', 'editor', 'viewer'],
}

export interface ChecklistItem {
  step: string
  tool: string
  why: string
  suggested?: unknown
}

/**
 * What to decide about access for a new site, each item naming its tool. `existingGroups` (when the
 * key can read groups) turns the standard mapping into a concrete suggestion and lists what is missing.
 */
export function accessChecklist(site: Record<string, unknown>, existingGroups: string[] | null): ChecklistItem[] {
  const roles = typeof site.roles === 'string' ? (ROLES_OF[site.roles] ?? []) : Object.keys((site.roles as object) ?? {})
  const standard = Object.entries(STANDARD_GROUPS).filter(([, role]) => roles.includes(role))
  const present = existingGroups ? standard.filter(([g]) => existingGroups.includes(g)) : standard
  const missing = existingGroups ? standard.filter(([g]) => !existingGroups.includes(g)).map(([g]) => g) : []
  const items: ChecklistItem[] = [
    {
      step: 'roles',
      tool: 'set_site_access',
      why: `The site defines the roles ${roles.join(', ') || '(none)'}${typeof site.roles === 'string' ? ` (the ${site.roles} preset)` : ''}. Once the routes are mapped, name roles for the job instead: set_site_access roles 'from-routes' (one role per permission the routes ask), then rename each (partner, activity-reader…), reusing the names sibling sites give the same access (find_sites_for_service names). A role carries only permissions a route asks.`,
      suggested: { roles: site.roles },
    },
    {
      step: 'groups',
      tool: 'set_site_access',
      why: 'Which platform groups get which role on this site. Nobody reaches a permission-gated route until a group maps to a role.',
      suggested: { groups: Object.fromEntries(present.map(([g, role]) => [g, [role]])) },
    },
  ]
  if (missing.length) {
    items.push({ step: 'missing_groups', tool: 'create_group', why: `These standard groups do not exist yet: ${missing.join(', ')}. Create them, or map existing groups instead.` })
  }
  items.push(
    { step: 'people', tool: 'add_user_to_groups', why: 'Put the people who need the site in those groups (protected).' },
    {
      step: 'second_factor',
      tool: 'set_site_access',
      why: "Require a second factor on writes (twoFactor 'writes') unless the site is read-only.",
      suggested: { twoFactor: 'writes' },
    },
    { step: 'catch_all', tool: 'update_site_routes', why: 'Everything not listed goes to the catch-all: make it deny or a permission, not public.' }
  )
  return items
}
