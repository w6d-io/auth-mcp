import type { ToolContext } from './registry.js'
import { hasScope } from '../auth/scopes.js'
import { ToolError } from '../safety/errors.js'
import { P } from './permissions.js'

/**
 * Which platform groups grant a jinbe permission, read from the published model the way jinbe's
 * permission-refusal.ts does: a group binds roles under `global` or `jinbe`, each role lists
 * permissions, `*` grants everything (listed last: rarely the group to ask for). Group names only.
 *
 * Two reads, only when the key can make them (groups:read for the groups, sites:read for the roles);
 * null when it cannot tell. Legacy aliases are not expanded: the answer may miss a group that holds
 * the permission only through `admin:write`.
 */

interface Group {
  name: string
  services?: Record<string, string[]>
}
interface Roles {
  roles?: Array<{ name: string; permissions?: string[] }>
}

export async function groupsGranting(ctx: ToolContext, permissions: readonly string[]): Promise<string[] | null> {
  if (!permissions.length) return []
  if (!hasScope(ctx.principal.scopes, P.GROUPS_READ) || !hasScope(ctx.principal.scopes, P.SITES_READ)) return null
  try {
    const [groups, jinbe, global] = await Promise.all([
      ctx.jinbe.get<{ groups?: Group[] }>(ctx.call, '/api/admin/rbac/groups'),
      ctx.jinbe.get<Roles>(ctx.call, '/api/admin/rbac/services/jinbe/roles').catch(() => ({ roles: [] }) as Roles),
      ctx.jinbe.get<Roles>(ctx.call, '/api/admin/rbac/services/global/roles').catch(() => ({ roles: [] }) as Roles),
    ])
    const rolePerms = (r: Roles) => new Map((r.roles ?? []).map((x) => [x.name, x.permissions ?? []]))
    const byScope: Record<string, Map<string, string[]>> = { jinbe: rolePerms(jinbe), global: rolePerms(global) }
    const held = (g: Group) =>
      Object.entries(byScope).flatMap(([scope, roles]) => (g.services?.[scope] ?? []).flatMap((role) => roles.get(role) ?? []))
    const hits = (groups.groups ?? [])
      .map((g) => ({ name: g.name, perms: held(g) }))
      .filter((g) => permissions.every((p) => g.perms.includes(p) || g.perms.includes('*')))
    const wildcard = (g: { perms: string[] }) => Number(g.perms.includes('*'))
    return hits.sort((a, b) => wildcard(a) - wildcard(b) || a.name.localeCompare(b.name)).map((g) => g.name)
  } catch (err) {
    if (err instanceof ToolError) return null
    throw err
  }
}
