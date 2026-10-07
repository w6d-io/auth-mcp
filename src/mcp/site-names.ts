import type { LintFinding, LintLevel } from './site-lint.js'

/**
 * Names on a site — permissions, roles, groups — kept the same for the same thing. Two assistants once
 * named one backend three ways (earning-service: `earnings` kept the template roles admin/editor/
 * viewer/user over routes asking earnings.external:read, `stairfleet` called the same access role
 * `partner`, a platform group `earnings-tech` said nothing of what it gave). The convention:
 *
 *   permission       resource[.sub]:verb   one colon: the backend's noun, the area, read/write/…
 *   role             named for the job (partner, activity-reader, editor), carrying only permissions
 *                    a route of the site asks
 *   platform group   <site>-<role>s        (jinbe counts `<site>-…` groups as the site's own)
 *   org group        <site>-<role>         (owners hold `<site>-<ownerRole>`)
 *
 * Here: the names already in use on the sites serving a Service (reuse them), the lint of a site's own
 * names, and the check against its siblings (a route on the same backend path asking another name).
 */

type Obj = Record<string, unknown>
const obj = (v: unknown): Obj => (v && typeof v === 'object' && !Array.isArray(v) ? (v as Obj) : {})
const arr = (v: unknown): unknown[] => (Array.isArray(v) ? v : [])
const str = (v: unknown): string | undefined => (typeof v === 'string' ? v : undefined)
const strings = (v: unknown): string[] => arr(v).filter((x): x is string => typeof x === 'string')

/** The verbs of the template roles (jinbe rbac-defaults.ts, render.ts userRole). */
const TEMPLATE_VERBS = ['list', 'read', 'create', 'update', 'delete', 'execute', 'use']
const TEMPLATE_ROLES = new Set(['admin', 'operator', 'editor', 'viewer', 'user'])
/** The template's org role for members holds site role `user` (site-templates.ts organizationTemplate). */
const ROLE_ALIASES: Record<string, string[]> = { user: ['member'] }
const NAMES_SHOWN = 200

/** Permissions the site's routes and catch-all ask (jinbe declaredPermissions). */
export function declaredPermissions(site: Obj): string[] {
  const routes = obj(site.routes)
  const asked = [...arr(routes.items).map((r) => obj(r).access), obj(routes.catchAll).access].map(obj)
  return [...new Set(asked.filter((a) => a.kind === 'permission').map((a) => str(a.permission)).filter((p): p is string => !!p))].sort()
}

/** The site's roles as permissions: a preset expanded as jinbe does (render.ts expandRoles), a map as is. */
export function siteRoles(site: Obj): Record<string, string[]> {
  const name = str(site.name) ?? 'site'
  const roles = site.roles
  if (typeof roles !== 'string') return Object.fromEntries(Object.entries(obj(roles)).map(([r, p]) => [r, strings(p)]))
  const v = (...verbs: string[]) => verbs.map((x) => `${name}:${x}`)
  const operator = v('list', 'read', 'create', 'update', 'delete', 'execute')
  const admin = [...new Set([...operator, ...declaredPermissions(site)])].sort()
  if (roles === 'standard') return { admin, editor: v('list', 'read', 'create', 'update'), viewer: v('list', 'read'), user: v('list', 'read', 'use') }
  if (roles === 'readonly') return { viewer: v('list', 'read') }
  if (roles === 'operator') return { admin, operator, editor: v('list', 'read', 'create', 'update'), viewer: v('list', 'read') }
  return {}
}

/** A permission a role carries, its wildcards (`res:*`, `*`) included. */
function covers(held: readonly string[], permission: string): boolean {
  return held.some((h) => h === permission || h === '*' || (h.endsWith(':*') && permission.startsWith(h.slice(0, -1))))
}

/** A role as the template made it: only `<site>:<verb>` permissions (admin also the routes' own). */
function templateShaped(site: Obj, role: string, perms: readonly string[]): boolean {
  if (!TEMPLATE_ROLES.has(role)) return false
  const name = str(site.name) ?? ''
  const declared = role === 'admin' ? new Set(declaredPermissions(site)) : new Set<string>()
  const verbs = perms.filter((p) => !declared.has(p))
  return verbs.length > 0 && verbs.every((p) => TEMPLATE_VERBS.some((x) => p === `${name}:${x}`))
}

/** The path the backend receives for a site path: strip_path removed, upstream.path prepended. */
export function backendPath(site: Obj, path: string): string {
  const u = obj(site.upstream)
  const strip = str(u.stripPath)
  const rest = strip && path.startsWith(strip) ? path.slice(strip.length) || '/' : path
  return `${str(u.path) ?? ''}${rest}`.replace(/\/\/+/g, '/')
}

/** A route's backend path with its parameters made comparable (`:id` and `:personId` are the same). */
const shape = (path: string) => path.split('/').map((s) => (s === ':any*' ? '*' : s.startsWith(':') ? ':' : s)).join('/')

interface SiteRouteName { site: string; method: string; path: string; backend: string; permission: string }

function routeNames(name: string, site: Obj): SiteRouteName[] {
  const out: SiteRouteName[] = []
  for (const r of arr(obj(site.routes).items).map(obj)) {
    const a = obj(r.access)
    const path = str(r.path)
    if (a.kind !== 'permission' || !path || !str(a.permission)) continue
    for (const method of strings(r.methods)) out.push({ site: name, method, path, backend: backendPath(site, path), permission: String(a.permission) })
  }
  return out
}

export interface ServiceNames {
  /** Every permission a route of these sites asks, with the routes asking it. */
  permissions: Array<{ permission: string; routes: Array<{ site: string; method: string; path: string; backend: string }> }>
  /** Every role, with what it carries (a preset expanded). */
  roles: Array<{ site: string; role: string; permissions: string[] }>
  /** Every group binding a role of these sites: platform groups and org groups. */
  groups: Array<{ site: string; kind: 'platform' | 'organization'; group: string; roles: string[] }>
  truncated?: boolean
}

/** The names already in use on the sites serving one Service: what a new route, role or group reuses. */
export function namesOf(sites: ReadonlyArray<{ name: string; site: Obj }>): ServiceNames {
  const byPermission = new Map<string, ServiceNames['permissions'][number]['routes']>()
  const roles: ServiceNames['roles'] = []
  const groups: ServiceNames['groups'] = []
  for (const { name, site } of sites) {
    for (const r of routeNames(name, site)) {
      byPermission.set(r.permission, [...(byPermission.get(r.permission) ?? []), { site: r.site, method: r.method, path: r.path, backend: r.backend }])
    }
    for (const [role, permissions] of Object.entries(siteRoles(site))) roles.push({ site: name, role, permissions })
    const g = obj(site.groups)
    for (const [group, rs] of Object.entries(obj(g.platform))) groups.push({ site: name, kind: 'platform', group, roles: strings(rs) })
    for (const [group, def] of Object.entries(obj(g.orgGrantable))) groups.push({ site: name, kind: 'organization', group, roles: strings(obj(def).roles) })
  }
  const permissions = [...byPermission.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([permission, routes]) => ({ permission, routes }))
  const truncated = permissions.length > NAMES_SHOWN || roles.length > NAMES_SHOWN || groups.length > NAMES_SHOWN
  return { permissions: permissions.slice(0, NAMES_SHOWN), roles: roles.slice(0, NAMES_SHOWN), groups: groups.slice(0, NAMES_SHOWN), ...(truncated ? { truncated } : {}) }
}

/** The name a group following the convention would have, for one role. */
const conventional = (site: string, role: string, kind: 'platform' | 'organization') => (kind === 'platform' ? `${site}-${role}s` : `${site}-${role}`)

function followsPattern(site: string, group: string, roles: readonly string[], kind: 'platform' | 'organization'): boolean {
  if (!group.startsWith(`${site}-`)) return true // a shared platform group: named elsewhere
  const suffix = group.slice(site.length + 1)
  return roles.some((r) => [r, ...(ROLE_ALIASES[r] ?? [])].some((n) => suffix === n || suffix === `${n}s` || (kind === 'platform' && suffix === `${n}es`)))
}

/** The access names of one site: roles that no route needs, routes no role reaches, template leftovers, group names. */
export function lintNames(site: Obj): LintFinding[] {
  const out: LintFinding[] = []
  const add = (code: string, level: LintLevel, message: string, path?: string) => out.push({ code, level, message, ...(path ? { path } : {}) })
  const name = str(site.name) ?? 'site'
  const asked = declaredPermissions(site)
  const roles = siteRoles(site)
  if (!asked.length || !Object.keys(roles).length) return out

  const template = Object.entries(roles).filter(([r, p]) => templateShaped(site, r, p))
  const templateVerbs = new Set(template.flatMap(([, p]) => p).filter((p) => TEMPLATE_VERBS.some((x) => p === `${name}:${x}`)))
  if (template.length && !asked.some((p) => templateVerbs.has(p))) {
    add('template_roles_unused', 'low', `The template roles ${template.map(([r]) => r).join(', ')} carry ${[...templateVerbs].sort().join(', ')}, which no route asks (the routes ask ${asked.join(', ')}). Replace them with roles named for the job carrying those permissions: set_site_access roles 'from-routes', then rename each (partner, activity-reader…), reusing the names sibling sites use`, 'roles')
  }
  for (const [role, perms] of Object.entries(roles)) {
    const shaped = templateShaped(site, role, perms)
    const unused = perms.filter((p) => !p.includes('*') && !asked.includes(p) && !(shaped && templateVerbs.has(p)))
    if (unused.length) add('role_permission_unused', 'low', `Role '${role}' carries ${unused.join(', ')}, which no route of this site asks: it grants nothing here — remove it, or add the route that needs it`, `roles.${role}`)
  }
  const held = Object.values(roles).flat()
  const orgKeys = obj(site.organizations).enabled === true
  for (const p of asked.filter((x) => !covers(held, x))) {
    add('route_permission_unheld', orgKeys ? 'low' : 'medium', orgKeys
      ? `No role carries ${p}: only organization API keys given it (and direct grants) reach its routes. Give it to a role if people should too`
      : `No role carries ${p}: nobody reaches its routes except through a direct grant. Give it to a role (set_site_access)`, 'roles')
  }

  const groups = obj(site.groups)
  for (const [kind, map] of [['platform', obj(groups.platform)], ['organization', obj(groups.orgGrantable)]] as const) {
    for (const [group, def] of Object.entries(map)) {
      const rs = kind === 'platform' ? strings(def) : strings(obj(def).roles)
      if (rs.length && !followsPattern(name, group, rs, kind)) {
        add('group_name_pattern', 'low', `Group '${group}' gives ${rs.join(', ')} but its name does not say so: name it ${rs.map((r) => `'${conventional(name, r, kind)}'`).join(' or ')} (${kind === 'platform' ? '<site>-<role>s' : '<site>-<role>'})`, `groups.${kind === 'platform' ? 'platform' : 'orgGrantable'}.${group}`)
      }
    }
  }
  return out
}

/**
 * A route asking another permission than a sibling site's route on the same backend method and path:
 * one backend operation, two names. Suggests the sibling's name.
 */
export function siblingNameFindings(site: Obj, siblings: ReadonlyArray<{ name: string; site: Obj }>): LintFinding[] {
  const known = new Map<string, SiteRouteName>()
  for (const s of siblings) for (const r of routeNames(s.name, s.site)) known.set(`${r.method} ${shape(r.backend)}`, r)
  const out: LintFinding[] = []
  const seen = new Set<string>()
  for (const r of routeNames(str(site.name) ?? 'site', site)) {
    const other = known.get(`${r.method} ${shape(r.backend)}`)
    const key = `${r.permission}|${other?.permission}`
    if (!other || other.permission === r.permission || seen.has(key)) continue
    seen.add(key)
    out.push({
      code: 'name_differs_from_sibling',
      level: 'medium',
      message: `${r.method} ${r.path} reaches the backend at ${r.backend}, which '${other.site}' already protects with ${other.permission}; this site asks ${r.permission}. Use ${other.permission} so one backend operation keeps one name`,
      path: 'routes.items',
    })
  }
  return out
}

/** One role per permission the routes ask, named from the permission (to be renamed for the job). */
export function rolesFromRoutes(site: Obj): Record<string, string[]> {
  const agent: Record<string, string> = { read: 'reader', write: 'writer', use: 'user', create: 'creator', update: 'updater', delete: 'deleter', execute: 'executor', list: 'lister' }
  const out: Record<string, string[]> = {}
  for (const p of declaredPermissions(site)) {
    if (p.includes('*')) continue
    const [resource, verb] = p.split(':')
    const area = (resource.split('.').pop() ?? resource).replace(/[^a-z0-9_-]/g, '-')
    const role = `${area}-${agent[verb] ?? `${verb}er`}`.replace(/^[^a-z]+/, '').slice(0, 40) || 'role'
    out[role] = [...new Set([...(out[role] ?? []), p])].sort()
  }
  return out
}
