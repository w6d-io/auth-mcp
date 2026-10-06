/**
 * New-site templates, the same ones kuma's wizard offers (kuma src/lib/sites/templates.ts): a name, an
 * address and an upstream become a complete intent — gates, routes, a catch-all, standard roles. Every
 * template has a catch-all, so a site never goes live answering 404 everywhere. Keep in step with kuma.
 */
import { buildGate, ORG_GATE, ORG_GATE_ID } from './gate-presets.js'

export type TemplateId = 'web-api' | 'app' | 'api' | 'spa-api' | 'public' | 'empty'
export const TEMPLATE_IDS = ['web-api', 'app', 'api', 'spa-api', 'public', 'empty'] as const

type Obj = Record<string, unknown>

// kuma's template gates, from the same presets (gate-presets.ts).
const PUBLIC_GATE = buildGate({ id: 'public', label: 'Public', who: 'anyone', pass: 'everyone', gets: 'nothing', fails: 'platform', methods: ['GET', 'HEAD'] })
const BROWSER_GATE = buildGate({ id: 'browser', label: 'Browser', who: 'signed-in', pass: 'policy', gets: 'identity', fails: 'website' })
const API_GATE = buildGate({ id: 'api', label: 'API', who: 'tokens', pass: 'policy', gets: 'identity', fails: 'api', preflight: true })
const SPA_API_GATE = buildGate({ id: 'api', label: 'API', who: 'signed-in-or-tokens', pass: 'policy', gets: 'identity', fails: 'api', preflight: true })

const publicRoute = (id: string, path: string): Obj => ({ id, methods: ['GET', 'HEAD'], path, gate: 'public', access: { kind: 'public' }, source: 'template' })
const ASSETS = [publicRoute('assets', '/assets/:any*'), publicRoute('favicon', '/favicon.ico'), publicRoute('health', '/health'), publicRoute('robots', '/robots.txt')]
const apiRoute = (prefix: string): Obj => ({
  id: 'api', methods: ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE'], path: `${prefix}/api/:any*`, gate: 'api', access: { kind: 'signed-in' }, source: 'template',
})

export interface SiteBasics {
  name: string
  displayName: string
  host: string
  pathPrefix?: string
  service: string
  namespace: string
  port: number
  scheme?: 'http' | 'https'
  /** A literal base path the upstream serves under (upstream.path). */
  upstreamPath?: string
}

const under = (prefix: string | undefined, r: Obj): Obj => (prefix ? { ...r, path: r.path === '/' ? prefix : `${prefix}${String(r.path)}` } : r)
const signedIn = { gate: 'browser', access: { kind: 'signed-in' } }

export function buildSite(template: TemplateId, b: SiteBasics): Obj {
  const prefix = b.pathPrefix || undefined
  const base: Obj = {
    name: b.name,
    displayName: b.displayName || b.name,
    address: { host: b.host, ...(prefix ? { pathPrefix: prefix } : {}) },
    upstream: { service: b.service, namespace: b.namespace, port: b.port, ...(b.scheme ? { scheme: b.scheme } : {}), ...(b.upstreamPath ? { path: b.upstreamPath } : {}) },
    exposure: { mode: 'zone' },
    roles: 'standard',
    groups: { platform: {}, orgGrantable: {} },
    orgs: [],
    login: { twoFactor: { scope: 'none', clients: 'exempt' }, reach: 'granted' },
    state: 'active',
  }
  const items = (rs: Obj[]) => rs.map((r) => under(prefix, r))
  switch (template) {
    case 'public':
      return { ...base, upstream: { ...(base.upstream as Obj), preserveHost: true }, gates: [PUBLIC_GATE], routes: { items: [], catchAll: { gate: 'public', access: { kind: 'public' } } } }
    case 'app':
      return { ...base, gates: [PUBLIC_GATE, BROWSER_GATE], routes: { items: items(ASSETS), catchAll: signedIn } }
    case 'api':
      return {
        ...base,
        gates: [{ ...PUBLIC_GATE, errors: 'api' }, API_GATE],
        routes: { items: items([publicRoute('health', '/health')]), catchAll: { gate: 'api', access: { kind: 'permission', permission: `${b.name}:read` } } },
      }
    case 'web-api':
      return { ...base, gates: [PUBLIC_GATE, BROWSER_GATE, API_GATE], routes: { items: [...items(ASSETS), apiRoute(prefix ?? '')], catchAll: signedIn } }
    case 'spa-api':
      return {
        ...base,
        gates: [PUBLIC_GATE, BROWSER_GATE, SPA_API_GATE],
        routes: { items: [...items(ASSETS), apiRoute(prefix ?? '')], catchAll: signedIn },
      }
    case 'empty':
      return { ...base, gates: [BROWSER_GATE], routes: { items: [], catchAll: signedIn } }
  }
}

/** The org role owners hold by default (jinbe sites/schemas.ts DEFAULT_OWNER_ROLE). */
export const DEFAULT_OWNER_ROLE = 'admin'

/** The org-scoped template route's path under a site's prefix: everything under /orgs/:orgId/. */
export const orgTemplatePath = (prefix?: string): string => `${prefix ?? ''}/orgs/:orgId/:any*`

/**
 * What turning organizations on adds, as jinbe's organizationTemplate (sites/organizations.ts; kuma
 * uses the same): the switch (owners hold `admin`), the organization gate, one org-scoped route
 * `/orgs/:orgId/:any*` asking `<site>:use`, and the org roles `<site>-admin` (site role admin) and
 * `<site>-member` (site role user, of the standard set).
 */
export function organizationTemplate(name: string, pathPrefix?: string) {
  return {
    organizations: { enabled: true, ownerRole: DEFAULT_OWNER_ROLE },
    gate: structuredClone(ORG_GATE),
    route: {
      id: 'org',
      methods: ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE'],
      path: orgTemplatePath(pathPrefix),
      gate: ORG_GATE_ID,
      access: { kind: 'permission', permission: `${name}:use` },
      orgParam: 'orgId',
      source: 'template',
    } as Obj,
    orgGrantable: {
      [`${name}-admin`]: { label: 'Admins', roles: ['admin'] },
      [`${name}-member`]: { label: 'Members', roles: ['user'] },
    } as Record<string, Obj>,
  }
}

const obj = (v: unknown): Obj => (v && typeof v === 'object' && !Array.isArray(v) ? (v as Obj) : {})

/** The site roles each preset defines (jinbe render.ts expandRoles), or a custom map's own. */
function siteRoleNames(roles: unknown): string[] {
  if (roles === 'standard') return ['admin', 'editor', 'viewer', 'user']
  if (roles === 'readonly') return ['viewer']
  if (roles === 'operator') return ['admin', 'editor', 'viewer']
  return Object.keys(obj(roles))
}

/**
 * A site with organizations turned on by the template. Adds, never replaces what the person already
 * has: an owner role already chosen stays, an org role already defined stays, a route already named
 * `org` (or on the same path) stays. The organization gate is put in as the template's, by id.
 * `added` says what was put in, `kept` what was already there, `problems` what jinbe would refuse.
 */
export function withOrganizations(site: Obj): { site: Obj; added: string[]; kept: string[]; problems: string[] } {
  const name = String(site.name ?? '')
  const t = organizationTemplate(name, typeof obj(site.address).pathPrefix === 'string' ? String(obj(site.address).pathPrefix) : undefined)
  const added: string[] = []
  const kept: string[] = []
  const problems: string[] = []

  const current = obj(site.organizations)
  const organizations = { ...current, enabled: true, ownerRole: typeof current.ownerRole === 'string' ? current.ownerRole : t.organizations.ownerRole }
  if (current.enabled === true) kept.push('organizations.enabled')
  else added.push('organizations.enabled')

  const gates = (Array.isArray(site.gates) ? site.gates : []).map(obj)
  const g = gates.findIndex((x) => x.id === ORG_GATE_ID)
  if (g >= 0 && JSON.stringify(gates[g]) === JSON.stringify(t.gate)) kept.push(`gate ${ORG_GATE_ID}`)
  else {
    if (g >= 0) gates[g] = t.gate
    else gates.push(t.gate)
    added.push(`gate ${ORG_GATE_ID}`)
  }

  const routes = obj(site.routes)
  const items = (Array.isArray(routes.items) ? routes.items : []).map(obj)
  const same = items.find((r) => r.id === t.route.id || r.path === t.route.path)
  if (same) kept.push(`route ${String(same.id)} (${String(same.path)})`)
  else {
    items.push(t.route)
    added.push(`route org (${String(t.route.path)})`)
  }

  const groups = obj(site.groups)
  const orgGrantable = { ...obj(groups.orgGrantable) }
  for (const [group, def] of Object.entries(t.orgGrantable)) {
    if (orgGrantable[group]) kept.push(`org role ${group}`)
    else {
      orgGrantable[group] = def
      added.push(`org role ${group}`)
    }
  }

  const known = new Set(siteRoleNames(site.roles))
  const missing = [...new Set(Object.values(orgGrantable).flatMap((d) => (Array.isArray(obj(d).roles) ? (obj(d).roles as unknown[]).map(String) : [])))].filter((r) => !known.has(r))
  if (missing.length) problems.push(`the org roles map to site role(s) ${missing.join(', ')} this site does not define: set roles to standard (set_site_access) or add them`)
  if (!orgGrantable[`${name}-${organizations.ownerRole}`]) {
    problems.push(`owners hold org role '${organizations.ownerRole}', which this site does not have: add ${name}-${organizations.ownerRole} as an org role`)
  }

  return {
    site: { ...site, organizations, gates, routes: { ...routes, items }, groups: { platform: obj(groups.platform), ...groups, orgGrantable } },
    added,
    kept,
    problems,
  }
}
