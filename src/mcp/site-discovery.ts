import type { ToolContext } from './registry.js'
import { seg } from '../jinbe/client.js'
import { ToolError } from '../safety/errors.js'
import type { SiteDetail, SiteSummary } from '../jinbe/types.js'

/**
 * What already serves a backend, before anything new is made for it. Two assistants once made two
 * sites for one Service (earning-service: `earnings` and `earning-service`), each set up differently,
 * neither aware of the other: create_site, check_site_draft and find_sites_for_service ask here first.
 *
 * jinbe's site list carries the host but not the upstream, so each site is read (a draft-only site
 * from its draft), at most DISCOVERY_MAX_SITES of them; past that the answer says it is truncated.
 */

const SITES = '/api/admin/sites'
export const DISCOVERY_MAX_SITES = 100
const CONCURRENCY = 8
const ROUTES_SHOWN = 20

type Obj = Record<string, unknown>
const obj = (v: unknown): Obj => (v && typeof v === 'object' && !Array.isArray(v) ? (v as Obj) : {})
const arr = (v: unknown): unknown[] => (Array.isArray(v) ? v : [])
const str = (v: unknown): string | undefined => (typeof v === 'string' ? v : undefined)

export interface ServiceRef {
  service: string
  namespace: string
}

/** One site as discovery reports it: enough to decide whether to extend it. */
export interface DiscoveredSite {
  name: string
  displayName: string
  host: string | null
  status: string
  appliedVersion: number | null
  upstream: { service?: string; namespace?: string; port?: number; stripPath?: string; path?: string }
  routes: { total: number; items: Array<{ id?: string; methods: string[]; path?: string; gate?: string; access: string }> }
  catchAll: string | null
  gates: Array<{ id?: string; label?: string }>
  organizations: { enabled: boolean; served: number }
  roles: string[]
  groups: { platform: string[]; orgGrantable: string[] }
}

export interface Discovery {
  /** Sites whose upstream is the Service. */
  byService: DiscoveredSite[]
  /** Their intents, for the names in use (site-names.ts): not shown as such. */
  intents: Array<{ name: string; site: Obj }>
  /** Sites answering on the host (from the list: no read needed). */
  byHost: Array<Pick<SiteSummary, 'name' | 'host' | 'status'>>
  /** How many sites were read for their upstream. */
  checked: number
  truncated: boolean
  /** Sites that could not be read (named, so the person can look). */
  unreadable: string[]
}

const accessOf = (a: unknown): string => {
  const o = obj(a)
  return o.kind === 'permission' ? `permission ${String(o.permission)}` : (str(o.kind) ?? '?')
}

export function sameService(site: Obj, ref: ServiceRef): boolean {
  const u = obj(site.upstream)
  return str(u.service)?.toLowerCase() === ref.service.toLowerCase() && str(u.namespace)?.toLowerCase() === ref.namespace.toLowerCase()
}

export function describeSite(site: Obj, summary: SiteSummary): DiscoveredSite {
  const u = obj(site.upstream)
  const routes = obj(site.routes)
  const items = arr(routes.items).map(obj)
  const groups = obj(site.groups)
  const orgs = obj(site.organizations)
  const roles = site.roles
  return {
    name: summary.name,
    displayName: summary.displayName,
    host: summary.host,
    status: summary.status,
    appliedVersion: summary.appliedVersion,
    upstream: {
      service: str(u.service), namespace: str(u.namespace), ...(typeof u.port === 'number' ? { port: u.port } : {}),
      ...(str(u.stripPath) ? { stripPath: str(u.stripPath) } : {}), ...(str(u.path) ? { path: str(u.path) } : {}),
    },
    routes: {
      total: items.length,
      items: items.slice(0, ROUTES_SHOWN).map((r) => ({ id: str(r.id), methods: arr(r.methods).filter((m): m is string => typeof m === 'string'), path: str(r.path), gate: str(r.gate), access: accessOf(r.access) })),
    },
    catchAll: Object.keys(obj(routes.catchAll)).length ? accessOf(obj(routes.catchAll).access) : null,
    gates: arr(site.gates).map(obj).map((g) => ({ id: str(g.id), label: str(g.label) })),
    organizations: { enabled: orgs.enabled === true, served: arr(site.orgs).length },
    roles: typeof roles === 'string' ? [`preset ${roles}`] : Object.keys(obj(roles)),
    groups: { platform: Object.keys(obj(groups.platform)), orgGrantable: Object.keys(obj(groups.orgGrantable)) },
  }
}

/** The intent of one site: its saved version, else its draft (a site not saved yet). */
async function intentOf(ctx: ToolContext, name: string): Promise<Obj | null> {
  try {
    return obj((await ctx.jinbe.get<SiteDetail>(ctx.call, `${SITES}/${seg(name)}`)).site)
  } catch (err) {
    if (!(err instanceof ToolError) || err.body.code !== 'not_found') throw err
  }
  try {
    return obj((await ctx.jinbe.get<{ site: Obj }>(ctx.call, `${SITES}/${seg(name)}/draft`)).site)
  } catch (err) {
    if (err instanceof ToolError && err.body.code === 'not_found') return null
    throw err
  }
}

/**
 * Sites serving `ref` and sites on `host`, leaving out `exclude` (the site being checked). Throws a
 * ToolError when the site list itself cannot be read; a site that cannot be read is only named.
 */
export async function discover(ctx: ToolContext, opts: { ref?: ServiceRef; host?: string; exclude?: string }): Promise<Discovery> {
  const all = (await ctx.jinbe.get<SiteSummary[]>(ctx.call, SITES)).filter((s) => s.name !== opts.exclude)
  const host = opts.host?.toLowerCase()
  const byHost = host ? all.filter((s) => (s.host ?? '').toLowerCase() === host).map(({ name, host: h, status }) => ({ name, host: h, status })) : []
  const out: Discovery = { byService: [], intents: [], byHost, checked: 0, truncated: false, unreadable: [] }
  if (!opts.ref) return out
  const ref = opts.ref
  const toRead = all.slice(0, DISCOVERY_MAX_SITES)
  out.truncated = all.length > toRead.length
  for (let i = 0; i < toRead.length; i += CONCURRENCY) {
    const batch = toRead.slice(i, i + CONCURRENCY)
    const read = await Promise.all(batch.map(async (s) => {
      try {
        return { s, site: await intentOf(ctx, s.name) }
      } catch {
        return { s, site: undefined }
      }
    }))
    for (const { s, site } of read) {
      if (site === undefined) { out.unreadable.push(s.name); continue }
      out.checked += 1
      if (site && sameService(site, ref)) {
        out.byService.push(describeSite(site, s))
        out.intents.push({ name: s.name, site })
      }
    }
  }
  return out
}

/** The sentence an assistant shows the person: what exists, and to extend it rather than add one. */
export function reuseAdvice(d: Pick<Discovery, 'byService' | 'byHost'>, ref?: ServiceRef): string {
  const parts: string[] = []
  if (d.byService.length) parts.push(`${ref ? `${ref.service}.${ref.namespace}` : 'This Service'} is already served by ${d.byService.map((s) => `'${s.name}' (${s.host ?? 'no host'})`).join(', ')}`)
  if (d.byHost.length) parts.push(`the host is already used by ${d.byHost.map((s) => `'${s.name}'`).join(', ')}`)
  return `${parts.join('; ')}. Extend one of these (update_site_routes, set_site_access, set_site_organizations) — or pass newSiteReason explaining why a separate site is needed (e.g. a different backend base path: upstream.path is site-wide).`
}
