import { z } from 'zod'
import { defineTool, type ToolContext, type ToolDef } from '../registry.js'
import { P } from '../permissions.js'
import { seg } from '../../jinbe/client.js'
import { toolError } from '../../safety/errors.js'
import { lintSite, summarize } from '../site-lint.js'
import { buildSite, TEMPLATE_IDS } from '../site-templates.js'
import { buildExpertGate, buildGate, expertGate, presetGate } from '../gate-presets.js'
import { accessChecklist, nextStep } from '../onboarding.js'
import { hasScope } from '../../auth/scopes.js'
import type { GroupDefinition } from '../../jinbe/types.js'
import type { SiteDetail } from '../../jinbe/types.js'
import { SITES, idempotencyKey, intent, isNotFound, note, obj, siteName, withoutActors } from './write-common.js'

/**
 * Site drafts, imports and saved versions: DIRECT through a key (sites:write), and none of them
 * changes what the gateway serves. Publishing is site-publish.ts.
 */

interface SiteDraft {
  site: Record<string, unknown>
  baseVersion: number
  updatedAt?: string
  updatedBy?: string
}

const WRITE_SCOPES = [P.SITES_WRITE]
export const lintOf = (site: Record<string, unknown>) => {
  const findings = lintSite(site)
  return { findings, summary: summarize(findings) }
}

/** The saved site, or null when there is none yet. */
export async function savedSite(ctx: ToolContext, name: string): Promise<SiteDetail | null> {
  try {
    return await ctx.jinbe.get<SiteDetail>(ctx.call, `${SITES}/${seg(name)}`)
  } catch (err) {
    if (isNotFound(err)) return null
    throw err
  }
}

export async function draftOf(ctx: ToolContext, name: string): Promise<SiteDraft | null> {
  try {
    return await ctx.jinbe.get<SiteDraft>(ctx.call, `${SITES}/${seg(name)}/draft`)
  } catch (err) {
    if (isNotFound(err)) return null
    throw err
  }
}

/** What an edit starts from: the draft if there is one, else the saved intent. */
export async function workingSite(ctx: ToolContext, name: string) {
  const [draft, saved] = await Promise.all([draftOf(ctx, name), savedSite(ctx, name)])
  if (draft) return { site: obj(draft.site), from: 'draft' as const, baseVersion: draft.baseVersion, saved }
  if (saved) return { site: obj(saved.site), from: 'saved' as const, baseVersion: saved.version, saved }
  throw toolError('not_found', `No site or draft named ${name}: start one with create_site`)
}

export async function putDraft(ctx: ToolContext, name: string, site: Record<string, unknown>, baseVersion: number | undefined, key?: string) {
  if (site.name !== undefined && site.name !== name) throw toolError('invalid_request', `The draft names '${String(site.name)}', not '${name}'`)
  const res = await ctx.jinbe.write<SiteDraft>(ctx.call, 'PUT', `${SITES}/${seg(name)}/draft`, {
    body: { site, ...(baseVersion !== undefined ? { baseVersion } : {}) },
    idempotencyKey: key,
  })
  const d = obj(res.body)
  return { baseVersion: d.baseVersion ?? baseVersion ?? null, updatedAt: d.updatedAt ?? null }
}

export const saveSiteDraft = defineTool({
  name: 'save_site_draft',
  title: 'Save a site draft',
  description:
    'Save the server-side draft of a site (it may be incomplete), with a security lint of it. Changes nothing live: save_site_version, then publish_site, do that.',
  scopes: WRITE_SCOPES,
  write: true,
  input: { name: siteName, site: intent, baseVersion: z.number().int().min(0).optional(), idempotencyKey },
  async run(args, ctx) {
    const draft = await putDraft(ctx, args.name, args.site, args.baseVersion, args.idempotencyKey)
    return { data: { name: args.name, draft, lint: lintOf(args.site) }, source: `jinbe:${SITES}/:name/draft`, notes: [nextStep('access')] }
  },
})

export const createSite = defineTool({
  name: 'create_site',
  title: 'Create a site (draft)',
  description:
    "Step 1 of onboarding: start a new site as a draft from a template (web-api, app, api, spa-api, public, empty): address, upstream Service, gates, a catch-all and standard roles. Gates may be replaced by preset (who, pass, gets, fails); raw handlers only through expert_gate. Returns the access checklist for step 2. Refused when the site or a draft already exists. Nothing is live until it is saved and published.",
  scopes: WRITE_SCOPES,
  write: true,
  input: {
    name: siteName,
    displayName: z.string().min(1).max(80),
    template: z.enum(TEMPLATE_IDS).default('app'),
    host: z.string().max(253).regex(/^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/, 'a lowercase DNS host name'),
    pathPrefix: z.string().max(256).regex(/^(\/[A-Za-z0-9._~@-]+)+$/, 'a literal prefix like /payroll').optional(),
    upstream: z
      .object({
        service: z.string().regex(/^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$/, 'a Service name'),
        namespace: z.string().regex(/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/, 'a namespace'),
        port: z.number().int().min(1).max(65535),
        scheme: z.enum(['http', 'https']).optional(),
      })
      .strict()
      .describe('The in-cluster Service the site sends traffic to'),
    gates: z.array(presetGate).max(20).optional().describe("Replace or add the template's gates, by id, as presets"),
    expert_gate: expertGate.optional().describe('One hand-built gate, only when no preset fits (flagged by check_site_draft)'),
    idempotencyKey,
  },
  async run(args, ctx) {
    const [draft, saved] = await Promise.all([draftOf(ctx, args.name), savedSite(ctx, args.name)])
    if (saved || draft) {
      throw toolError('conflict', `A site or draft named ${args.name} already exists: edit it (update_site_routes, save_site_draft) instead`)
    }
    const site = buildSite(args.template, {
      name: args.name, displayName: args.displayName, host: args.host, pathPrefix: args.pathPrefix, ...args.upstream,
    })
    const gates = (site.gates as Array<Record<string, unknown>>).slice()
    for (const g of [...(args.gates ?? []).map((x) => buildGate(x)), ...(args.expert_gate ? [buildExpertGate(args.expert_gate)] : [])]) {
      const i = gates.findIndex((x) => x.id === g.id)
      if (i >= 0) gates[i] = g
      else gates.push(g)
    }
    site.gates = gates
    const out = await putDraft(ctx, args.name, site, 0, args.idempotencyKey)
    let existing: string[] | null = null
    if (hasScope(ctx.principal.scopes, P.GROUPS_READ)) {
      try {
        existing = (await ctx.jinbe.get<{ groups?: GroupDefinition[] }>(ctx.call, '/api/admin/rbac/groups')).groups?.map((g) => g.name) ?? null
      } catch {
        existing = null
      }
    }
    return {
      data: { name: args.name, template: args.template, draft: out, site, lint: lintOf(site), accessChecklist: accessChecklist(site, existing) },
      source: `jinbe:${SITES}/:name/draft`,
      notes: ['Draft only: nothing is live.', nextStep('create')],
    }
  },
})

// jinbe sites/schemas.ts routeSchema, repeated so a bad route is refused before any call.
const routeId = z.string().regex(/^[a-z][a-z0-9-]{0,31}$/, 'lowercase letters, digits and dashes')
const method = z.enum(['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'])
const routePath = z
  .string()
  .max(512)
  .regex(/^\/([A-Za-z0-9._~@-]+|:[A-Za-z_][A-Za-z0-9_]*|:any\*)?(\/([A-Za-z0-9._~@-]+|:[A-Za-z_][A-Za-z0-9_]*|:any\*))*$/, 'a path like /api/:id or /assets/:any*')
const access = z.discriminatedUnion('kind', [
  z.object({ kind: z.literal('public') }).strict(),
  z.object({ kind: z.literal('signed-in') }).strict(),
  z.object({ kind: z.literal('permission'), permission: z.string().regex(/^[a-z][a-z0-9_.-]*:[a-z*][a-z0-9_*-]*$/) }).strict(),
  z.object({ kind: z.literal('deny') }).strict(),
])
const orgParam = z.string().regex(/^[A-Za-z_][A-Za-z0-9_]*$/)
export const route = z
  .object({ id: routeId, methods: z.array(method).min(1), path: routePath, gate: routeId, access, orgParam: orgParam.optional(), pinned: z.boolean().optional() })
  .strict()
const routeChange = z
  .object({ id: routeId, methods: z.array(method).min(1).optional(), path: routePath.optional(), gate: routeId.optional(), access: access.optional(), orgParam: orgParam.nullable().optional(), pinned: z.boolean().optional() })
  .strict()

export const updateSiteRoutes = defineTool({
  name: 'update_site_routes',
  title: 'Add, change or remove site routes (draft)',
  description:
    "Edit the routes of a site's draft in one call (up to 500 changes): add routes, change fields of existing ones by id, take routes out of the draft, or set the catch-all. Starts from the draft, else the saved site. Writes the draft only, with a security lint; nothing is live until saved and published.",
  scopes: WRITE_SCOPES,
  write: true,
  input: {
    name: siteName,
    add: z.array(route).max(500).default([]),
    change: z.array(routeChange).max(500).default([]),
    remove: z.array(routeId).max(500).default([]).describe('Route ids to take out of the draft'),
    catchAll: z.object({ gate: routeId, access }).strict().optional(),
    idempotencyKey,
  },
  async run(args, ctx) {
    if (!args.add.length && !args.change.length && !args.remove.length && !args.catchAll) throw toolError('invalid_request', 'Nothing to change')
    const base = await workingSite(ctx, args.name)
    const routes = obj(base.site.routes)
    let items = (Array.isArray(routes.items) ? routes.items : []).map(obj)
    const ids = () => new Set(items.map((r) => String(r.id)))
    const problems: string[] = []

    for (const id of args.remove) if (!ids().has(id)) problems.push(`remove: no route ${id}`)
    items = items.filter((r) => !args.remove.includes(String(r.id)))
    for (const c of args.change) {
      const i = items.findIndex((r) => r.id === c.id)
      if (i < 0) {
        problems.push(`change: no route ${c.id}`)
        continue
      }
      const next: Record<string, unknown> = { ...items[i], ...c }
      if (c.orgParam === null) delete next.orgParam
      items[i] = next
    }
    for (const r of args.add) {
      if (ids().has(r.id)) problems.push(`add: route ${r.id} already exists (use change)`)
      else items.push({ ...r, source: 'manual' })
    }
    const gates = new Set((Array.isArray(base.site.gates) ? base.site.gates : []).map((g) => String(obj(g).id)))
    for (const r of [...args.add, ...args.change, ...(args.catchAll ? [args.catchAll] : [])]) {
      if (r.gate && gates.size && !gates.has(r.gate)) problems.push(`gate ${r.gate} is not a gate of this site (${[...gates].join(', ')})`)
    }
    if (problems.length) throw toolError('invalid_request', `Nothing written: ${problems.slice(0, 20).join('; ')}`, { details: { problems } })

    const site = { ...base.site, routes: { ...routes, items, ...(args.catchAll ? { catchAll: args.catchAll } : {}) } }
    const draft = await putDraft(ctx, args.name, site, base.baseVersion, args.idempotencyKey)
    return {
      data: {
        name: args.name,
        from: base.from,
        counts: { added: args.add.length, changed: args.change.length, removed: args.remove.length, total: items.length },
        draft,
        lint: lintOf(site),
      },
      source: `jinbe:${SITES}/:name/draft`,
      notes: ['Draft only. Review with diff_site.', nextStep('access')],
    }
  },
})

export const diffSite = defineTool({
  name: 'diff_site',
  title: 'Diff a site',
  description:
    "What would change against the applied version, per artefact (rules, roles, groups), with risk flags. Diffs the draft by default, the saved version with source 'saved', or a site you pass.",
  scopes: WRITE_SCOPES,
  input: { name: siteName, source: z.enum(['draft', 'saved']).default('draft'), site: intent.optional() },
  async run(args, ctx) {
    let site = args.site
    if (!site && args.source === 'draft') {
      const draft = await draftOf(ctx, args.name)
      if (!draft) throw toolError('not_found', `No draft for ${args.name}: diff the saved version with source 'saved'`)
      site = obj(draft.site)
    }
    const data = await ctx.jinbe.post<unknown>(ctx.call, `${SITES}/${seg(args.name)}/diff`, site ? { site } : {})
    return { data, source: `jinbe:${SITES}/:name/diff` }
  },
})

export const saveSiteVersion = defineTool({
  name: 'save_site_version',
  title: 'Save a site version',
  description:
    "Save the draft (or a site you pass) as a new version. Refused when someone saved since the draft started (conflict: diff and retry). Does not publish it: publish_site does.",
  scopes: WRITE_SCOPES,
  write: true,
  input: {
    name: siteName,
    site: intent.optional().describe('Omit to save the draft'),
    etag: z.string().regex(/^[A-Za-z0-9._-]{1,128}$/).optional().describe('The etag you edited (get_site); needed with site for an existing one'),
    note,
    idempotencyKey,
  },
  async run(args, ctx) {
    const saved = await savedSite(ctx, args.name)
    let site = args.site
    let etag = args.etag
    if (!site) {
      const draft = await draftOf(ctx, args.name)
      if (!draft) throw toolError('not_found', `No draft for ${args.name} to save`)
      if (saved && !etag && draft.baseVersion !== saved.version) {
        throw toolError('conflict', `Version ${saved.version} was saved after this draft started (from version ${draft.baseVersion}): diff_site, then save with the etag from get_site`)
      }
      site = obj(draft.site)
    } else if (saved && !etag) {
      throw toolError('invalid_request', 'This site exists: pass the etag you edited (get_site) with the site')
    }
    if (saved) etag ??= saved.etag
    const res = await ctx.jinbe.write<Record<string, unknown>>(ctx.call, 'PUT', `${SITES}/${seg(args.name)}`, {
      body: { site, ...(args.note ? { note: args.note } : {}) },
      idempotencyKey: args.idempotencyKey,
      headers: etag ? { 'if-match': `"${etag}"` } : {},
    })
    return {
      data: withoutActors(obj(res.body)),
      source: `jinbe:${SITES}/:name`,
      notes: ['Saved, not live.', nextStep('save')],
    }
  },
})

export const siteWriteTools: ToolDef[] = [createSite, saveSiteDraft, updateSiteRoutes, diffSite, saveSiteVersion] as ToolDef[]
