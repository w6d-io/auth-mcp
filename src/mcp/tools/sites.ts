import { z } from 'zod'
import { defineTool, type ToolDef } from '../registry.js'
import { P } from '../permissions.js'
import { hasScope } from '../../auth/scopes.js'
import { seg } from '../../jinbe/client.js'
import { paginate, MAX_LIMIT } from '../../safety/pagination.js'
import { ToolError, toolError } from '../../safety/errors.js'
import { SITE_NAME } from '../../safety/untrusted.js'
import { lintSite, summarize } from '../site-lint.js'
import { nextStep } from '../onboarding.js'
import { withoutActors } from './write-common.js'
import type { BlastRadius, SiteDetail, SitePreview, SiteSummary } from '../../jinbe/types.js'

const BASE = '/api/admin/sites'
const siteName = z.string().regex(SITE_NAME, 'a site name: lowercase letters, digits and dashes, 2-40 characters')
const page = {
  limit: z.number().int().min(1).max(MAX_LIMIT).optional().describe('Page size, at most 100 (default 50)'),
  cursor: z.string().max(256).optional().describe('nextCursor from the previous page'),
}
const method = z.enum(['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'])
// A draft is validated by jinbe (zod, strict); here only its size is bounded.
const intent = z.record(z.unknown()).describe('A Site intent (the object get_site returns under data.site)')

export const listSites = defineTool({
  name: 'list_sites',
  title: 'List sites',
  description: 'Sites plugged into the gateway, with status (draft, live, attention, paused), host, saved and applied versions.',
  scopes: [P.SITES_READ],
  input: {
    status: z.enum(['draft', 'live', 'attention', 'paused']).optional(),
    query: z.string().max(64).optional().describe('Substring of the site name or host'),
    ...page,
  },
  async run(args, { jinbe, call }) {
    const all = await jinbe.get<SiteSummary[]>(call, BASE)
    const q = args.query?.toLowerCase()
    const rows = all
      .filter((s) => !args.status || s.status === args.status)
      .filter((s) => !q || s.name.includes(q) || (s.host ?? '').toLowerCase().includes(q))
      // Who applied or drafted is an email: left out (minimal PII); get_site has the dates.
      .map(({ appliedBy: _by, draft, ...s }) => ({ ...s, ...(draft ? { draftAt: draft.at } : {}) }))
    const p = paginate(rows, { limit: args.limit, cursor: args.cursor, query: `list_sites:${args.status ?? ''}:${q ?? ''}` })
    return { data: { items: p.items, total: p.total }, nextCursor: p.nextCursor, source: `jinbe:${BASE}` }
  },
})

export const getSite = defineTool({
  name: 'get_site',
  title: 'Get a site',
  description: "One site: its saved intent (address, upstream, gates, routes, roles, groups, login), version, etag, applied state, its login second factor (which routes need one), the resolved gate config (each handler's effective settings, every field marked explicit or platform default) and, for an ephemeral site, its expiry.",
  scopes: [P.SITES_READ],
  input: { name: siteName },
  async run(args, { jinbe, call }) {
    const s = await jinbe.get<SiteDetail>(call, `${BASE}/${seg(args.name)}`)
    return {
      data: {
        site: s.site,
        version: s.version,
        etag: s.etag,
        status: s.status,
        savedAt: s.savedAt,
        applied: s.applied ? { version: s.applied.version, at: s.applied.at, rules: s.applied.rules.length } : null,
        // Each rendered gate's handlers with the effective config, every field marked explicit or default (jinbe wave19).
        ...(s.resolvedGates !== undefined ? { resolvedGates: s.resolvedGates } : {}),
        // The site's login second factor (jinbe wave19): {scope, routes, clients, minAal, summary}.
        ...(s.secondFactor !== undefined ? { secondFactor: s.secondFactor } : {}),
        // Ephemeral sites (jinbe wave19): {ttlSec, expiresAt, remainingSec, expired} or null (permanent).
        ...(s.ephemeral !== undefined ? { ephemeral: s.ephemeral && typeof s.ephemeral === 'object' ? withoutActors(s.ephemeral) : null } : {}),
      },
      source: `jinbe:${BASE}/:name`,
    }
  },
})

export const siteVersions = defineTool({
  name: 'site_versions',
  title: 'Site version history',
  description: 'The append-only version history of a site, newest last.',
  scopes: [P.SITES_READ],
  input: { name: siteName, ...page },
  async run(args, { jinbe, call }) {
    const all = await jinbe.get<Array<Record<string, unknown>>>(call, `${BASE}/${seg(args.name)}/versions`)
    const rows = all.map(({ by: _by, savedBy: _savedBy, ...v }) => v)
    const p = paginate(rows, { limit: args.limit, cursor: args.cursor, query: `site_versions:${args.name}` })
    return { data: { items: p.items, total: p.total }, nextCursor: p.nextCursor, source: `jinbe:${BASE}/:name/versions` }
  },
})

export const blastRadius = defineTool({
  name: 'blast_radius',
  title: 'Blast radius of a site',
  description: 'What deleting or breaking a site would take with it: groups, org-grantable groups, organisations with grants, rules and routes.',
  scopes: [P.SITES_READ],
  input: { name: siteName },
  async run(args, { jinbe, call }) {
    const data = await jinbe.get<BlastRadius>(call, `${BASE}/${seg(args.name)}/blast-radius`)
    return { data, source: `jinbe:${BASE}/:name/blast-radius` }
  },
})

export const getPlatform = defineTool({
  name: 'get_platform',
  title: 'Platform settings for sites',
  description: 'This environment as the site editor sees it: name, production flag, four-eyes mode, zones and SSO coverage, reserved hosts.',
  scopes: [P.SITES_READ],
  input: {},
  async run(_args, { jinbe, call }) {
    return { data: await jinbe.get<unknown>(call, `${BASE}/platform`), source: `jinbe:${BASE}/platform` }
  },
})

export const checkSiteDraft = defineTool({
  name: 'check_site_draft',
  title: 'Check a site draft',
  description:
    "Step 3 of onboarding. Lint a Site intent (a site's draft by name, or an intent you pass) for insecure choices (public writes, public catch-all, no second factor on privileged writes, allow-all handlers, hand-built gates, open CORS, wildcard roles) and, when the key carries sites:write, run the platform preview (gatekit compile, overlaps with live rules, ties, zone and host checks). Writes nothing.",
  scopes: [P.SITES_READ, P.SITES_WRITE],
  input: { name: siteName.optional().describe("Check this site's draft"), site: intent.optional() },
  async run(args, { jinbe, call, principal }) {
    let site = args.site
    if (!site) {
      if (!args.name) throw toolError('invalid_request', 'Pass a site name (its draft is checked) or a site intent')
      site = (await jinbe.get<{ site: Record<string, unknown> }>(call, `${BASE}/${seg(args.name)}/draft`)).site
    }
    const findings = lintSite(site)
    const lint = { findings, summary: summarize(findings) }
    const notes: string[] = []
    let preview: unknown = null
    // Preview is behind sites:write in jinbe; never send a call the token cannot carry.
    if (hasScope(principal.scopes, P.SITES_WRITE)) {
      try {
        const p = await jinbe.post<SitePreview>(call, `${BASE}/preview`, { site })
        preview = {
          checks: p.checks,
          risk: p.risk,
          words: p.words,
          ...(p.suggestedZone ? { suggestedZone: p.suggestedZone } : {}),
          ...(p.findings ? { findings: p.findings } : {}),
          ...(p.publish ? { publish: p.publish } : {}),
          ...(p.resolvedGates !== undefined ? { resolvedGates: p.resolvedGates } : {}),
        }
        if (p.publish?.blocked) notes.push('Publishing is blocked: fix every finding of level error first (each says how in fix).')
        if (p.publish?.acknowledge?.length) {
          notes.push(`Before publishing, show the person the confirm findings (${p.publish.acknowledge.join(', ')}) and pass the ones they accept to publish_site as acknowledge.`)
        }
      } catch (err) {
        if (!(err instanceof ToolError)) throw err
        preview = { error: err.body }
        // The lint stands on its own: a failed preview is a partial result, never the whole tool failing.
        notes.push(
          `Partial result: the lint above is complete, but the platform preview failed (${err.body.code}: ${err.body.message}).${err.body.retryable ? ' Retry check_site_draft shortly for the preview.' : ''}`
        )
      }
    } else {
      notes.push('Platform preview skipped: it needs sites:write, which this key does not carry. Lint only.')
    }
    notes.push(nextStep('check'))
    return { data: { lint, preview }, source: 'auth-mcp:site-lint+jinbe:/api/admin/sites/preview', notes }
  },
})

export const matchRequest = defineTool({
  name: 'match_request',
  title: 'Which rule a request hits',
  description: 'Which gateway rule and which site route a request would hit, against the live rules or a draft intent (gatekit dry run).',
  scopes: [P.SITES_READ],
  input: {
    method,
    url: z.string().url().max(2048),
    against: z.enum(['draft', 'live']).default('live'),
    site: intent.optional(),
  },
  async run(args, { jinbe, call }) {
    return { data: await jinbe.post<unknown>(call, `${BASE}/match`, args), source: `jinbe:${BASE}/match` }
  },
})

export const renderTemplate = defineTool({
  name: 'render_template',
  title: 'Render a gateway template',
  description: 'Render a header, cookie, payload or claims template exactly as the gateway would, against a sample request (gatekit).',
  scopes: [P.SITES_READ],
  input: {
    template: z.string().min(1).max(8192),
    kind: z.enum(['header', 'cookie', 'payload', 'claims']),
    name: z.string().max(128).optional(),
    sample: z
      .object({
        subject: z.string().max(128).optional(),
        email: z.string().email().optional(),
        aal: z.enum(['aal1', 'aal2']).optional(),
        anonymous: z.boolean().optional(),
        method,
        url: z.string().url().max(2048),
        pattern: z.string().max(4096).optional(),
      })
      .strict(),
  },
  async run(args, { jinbe, call }) {
    return { data: await jinbe.post<unknown>(call, `${BASE}/render`, args), source: `jinbe:${BASE}/render` }
  },
})

export const siteTools: ToolDef[] = [listSites, getSite, siteVersions, blastRadius, getPlatform, checkSiteDraft, matchRequest, renderTemplate] as ToolDef[]
