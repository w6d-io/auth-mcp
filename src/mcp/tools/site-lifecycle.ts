import { z } from 'zod'
import { defineTool, type ToolDef } from '../registry.js'
import { P } from '../permissions.js'
import { seg } from '../../jinbe/client.js'
import { SITES, idempotencyKey, obj, siteName, withoutActors } from './write-common.js'

/**
 * Ephemeral sites and deletion requests (jinbe wave19/site-lifecycle). An ephemeral site is PAUSED
 * when its time to live passes, never deleted; deleting any site is a request that a person holding
 * sites:delete — not the requester — approves in the console. Approving or rejecting is never
 * available through MCP (sites:delete is delegable 'never'), so there is no tool for it.
 */

const UNIT_SEC = { m: 60, h: 3600, d: 86400 } as const
export const TTL_MIN_SEC = 3600
export const TTL_MAX_SEC = 7 * 86400

/** jinbe's ttlSchema, checked before any call: seconds, or 30m / 12h / 3d; 1 hour to 7 days. */
export const ttl = z
  .union([z.number().int(), z.string().regex(/^\d{1,5}[mhd]$/, 'seconds, or a duration like 30m, 12h, 3d')])
  .refine((v) => {
    const sec = typeof v === 'number' ? v : Number(v.slice(0, -1)) * UNIT_SEC[v.slice(-1) as keyof typeof UNIT_SEC]
    return sec >= TTL_MIN_SEC && sec <= TTL_MAX_SEC
  }, 'between 1 hour and 7 days')
  .describe('Time to live: seconds, or 30m / 12h / 3d; 1 hour to 7 days (24 h when left out)')

/** `ephemeral` on a save: {ttl?} makes the site expire (paused) counted from this save; null makes it permanent. */
export const ephemeral = z.object({ ttl: ttl.optional() }).strict()

const pausedNote = (state: unknown) =>
  state === 'paused' ? ['The site is paused (it had expired): resume_site serves it again (protected: sites:apply).'] : []

export const extendSiteTtl = defineTool({
  name: 'extend_site_ttl',
  title: "Extend an ephemeral site's expiry",
  description:
    "Move an ephemeral site's expiry to now + ttl (its own TTL when left out; 1 hour to 7 days). An expired site stays paused after renewal: resume_site serves it again. Refused (conflict, not_ephemeral) for a permanent site.",
  scopes: [P.SITES_WRITE],
  write: true,
  requiresJinbe: 'wave19/site-lifecycle',
  input: { name: siteName, ttl: ttl.optional(), idempotencyKey },
  async run(args, ctx) {
    const res = await ctx.jinbe.write<Record<string, unknown>>(ctx.call, 'POST', `${SITES}/${seg(args.name)}/ttl`, {
      body: args.ttl === undefined ? {} : { ttl: args.ttl },
      idempotencyKey: args.idempotencyKey,
    })
    const b = obj(res.body)
    return {
      data: { name: b.name ?? args.name, state: b.state ?? null, ephemeral: b.ephemeral ? withoutActors(obj(b.ephemeral)) : null },
      source: `jinbe:${SITES}/:name/ttl`,
      notes: pausedNote(b.state),
    }
  },
})

export const requestSiteDeletion = defineTool({
  name: 'request_site_deletion',
  title: 'Request a site deletion',
  description:
    'Ask for a site to be deleted. Nothing is deleted now: a person holding sites:delete, other than you, approves or rejects it in the console. One open request per site. MCP can never approve a deletion.',
  scopes: [P.SITES_WRITE],
  write: true,
  requiresJinbe: 'wave19/site-lifecycle',
  input: { name: siteName, reason: z.string().min(3).max(280).optional().describe('Why: shown to the approver'), idempotencyKey },
  async run(args, ctx) {
    const res = await ctx.jinbe.write<Record<string, unknown>>(ctx.call, 'POST', `${SITES}/${seg(args.name)}/deletion-requests`, {
      body: args.reason ? { reason: args.reason } : {},
      idempotencyKey: args.idempotencyKey,
    })
    const r = obj(res.body)
    return {
      data: { id: r.id, site: r.site ?? args.name, state: r.state, requestedAt: r.requestedAt, ...(r.reason ? { reason: r.reason } : {}) },
      source: `jinbe:${SITES}/:name/deletion-requests`,
      notes: ['Pending: a person holding sites:delete, other than you, decides in the console (Sites → Deletion requests). This connection cannot approve it.'],
    }
  },
})

export const listDeletionRequests = defineTool({
  name: 'list_deletion_requests',
  title: 'Site deletion requests',
  description: 'Site deletion requests, newest first, by state (pending, approved, rejected, cancelled) and site. Who asked is left out.',
  scopes: [P.SITES_READ],
  requiresJinbe: 'wave19/site-lifecycle',
  input: { state: z.enum(['pending', 'approved', 'rejected', 'cancelled']).optional(), site: siteName.optional() },
  async run(args, ctx) {
    const rows = await ctx.jinbe.get<unknown[]>(ctx.call, `${SITES}/deletion-requests`, { state: args.state, site: args.site })
    const items = (Array.isArray(rows) ? rows : []).map((r) => {
      const row = withoutActors(obj(r)) as Record<string, unknown>
      // Ids of who asked and who decided: people, not needed to follow a request.
      delete row.requesterId
      delete row.decidedById
      return row
    })
    return { data: { items }, source: `jinbe:${SITES}/deletion-requests` }
  },
})

export const siteLifecycleTools: ToolDef[] = [extendSiteTtl, requestSiteDeletion, listDeletionRequests] as ToolDef[]
