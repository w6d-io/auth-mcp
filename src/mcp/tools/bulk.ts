import { z } from 'zod'
import { defineTool, type ToolDef } from '../registry.js'
import { P } from '../permissions.js'
import { seg } from '../../jinbe/client.js'
import { toolError } from '../../safety/errors.js'
import { GROUP_NAME, SITE_NAME } from '../../safety/untrusted.js'
import { idempotencyKey, obj, withoutActors } from './write-common.js'
import { route } from './site-writes.js'

/**
 * Bulk changes, one operation at a time (jinbe bulk/routes.ts, requires jinbe ≥ wave17/mcp-endpoints):
 *   POST /api/admin/bulk/<op>/plan     {items[≤200], params?} → plan: per-item outcome, planHash (1 h)
 *   POST /api/admin/bulk/<op>/execute  {planId, planHash}     → 202 job (200 when already finished)
 *   GET  /api/admin/bulk/jobs/:id                             → the job, for whoever started it
 * Each route declares its op's permission, so jinbe decides a key's scope per op. A bulk call is one
 * write of the key's budget. Every op adds or sends: none removes anything (owner rule: no deletes).
 */

const BULK = '/api/admin/bulk'
const JINBE_W17 = 'wave17/mcp-endpoints'

export const BULK_OPS = ['sites.routes.upsert', 'users.invite', 'users.verification', 'groups.members.add'] as const
type Op = (typeof BULK_OPS)[number]

const userRef = z.string().min(1).max(320).describe('An identity id or an email')

/** Per op: the permission jinbe's route declares, and the item and params shapes it validates. */
export const BULK_SPEC: Record<Op, { permission: string; item: z.ZodTypeAny; params: z.ZodTypeAny }> = {
  'sites.routes.upsert': { permission: P.SITES_WRITE, item: route, params: z.object({ site: z.string().regex(SITE_NAME) }).strict() },
  'users.invite': {
    permission: P.USERS_CREATE,
    item: z.object({ email: z.string().email().max(254), name: z.string().min(1).max(120).optional() }).strict(),
    params: z.object({ sendInvite: z.boolean().optional() }).strict(),
  },
  'users.verification': { permission: P.USERS_VERIFY, item: z.object({ user: userRef }).strict(), params: z.object({}).strict() },
  'groups.members.add': {
    permission: P.GROUPS_MEMBERS_WRITE,
    item: z.object({ user: userRef, groups: z.array(z.string().regex(GROUP_NAME)).min(1).max(20) }).strict(),
    params: z.object({}).strict(),
  },
}

const BULK_SCOPES = [...new Set([...Object.values(BULK_SPEC).map((s) => s.permission)])]
const op = z.enum(BULK_OPS)

/** Items and params checked against the op's own shape before jinbe sees them. */
function checked(name: Op, items: unknown[], params: unknown) {
  const spec = BULK_SPEC[name]
  const bad: string[] = []
  items.forEach((it, i) => {
    if (!spec.item.safeParse(it).success) bad.push(`items[${i}]`)
  })
  const p = spec.params.safeParse(params ?? {})
  if (!p.success) bad.push('params')
  if (bad.length) throw toolError('invalid_request', `Not a valid ${name} request: ${bad.slice(0, 20).join(', ')}`, { details: { invalid: bad } })
  return p.data as Record<string, unknown>
}

export const planBulk = defineTool({
  name: 'plan_bulk',
  title: 'Plan a bulk change',
  description:
    'A dry run of one operation over up to 200 items: per item ok, skip (already done), refused or not_found, with counts, warnings, a planId and a planHash. Changes nothing. Ops: sites.routes.upsert (items: site routes, params {site}; into the draft only), users.invite (items {email, name?}, params {sendInvite?}), users.verification (items {user}), groups.members.add (items {user, groups[]}; protected, add-only).',
  scopes: BULK_SCOPES,
  write: true,
  requiresJinbe: JINBE_W17,
  input: { op, items: z.array(z.record(z.unknown())).min(1).max(200), params: z.record(z.unknown()).optional(), idempotencyKey },
  async run(args, ctx) {
    const params = checked(args.op, args.items, args.params)
    const res = await ctx.jinbe.write<Record<string, unknown>>(ctx.call, 'POST', `${BULK}/${args.op}/plan`, {
      body: { items: args.items, ...(Object.keys(params).length ? { params } : {}) },
      idempotencyKey: args.idempotencyKey,
    })
    const p = obj(res.body)
    return {
      data: {
        planId: p.planId,
        planHash: p.planHash,
        op: p.op ?? args.op,
        counts: p.counts,
        warnings: p.warnings ?? [],
        expiresAt: p.expiresAt ?? null,
        items: Array.isArray(p.items) ? p.items : [],
      },
      source: `jinbe:${BULK}/:op/plan`,
      notes: ['Nothing changed yet. Show the refused and not_found rows and the warnings; execute_bulk with this op, planId and planHash runs exactly this plan.'],
    }
  },
})

export const executeBulk = defineTool({
  name: 'execute_bulk',
  title: 'Run a bulk plan',
  description:
    'Run a plan from plan_bulk exactly as planned: refused (conflict) when the hash does not match or when planning again gives another result (the new plan comes back to review). Runs as a job; follow it with get_bulk_job.',
  scopes: BULK_SCOPES,
  write: true,
  destructive: true,
  requiresJinbe: JINBE_W17,
  input: {
    op,
    planId: z.string().regex(/^[A-Za-z0-9-]{8,64}$/),
    planHash: z.string().regex(/^[A-Za-z0-9_-]{16,64}$/),
    idempotencyKey,
  },
  async run(args, ctx) {
    const res = await ctx.jinbe.write<Record<string, unknown>>(ctx.call, 'POST', `${BULK}/${args.op}/execute`, {
      body: { planId: args.planId, planHash: args.planHash },
      idempotencyKey: args.idempotencyKey,
    })
    const j = withoutActors(obj(res.body))
    return { data: { jobId: j.id, op: j.op, state: j.state, total: j.total, counts: j.counts ?? null }, source: `jinbe:${BULK}/:op/execute`, notes: ['Follow it with get_bulk_job.'] }
  },
})

export const getBulkJob = defineTool({
  name: 'get_bulk_job',
  title: 'Bulk job progress',
  description: 'Progress and per-item status (pending, done, skipped, refused, failed) of a bulk job you started.',
  scopes: [P.MCP],
  requiresJinbe: JINBE_W17,
  input: { jobId: z.string().regex(/^[A-Za-z0-9-]{8,64}$/) },
  async run(args, ctx) {
    const j = obj(await ctx.jinbe.get<unknown>(ctx.call, `${BULK}/jobs/${seg(args.jobId)}`))
    return { data: { ...withoutActors(j), items: Array.isArray(j.items) ? j.items : [] }, source: `jinbe:${BULK}/jobs/:id` }
  },
})

export const bulkTools: ToolDef[] = [planBulk, executeBulk, getBulkJob] as ToolDef[]
