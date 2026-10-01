import { z } from 'zod'
import { defineTool, type ToolDef } from '../registry.js'
import { P } from '../permissions.js'
import { seg } from '../../jinbe/client.js'
import { ToolError, toolError } from '../../safety/errors.js'
import { SITES, idempotencyKey, obj, siteName, withoutActors } from './write-common.js'

/**
 * OpenAPI → site routes (jinbe sites/openapi/routes.ts). One tool, two steps:
 *   1. preview (no `commit`): jinbe reads the spec and proposes one route per operation, with risk;
 *   2. commit (`commit: {specSha256, baseEtag}` from the preview): merged into the DRAFT only.
 * High-risk rows (`needsConfirm`) and rows that lower protection need a decision with `confirm: true`;
 * jinbe refuses the commit (import_blocked) until each has one. The spec is somebody else's text: its
 * titles and descriptions come back framed as data like everything else.
 */

/** jinbe's own limit (sites/openapi/limits.ts LIMITS.bytes: 5 MiB); MCP_BODY_LIMIT_BYTES leaves room for the envelope. */
const MAX_SPEC_CHARS = 5 * 1024 * 1024
/**
 * Past this, the edge WAF in front of the MCP host refuses the JSON body (128 KiB) before it reaches
 * auth-mcp — the platform fix is pending. A refusal that does reach us says what to do instead.
 */
export const EDGE_BODY_HINT_CHARS = 120 * 1024
const BIG_SPEC_HINT = 'A spec this large may be refused on the way in (the platform currently limits request bodies to 128 KiB at its edge): use the console upload, or wait for the platform limit fix.'
const paramName = z.string().regex(/^[A-Za-z_][A-Za-z0-9_]{0,63}$/)
const routeId = z.string().regex(/^[a-z][a-z0-9-]{0,31}$/)
const permission = z.string().max(128).regex(/^[a-z][a-z0-9_.-]*:[a-z*][a-z0-9_*-]*$/)
const access = z.discriminatedUnion('kind', [
  z.object({ kind: z.literal('public') }).strict(),
  z.object({ kind: z.literal('signed-in') }).strict(),
  z.object({ kind: z.literal('permission'), permission }).strict(),
  z.object({ kind: z.literal('deny') }).strict(),
])

const options = z
  .object({
    basePath: z.string().max(256).regex(/^(\/[A-Za-z0-9._~@-]+)*$/).optional(),
    basePathMode: z.enum(['prepend', 'strip', 'none']).optional(),
    resourceFrom: z.enum(['tag', 'path', 'operationId']).optional(),
    listAsRead: z.boolean().optional(),
    scopeMap: z.record(z.string().min(1).max(256), permission).optional(),
    orgParam: paramName.optional(),
    defaultGate: routeId.optional(),
  })
  .strict()
  .default({})

const decision = z
  .object({
    op: z.string().min(1).max(600).describe('The row op, as the preview returned it'),
    access: access.optional(),
    gate: routeId.optional(),
    orgParam: paramName.nullable().optional(),
    skip: z.boolean().optional(),
    remove: z.boolean().optional(),
    confirm: z.boolean().optional().describe('Required for high-risk rows (needsConfirm) and anything that lowers protection'),
  })
  .strict()

type Row = Record<string, unknown> & { op?: string; needsConfirm?: boolean; blocking?: unknown; risk?: unknown[]; status?: string }

/** Rows a person (or the model, on their behalf) must look at; the rest compacted. */
function splitRows(rows: Row[]) {
  const attention = rows.filter((r) => r.needsConfirm || r.blocking || (Array.isArray(r.risk) && r.risk.length > 0))
  const items = rows
    .filter((r) => !attention.includes(r))
    .map((r) => {
      const route = obj(r.route)
      return { op: r.op, method: r.method, path: route.path ?? r.specPath ?? null, status: r.status, access: route.access ?? null }
    })
  return { attention, items }
}

export const importOpenapi = defineTool({
  name: 'import_openapi',
  title: 'Import OpenAPI routes into a site draft',
  description:
    "Map an OpenAPI 2.0/3.x document to site routes. Without `commit`: a preview (writes nothing but the spec, kept 24 h) returning specSha256, baseEtag, the rows needing attention (needsConfirm, blocking, risk) and the rest. With `commit` (specSha256 and baseEtag from the preview) and `decisions`: merged into the site's DRAFT only, never saved or published. High-risk rows need a decision with confirm: true.",
  scopes: [P.SITES_WRITE],
  write: true,
  input: {
    name: siteName,
    spec: z.string().min(1).max(MAX_SPEC_CHARS).optional().describe('The OpenAPI document (JSON or YAML, at most 5 MiB; over about 120 KiB, use the console upload until the platform edge limit is raised), for the preview'),
    format: z.enum(['auto', 'json', 'yaml']).default('auto'),
    options,
    decisions: z.array(decision).max(2000).default([]),
    acceptDenied: z.boolean().default(false).describe('Commit: leave operations with no derivable permission denied'),
    commit: z
      .object({ specSha256: z.string().regex(/^[a-f0-9]{64}$/), baseEtag: z.string().regex(/^[a-f0-9]{16}$/) })
      .strict()
      .optional(),
    idempotencyKey,
  },
  async run(args, ctx) {
    const ops = args.decisions.map((d) => d.op)
    if (new Set(ops).size !== ops.length) throw toolError('invalid_request', 'One decision per operation')
    const base = `${SITES}/${seg(args.name)}/import`

    if (!args.commit) {
      if (!args.spec) throw toolError('invalid_request', 'Pass the spec to preview, or commit with the specSha256 and baseEtag of a preview')
      let res
      try {
        res = await ctx.jinbe.write<Record<string, unknown>>(ctx.call, 'POST', `${base}/preview`, {
          body: { source: { content: args.spec, format: args.format }, options: args.options, decisions: args.decisions },
          idempotencyKey: args.idempotencyKey,
        })
      } catch (err) {
        if (err instanceof ToolError && args.spec.length > EDGE_BODY_HINT_CHARS) throw new ToolError({ ...err.body, hint: BIG_SPEC_HINT })
        throw err
      }
      const p = obj(res.body)
      const spec = obj(p.spec)
      const { attention, items } = splitRows((Array.isArray(p.rows) ? p.rows : []) as Row[])
      return {
        data: {
          commit: { specSha256: spec.sha256 ?? null, baseEtag: obj(p.base).etag ?? null },
          spec: { title: spec.title, version: spec.version, format: spec.format, counts: spec.counts, notes: spec.notes },
          base: p.base,
          counts: p.reimport,
          risk: p.risk,
          blocking: p.blocking,
          checks: p.checks,
          notes: p.notes,
          attention,
          items,
        },
        source: `jinbe:${base}/preview`,
        notes: [
          ...(args.spec.length > EDGE_BODY_HINT_CHARS ? [BIG_SPEC_HINT] : []),
          'Preview only: nothing is in the draft yet. Show the rows under attention to the person; commit with decisions (confirm: true where needsConfirm) and the commit values above.',
        ],
      }
    }

    const res = await ctx.jinbe.write<Record<string, unknown>>(ctx.call, 'POST', `${base}/commit`, {
      body: { ...args.commit, options: args.options, decisions: args.decisions, acceptDenied: args.acceptDenied },
      idempotencyKey: args.idempotencyKey,
    })
    const out = obj(res.body)
    return {
      data: { ...out, ...(out.draft ? { draft: withoutActors(obj(out.draft)) } : {}) },
      source: `jinbe:${base}/commit`,
      notes: ['In the draft only. Review with diff_site.', "Step 3/6: check_site_draft on the draft. Fix high findings; show the person every finding marked confirm."],
    }
  },
})

export const siteImportTools: ToolDef[] = [importOpenapi] as ToolDef[]
