import { z } from 'zod'
import { defineTool, type ToolContext, type ToolDef } from '../registry.js'
import { P } from '../permissions.js'
import { seg } from '../../jinbe/client.js'
import type { SiteDetail } from '../../jinbe/types.js'
import { SITES, idempotencyKey, note, obj, siteName, withoutActors } from './write-common.js'
import { nextStep } from '../onboarding.js'

/**
 * Changing what the gateway serves. `sites:apply` is a PROTECTED permission: a key does it only when
 * created with protected actions allowed (jinbe 422 step_up_unavailable otherwise → the tool error
 * protected_actions_off). In production (SITES_PRODUCTION) jinbe refuses a key's apply and rollback with
 * use_apply_request: request_site_apply asks, and a person approves in the console.
 */

const APPLY_SCOPES = [P.SITES_APPLY]

/** An apply record without who ran it, and with stages as {name, state}. */
function applyView(v: unknown) {
  // `previous` is the whole former gateway state: large, and not what the caller asked about.
  const a = withoutActors(obj(v))
  delete a.previous
  const stages = Array.isArray(a.stages)
    ? a.stages.map((s) => {
        const o = obj(s)
        return { name: o.name ?? o.id, state: o.state }
      })
    : undefined
  return { ...a, ...(stages ? { stages } : {}) }
}

async function savedVersion(ctx: ToolContext, name: string): Promise<number> {
  return (await ctx.jinbe.get<SiteDetail>(ctx.call, `${SITES}/${seg(name)}`)).version
}

const version = z.number().int().min(1).optional().describe('The saved version (site_versions); default: the latest saved one')
/** Findings the person accepted (check_site_draft marks them confirm). Never acknowledge one the person has not seen. */
export const acknowledge = z
  .array(z.string().regex(/^[a-z][a-z0-9_]{0,63}$/))
  .max(32)
  .optional()
  .describe('The codes of the confirm findings (check_site_draft preview.publish.acknowledge) the person has read and accepted; a code covers every finding with it')

export const publishSite = defineTool({
  name: 'publish_site',
  title: 'Publish a site',
  description:
    "Apply a saved version to the gateway (permissions first, then the site's rules). Protected: needs a key created with protected actions allowed. In production a key cannot publish directly: use request_site_apply.",
  scopes: APPLY_SCOPES,
  write: true,
  destructive: true,
  protectedAction: true,
  input: { name: siteName, version, acknowledge, idempotencyKey },
  async run(args, ctx) {
    const v = args.version ?? (await savedVersion(ctx, args.name))
    const res = await ctx.jinbe.write<unknown>(ctx.call, 'POST', `${SITES}/${seg(args.name)}/apply`, {
      body: { version: v, ...(args.acknowledge?.length ? { acknowledge: args.acknowledge } : {}) },
      idempotencyKey: args.idempotencyKey,
    })
    return { data: applyView(res.body), source: `jinbe:${SITES}/:name/apply`, notes: ['Follow the rollout with get_site.', nextStep('publish')] }
  },
})

export const requestSiteApply = defineTool({
  name: 'request_site_apply',
  title: 'Request a site publish',
  description:
    'Ask for a saved version to be applied; a person approves it in the console (Sites, Requests), with a second person where four-eyes applies. The way to publish in production.',
  scopes: [P.SITES_WRITE],
  write: true,
  input: { name: siteName, version, note, acknowledge, idempotencyKey },
  async run(args, ctx) {
    const v = args.version ?? (await savedVersion(ctx, args.name))
    const res = await ctx.jinbe.write<unknown>(ctx.call, 'POST', `${SITES}/${seg(args.name)}/requests`, {
      body: { version: v, ...(args.note ? { note: args.note } : {}), ...(args.acknowledge?.length ? { acknowledge: args.acknowledge } : {}) },
      idempotencyKey: args.idempotencyKey,
    })
    const r = withoutActors(obj(res.body))
    return {
      data: { id: r.id, site: r.site, version: r.version, state: r.state, risk: r.risk, needsSecondApprover: r.needsSecondApprover, requestedAt: r.requestedAt },
      source: `jinbe:${SITES}/:name/requests`,
      notes: ['Pending: a person approves it in the console (Sites, Requests). This connection cannot approve it.', 'Once applied, step 6/6: verify_site, then report to the person.'],
    }
  },
})

function stateTool(name: 'pause_site' | 'resume_site', title: string, description: string, verb: 'pause' | 'resume') {
  return defineTool({
    name,
    title,
    description,
    scopes: APPLY_SCOPES,
    write: true,
    destructive: true,
    protectedAction: true,
    input: { name: siteName, idempotencyKey },
    async run(args, ctx) {
      const res = await ctx.jinbe.write<unknown>(ctx.call, 'POST', `${SITES}/${seg(args.name)}/${verb}`, { body: {}, idempotencyKey: args.idempotencyKey })
      return { data: applyView(res.body), source: `jinbe:${SITES}/:name/${verb}` }
    },
  })
}

export const pauseSite = stateTool('pause_site', 'Pause a site', 'Stop serving a site (its rules are removed); everything else is kept. Protected: needs a key created with protected actions allowed.', 'pause')
export const resumeSite = stateTool('resume_site', 'Resume a site', 'Serve a paused site again. Protected: needs a key created with protected actions allowed.', 'resume')

export const rollbackSite = defineTool({
  name: 'rollback_site',
  title: 'Roll back a site',
  description:
    'Save an older version as a new one and apply it. Protected: needs a key created with protected actions allowed. In production: save that version again (save_site_version) and request_site_apply.',
  scopes: APPLY_SCOPES,
  write: true,
  destructive: true,
  protectedAction: true,
  input: { name: siteName, toVersion: z.number().int().min(1), note, idempotencyKey },
  async run(args, ctx) {
    const res = await ctx.jinbe.write<unknown>(ctx.call, 'POST', `${SITES}/${seg(args.name)}/rollback`, {
      body: { toVersion: args.toVersion, ...(args.note ? { note: args.note } : {}) },
      idempotencyKey: args.idempotencyKey,
    })
    return { data: applyView(res.body), source: `jinbe:${SITES}/:name/rollback` }
  },
})

export const sitePublishTools: ToolDef[] = [publishSite, requestSiteApply, pauseSite, resumeSite, rollbackSite] as ToolDef[]
