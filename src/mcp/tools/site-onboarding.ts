import { z } from 'zod'
import { defineTool, type ToolDef } from '../registry.js'
import { P } from '../permissions.js'
import { seg } from '../../jinbe/client.js'
import { toolError } from '../../safety/errors.js'
import { buildExpertGate, buildGate, expertGate, presetGate } from '../gate-presets.js'
import { nextStep } from '../onboarding.js'
import { SITES, idempotencyKey, obj, siteName } from './write-common.js'
import { lintOf, putDraft, workingSite } from './site-writes.js'

/**
 * Onboarding tools that edit the draft (gates, access) and verify a published site. Gates are given by
 * preset (gate-presets.ts); raw handlers only through the explicit `expert_gate`, flagged by the lint.
 */

const roleName = z.string().regex(/^[a-z][a-z0-9_-]{0,39}$/)
const permission = z.string().max(128).regex(/^[a-z][a-z0-9_.-]*:[a-z*][a-z0-9_*-]*$/, 'a permission like resource:verb')
const groupKey = z.string().min(1).max(64).regex(/^[a-z0-9][a-z0-9_-]{0,63}$/)

export const setSiteGates = defineTool({
  name: 'set_site_gates',
  title: 'Set site gates (draft)',
  description:
    "Add or replace gates of a site's draft by id, each by preset: who (signed-in, signed-in-or-tokens, tokens, machines, anyone, optional), pass (policy, everyone, nobody), gets (identity, nothing, enrich), fails (website, api, platform). Raw handlers only through expert_gate, with a reason; check_site_draft flags it.",
  scopes: [P.SITES_WRITE],
  write: true,
  input: {
    name: siteName,
    gates: z.array(presetGate).max(20).default([]),
    expert_gate: expertGate.optional().describe('One hand-built gate, only when no preset fits'),
    idempotencyKey,
  },
  async run(args, ctx) {
    if (!args.gates.length && !args.expert_gate) throw toolError('invalid_request', 'Nothing to change')
    const incoming = [...args.gates.map((g) => buildGate(g)), ...(args.expert_gate ? [buildExpertGate(args.expert_gate)] : [])]
    const ids = incoming.map((g) => String(g.id))
    if (new Set(ids).size !== ids.length) throw toolError('invalid_request', 'One entry per gate id')
    const base = await workingSite(ctx, args.name)
    const gates = (Array.isArray(base.site.gates) ? base.site.gates : []).map(obj)
    for (const g of incoming) {
      const i = gates.findIndex((x) => x.id === g.id)
      if (i >= 0) gates[i] = g
      else gates.push(g)
    }
    const site = { ...base.site, gates }
    const draft = await putDraft(ctx, args.name, site, base.baseVersion, args.idempotencyKey)
    return {
      data: { name: args.name, gates: ids, draft, lint: lintOf(site), ...(args.expert_gate ? { expertGateReason: args.expert_gate.reason } : {}) },
      source: `jinbe:${SITES}/:name/draft`,
      notes: [nextStep('access')],
    }
  },
})

export const setSiteAccess = defineTool({
  name: 'set_site_access',
  title: 'Design site access (draft)',
  description:
    "Set who can do what on a site, in its draft: the roles (a preset, standard, readonly or operator, or your own role → permissions), which platform groups get which roles, and the second factor (none, writes, all). Published with the site, so it is the way to give a site's access (set_site_roles is overwritten by the next publish).",
  scopes: [P.SITES_WRITE],
  write: true,
  input: {
    name: siteName,
    roles: z.union([z.enum(['standard', 'readonly', 'operator']), z.record(roleName, z.array(permission).max(200))]).optional(),
    groups: z.record(groupKey, z.array(roleName).max(20)).optional().describe('Platform group → the roles it gets on this site, e.g. {"devs": ["editor"]}'),
    twoFactor: z.enum(['none', 'writes', 'all']).optional(),
    idempotencyKey,
  },
  async run(args, ctx) {
    if (args.roles === undefined && !args.groups && !args.twoFactor) throw toolError('invalid_request', 'Nothing to change')
    if (args.roles && typeof args.roles === 'object' && Object.values(args.roles).some((perms) => perms.includes('*'))) {
      throw toolError('invalid_request', "A role granting '*' is made by a person in the console, not through MCP")
    }
    const base = await workingSite(ctx, args.name)
    const site: Record<string, unknown> = { ...base.site }
    if (args.roles !== undefined) site.roles = args.roles
    if (args.groups) site.groups = { ...obj(site.groups), orgGrantable: obj(obj(site.groups).orgGrantable), platform: args.groups }
    if (args.twoFactor) {
      const login = obj(site.login)
      site.login = { reach: 'granted', ...login, twoFactor: { clients: 'exempt', ...obj(login.twoFactor), scope: args.twoFactor } }
    }
    const draft = await putDraft(ctx, args.name, site, base.baseVersion, args.idempotencyKey)
    return {
      data: { name: args.name, roles: site.roles, groups: obj(site.groups).platform ?? {}, twoFactor: obj(obj(site.login).twoFactor).scope ?? 'none', draft, lint: lintOf(site) },
      source: `jinbe:${SITES}/:name/draft`,
      notes: ['People: add_user_to_groups (protected); a missing group: create_group.', nextStep('access')],
    }
  },
})

/** jinbe caps the probes at a 25 s budget; with TLS, OPA, WAF, DNS and Kubernetes, about 45 s at worst. */
const VERIFY_TIMEOUT_MS = 60_000

interface VerifyAnswer {
  rollout?: { ready?: boolean }
  probe?: { available?: boolean; reason?: string; stoppedBy?: string; notProbed?: string[] }
  summary?: { ok?: boolean; errors?: string[]; warnings?: string[] }
}

/**
 * requires jinbe wave18/site-onboarding: POST /api/admin/sites/:name/verify {waf?} → rollout checks,
 * anonymous probes of each route, the access matrix from OPA, the WAF probe, curl commands, summary.
 * One run per site per 30 s (429 verify_rate_limited → rate_limited with retryAfterSec).
 */
export const verifySite = defineTool({
  name: 'verify_site',
  title: 'Verify a published site',
  description:
    'Step 6 of onboarding. Check a published site from the platform side: rollout (applied, rules loaded, DNS, TLS), each route probed anonymously (protected routes must refuse), who can reach what (the policy engine), optionally the WAF, and curl commands to try it. Passed when summary.ok is true. Changes nothing. Takes a few seconds (under a minute at worst); at most once per 30 s per site.',
  scopes: [P.SITES_READ],
  requiresJinbe: 'wave18/site-onboarding',
  input: { name: siteName, waf: z.boolean().optional().describe('Also probe that the WAF blocks an attack pattern') },
  async run(args, ctx) {
    // Synchronous: probes in series within jinbe's 25 s budget, the rest listed in probe.notProbed.
    const res = await ctx.jinbe.request<VerifyAnswer>(ctx.call, 'POST', `${SITES}/${seg(args.name)}/verify`, {
      body: args.waf === undefined ? {} : { waf: args.waf },
      timeoutMs: VERIFY_TIMEOUT_MS,
    })
    const data = res.body
    const notes: string[] = []
    if (data.rollout?.ready === false) notes.push('The rollout is not finished: run verify_site again in a little while (at most once per 30 s).')
    if (data.probe?.available === false && data.probe.reason) notes.push(`Routes were not probed (${data.probe.reason}): the curl commands let the person try them.`)
    if (data.probe?.stoppedBy === 'budget') {
      notes.push(`The probe time budget ran out: ${data.probe.notProbed?.length ?? 'some'} route(s) were not probed (probe.notProbed); their curl commands let the person try them.`)
    }
    if (data.summary?.ok === false) notes.push('Verification found problems (summary.errors): fix them in the draft, save and publish again.')
    notes.push(nextStep('verify'))
    return { data, source: `jinbe:${SITES}/:name/verify`, notes }
  },
})

export const siteOnboardingTools: ToolDef[] = [setSiteGates, setSiteAccess, verifySite] as ToolDef[]
