import { z } from 'zod'
import { defineTool, type ToolDef } from '../registry.js'
import { P } from '../permissions.js'
import { seg } from '../../jinbe/client.js'
import { toolError } from '../../safety/errors.js'
import { buildExpertGate, buildGate, expertGate, presetGate } from '../gate-presets.js'
import { nextStep } from '../onboarding.js'
import { SITES, idempotencyKey, obj, siteName } from './write-common.js'
import { ORGS_NOTE, lintOf, putDraft, workingSite } from './site-writes.js'
import { withOrganizations } from '../site-templates.js'
import { rolesFromRoutes } from '../site-names.js'

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
    "Add or replace gates of a site's draft by id, each by preset: who (signed-in, signed-in-or-tokens, people-and-org-keys, tokens, machines, anyone, optional), pass (policy, everyone, nobody; a gate admitting tokens must use policy), gets (identity, nothing, enrich), fails (website, api, platform). A partner's program comes in with its organization's API key: turn organizations on (set_site_organizations, which adds the people-and-org-keys gate) rather than a machines gate with a required_scope or a secret header. Raw handlers only through expert_gate, with a reason; check_site_draft flags it.",
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
    const draft = await putDraft(ctx, args.name, site, base.baseVersion, args.idempotencyKey, base.etag)
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
    "Set who can do what on a site, in its draft: the roles (a preset, standard, readonly or operator; 'from-routes', one role per permission the site's routes ask, named from it, to rename for the job; or your own role → permissions), which platform groups get which roles, and the second factor (none, writes, all). Name roles for the job and give them only permissions a route asks; groups <site>-<role>s; reuse the names sibling sites use (find_sites_for_service names). Published with the site, so it is the way to give a site's access (set_site_roles is overwritten by the next publish).",
  scopes: [P.SITES_WRITE],
  write: true,
  input: {
    name: siteName,
    roles: z.union([z.enum(['standard', 'readonly', 'operator', 'from-routes']), z.record(roleName, z.array(permission).max(200))]).optional(),
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
    if (args.roles === 'from-routes') {
      const generated = rolesFromRoutes(site)
      if (!Object.keys(generated).length) throw toolError('invalid_request', "No route of this draft asks a permission yet: map the routes first (update_site_routes, import_openapi), then roles 'from-routes'")
      site.roles = generated
    } else if (args.roles !== undefined) site.roles = args.roles
    if (args.groups) site.groups = { ...obj(site.groups), orgGrantable: obj(obj(site.groups).orgGrantable), platform: args.groups }
    if (args.twoFactor) {
      const login = obj(site.login)
      site.login = { reach: 'granted', ...login, twoFactor: { clients: 'exempt', ...obj(login.twoFactor), scope: args.twoFactor } }
    }
    const draft = await putDraft(ctx, args.name, site, base.baseVersion, args.idempotencyKey, base.etag)
    return {
      data: { name: args.name, roles: site.roles, groups: obj(site.groups).platform ?? {}, twoFactor: obj(obj(site.login).twoFactor).scope ?? 'none', draft, lint: lintOf(site) },
      source: `jinbe:${SITES}/:name/draft`,
      notes: [
        ...(args.roles === 'from-routes' ? [`Roles made from the routes: ${Object.keys(obj(site.roles)).join(', ')}. Rename each for the job (partner, activity-reader…) with set_site_access roles, keeping a name a sibling site already gives the same access (find_sites_for_service names).`] : []),
        'People: add_user_to_groups (protected); a missing group: create_group.',
        nextStep('access'),
      ],
    }
  },
})

export const setSiteOrganizations = defineTool({
  name: 'set_site_organizations',
  title: 'Turn organizations on for a site (draft)',
  description:
    "Turn organizations on in a site's draft, so many people share the same objects of its backend per organization: adds the organization gate (organization members and their organization's API keys, the policy decides), a route /orgs/:orgId/:any* on it asking <site>:use, the org roles <site>-admin (site role admin, held by owners) and <site>-member (site role user), and the organizations the site serves (serve, added to the ones it has). Adds only: what the draft already has stays. Turning organizations off or removing a served organization is done in the console.",
  scopes: [P.SITES_WRITE],
  write: true,
  input: {
    name: siteName,
    serve: z.array(z.string().uuid()).max(100).default([]).describe('Organization ids (list_orgs) the site serves: added to its orgs'),
    idempotencyKey,
  },
  async run(args, ctx) {
    const base = await workingSite(ctx, args.name)
    const { site, added, kept, problems } = withOrganizations({ ...base.site, name: base.site.name ?? args.name })
    const orgs = Array.isArray(site.orgs) ? site.orgs.map(String) : []
    const served = args.serve.filter((o) => !orgs.includes(o))
    const nextOrgs = [...orgs, ...served]
    site.orgs = nextOrgs
    if (served.length) added.push(`served organizations ${served.join(', ')}`)
    if (!added.length) throw toolError('invalid_request', 'Nothing to change: organizations are already on with the template, and those organizations already served')
    const draft = await putDraft(ctx, args.name, site, base.baseVersion, args.idempotencyKey, base.etag)
    return {
      data: { name: args.name, from: base.from, added, kept, problems, organizations: site.organizations, orgs: nextOrgs, draft, lint: lintOf(site) },
      source: `jinbe:${SITES}/:name/draft`,
      notes: [
        ORGS_NOTE,
        ...(problems.length ? ['problems lists what the platform would refuse at preview: fix it in the draft before saving.'] : []),
        ...(nextOrgs.length ? [] : ['The site serves no organization yet: pass serve with organization ids (list_orgs).']),
        nextStep('access'),
      ],
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

export const siteOnboardingTools: ToolDef[] = [setSiteGates, setSiteAccess, setSiteOrganizations, verifySite] as ToolDef[]
