import { z } from 'zod'
import { defineTool, type ToolContext, type ToolDef } from '../registry.js'
import { P } from '../permissions.js'
import { hasAnyScope, hasScope } from '../../auth/scopes.js'
import { protectedActionsOf } from '../../auth/protected-actions.js'
import { ToolError } from '../../safety/errors.js'
import { groupsGranting } from '../granted-by.js'

/**
 * `can_i`: would this connection be allowed to run a tool, without running it.
 *
 * Every tool gets the BASE checks, all local: kill switches, read-only, scopes (with the groups that
 * grant a missing one), the protected-actions state, the arguments and the tool's own guard (e.g. no
 * self-targeting). A write tool's EXTRA checks are declared in CAN_I_RULES — a jinbe read where only
 * jinbe knows the answer — and a test fails when a write tool has no entry, so a new write tool cannot
 * be added without deciding what can_i says about it. jinbe still decides the real call: `allowed: true`
 * is "nothing here refuses it", not a promise.
 */

/**
 * - base:         the local checks above, nothing else to know
 * - production:   a key's apply is refused in production (use_apply_request): read the platform flag
 * - publish_gate: the site's security findings (error findings block; confirm ones need acknowledge)
 */
export type CanIRule = 'base' | 'production' | 'publish_gate'

export const CAN_I_RULES: Readonly<Record<string, readonly CanIRule[]>> = {
  // Sites: drafts, imports, versions (nothing live changes)
  create_site: ['base'],
  save_site_draft: ['base'],
  update_site_routes: ['base'],
  set_site_gates: ['base'],
  set_site_access: ['base'],
  import_openapi: ['base'],
  save_site_version: ['base'],
  // Sites: what the gateway serves
  publish_site: ['base', 'production', 'publish_gate'],
  request_site_apply: ['base', 'publish_gate'],
  rollback_site: ['base', 'production'],
  pause_site: ['base'],
  resume_site: ['base'],
  // Sites: lifecycle (an expiry pauses, never deletes; deletion is a request a person approves)
  extend_site_ttl: ['base'],
  request_site_deletion: ['base'],
  // People
  invite_user: ['base'],
  send_recovery_email: ['base'],
  send_login_link: ['base'],
  resend_verification_email: ['base'],
  change_user_email: ['base'],
  add_user_to_groups: ['base'],
  // Access model
  create_group: ['base'],
  update_group: ['base'],
  set_site_roles: ['base'],
  // Bulk
  plan_bulk: ['base'],
  execute_bulk: ['base'],
  // This connection
  revoke_my_key: ['base'],
}

type Answer = (extra: Record<string, unknown>) => { data: Record<string, unknown>; source: string }

/** A rule's verdict: a refusal to answer with, or notes to add (it could not tell, or it passed). */
type Verdict = { refuse: Record<string, unknown> } | { notes: string[] }

async function productionRule(ctx: ToolContext): Promise<Verdict> {
  if (!hasScope(ctx.principal.scopes, P.SITES_READ)) {
    return { notes: ['Without sites:read this cannot tell whether this is production: there, publish and rollback answer use_apply_request.'] }
  }
  try {
    const platform = await ctx.jinbe.get<{ production?: unknown }>(ctx.call, '/api/admin/sites/platform')
    return platform.production === true ? { refuse: { wouldRefuseBecause: 'use_apply_request', instead: 'request_site_apply' } } : { notes: [] }
  } catch (err) {
    if (!(err instanceof ToolError)) throw err
    return { notes: ['Could not read whether this is production: in production, publish and rollback answer use_apply_request.'] }
  }
}

interface PublishGate {
  findings?: Array<{ code: string; level: string; message?: string; fix?: string }>
  publish?: { blocked?: boolean; acknowledge?: string[] }
}

/** The platform preview of the SAVED intent (compute only, writes nothing), against the codes the caller would acknowledge. */
async function publishGateRule(ctx: ToolContext, args: Record<string, unknown> | undefined): Promise<Verdict> {
  const name = typeof args?.name === 'string' ? args.name : null
  if (!name) return { notes: ['Pass the arguments (the site name) to check the publish gate too.'] }
  if (!hasScope(ctx.principal.scopes, P.SITES_WRITE)) return { notes: ["Without sites:write the publish gate (the site's security findings) was not checked."] }
  try {
    const saved = await ctx.jinbe.get<{ site?: unknown }>(ctx.call, `/api/admin/sites/${encodeURIComponent(name)}`)
    const p = await ctx.jinbe.post<PublishGate>(ctx.call, '/api/admin/sites/preview', { site: saved.site })
    if (!p.publish) return { notes: [] }
    const acked = Array.isArray(args?.acknowledge) ? args.acknowledge.map(String) : []
    const errors = (p.findings ?? []).filter((f) => f.level === 'error')
    if (p.publish.blocked) return { refuse: { wouldRefuseBecause: 'unconfirmed_findings', errors: errors.map((f) => ({ code: f.code, fix: f.fix })) } }
    const acknowledge = p.publish.acknowledge ?? []
    const missing = acknowledge.filter((c) => !acked.includes(c))
    if (missing.length) return { refuse: { wouldRefuseBecause: 'unconfirmed_findings', acknowledgeMissing: missing } }
    return { notes: [acknowledge.length ? `The publish gate passes with acknowledge [${acknowledge.join(', ')}].` : 'The publish gate has nothing to acknowledge.'] }
  } catch (err) {
    if (!(err instanceof ToolError)) throw err
    return { notes: ["Could not check the publish gate (the site's security findings): check_site_draft shows them."] }
  }
}

const RULE_CHECKS: Record<Exclude<CanIRule, 'base'>, (ctx: ToolContext, args: Record<string, unknown> | undefined) => Promise<Verdict>> = {
  production: (ctx) => productionRule(ctx),
  publish_gate: publishGateRule,
}

/** Built with the tool list (a thunk: the list includes this tool). */
export function makeCanI(tools: () => readonly ToolDef[]) {
  return defineTool({
    name: 'can_i',
    title: 'Can I run this tool?',
    description:
      'Whether this connection may run a tool (optionally with its arguments), with no side effect: the missing permissions and the groups that grant them, whether it is a protected action and whether this connection may do protected actions, and the refusal code it would get (read_only, insufficient_scope, protected_actions_off, self_target_refused, use_apply_request, unconfirmed_findings, invalid_request, not_wired, unknown_tool). Use it instead of trying a write to find out.',
    scopes: [P.MCP],
    input: {
      tool: z.string().regex(/^[a-z][a-z0-9_]{1,63}$/).describe('The tool name'),
      arguments: z.record(z.unknown()).optional().describe('The arguments you would pass, to check them and the self-target rule too'),
    },
    async run(args, ctx) {
      const def = tools().find((t) => t.name === args.tool)
      const pa = protectedActionsOf(ctx.principal)
      const answer: Answer = (extra) => ({
        data: {
          tool: args.tool,
          allowed: false,
          needs: [] as string[],
          protectedAction: !!def?.protectedAction,
          protectedActionsAllowed: pa.allowed,
          ...(pa.reason ? { protectedActionsReason: pa.reason } : {}),
          ...(pa.guidance ? { protectedActionsGuidance: pa.guidance } : {}),
          ...extra,
        },
        source: 'auth-mcp:can_i',
      })
      if (!def) return answer({ wouldRefuseBecause: 'unknown_tool' })
      if (def.wired === false) return answer({ wouldRefuseBecause: 'not_wired' })
      const deps = ctx.deps
      if (deps?.killSwitches.check(ctx.principal).refused) return answer({ wouldRefuseBecause: 'mcp_disabled' })
      if (def.write && deps?.killSwitches.current().readOnly) return answer({ wouldRefuseBecause: 'read_only' })
      if (!hasAnyScope(ctx.principal.scopes, def.scopes)) {
        // Which groups would give it (best effort, group names only): who to ask.
        const grantedBy = await groupsGranting(ctx, def.scopes.slice(0, 1))
        return answer({
          needs: def.scopes,
          wouldRefuseBecause: 'insufficient_scope',
          ...(grantedBy ? { grantedBy } : {}),
          hint: grantedBy?.length
            ? `Use a connection that carries ${def.scopes[0]}. If you do not hold it: ask an administrator to add you to one of ${grantedBy.join(', ')}.`
            : `Use a connection that carries ${def.scopes[0]}; if you do not hold it, ask an administrator.`,
        })
      }
      if (def.protectedAction && !pa.allowed) return answer({ wouldRefuseBecause: 'protected_actions_off' })

      if (args.arguments) {
        const parsed = z.object(def.input).safeParse(args.arguments)
        if (!parsed.success) {
          return answer({ wouldRefuseBecause: 'invalid_request', invalid: parsed.error.issues.map((i) => i.path.join('.') || '(root)') })
        }
        try {
          def.guard?.(parsed.data as never, ctx)
        } catch (err) {
          if (!(err instanceof ToolError)) throw err
          return answer({ wouldRefuseBecause: err.body.code })
        }
      }

      const rules = def.write ? CAN_I_RULES[def.name] : ['base' as const]
      if (!rules) return { ...answer({ allowed: null }), notes: ['can_i has no rule for this tool: it cannot tell. The platform decides the call.'] }
      const notes: string[] = []
      for (const rule of rules) {
        if (rule === 'base') continue
        const verdict = await RULE_CHECKS[rule](ctx, args.arguments)
        if ('refuse' in verdict) return answer(verdict.refuse)
        notes.push(...verdict.notes)
      }
      return { ...answer({ allowed: true }), notes: ['The platform still decides the real call.', ...notes] }
    },
  })
}
