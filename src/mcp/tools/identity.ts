import { z } from 'zod'
import { defineTool, type ToolContext, type ToolDef } from '../registry.js'
import { P } from '../permissions.js'
import { hasAnyScope, hasScope, isWriteScope } from '../../auth/scopes.js'
import { protectedActionsOf } from '../../auth/protected-actions.js'
import { ToolError } from '../../safety/errors.js'
import { groupsGranting } from '../granted-by.js'

/**
 * Not called `whoami`: the edge WAF (Coraza, OWASP CRS 932260 "Direct Unix Command Execution") blocks
 * any JSON body whose value is a bare shell command, so `"name":"whoami"` got a 403 before reaching
 * the server. Tool names stay `verb_noun` (see registry-drafts.test.ts).
 */

/** Read-only for this connection: MCP switched to read-only, or no write permission in its scopes. */
const readOnlyOf = (ctx: ToolContext) => !!ctx.deps?.killSwitches.current().readOnly || !ctx.principal.scopes.some(isWriteScope)

export const getMyIdentity = defineTool({
  name: 'get_my_identity',
  title: 'Who this connection acts as',
  description:
    'The person this connection acts for, its effective scopes (what the person still holds now), whether it is read-only, whether it may do protected actions (publish, change an email, add to groups, edit groups and roles) and until when, the client, whether it is a personal key, and when the current token expires. Answered locally, from the verified token. Call it before a protected action.',
  scopes: [P.MCP],
  input: {},
  async run(_args, ctx) {
    const { principal } = ctx
    return {
      data: {
        subject: principal.subject,
        email: principal.email,
        org: principal.org,
        scopes: principal.scopes,
        readOnly: readOnlyOf(ctx),
        protectedActions: protectedActionsOf(principal),
        clientId: principal.clientId,
        credentialType: principal.kind === 'personal' ? 'personal_key' : 'oauth',
        keyId: principal.keyId,
        tokenExpiresAt: Number.isFinite(principal.expiresAt) ? new Date(principal.expiresAt * 1000).toISOString() : null,
      },
      source: 'auth-mcp:token',
    }
  },
})

/** Tools whose apply is refused to a key in production (jinbe middleware/delegated-writes.ts). */
const PRODUCTION_REQUEST = new Set(['publish_site', 'rollback_site'])
/** Tools behind jinbe's publish gate: error findings block, confirm findings need acknowledging. */
const PUBLISH_GATED = new Set(['publish_site', 'request_site_apply'])

interface PublishGate {
  findings?: Array<{ code: string; level: string; message?: string; fix?: string }>
  publish?: { blocked?: boolean; acknowledge?: string[] }
}

/**
 * Would the publish gate refuse this site as saved, given the codes the caller would acknowledge?
 * The platform preview of the saved intent (compute only, writes nothing). null when it cannot tell.
 */
async function publishGate(ctx: ToolContext, name: string, acknowledged: string[]) {
  const saved = await ctx.jinbe.get<{ site?: unknown }>(ctx.call, `/api/admin/sites/${encodeURIComponent(name)}`)
  const p = await ctx.jinbe.post<PublishGate>(ctx.call, '/api/admin/sites/preview', { site: saved.site })
  if (!p.publish) return null
  const errors = (p.findings ?? []).filter((f) => f.level === 'error')
  const missing = (p.publish.acknowledge ?? []).filter((c) => !acknowledged.includes(c))
  return { blocked: !!p.publish.blocked, errors, missing, acknowledge: p.publish.acknowledge ?? [] }
}

/**
 * `can_i`: would this connection be allowed to run a tool, without running it. Built with the tool list
 * (a thunk: the list includes this tool). Every check is local — kill switches, read-only, scopes, the
 * protected-actions state, the arguments and the tool's own guard (self-targeting) — plus one jinbe
 * read where only jinbe knows: whether this is production (publish/rollback become requests). jinbe
 * still decides the real call: `allowed: true` is "nothing here refuses it", not a promise.
 */
export function makeCanI(tools: () => readonly ToolDef[]) {
  return defineTool({
    name: 'can_i',
    title: 'Can I run this tool?',
    description:
      'Whether this connection may run a tool (optionally with its arguments), with no side effect: the missing permissions, whether it is a protected action and whether this key may do protected actions, and the refusal code it would get (read_only, insufficient_scope, protected_actions_off, self_target_refused, use_apply_request, invalid_request, not_wired, unknown_tool). Use it instead of trying a write to find out.',
    scopes: [P.MCP],
    input: {
      tool: z.string().regex(/^[a-z][a-z0-9_]{1,63}$/).describe('The tool name'),
      arguments: z.record(z.unknown()).optional().describe('The arguments you would pass, to check them and the self-target rule too'),
    },
    async run(args, ctx) {
      const def = tools().find((t) => t.name === args.tool)
      const pa = protectedActionsOf(ctx.principal)
      const answer = (extra: Record<string, unknown>) => ({
        data: {
          tool: args.tool,
          allowed: false,
          needs: [] as string[],
          protectedAction: !!def?.protectedAction,
          protectedActionsAllowed: pa.allowed,
          ...(pa.reason ? { protectedActionsReason: pa.reason } : {}),
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
            ? `Use a key that carries ${def.scopes[0]}. If you do not hold it: ask an administrator to add you to one of ${grantedBy.join(', ')}.`
            : `Use a key that carries ${def.scopes[0]}; if you do not hold it, ask an administrator.`,
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

      const notes: string[] = []
      if (PRODUCTION_REQUEST.has(def.name)) {
        if (hasScope(ctx.principal.scopes, P.SITES_READ)) {
          try {
            const platform = await ctx.jinbe.get<{ production?: unknown }>(ctx.call, '/api/admin/sites/platform')
            if (platform.production === true) return answer({ wouldRefuseBecause: 'use_apply_request', instead: 'request_site_apply' })
          } catch (err) {
            if (!(err instanceof ToolError)) throw err
            notes.push('Could not read whether this is production: in production, publish and rollback answer use_apply_request.')
          }
        } else {
          notes.push('Without sites:read this cannot tell whether this is production: there, publish and rollback answer use_apply_request.')
        }
      }
      const siteArg = typeof args.arguments?.name === 'string' ? args.arguments.name : null
      if (PUBLISH_GATED.has(def.name) && siteArg) {
        if (hasScope(ctx.principal.scopes, P.SITES_WRITE)) {
          try {
            const acked = Array.isArray(args.arguments?.acknowledge) ? args.arguments.acknowledge.map(String) : []
            const gate = await publishGate(ctx, siteArg, acked)
            if (gate?.blocked) return answer({ wouldRefuseBecause: 'unconfirmed_findings', errors: gate.errors.map((f) => ({ code: f.code, fix: f.fix })) })
            if (gate?.missing.length) return answer({ wouldRefuseBecause: 'unconfirmed_findings', acknowledgeMissing: gate.missing })
            if (gate) notes.push(gate.acknowledge.length ? `The publish gate passes with acknowledge [${gate.acknowledge.join(', ')}].` : 'The publish gate has nothing to acknowledge.')
          } catch (err) {
            if (!(err instanceof ToolError)) throw err
            notes.push("Could not check the publish gate (the site's security findings): check_site_draft shows them.")
          }
        } else {
          notes.push("Without sites:write the publish gate (the site's security findings) was not checked.")
        }
      }
      return { ...answer({ allowed: true }), notes: ['The platform still decides the real call.', ...notes] }
    },
  })
}

export const identityTools: ToolDef[] = [getMyIdentity] as ToolDef[]
