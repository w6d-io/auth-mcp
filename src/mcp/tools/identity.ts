import { defineTool, type ToolContext, type ToolDef } from '../registry.js'
import { P } from '../permissions.js'
import { isWriteScope } from '../../auth/scopes.js'
import { PROTECTED_PERMISSIONS, protectedActionsOf, type ProtectedActions } from '../../auth/protected-actions.js'
import { ToolError } from '../../safety/errors.js'
import type { MyPermissions, SecondFactorPicture } from '../../jinbe/types.js'

/**
 * Not called `whoami`: the edge WAF (Coraza, OWASP CRS 932260 "Direct Unix Command Execution") blocks
 * any JSON body whose value is a bare shell command, so `"name":"whoami"` got a 403 before reaching
 * the server. Tool names stay `verb_noun` (see registry-drafts.test.ts).
 */

/** Read-only for this connection: MCP switched to read-only, or no write permission in its scopes. */
const readOnlyOf = (ctx: ToolContext) => !!ctx.deps?.killSwitches.current().readOnly || !ctx.principal.scopes.some(isWriteScope)

/**
 * "Which of my actions need a second factor": the permissions this person holds that need one proven in
 * the last 15 minutes (jinbe's stepUpPermissions), the tools they open, and what THIS connection can do
 * about it — stand in (protected actions allowed), fixable (a new key, a new sign-in), or console only.
 */
async function secondFactorSummary(ctx: ToolContext, pa: ProtectedActions) {
  let mine: SecondFactorPicture | null = null
  try {
    mine = (await ctx.jinbe.get<MyPermissions>(ctx.call, '/api/me/permissions')).secondFactor ?? null
  } catch (err) {
    if (!(err instanceof ToolError)) throw err
  }
  if (!mine) return { available: false, note: 'The platform did not report your second-factor picture (older jinbe, or unreachable).' }
  const { allTools } = await import('./index.js')
  const standIn = new Set<string>(PROTECTED_PERMISSIONS)
  const actions = (mine.stepUpPermissions ?? []).map((permission) => ({
    permission,
    tools: allTools.filter((t) => t.write && t.scopes.includes(permission)).map((t) => t.name),
    thisConnection: !standIn.has(permission) ? 'console_only' : pa.allowed ? 'allowed' : (pa.reason ?? 'not_allowed'),
  }))
  return {
    available: true,
    signIn: { required: mine.required ?? null, requiredBecause: mine.requiredBecause ?? [], enrolled: mine.enrolled ?? null, methods: mine.methods ?? null },
    actionsNeedingIt: actions,
  }
}

export const getMyIdentity = defineTool({
  name: 'get_my_identity',
  title: 'Who this connection acts as',
  description:
    'The person this connection acts for, its effective scopes (what the person still holds now), whether it is read-only, whether it may do protected actions (publish, change an email, add to groups, edit groups and roles), until when and how to get them back, the client, whether it is a personal key or a browser sign-in (and when that sign-in ends), when the current token expires, and which of your actions need a second factor (why your sign-in requires one, whether you are enrolled, and for each such action whether this connection can do it, or only the console). Call it before a protected action.',
  scopes: [P.MCP],
  input: {},
  async run(_args, ctx) {
    const { principal } = ctx
    const protectedActions = protectedActionsOf(principal)
    return {
      data: {
        subject: principal.subject,
        email: principal.email,
        org: principal.org,
        scopes: principal.scopes,
        readOnly: readOnlyOf(ctx),
        protectedActions,
        clientId: principal.clientId,
        credentialType: principal.kind === 'personal' ? 'personal_key' : 'oauth',
        keyId: principal.keyId,
        ...(principal.kind === 'oauth'
          ? {
              signIn: {
                client: principal.clientName ?? null,
                permissions: principal.scopeMode ?? null,
                expiresAt: principal.grantExpiresAt ?? null,
              },
            }
          : {}),
        tokenExpiresAt: Number.isFinite(principal.expiresAt) ? new Date(principal.expiresAt * 1000).toISOString() : null,
        secondFactor: await secondFactorSummary(ctx, protectedActions),
      },
      source: 'auth-mcp:token+jinbe:/api/me/permissions',
    }
  },
})

export const identityTools: ToolDef[] = [getMyIdentity] as ToolDef[]
