import { defineTool, type ToolContext, type ToolDef } from '../registry.js'
import { P } from '../permissions.js'
import { isWriteScope } from '../../auth/scopes.js'
import { protectedActionsOf } from '../../auth/protected-actions.js'

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

export const identityTools: ToolDef[] = [getMyIdentity] as ToolDef[]
