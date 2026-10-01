import { defineTool, type ToolDef } from '../registry.js'
import { P } from '../permissions.js'
import { protectedActionsOf } from '../../auth/protected-actions.js'
import { createStepUpLink, STEP_UP_LAG, STEP_UP_NOTE, STEP_UP_PATH } from '../step-up-link.js'
import { ToolError } from '../../safety/errors.js'

/**
 * refresh_second_factor: a browser link for the person to refresh the second factor behind THIS
 * connection, so its protected actions stand again (jinbe POST /api/me/mcp/step-up-requests). For the
 * connection's own holder only; it grants nothing until they confirm their second factor themselves.
 */
export const refreshSecondFactor = defineTool({
  name: 'refresh_second_factor',
  title: 'Refresh my second factor',
  description:
    "A single-use link, valid 10 minutes, for you to refresh the second factor this connection stands on (open it, confirm with your second factor in the browser), so its protected actions work again: 12 hours more for a browser sign-in, 30 days for a personal key. Use it when get_my_identity or a refusal says the proof expired. It does nothing until you confirm. At most 5 links per 10 minutes: reuse the last one.",
  scopes: [P.MCP],
  write: true,
  requiresJinbe: 'wave20/step-up-refresh',
  input: {},
  async run(_args, ctx) {
    let link
    try {
      link = await createStepUpLink(ctx.jinbe, ctx.call)
    } catch (err) {
      if (err instanceof ToolError && err.body.code === 'rate_limited') {
        throw new ToolError({ ...err.body, hint: 'At most 5 links per 10 minutes: use the last link you were given (it stays valid 10 minutes), or wait.' })
      }
      throw err
    }
    const pa = protectedActionsOf(ctx.principal)
    return {
      data: { url: link.url, expiresAt: link.expiresAt },
      source: `jinbe:${STEP_UP_PATH}`,
      notes: [
        STEP_UP_NOTE,
        STEP_UP_LAG,
        ...(ctx.principal.stepUpActions === false
          ? ['This connection was created without protected actions: a fresh second factor does not turn them on (create a new key, or sign in again allowing them).']
          : []),
        ...(pa.allowed ? ['Protected actions already work on this connection; refreshing extends them.'] : []),
      ],
    }
  },
})

export const stepUpTools: ToolDef[] = [refreshSecondFactor] as ToolDef[]
