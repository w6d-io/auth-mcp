import { defineTool, type ToolDef } from '../registry.js'
import { P } from '../permissions.js'
import { protectedActionsOf } from '../../auth/protected-actions.js'
import { createStepUpLink, STEP_UP_NOTE, STEP_UP_PATH } from '../step-up-link.js'

/**
 * refresh_second_factor: a browser link for the person to refresh the second factor behind THIS
 * connection, so its protected actions stand again (jinbe POST /api/me/mcp/step-up-requests). For the
 * connection's own holder only; it grants nothing until they confirm their second factor themselves.
 */
export const refreshSecondFactor = defineTool({
  name: 'refresh_second_factor',
  title: 'Refresh my second factor',
  description:
    "A short-lived link for you to refresh the second factor this connection stands on (open it, confirm your second factor in the browser), so its protected actions work again. Use it when get_my_identity or a refusal says the proof expired. It does nothing until you confirm in the browser.",
  scopes: [P.MCP],
  write: true,
  requiresJinbe: 'wave20/step-up-requests',
  input: {},
  async run(_args, ctx) {
    const link = await createStepUpLink(ctx.jinbe, ctx.call)
    const pa = protectedActionsOf(ctx.principal)
    return {
      data: { url: link.url, expiresAt: link.expiresAt },
      source: `jinbe:${STEP_UP_PATH}`,
      notes: [
        STEP_UP_NOTE,
        ...(ctx.principal.stepUpActions === false
          ? ['This connection was created without protected actions: a fresh second factor does not turn them on (create a new key, or sign in again allowing them).']
          : []),
        ...(pa.allowed ? ['Protected actions already work on this connection; refreshing extends them.'] : []),
      ],
    }
  },
})

export const stepUpTools: ToolDef[] = [refreshSecondFactor] as ToolDef[]
