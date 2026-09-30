import { z } from 'zod'
import { defineTool, type ToolOutput, type ToolDef } from '../registry.js'
import { P } from '../permissions.js'
import { toolError } from '../../safety/errors.js'
import { GROUP_NAME, IDENTITY_ID } from '../../safety/untrusted.js'

/**
 * Stubs: declared so the surface can be reviewed, NOT wired. Each refuses with `not_wired` and none
 * calls jinbe. Listed only with MCP_EXPOSE_UNWIRED_TOOLS=true.
 *
 * The write wave replaced the change-request stubs (request_site_publish, rollback_request,
 * propose_group_change, propose_role_change, get_change_request): writes are direct now (see
 * site-writes.ts, site-publish.ts, user-writes.ts, group-writes.ts, bulk.ts).
 */

const notWired = async (): Promise<ToolOutput> => {
  throw toolError('not_wired', 'Not connected to the platform yet')
}

export const simulateGrant = defineTool({
  wired: false,
  run: notWired,
  name: 'simulate_grant',
  title: 'Simulate a grant',
  description: 'What a person could newly reach if they were added to groups; flags admin, apply and wildcard permissions.',
  scopes: [P.ACCESS_READ],
  input: { userId: z.string().regex(IDENTITY_ID), addGroups: z.array(z.string().regex(GROUP_NAME)).max(20) },
})

export const draftTools: ToolDef[] = [simulateGrant] as ToolDef[]
