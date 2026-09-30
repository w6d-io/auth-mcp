import { z } from 'zod'
import { defineTool, type ToolDef } from '../registry.js'
import { P } from '../permissions.js'

/**
 * explain_admin_access (jinbe wave19/admin-explain, POST /api/admin/rbac/explain-route): why a call to
 * a jinbe ADMIN route — the platform's own API, not a site — is allowed or refused, guard by guard,
 * with the exact policy input and where two sources of truth disagree. Access 'self': a connection may
 * explain its own calls with no scope; asking about somebody else needs access:check (jinbe decides).
 * It evaluates, never executes: nothing is written and no write budget is spent.
 */

interface Explained {
  verdict?: { status?: number; allowed?: boolean; code?: string; reason?: string; message?: string }
  decidedBy?: string
  steps?: Array<{ step: string; verdict: string; detail?: unknown }>
  disagreements?: Array<{ kind: string; detail?: string }>
}

const method = z.enum(['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE'])

function notesOf(d: Explained): string[] {
  const notes: string[] = []
  const v = d.verdict ?? {}
  if (v.allowed === true) notes.push('Every guard passes: the handler may still refuse for a reason of its own (validation, conflict).')
  else if (d.decidedBy) notes.push(`Refused by ${d.decidedBy}${v.code ? ` (${v.code})` : ''}.`)
  if (v.code === 'needs_2fa') notes.push('The only failing condition is the second factor: it would pass with one proven in the last 15 minutes (in a browser).')
  if (v.code === 'step_up_unavailable') notes.push('A second factor is required and this kind of connection cannot stand in for it here: see get_my_identity protectedActions.')
  for (const x of d.disagreements ?? []) if (typeof x.detail === 'string') notes.push(`Disagreement (${x.kind}): ${x.detail}`)
  const opa = d.steps?.find((s) => s.step === 'opa')?.detail as { explain?: { available?: boolean } } | undefined
  if (opa?.explain?.available === false) notes.push('The policy engine\'s own explanation is not deployed yet: the verdict stands, the "granted by" detail is inferred.')
  return notes
}

export const explainAdminAccess = defineTool({
  name: 'explain_admin_access',
  title: 'Explain access to a platform API call',
  description:
    "Why a call to the platform's own admin API (METHOD /api/...) is allowed or refused, for you or (with access:check) somebody else, as a session, a key or a machine, at aal1 or aal2: the verdict and the guard that decided, each step (route, catalogue, delegation, policy input and answer, organisation roster, guards), and any disagreement between sources. Evaluates only, runs nothing. For a site's routes use explain_access.",
  scopes: [P.MCP],
  requiresJinbe: 'wave19/admin-explain',
  input: {
    method,
    path: z.string().max(2048).regex(/^\/api\/[^\s?#]*$/, 'a jinbe path like /api/admin/users'),
    subject: z.string().min(1).max(320).optional().describe('An identity id or email; default: you'),
    via: z.enum(['session', 'delegated', 'machine']).optional().describe('How the call arrives; default: this connection (delegated)'),
    aal: z.enum(['aal1', 'aal2']).optional(),
    scopes: z.array(z.string().regex(/^[a-z][a-z0-9_.-]*:[a-z][a-z0-9_-]*$|^mcp$/)).max(100).optional().describe('Delegated: the scopes to assume'),
    clientId: z.string().max(128).optional(),
    body: z.record(z.unknown()).optional().describe('The request body, for guards that read it (e.g. a group change)'),
  },
  async run(args, { jinbe, call }) {
    const data = await jinbe.post<Explained>(call, '/api/admin/rbac/explain-route', args)
    return { data, source: 'jinbe:/api/admin/rbac/explain-route', notes: notesOf(data) }
  },
})

export const adminExplainTools: ToolDef[] = [explainAdminAccess] as ToolDef[]
