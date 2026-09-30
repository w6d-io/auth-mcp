import { z } from 'zod'
import { defineTool, type ToolDef } from '../registry.js'
import { P } from '../permissions.js'
import { seg } from '../../jinbe/client.js'
import type { AuditPage } from '../../jinbe/types.js'

/**
 * The audit trail (jinbe /api/audit, audit/v1 from Loki). Tokens are not bound to an organisation: an
 * optional `org` narrows the search, and jinbe's own scope guard decides what is visible (a platform
 * reader sees every org, an org admin only the orgs they administer).
 * Pseudonymised fields (identifier_hmac, ip_hmac) come back as they are stored — never re-identified.
 */

const DAY_MS = 86_400_000
const ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/
const EVENT = /^[a-z][a-z_]*(\.[a-z_]+)*(\.\*)?$/
const time = z.string().datetime({ offset: true })

export const searchAudit = defineTool({
  name: 'search_audit',
  title: 'Search the audit trail',
  description:
    'Audit events you may read (optionally of one organisation), newest first, filtered by time window (at most 30 days, default the last 24 hours), event, category, result, severity, actor id, target, site or text. Paginated by cursor.',
  scopes: [P.AUDIT_READ],
  input: {
    org: z.string().uuid().optional().describe('Only this organisation'),
    from: time.optional(),
    to: time.optional(),
    event: z.array(z.string().regex(EVENT)).max(10).optional().describe('audit/v1 event keys or prefixes like sites.*'),
    category: z.string().regex(/^[a-z_]{1,32}$/).optional(),
    result: z.enum(['success', 'denied', 'failure', 'error']).optional(),
    severity: z.enum(['info', 'warn', 'high']).optional(),
    actor: z.string().regex(ID).optional().describe('Actor id'),
    target: z.string().regex(/^[A-Za-z0-9._:/ -]{1,256}$/).optional(),
    site: z.string().regex(/^[a-z0-9_-]{1,63}$/).optional(),
    q: z.string().min(1).max(64).optional(),
    limit: z.number().int().min(1).max(100).optional(),
    cursor: z.string().max(1024).optional(),
  },
  async run(args, { jinbe, call }) {
    const to = args.to ?? new Date().toISOString()
    const from = args.from ?? new Date(Date.parse(to) - DAY_MS).toISOString()
    const page = await jinbe.get<AuditPage>(call, '/api/audit/events', {
      from,
      to,
      org: args.org,
      event: args.event,
      category: args.category,
      result: args.result,
      severity: args.severity,
      actor: args.actor,
      target: args.target,
      site: args.site,
      q: args.q,
      limit: args.limit ?? 50,
      cursor: args.cursor,
    })
    return {
      data: { items: page.events, range: page.range, upstreamTruncated: page.truncated },
      nextCursor: page.nextCursor,
      source: 'jinbe:/api/audit/events',
    }
  },
})

export const getAuditEvent = defineTool({
  name: 'get_audit_event',
  title: 'One audit event',
  description: 'One audit event by id, if it is in your scope (out of scope and absent read the same).',
  scopes: [P.AUDIT_READ],
  input: { eventId: z.string().uuid(), ts: time.optional().describe('The event time, to narrow the search') },
  async run(args, { jinbe, call }) {
    const data = await jinbe.get<unknown>(call, `/api/audit/events/${seg(args.eventId)}`, { ts: args.ts })
    return { data, source: 'jinbe:/api/audit/events/:id' }
  },
})

export const auditTools: ToolDef[] = [searchAudit, getAuditEvent] as ToolDef[]
