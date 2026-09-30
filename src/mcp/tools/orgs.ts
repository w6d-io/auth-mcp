import { z } from 'zod'
import { defineTool, type ToolDef } from '../registry.js'
import { P } from '../permissions.js'
import { seg } from '../../jinbe/client.js'
import { paginate, MAX_LIMIT } from '../../safety/pagination.js'
import type { AssignableGroups, MyOrganizations, OrgUsers } from '../../jinbe/types.js'

/**
 * Organisation tools. A token is NOT bound to an organisation (owner decision: a personal key inherits
 * its holder's rights): each org tool names its org explicitly, and jinbe decides — membership, org
 * grants, the org's admin roster — whether this person may act there. The uuid check here only stops
 * a malformed path; it is not the enforcement.
 */

const orgPath = (org: string) => `/api/organizations/${seg(org)}`
const org = z.string().uuid().describe('The organisation id (see list_orgs)')
const page = {
  limit: z.number().int().min(1).max(MAX_LIMIT).optional(),
  cursor: z.string().max(256).optional(),
}

export const listOrgs = defineTool({
  name: 'list_orgs',
  title: 'My organisations',
  description: 'The organisations your account administers, with their names — the ids the other org tools take.',
  scopes: [P.MCP],
  input: {},
  async run(_args, { jinbe, call }) {
    const me = await jinbe.get<MyOrganizations>(call, '/api/me/organizations')
    const items = me.organizations.map((id) => ({ id, name: me.names?.[id] ?? null }))
    return { data: { items }, source: 'jinbe:/api/me/organizations' }
  },
})

export const getOrg = defineTool({
  name: 'get_org',
  title: 'One organisation',
  description: 'One organisation: its name and the groups you may grant in it, with their roles per service.',
  scopes: [P.ORG_MEMBERS_READ],
  input: { org },
  async run(args, { jinbe, call }) {
    const [me, assignable] = await Promise.all([
      jinbe.get<MyOrganizations>(call, '/api/me/organizations'),
      jinbe.get<AssignableGroups>(call, `${orgPath(args.org)}/assignable-groups`),
    ])
    return {
      data: { id: args.org, name: me.names?.[args.org] ?? null, assignableGroups: assignable.groups },
      source: 'jinbe:/api/organizations/:org/assignable-groups',
    }
  },
})

export const listOrgUsers = defineTool({
  name: 'list_org_users',
  title: 'Members of an organisation',
  description: 'Members of one organisation: id, email, name and state only (no traits dump, no credentials).',
  scopes: [P.ORG_MEMBERS_READ],
  input: {
    org,
    email: z.string().max(320).optional().describe('Exact email (credentials identifier) to look up'),
    ...page,
  },
  async run(args, { jinbe, call }) {
    const res = await jinbe.get<OrgUsers>(call, `${orgPath(args.org)}/users`, {
      credentials_identifier: args.email,
      page_size: '250',
    })
    const rows = (res.data ?? []).map((u) => {
      const traits = (u.traits ?? {}) as { email?: unknown; name?: unknown }
      const name = traits.name
      const display =
        typeof name === 'string'
          ? name
          : name && typeof name === 'object'
            ? [(name as { first?: unknown }).first, (name as { last?: unknown }).last].filter((x) => typeof x === 'string').join(' ') || null
            : null
      return { id: u.id, email: typeof traits.email === 'string' ? traits.email : null, name: display, state: u.state ?? null }
    })
    const p = paginate(rows, { limit: args.limit, cursor: args.cursor, query: `list_org_users:${args.org}:${args.email ?? ''}` })
    return { data: { items: p.items, total: p.total }, nextCursor: p.nextCursor, source: 'jinbe:/api/organizations/:org/users' }
  },
})

export const listOrgGrants = defineTool({
  name: 'list_org_grants',
  title: 'Grants in an organisation',
  description: 'The groups handed out in one organisation, per member.',
  scopes: [P.ORG_MEMBERS_READ],
  input: { org, ...page },
  async run(args, { jinbe, call }) {
    const { grants } = await jinbe.get<{ grants: Record<string, string[]> }>(call, `${orgPath(args.org)}/grants`)
    const rows = Object.entries(grants ?? {}).map(([member, groups]) => ({ member, groups }))
    const p = paginate(rows, { limit: args.limit, cursor: args.cursor, query: `list_org_grants:${args.org}` })
    return { data: { items: p.items, total: p.total }, nextCursor: p.nextCursor, source: 'jinbe:/api/organizations/:org/grants' }
  },
})

export const orgTools: ToolDef[] = [listOrgs, getOrg, listOrgUsers, listOrgGrants] as ToolDef[]
