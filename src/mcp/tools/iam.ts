import { z } from 'zod'
import { defineTool, type ToolDef } from '../registry.js'
import { P } from '../permissions.js'
import { seg } from '../../jinbe/client.js'
import { paginate, MAX_LIMIT } from '../../safety/pagination.js'
import { SERVICE_NAME } from '../../safety/untrusted.js'
import type { GroupDefinition, MyPermissions } from '../../jinbe/types.js'

const RBAC = '/api/admin/rbac'
const service = z.string().regex(SERVICE_NAME, 'a service name')
const page = {
  limit: z.number().int().min(1).max(MAX_LIMIT).optional(),
  cursor: z.string().max(256).optional(),
}

export const listGroups = defineTool({
  name: 'list_groups',
  title: 'List groups',
  description: 'Group definitions: each group and the roles it gives per service.',
  scopes: [P.GROUPS_READ],
  input: { query: z.string().max(64).optional().describe('Substring of the group name'), ...page },
  async run(args, { jinbe, call }) {
    const { groups } = await jinbe.get<{ groups: GroupDefinition[] }>(call, `${RBAC}/groups`)
    const q = args.query?.toLowerCase()
    const rows = groups.filter((g) => !q || g.name.includes(q))
    const p = paginate(rows, { limit: args.limit, cursor: args.cursor, query: `list_groups:${q ?? ''}` })
    return { data: { items: p.items, total: p.total }, nextCursor: p.nextCursor, source: `jinbe:${RBAC}/groups` }
  },
})

export const listServices = defineTool({
  name: 'list_services',
  title: 'List services',
  description: 'Services known to the access model (each plugged site is one).',
  scopes: [P.SITES_READ],
  input: { ...page },
  async run(args, { jinbe, call }) {
    const { services } = await jinbe.get<{ services: unknown[] }>(call, `${RBAC}/services`)
    const p = paginate(services, { limit: args.limit, cursor: args.cursor, query: 'list_services' })
    return { data: { items: p.items, total: p.total }, nextCursor: p.nextCursor, source: `jinbe:${RBAC}/services` }
  },
})

export const listRoles = defineTool({
  name: 'list_roles',
  title: 'Roles of a service',
  description: "A service's roles and the permissions each grants.",
  scopes: [P.SITES_READ],
  input: { service },
  async run(args, { jinbe, call }) {
    const data = await jinbe.get<unknown>(call, `${RBAC}/services/${seg(args.service)}/roles`)
    return { data, source: `jinbe:${RBAC}/services/:name/roles` }
  },
})

export const getPermissionCatalog = defineTool({
  name: 'get_permission_catalog',
  title: 'Permission catalog of a service',
  description: 'Every permission a service defines (from its roles and routes), to reason about what a grant would give.',
  scopes: [P.SITES_READ],
  input: { service },
  async run(args, { jinbe, call }) {
    const data = await jinbe.get<unknown>(call, `${RBAC}/services/${seg(args.service)}/permissions`)
    return { data, source: `jinbe:${RBAC}/services/:name/permissions` }
  },
})

export const getMyPermissions = defineTool({
  name: 'get_my_permissions',
  title: 'My effective permissions',
  description:
    'What your account holds on the platform (groups, roles, permissions), as the policy engine resolves it. This connection can use only the part covered by its granted scopes (see get_my_identity).',
  scopes: [P.MCP],
  input: {},
  async run(_args, { jinbe, call }) {
    const me = await jinbe.get<MyPermissions>(call, '/api/me/permissions')
    return { data: { groups: me.groups, roles: me.roles, permissions: me.permissions, actions: me.actions ?? {} }, source: 'jinbe:/api/me/permissions' }
  },
})

export const iamTools: ToolDef[] = [listGroups, listServices, listRoles, getPermissionCatalog, getMyPermissions] as ToolDef[]
