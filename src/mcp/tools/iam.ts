import { z } from 'zod'
import { defineTool, type ToolContext, type ToolDef } from '../registry.js'
import { ToolError } from '../../safety/errors.js'
import { obj } from './write-common.js'
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
  description:
    "Group definitions: each group, the roles it gives per service, and whether the group requires its members to use 2FA (secondFactor.required, the group's \"Members must use 2FA\" switch: members sign in with a second factor, and nobody joins before setting one up; source says whether it was set for the group or is the default). The switch is changed only by a super admin in the console, never through MCP.",
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

/**
 * jinbe's own permissions carry their second-factor rule (GET /api/catalog: stepUpRule per permission,
 * stepUpPermissions per staff role). Best effort: without it the answer is the service's roles alone.
 */
interface Catalog {
  permissions?: Array<{ name: string; stepUpRule?: unknown; fourEyes?: unknown }>
  roles?: Array<{ name: string; stepUpPermissions?: string[] }>
}
async function catalogOf(ctx: ToolContext): Promise<Catalog | null> {
  try {
    return await ctx.jinbe.get<Catalog>(ctx.call, '/api/catalog')
  } catch (err) {
    if (err instanceof ToolError) return null
    throw err
  }
}

export const listRoles = defineTool({
  name: 'list_roles',
  title: 'Roles of a service',
  description:
    "A service's roles and the permissions each grants. For jinbe (the platform itself), also the permissions of each role that need a recent second factor (stepUpPermissions).",
  scopes: [P.SITES_READ],
  input: { service },
  async run(args, ctx) {
    const data = await ctx.jinbe.get<{ roles?: Array<{ name: string; permissions?: string[] }> } & Record<string, unknown>>(ctx.call, `${RBAC}/services/${seg(args.service)}/roles`)
    if (args.service === 'jinbe' && Array.isArray(data.roles)) {
      const stepUp = new Set(((await catalogOf(ctx))?.permissions ?? []).filter((p) => obj(p.stepUpRule).required === true).map((p) => p.name))
      if (stepUp.size) data.roles = data.roles.map((r) => ({ ...r, stepUpPermissions: (r.permissions ?? []).filter((p) => stepUp.has(p)) }))
    }
    return { data, source: `jinbe:${RBAC}/services/:name/roles` }
  },
})

export const getPermissionCatalog = defineTool({
  name: 'get_permission_catalog',
  title: 'Permission catalog of a service',
  description: 'Every permission a service defines (from its roles and routes), to reason about what a grant would give.',
  scopes: [P.SITES_READ],
  input: { service },
  async run(args, ctx) {
    const data = await ctx.jinbe.get<unknown>(ctx.call, `${RBAC}/services/${seg(args.service)}/permissions`)
    if (args.service !== 'jinbe') return { data, source: `jinbe:${RBAC}/services/:name/permissions` }
    // jinbe's own permissions: each with its second-factor rule {required, maxAgeMin, viaPersonalKey, fourEyes}.
    const rules = Object.fromEntries(((await catalogOf(ctx))?.permissions ?? []).filter((p) => p.stepUpRule).map((p) => [p.name, p.stepUpRule]))
    return { data: { permissions: data, stepUpRules: rules }, source: `jinbe:${RBAC}/services/:name/permissions+/api/catalog` }
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
    return {
      data: { groups: me.groups, roles: me.roles, permissions: me.permissions, actions: me.actions ?? {}, ...(me.secondFactor !== undefined ? { secondFactor: me.secondFactor } : {}) },
      source: 'jinbe:/api/me/permissions',
    }
  },
})

export const getSecondFactorMap = defineTool({
  name: 'get_second_factor_map',
  title: 'Where a second factor is required',
  description:
    'Every second-factor rule in one read: sign-in (groups that must use one), step-up (permissions that need one proven in the last 15 minutes, and which a personal key can stand in for), roles, sites (their login 2FA scope) and limits. A section you may not read is null and named in unavailable.',
  scopes: [P.GROUPS_READ, P.SITES_READ],
  input: {},
  async run(_args, { jinbe, call }) {
    return { data: await jinbe.get<unknown>(call, `${RBAC}/second-factor-map`), source: `jinbe:${RBAC}/second-factor-map` }
  },
})

export const iamTools: ToolDef[] = [getSecondFactorMap, listGroups, listServices, listRoles, getPermissionCatalog, getMyPermissions] as ToolDef[]
