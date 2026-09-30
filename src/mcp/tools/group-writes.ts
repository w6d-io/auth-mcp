import { z } from 'zod'
import { defineTool, type ToolDef } from '../registry.js'
import { P } from '../permissions.js'
import { seg } from '../../jinbe/client.js'
import { toolError } from '../../safety/errors.js'
import { GROUP_NAME, SERVICE_NAME } from '../../safety/untrusted.js'
import type { GroupDefinition } from '../../jinbe/types.js'
import { idempotencyKey, obj } from './write-common.js'

/**
 * The access model: create and edit groups, and replace a service's roles (jinbe /api/admin/rbac,
 * `groups:write`, PROTECTED: a key created with protected actions allowed). Never a delete: a group is
 * removed in the console. jinbe's escalation guard decides what a caller may hand out.
 *
 * No bare `*` from here: a role or group granting everything is made by a person in the console.
 */

const RBAC = '/api/admin/rbac'
const SCOPES = [P.GROUPS_WRITE]
const roleName = z.string().regex(/^[a-z][a-z0-9_-]{0,39}$/, 'a role name')
const permission = z.string().max(128).regex(/^[a-z][a-z0-9_.-]*:[a-z*][a-z0-9_*-]*$/, 'a permission like resource:verb')
const serviceRoles = z
  .record(z.string().regex(SERVICE_NAME, 'a service name'), z.array(roleName).max(20))
  .refine((m) => Object.keys(m).length <= 50, 'at most 50 services')
  .describe('Service → the roles this group gives on it, e.g. {"billing": ["viewer"]}')

export const createGroup = defineTool({
  name: 'create_group',
  title: 'Create a group',
  description:
    'Create a platform group and the roles it gives per service. Protected: needs a key created with protected actions allowed. Refused when it exists (conflict).',
  scopes: SCOPES,
  write: true,
  protectedAction: true,
  input: {
    name: z.string().max(64).regex(/^[a-z_]+$/, 'lowercase letters and underscores'),
    services: serviceRoles,
    idempotencyKey,
  },
  async run(args, ctx) {
    const res = await ctx.jinbe.write<unknown>(ctx.call, 'POST', `${RBAC}/groups`, {
      body: { name: args.name, services: args.services },
      idempotencyKey: args.idempotencyKey,
    })
    return { data: { name: args.name, services: args.services, created: obj(res.body).success ?? true }, source: `jinbe:${RBAC}/groups` }
  },
})

export const updateGroup = defineTool({
  name: 'update_group',
  title: 'Edit a group',
  description:
    "Change the roles a group gives. mode 'merge' (default) sets the roles of the services you name and keeps the others; 'replace' makes the group exactly what you pass. Never deletes the group. Protected: needs a key created with protected actions allowed.",
  scopes: SCOPES,
  write: true,
  protectedAction: true,
  input: {
    name: z.string().regex(GROUP_NAME),
    services: serviceRoles,
    mode: z.enum(['merge', 'replace']).default('merge'),
    idempotencyKey,
  },
  async run(args, ctx) {
    const { groups } = await ctx.jinbe.get<{ groups: GroupDefinition[] }>(ctx.call, `${RBAC}/groups`)
    const current = (groups ?? []).find((g) => g.name === args.name)
    if (!current) throw toolError('not_found', `No group named ${args.name}: create_group makes one`)
    const services = args.mode === 'replace' ? args.services : { ...current.services, ...args.services }
    await ctx.jinbe.write(ctx.call, 'PUT', `${RBAC}/groups/${seg(args.name)}`, { body: { services }, idempotencyKey: args.idempotencyKey })
    return { data: { name: args.name, before: current.services, after: services }, source: `jinbe:${RBAC}/groups/:name` }
  },
})

export const setSiteRoles = defineTool({
  name: 'set_site_roles',
  title: "Set a site's roles",
  description:
    "Replace the roles a service (a site) defines and the permissions each grants, e.g. {\"viewer\": [\"billing:read\"], \"editor\": [\"billing:read\", \"billing:write\"]}. Returns the roles before and after. Protected: needs a key created with protected actions allowed.",
  scopes: SCOPES,
  write: true,
  protectedAction: true,
  input: {
    service: z.string().regex(SERVICE_NAME),
    roles: z
      .record(roleName, z.array(permission).max(200))
      .refine((m) => Object.keys(m).length >= 1 && Object.keys(m).length <= 40, '1 to 40 roles'),
    idempotencyKey,
  },
  async run(args, ctx) {
    const path = `${RBAC}/services/${seg(args.service)}/roles`
    const before = obj(await ctx.jinbe.get<unknown>(ctx.call, path)).roles ?? null
    await ctx.jinbe.write(ctx.call, 'PUT', path, { body: { roles: args.roles }, idempotencyKey: args.idempotencyKey })
    return {
      data: { service: args.service, before, after: args.roles },
      source: `jinbe:${RBAC}/services/:name/roles`,
      notes: ['For a site, use set_site_access: a site publishes the roles in its intent, so its next publish replaces these.'],
    }
  },
})

export const groupWriteTools: ToolDef[] = [createGroup, updateGroup, setSiteRoles] as ToolDef[]
