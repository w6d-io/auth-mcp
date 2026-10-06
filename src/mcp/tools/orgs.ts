import { z } from 'zod'
import { defineTool, type ToolContext, type ToolDef } from '../registry.js'
import { P } from '../permissions.js'
import { hasScope } from '../../auth/scopes.js'
import { seg } from '../../jinbe/client.js'
import { ToolError } from '../../safety/errors.js'
import { paginate, MAX_LIMIT } from '../../safety/pagination.js'
import type {
  MyOrganizations, MyPermissions, OrgMemberGrants, OrgMemberRoles, OrgRoles, OrgUsers, PlatformOrganization,
} from '../../jinbe/types.js'

/**
 * Organisation tools. A token is NOT bound to an organisation (owner decision: a personal key inherits
 * its holder's rights): each org tool names its org explicitly, and jinbe decides — membership, the
 * caller's org roles there, platform roles reaching every org — whether this person may act there. The
 * uuid check here only stops a malformed path; it is not the enforcement.
 *
 * An org role is `<app>:<role>` (jinbe's owner, member_manager, key_manager, auditor, viewer; a site's
 * come from its intent), assigned per member per organisation. These tools only read.
 */

const orgPath = (org: string) => `/api/organizations/${seg(org)}`
const org = z.string().uuid().describe('The organisation id (see list_orgs)')
const page = {
  limit: z.number().int().min(1).max(MAX_LIMIT).optional(),
  cursor: z.string().max(256).optional(),
}

/** A read that may be refused: the refusal comes back instead of failing the whole tool. */
async function attempt<T>(read: () => Promise<T>): Promise<{ ok: T } | { err: ToolError }> {
  try {
    return { ok: await read() }
  } catch (err) {
    if (err instanceof ToolError) return { err }
    throw err
  }
}

/** The caller's org permissions per org id (best effort: null when jinbe does not say). */
async function myOrgPermissions(ctx: ToolContext): Promise<MyPermissions | null> {
  const r = await attempt(() => ctx.jinbe.get<MyPermissions>(ctx.call, '/api/me/permissions', { orgLimit: '1000' }))
  return 'ok' in r && r.ok.orgPermissions ? r.ok : null
}

function displayName(traits: Record<string, unknown>): string | null {
  const name = traits.name
  if (typeof name === 'string') return name
  if (!name || typeof name !== 'object') return null
  const { first, last } = name as { first?: unknown; last?: unknown }
  return [first, last].filter((x) => typeof x === 'string').join(' ') || null
}

const emailOf = (traits: Record<string, unknown>) => (typeof traits.email === 'string' ? traits.email : null)

export const listOrgs = defineTool({
  name: 'list_orgs',
  title: 'My organisations',
  description:
    'The organisations you belong to, with their names and what you may do in each (your org permissions there: from your org roles, ' +
    'direct grants there, and platform roles that reach every org) — the ids the other org tools take.',
  scopes: [P.MCP],
  input: {},
  async run(_args, ctx) {
    const [me, perms] = await Promise.all([ctx.jinbe.get<MyOrganizations>(ctx.call, '/api/me/organizations'), myOrgPermissions(ctx)])
    const next = perms?.orgPermissionsPage?.next
    // Sorted by org id and paged: an org past the last page read is unknown, not empty.
    const permissionsIn = (id: string) => (!perms ? null : (perms.orgPermissions?.[id] ?? (next && id > next ? null : [])))
    const items = me.organizations.map((id) => ({ id, name: me.names?.[id] ?? null, permissions: permissionsIn(id) }))
    const notes = perms
      ? ['permissions: [] means you belong there but hold no org permission (not even org.members:read).']
      : ['What you may do in each organisation was not reported (permissions: null); get_org tells per organisation.']
    return { data: { items }, notes, source: `jinbe:/api/me/organizations${perms ? '+/api/me/permissions' : ''}` }
  },
})

export const getOrg = defineTool({
  name: 'get_org',
  title: 'One organisation',
  description:
    'One organisation: its name and whether you belong to it; with orgs:read, its owners (identity ids holding jinbe:owner), the sites ' +
    'it is entitled to and its tenant; with org.members:read there, its org roles (`<app>:<role>`), the permissions each gives and ' +
    'which you may assign.',
  scopes: [P.ORGS_READ, P.ORG_MEMBERS_READ],
  input: { org },
  async run(args, ctx) {
    const { jinbe, call, principal } = ctx
    const me = await jinbe.get<MyOrganizations>(call, '/api/me/organizations')
    const [platform, roles] = await Promise.all([
      hasScope(principal.scopes, P.ORGS_READ) ? attempt(() => jinbe.get<PlatformOrganization>(call, `/api/admin/organizations/${seg(args.org)}`)) : null,
      hasScope(principal.scopes, P.ORG_MEMBERS_READ) ? attempt(() => jinbe.get<OrgRoles>(call, `${orgPath(args.org)}/roles`)) : null,
    ])
    const refusals = [platform, roles].flatMap((r) => (r && 'err' in r ? [r.err] : []))
    // An organisation that does not exist is that, whatever else answered.
    const missing = refusals.find((e) => e.body.code === 'not_found')
    if (missing) throw missing
    const p = platform && 'ok' in platform ? platform.ok : null
    const r = roles && 'ok' in roles ? roles.ok : null
    if (!p && !r) throw refusals[0]

    const notes: string[] = []
    if (r) notes.push('Org roles are assigned per member in this organisation; assignable says whether you may hand one out here. Who holds which: list_org_member_roles.')
    // Partial answers say which half is missing and why.
    if (!r && roles && 'err' in roles) notes.push(`No org roles: ${roles.err.body.code === 'forbidden' ? 'your account may not read this organisation\'s members (org.members:read there)' : roles.err.body.message}.`)
    if (!p && platform && 'err' in platform) notes.push(`No platform view (owners, sites): ${platform.err.body.code === 'forbidden' ? 'your account does not hold orgs:read' : platform.err.body.message}.`)
    return {
      data: {
        id: args.org,
        name: p?.name ?? me.names?.[args.org] ?? null,
        member: me.organizations.includes(args.org),
        platform: p ? { tenant: p.tenant ?? null, owners: p.owners ?? [], sites: p.sites ?? [], applications: p.applications ?? [] } : null,
        roles: r ? (r.roles ?? []).map((x) => ({ role: x.role, permissions: x.permissions ?? [], assignable: x.assignable === true })) : null,
      },
      notes,
      source: ['jinbe:/api/me/organizations', p && '/api/admin/organizations/:id', r && '/api/organizations/:org/roles'].filter(Boolean).join('+'),
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
      const traits = (u.traits ?? {}) as Record<string, unknown>
      return { id: u.id, email: emailOf(traits), name: displayName(traits), state: u.state ?? null }
    })
    const p = paginate(rows, { limit: args.limit, cursor: args.cursor, query: `list_org_users:${args.org}:${args.email ?? ''}` })
    return { data: { items: p.items, total: p.total }, nextCursor: p.nextCursor, source: 'jinbe:/api/organizations/:org/users' }
  },
})

export const listOrgMemberRoles = defineTool({
  name: 'list_org_member_roles',
  title: 'Who holds which org roles',
  description:
    'The org roles (`<app>:<role>`) each member of one organisation holds there. With userId, that one member\'s roles and direct ' +
    'grants in this organisation (roles or permissions held without an org role, with expiry).',
  scopes: [P.ORG_MEMBERS_READ],
  input: {
    org,
    userId: z.string().uuid().optional().describe('One member (identity id, see list_org_users): adds their direct grants here'),
    email: z.string().max(320).optional().describe('Exact email (credentials identifier) to look up'),
    ...page,
  },
  async run(args, { jinbe, call }) {
    if (args.userId) {
      const base = `${orgPath(args.org)}/users/${seg(args.userId)}`
      const [roles, grants] = await Promise.all([
        jinbe.get<OrgMemberRoles>(call, `${base}/roles`),
        jinbe.get<OrgMemberGrants>(call, `${base}/grants`),
      ])
      const directGrants = (grants.grants ?? []).map((g) => ({
        id: g.id ?? null, app: g.app ?? null, kind: g.kind ?? null, name: g.name ?? null, active: g.active !== false,
        expiresAt: g.expiresAt ?? null, grantedBy: g.grantedBy ?? null, reason: g.reason ?? null,
      }))
      return {
        data: { items: [{ id: args.userId, email: grants.email ?? null, roles: roles.roles ?? [], directGrants }], total: 1 },
        source: 'jinbe:/api/organizations/:org/users/:id/roles+/grants',
      }
    }
    const res = await jinbe.get<OrgUsers>(call, `${orgPath(args.org)}/users`, { credentials_identifier: args.email, page_size: '250' })
    const rows = (res.data ?? []).map((u) => ({ id: u.id, email: emailOf((u.traits ?? {}) as Record<string, unknown>), roles: u.roles ?? [] }))
    const p = paginate(rows, { limit: args.limit, cursor: args.cursor, query: `list_org_member_roles:${args.org}:${args.email ?? ''}` })
    return {
      data: { items: p.items, total: p.total },
      nextCursor: p.nextCursor,
      notes: ['Direct grants are per member: call again with userId. What each role gives: get_org.'],
      source: 'jinbe:/api/organizations/:org/users',
    }
  },
})

export const orgTools: ToolDef[] = [listOrgs, getOrg, listOrgUsers, listOrgMemberRoles] as ToolDef[]
