import { z } from 'zod'
import { defineTool, type ToolDef } from '../registry.js'
import { P } from '../permissions.js'
import { seg } from '../../jinbe/client.js'
import { toolError } from '../../safety/errors.js'
import { SITES, idempotencyKey, obj, siteName } from './write-common.js'
import { lintOf, putDraft, workingSite } from './site-writes.js'

/**
 * Public sign-up through a site (jinbe sites/signup): its draft settings, what one signed-up person
 * reaches, and who joined. Opening or widening sign-up is published like any change, and needs
 * sites.signup:write on top of the publish — a person, with a second factor proven in a browser.
 * Removing people is the console's (never through MCP).
 */

const roleName = z.string().regex(/^[a-z][a-z0-9_-]{0,39}$/)
const domain = z.string().trim().toLowerCase().regex(/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/, 'a domain like example.com')

type SignUp = { mode: 'closed' | 'open' | 'domains'; domains: string[]; roles: string[]; orgs: 'personal' | 'domain' | 'invite' | 'none' }

/** Role presets as jinbe expands them (render.ts expandRoles, rbac-defaults.ts). */
export function rolePermissions(site: Record<string, unknown>): Record<string, string[]> {
  const name = String(site.name ?? '')
  const routes = obj(site.routes)
  const items = (Array.isArray(routes.items) ? routes.items : []).map(obj)
  const declared = new Set<string>()
  for (const a of [...items.map((r) => obj(r.access)), obj(obj(routes.catchAll).access)]) if (a.kind === 'permission' && typeof a.permission === 'string') declared.add(a.permission)
  const operator = ['list', 'read', 'create', 'update', 'delete', 'execute'].map((v) => `${name}:${v}`)
  const editor = ['list', 'read', 'create', 'update'].map((v) => `${name}:${v}`)
  const viewer = ['list', 'read'].map((v) => `${name}:${v}`)
  const user = ['list', 'read', 'use'].map((v) => `${name}:${v}`)
  const admin = [...new Set([...operator, ...declared])].sort()
  if (site.roles === 'standard') return { admin, editor, viewer, user }
  if (site.roles === 'readonly') return { viewer }
  if (site.roles === 'operator') return { admin, operator, editor, viewer }
  return Object.fromEntries(Object.entries(obj(site.roles)).map(([r, p]) => [r, Array.isArray(p) ? p.map(String) : []]))
}

/** Every route and the catch-all, as one signed-up person with these roles meets them. */
export function signUpReach(site: Record<string, unknown>, roles: readonly string[]) {
  const all = rolePermissions(site)
  const held = roles.filter((r) => all[r])
  const routes = obj(site.routes)
  const reach = (access: Record<string, unknown>) => {
    if (access.kind === 'public') return { reach: 'anyone' }
    if (access.kind === 'signed-in') return { reach: 'any signed-in account' }
    if (access.kind === 'permission') {
      const via = held.filter((r) => all[r].includes(String(access.permission)))
      return via.length ? { reach: 'yes', permission: access.permission, via } : { reach: 'no', permission: access.permission }
    }
    return { reach: 'no' }
  }
  const rows = (Array.isArray(routes.items) ? routes.items : []).map(obj).map((r) => ({
    route: `${(Array.isArray(r.methods) ? r.methods : []).join(' ')} ${String(r.path)}`,
    ...reach(obj(r.access)),
  }))
  rows.push({ route: 'catch-all', ...reach(obj(obj(routes.catchAll).access)) })
  return rows
}

export const setSiteSignUp = defineTool({
  name: 'set_site_signup',
  title: 'Set site sign-up (draft)',
  description:
    "Public sign-up through a site, in its draft: who may create an account from its sign-in page (mode closed, open, or domains with a list), the site roles they get (the <site>-users group; `user` in the standard set), and the organization they land in (personal: their own; domain: the org that proved the email domain; invite: none until invited; none). People join once their address is verified. Publishing a version that opens or widens it needs sites.signup:write on top of the publish (a person, second factor in a browser); closing or narrowing does not.",
  scopes: [P.SITES_WRITE],
  write: true,
  input: {
    name: siteName,
    mode: z.enum(['closed', 'open', 'domains']).optional(),
    domains: z.array(domain).max(100).optional(),
    roles: z.array(roleName).max(20).optional(),
    orgs: z.enum(['personal', 'domain', 'invite', 'none']).optional(),
    idempotencyKey,
  },
  async run(args, ctx) {
    if (!args.mode && !args.domains && !args.roles && !args.orgs) throw toolError('invalid_request', 'Nothing to change')
    const base = await workingSite(ctx, args.name)
    const roles = rolePermissions(base.site)
    const current = obj(base.site.signUp) as Partial<SignUp>
    const signUp: SignUp = {
      mode: args.mode ?? current.mode ?? 'closed',
      domains: args.domains ?? current.domains ?? [],
      roles: args.roles ?? current.roles ?? (roles.user ? ['user'] : roles.viewer ? ['viewer'] : []),
      orgs: args.orgs ?? current.orgs ?? 'personal',
    }
    const unknown = signUp.roles.filter((r) => !roles[r])
    if (unknown.length) throw toolError('invalid_request', `The site defines no role ${unknown.join(', ')} (it has ${Object.keys(roles).join(', ') || 'none'})`)
    if (signUp.roles.includes('admin')) throw toolError('invalid_request', "Giving every sign-up the admin role is a person's decision in the console, not through MCP")
    if (signUp.mode === 'domains' && signUp.domains.length === 0) throw toolError('invalid_request', 'Domains mode needs at least one domain')
    const site = { ...base.site, signUp }
    const draft = await putDraft(ctx, args.name, site, base.baseVersion, args.idempotencyKey, base.etag)
    const notes = ['Nothing is live until the version is saved and published.']
    if (signUp.mode !== 'closed') notes.push('Publishing it needs sites.signup:write as well as sites:apply: publish_site hands the person a link to confirm with their second factor.')
    return { data: { name: args.name, signUp, draft, whatUsersCanDo: signUpReach(site, signUp.roles), lint: lintOf(site) }, source: `jinbe:${SITES}/:name/draft`, notes }
  },
})

export const whatCanUsersDo = defineTool({
  name: 'what_can_users_do',
  title: 'What a signed-up user can do on a site',
  description:
    "Route by route, what one person who signed up through a site reaches with the sign-up roles (or the roles you name): anyone, any signed-in account, yes (through which role, for which permission) or no. Reads the draft when there is one, else the saved site. Changes nothing.",
  scopes: [P.SITES_READ],
  input: { name: siteName, roles: z.array(roleName).max(20).optional().describe('Roles to check instead of the sign-up roles') },
  async run(args, ctx) {
    const base = await workingSite(ctx, args.name)
    const signUp = obj(base.site.signUp) as Partial<SignUp>
    const roles = args.roles ?? signUp.roles ?? []
    return {
      data: { name: args.name, from: base.from, signUp: base.site.signUp ?? null, roles, routes: signUpReach(base.site, roles) },
      source: `jinbe:${SITES}/:name (intent)`,
      notes: roles.length ? [] : ['No sign-up roles yet: set them with set_site_signup.'],
    }
  },
})

export const listSignUpMembers = defineTool({
  name: 'list_signup_members',
  title: 'Who signed up through a site',
  description: "The people in a site's sign-up group (<site>-users): id, email, name, organization, when the account was made; total counts everyone. Removing someone is done by a person in the console.",
  scopes: [P.USERS_READ],
  input: { name: siteName, limit: z.number().int().min(1).max(1000).default(200) },
  async run(args, ctx) {
    const data = await ctx.jinbe.get<unknown>(ctx.call, `${SITES}/${seg(args.name)}/sign-up/members`, { limit: String(args.limit) })
    return { data, source: `jinbe:${SITES}/:name/sign-up/members` }
  },
})

export const siteSignUpTools: ToolDef[] = [setSiteSignUp, whatCanUsersDo, listSignUpMembers] as ToolDef[]
