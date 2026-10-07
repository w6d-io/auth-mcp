/**
 * Static lint of a Site intent (jinbe sites/schemas.ts), run locally before — and in addition to —
 * jinbe's preview. jinbe's preview answers "is it valid and does it collide" (gatekit compile,
 * overlaps, ties, zones); this answers "is it a secure choice", so the secure config is the easy path:
 * public writes, a public catch-all, no 2FA on privileged writes, allow-all handlers, open CORS. It
 * also says early what jinbe's render would refuse anyway: a gate admitting API tokens without the
 * policy (tokens_need_policy), org features while organizations are off (organizations_off).
 *
 * It also flags the habits of the old way of opening an API to a partner: a permission named with two
 * colons (one colon: resource[.sub]:verb), a required_scope on the token authenticator (the policy
 * decides, from the organization key's scopes), a secret written into a header the gateway adds.
 *
 * And the access names (site-names.ts): roles carrying permissions no route asks, routes no role
 * reaches, the template's roles left over routes asking others, groups not named for what they give.
 *
 * It reads the intent defensively (a draft can be half-written) and never throws on shape.
 */
import { isExpertGate, tokensWithoutPolicy } from './gate-presets.js'
import { lintNames } from './site-names.js'

export type LintLevel = 'high' | 'medium' | 'low'

export interface LintFinding {
  code: string
  level: LintLevel
  message: string
  path?: string
}

type Obj = Record<string, unknown>
const isObj = (v: unknown): v is Obj => !!v && typeof v === 'object' && !Array.isArray(v)
const arr = (v: unknown): unknown[] => (Array.isArray(v) ? v : [])
const str = (v: unknown): string | undefined => (typeof v === 'string' ? v : undefined)

const WRITE_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE'])
const PLATFORM_NAMESPACES = new Set(['auth', 'kube-system', 'kube-public', 'default', 'cert-manager', 'envoy-gateway-system'])

/** A permission as the platform names it: exactly one colon, `resource[.sub]:verb` (jinbe valid_permission). */
export const PERMISSION_NAME = /^[a-z][a-z0-9_.-]{0,127}:[a-z][a-z0-9_-]{0,127}$/

/** A header the gateway must never add from a literal: credentials belong to the caller, not the draft. */
const SECRET_HEADER = /^(authorization|proxy-authorization|cookie)$|token|secret|password|api[-_]?key/i

function accessKind(access: unknown): string | undefined {
  return isObj(access) ? str(access.kind) : undefined
}

function handlerName(h: unknown): string | undefined {
  return isObj(h) ? str(h.handler) : undefined
}

/** Anywhere in a handler config: allowed_origins containing '*', or an Access-Control-Allow-Origin: * header. */
function hasOpenCors(value: unknown, depth = 0): boolean {
  if (depth > 8) return false
  if (Array.isArray(value)) return value.some((v) => hasOpenCors(v, depth + 1))
  if (!isObj(value)) return false
  for (const [k, v] of Object.entries(value)) {
    const key = k.toLowerCase()
    if ((key === 'allowed_origins' || key === 'allow_origins') && arr(v).includes('*')) return true
    if (key === 'access-control-allow-origin' && (v === '*' || arr(v).includes('*'))) return true
    if (hasOpenCors(v, depth + 1)) return true
  }
  return false
}

export function lintSite(intent: unknown): LintFinding[] {
  const out: LintFinding[] = []
  const add = (code: string, level: LintLevel, message: string, path?: string) => out.push({ code, level, message, ...(path ? { path } : {}) })
  if (!isObj(intent)) return [{ code: 'not_an_object', level: 'high', message: 'The site intent must be an object' }]

  const address = isObj(intent.address) ? intent.address : {}
  const host = str(address.host) ?? ''
  if (host.includes('*')) add('wildcard_host', 'high', 'A wildcard host serves every name under it; give the site one host', 'address.host')

  const upstream = isObj(intent.upstream) ? intent.upstream : {}
  const ns = str(upstream.namespace)
  if (ns && PLATFORM_NAMESPACES.has(ns)) add('upstream_platform_namespace', 'medium', `The upstream is in the platform namespace '${ns}'`, 'upstream.namespace')

  const routes = isObj(intent.routes) ? intent.routes : {}
  const items = arr(routes.items)
  let privilegedWrites = false
  items.forEach((r, i) => {
    if (!isObj(r)) return
    const methods = arr(r.methods).map(String)
    const writes = methods.some((m) => WRITE_METHODS.has(m))
    const kind = accessKind(r.access)
    const path = str(r.path) ?? ''
    if (kind === 'public' && writes) add('public_write_route', 'high', 'A route anyone can write to without signing in', `routes.items[${i}]`)
    else if (kind === 'public' && path.endsWith(':any*')) add('public_wildcard_path', 'medium', 'A public route with a trailing wildcard exposes everything under it', `routes.items[${i}].path`)
    if (kind === 'signed-in' && writes) add('signed_in_write_route', 'medium', 'Any signed-in account can write here; require a permission instead', `routes.items[${i}].access`)
    if (kind === 'permission' && writes) privilegedWrites = true
  })

  const badPermission = (access: unknown, path: string) => {
    const p = isObj(access) && access.kind === 'permission' ? str(access.permission) : undefined
    if (p !== undefined && !p.includes('*') && !PERMISSION_NAME.test(p)) add('permission_name', 'high', `'${p}' is not a permission name: exactly one colon, resource[.sub]:verb (like earnings.external:read)`, path)
  }
  items.forEach((r, i) => { if (isObj(r)) badPermission(r.access, `routes.items[${i}].access.permission`) })

  const catchAll = isObj(routes.catchAll) ? routes.catchAll : {}
  badPermission(catchAll.access, 'routes.catchAll.access.permission')
  const catchKind = accessKind(catchAll.access)
  if (catchKind === 'public') add('public_catch_all', 'high', 'Every path not listed is public; make the catch-all deny or a permission', 'routes.catchAll.access')
  else if (catchKind === 'signed-in') add('signed_in_catch_all', 'medium', 'Every path not listed is open to any signed-in account', 'routes.catchAll.access')

  arr(intent.gates).forEach((g, i) => {
    if (!isObj(g)) return
    if (tokensWithoutPolicy(g.authenticators, g.authorizer)) {
      add('tokens_need_policy', 'high', "The gate admits API tokens but lets them pass without the policy: any organization's key would get in, and the platform refuses it. Set pass to policy", `gates[${i}].authorizer`)
    }
    const authenticators = arr(g.authenticators).map(handlerName)
    if (authenticators.includes('noop')) add('noop_authenticator', 'high', 'The noop authenticator lets every request through unauthenticated', `gates[${i}].authenticators`)
    if (authenticators.includes('anonymous')) add('anonymous_authenticator', 'medium', 'The anonymous authenticator admits callers without credentials', `gates[${i}].authenticators`)
    if (handlerName(g.authorizer) === 'allow') add('allow_authorizer', 'high', 'The allow authorizer skips the policy: nobody is ever refused', `gates[${i}].authorizer`)
    if (isObj(g.expert) && g.expert.matchUrl) add('expert_match_url', 'low', 'A raw match URL bypasses the route model; review it by hand', `gates[${i}].expert.matchUrl`)
    else if (isExpertGate(g)) add('expert_gate_used', 'medium', 'A hand-built gate (not a who/pass/gets/fails preset): review its handlers by hand', `gates[${i}]`)
    if (hasOpenCors([g.authenticators, g.authorizer, g.mutators, g.errors])) add('open_cors', 'medium', 'CORS allows any origin', `gates[${i}]`)
    arr(g.authenticators).forEach((a, j) => {
      const config = isObj(a) && isObj(a.config) ? a.config : null
      if (!config || config.required_scope === undefined) return
      const at = `gates[${i}].authenticators[${j}].config.required_scope`
      add('required_scope_on_gate', 'medium', "The token authenticator asks a required_scope: let the policy decide instead (routes ask a permission; the platform expands an organization key's scopes)", at)
      for (const scope of arr(config.required_scope)) {
        if (typeof scope === 'string' && scope.split(':').length > 2) add('permission_name', 'high', `'${scope}' has two colons: a permission has exactly one (resource[.sub]:verb)`, at)
      }
    })
    arr(g.mutators).forEach((m, j) => {
      const headers = handlerName(m) === 'header' && isObj(m) && isObj(m.config) && isObj(m.config.headers) ? m.config.headers : {}
      for (const [name, value] of Object.entries(headers)) {
        if (!SECRET_HEADER.test(name) || typeof value !== 'string' || value.includes('{{')) continue
        add('secret_in_header', 'high', `The gateway would add '${name}' from a value written in the draft: every site editor and the audit can read it. Callers bring their own credentials (an organization key); the service reads X-Org-Id and X-Client-Id`, `gates[${i}].mutators[${j}].config.headers`)
      }
    })
  })

  const organizations = isObj(intent.organizations) ? intent.organizations : {}
  if (organizations.enabled !== true) {
    const groups = isObj(intent.groups) ? intent.groups : {}
    const uses = [
      items.some((r) => isObj(r) && !!r.orgParam) && 'routes scoped to an organization (orgParam)',
      isObj(groups.orgGrantable) && Object.keys(groups.orgGrantable).length > 0 && 'org roles (groups.orgGrantable)',
      isObj(intent.everyOrg) && Object.keys(intent.everyOrg).length > 0 && 'everyOrg',
      arr(intent.orgs).length > 0 && 'served organizations (orgs)',
      isObj(intent.signUp) && intent.signUp.orgs !== undefined && intent.signUp.orgs !== 'none' && 'sign-up into an organization (signUp.orgs)',
    ].filter((x): x is string => !!x)
    if (uses.length) add('organizations_off', 'high', `Organizations are off but the site uses ${uses.join(', ')}: the platform refuses it. Turn them on (set_site_organizations)`, 'organizations')
  }

  const roles = intent.roles
  if (isObj(roles) && Object.values(roles).some((perms) => arr(perms).includes('*'))) {
    add('role_wildcard', 'high', "A role grants '*' (every permission of the site)", 'roles')
  }

  const login = isObj(intent.login) ? intent.login : null
  const twoFactor = login && isObj(login.twoFactor) ? login.twoFactor : null
  const tfScope = twoFactor ? str(twoFactor.scope) : 'none'
  if (privilegedWrites && (!tfScope || tfScope === 'none')) {
    add('no_two_factor_on_writes', 'medium', 'Permission-gated writes without a second factor; set login.twoFactor.scope to writes or all', 'login.twoFactor')
  }
  if (twoFactor && tfScope !== 'none' && twoFactor.clients === 'exempt') {
    add('two_factor_clients_exempt', 'low', 'Machine clients are exempt from the second factor', 'login.twoFactor.clients')
  }
  if (login && login.reach === 'any-account') add('any_account_reach', 'medium', 'Any account can sign in to this site, granted or not', 'login.reach')

  out.push(...lintNames(intent))
  return out
}

export function summarize(findings: readonly LintFinding[]): Record<LintLevel, number> {
  return {
    high: findings.filter((f) => f.level === 'high').length,
    medium: findings.filter((f) => f.level === 'medium').length,
    low: findings.filter((f) => f.level === 'low').length,
  }
}
