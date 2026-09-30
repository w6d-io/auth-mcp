/**
 * New-site templates, the same ones kuma's wizard offers (kuma src/lib/sites/templates.ts): a name, an
 * address and an upstream become a complete intent — gates, routes, a catch-all, standard roles. Every
 * template has a catch-all, so a site never goes live answering 404 everywhere. Keep in step with kuma.
 */
import { buildGate } from './gate-presets.js'

export type TemplateId = 'web-api' | 'app' | 'api' | 'spa-api' | 'public' | 'empty'
export const TEMPLATE_IDS = ['web-api', 'app', 'api', 'spa-api', 'public', 'empty'] as const

type Obj = Record<string, unknown>

// kuma's template gates, from the same presets (gate-presets.ts).
const PUBLIC_GATE = buildGate({ id: 'public', label: 'Public', who: 'anyone', pass: 'everyone', gets: 'nothing', fails: 'platform', methods: ['GET', 'HEAD'] })
const BROWSER_GATE = buildGate({ id: 'browser', label: 'Browser', who: 'signed-in', pass: 'policy', gets: 'identity', fails: 'website' })
const API_GATE = buildGate({ id: 'api', label: 'API', who: 'tokens', pass: 'policy', gets: 'identity', fails: 'api', preflight: true })
const SPA_API_GATE = buildGate({ id: 'api', label: 'API', who: 'signed-in-or-tokens', pass: 'policy', gets: 'identity', fails: 'api', preflight: true })

const publicRoute = (id: string, path: string): Obj => ({ id, methods: ['GET', 'HEAD'], path, gate: 'public', access: { kind: 'public' }, source: 'template' })
const ASSETS = [publicRoute('assets', '/assets/:any*'), publicRoute('favicon', '/favicon.ico'), publicRoute('health', '/health'), publicRoute('robots', '/robots.txt')]
const apiRoute = (prefix: string): Obj => ({
  id: 'api', methods: ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE'], path: `${prefix}/api/:any*`, gate: 'api', access: { kind: 'signed-in' }, source: 'template',
})

export interface SiteBasics {
  name: string
  displayName: string
  host: string
  pathPrefix?: string
  service: string
  namespace: string
  port: number
  scheme?: 'http' | 'https'
}

const under = (prefix: string | undefined, r: Obj): Obj => (prefix ? { ...r, path: r.path === '/' ? prefix : `${prefix}${String(r.path)}` } : r)
const signedIn = { gate: 'browser', access: { kind: 'signed-in' } }

export function buildSite(template: TemplateId, b: SiteBasics): Obj {
  const prefix = b.pathPrefix || undefined
  const base: Obj = {
    name: b.name,
    displayName: b.displayName || b.name,
    address: { host: b.host, ...(prefix ? { pathPrefix: prefix } : {}) },
    upstream: { service: b.service, namespace: b.namespace, port: b.port, ...(b.scheme ? { scheme: b.scheme } : {}) },
    exposure: { mode: 'zone' },
    roles: 'standard',
    groups: { platform: {}, orgGrantable: {} },
    orgs: [],
    login: { twoFactor: { scope: 'none', clients: 'exempt' }, reach: 'granted' },
    state: 'active',
  }
  const items = (rs: Obj[]) => rs.map((r) => under(prefix, r))
  switch (template) {
    case 'public':
      return { ...base, upstream: { ...(base.upstream as Obj), preserveHost: true }, gates: [PUBLIC_GATE], routes: { items: [], catchAll: { gate: 'public', access: { kind: 'public' } } } }
    case 'app':
      return { ...base, gates: [PUBLIC_GATE, BROWSER_GATE], routes: { items: items(ASSETS), catchAll: signedIn } }
    case 'api':
      return {
        ...base,
        gates: [{ ...PUBLIC_GATE, errors: 'api' }, API_GATE],
        routes: { items: items([publicRoute('health', '/health')]), catchAll: { gate: 'api', access: { kind: 'permission', permission: `${b.name}:read` } } },
      }
    case 'web-api':
      return { ...base, gates: [PUBLIC_GATE, BROWSER_GATE, API_GATE], routes: { items: [...items(ASSETS), apiRoute(prefix ?? '')], catchAll: signedIn } }
    case 'spa-api':
      return {
        ...base,
        gates: [PUBLIC_GATE, BROWSER_GATE, SPA_API_GATE],
        routes: { items: [...items(ASSETS), apiRoute(prefix ?? '')], catchAll: signedIn },
      }
    case 'empty':
      return { ...base, gates: [BROWSER_GATE], routes: { items: [], catchAll: signedIn } }
  }
}
