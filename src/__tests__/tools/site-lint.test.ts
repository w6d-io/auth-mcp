import { describe, expect, it } from 'vitest'
import { lintSite, summarize } from '../../mcp/site-lint.js'

const base = () => ({
  name: 'payroll',
  address: { host: 'payroll.example.com' },
  upstream: { service: 'payroll', namespace: 'payroll', port: 80 },
  gates: [{ id: 'main', authenticators: [{ handler: 'cookie_session' }], authorizer: 'policy', mutators: [{ handler: 'header' }], errors: 'website' }],
  routes: {
    items: [{ id: 'r', methods: ['GET'], path: '/api/:id', gate: 'main', access: { kind: 'permission', permission: 'payroll:read' } }],
    catchAll: { gate: 'main', access: { kind: 'deny' } },
  },
  roles: 'standard',
  login: { twoFactor: { scope: 'writes', clients: 'refused' }, reach: 'granted' },
})

const codes = (site: unknown) => lintSite(site).map((f) => f.code)

describe('lintSite', () => {
  it('a secure site has no findings', () => expect(lintSite(base())).toEqual([]))

  it('flags a public write and a public catch-all', () => {
    const s = base()
    s.routes.items.push({ id: 'w', methods: ['POST'], path: '/api/pay', gate: 'main', access: { kind: 'public' } as never })
    s.routes.catchAll.access = { kind: 'public' }
    expect(codes(s)).toEqual(expect.arrayContaining(['public_write_route', 'public_catch_all']))
  })

  it('flags permission-gated writes without a second factor', () => {
    const s = base()
    s.routes.items.push({ id: 'w', methods: ['DELETE'], path: '/api/:id', gate: 'main', access: { kind: 'permission', permission: 'payroll:write' } })
    s.login.twoFactor.scope = 'none'
    expect(codes(s)).toContain('no_two_factor_on_writes')
    delete (s as { login?: unknown }).login
    expect(codes(s)).toContain('no_two_factor_on_writes')
  })

  it('flags allow-all handlers, anonymous, open CORS, wildcard roles, any-account reach, platform namespace, wildcard host', () => {
    const s = base() as Record<string, any>
    s.gates[0].authenticators = [{ handler: 'noop' }, { handler: 'anonymous' }]
    s.gates[0].authorizer = { handler: 'allow' }
    s.gates[0].mutators = [{ handler: 'header', config: { headers: { 'Access-Control-Allow-Origin': '*' } } }]
    s.roles = { admin: ['*'] }
    s.login.reach = 'any-account'
    s.upstream.namespace = 'auth'
    s.address.host = '*.example.com'
    expect(codes(s)).toEqual(
      expect.arrayContaining(['noop_authenticator', 'anonymous_authenticator', 'allow_authorizer', 'open_cors', 'role_wildcard', 'any_account_reach', 'upstream_platform_namespace', 'wildcard_host'])
    )
    expect(summarize(lintSite(s)).high).toBeGreaterThanOrEqual(4)
  })

  it('flags the old way of opening an API to a partner: two-colon permissions, a required_scope, a secret header', () => {
    const s = base() as Record<string, any>
    s.routes.items[0].access.permission = 'earnings:external:read'
    s.gates.push({
      id: 'partner', authorizer: 'policy', errors: 'api',
      authenticators: [{ handler: 'oauth2_introspection', config: { required_scope: ['earnings:external:read'] } }],
      mutators: [{ handler: 'header', config: { headers: { 'X-Api-Key': 'PLACEHOLDER', 'X-User-Id': '{{ print .Subject }}' } } }],
    })
    const found = lintSite(s)
    expect(found.filter((f) => f.code === 'permission_name').map((f) => f.path)).toEqual(['routes.items[0].access.permission', 'gates[1].authenticators[0].config.required_scope'])
    expect(found.find((f) => f.code === 'required_scope_on_gate')).toMatchObject({ level: 'medium' })
    expect(found.filter((f) => f.code === 'secret_in_header')).toHaveLength(1)
    expect(found.find((f) => f.code === 'secret_in_header')?.message).toContain("'X-Api-Key'")
  })

  it('a one-colon permission with a dotted resource, a templated header and a wildcard verb are not flagged as names', () => {
    const s = base() as Record<string, any>
    s.routes.items[0].access.permission = 'earnings.external:read'
    s.routes.catchAll.access = { kind: 'permission', permission: 'payroll:*' }
    s.gates[0].mutators = [{ handler: 'header', config: { headers: { 'X-Session-Token': '{{ print .Extra.token }}' } } }]
    expect(codes(s)).not.toContain('permission_name')
    expect(codes(s)).not.toContain('secret_in_header')
  })

  it('never throws on a half-written or hostile draft', () => {
    for (const draft of [null, 'x', [], { routes: 'x' }, { gates: [null, 1, 'a'] }, { routes: { items: [null, { methods: 'POST' }] } }]) {
      expect(() => lintSite(draft)).not.toThrow()
    }
  })
})
