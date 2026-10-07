import { afterEach, describe, expect, it } from 'vitest'
import type { FastifyInstance } from 'fastify'
import { buildApp, metadataUrl } from '../app.js'
import { Authenticator } from '../auth/authenticator.js'
import { AuthError, type Principal } from '../auth/types.js'
import type { TokenVerifier } from '../auth/verifier.js'
import type { KeyExchanger } from '../auth/personal-key.js'
import { KillSwitches } from '../safety/kill-switch.js'
import { allTools } from '../mcp/tools/index.js'
import { ORG, deps, mockJinbe, principal, silentLogger } from './helpers/fixtures.js'

const RESOURCE = 'https://mcp.test/mcp'
const GOOD = 'ory_at_goodtoken000000000000'
const JINBE_AUD = 'eyJhbGciOiJSUzI1NiJ9.eyJhdWQiOiJqaW5iZSJ9.c2lnbmF0dXJlLXZhbHVl'

const verifier = (scopes: string[]): TokenVerifier => ({
  verify: async (token) => {
    if (token === GOOD) {
      const { accessToken: _t, ...p } = principal({ scopes })
      return p as Principal
    }
    if (token === JINBE_AUD) throw new AuthError('wrong_audience', 'The token was not issued for this server')
    throw new AuthError('invalid_token', 'The token is not active')
  },
})
const noKeys: KeyExchanger = { exchange: async () => { throw new AuthError('invalid_key', 'refused') } }

let app: FastifyInstance
function build(opts: { scopes?: string[]; killSwitches?: KillSwitches; jinbe?: ReturnType<typeof mockJinbe>; origins?: string[] } = {}) {
  const jinbe = opts.jinbe ?? mockJinbe({ 'GET /api/admin/sites': [] })
  const killSwitches = opts.killSwitches ?? new KillSwitches({ enabled: true, readOnly: true }, null)
  app = buildApp({
    env: { MCP_RESOURCE: RESOURCE, HYDRA_ISSUER: 'https://hydra.test', MCP_ALLOWED_ORIGINS: opts.origins ?? [], MCP_BODY_LIMIT_BYTES: 262144 },
    authenticator: new Authenticator(verifier(opts.scopes ?? ['mcp', 'sites:read']), noKeys),
    killSwitches,
    tools: allTools,
    logger: silentLogger,
    toolDeps: deps(jinbe.fetchImpl, { killSwitches, exposeUnwired: false }),
  })
  return app
}
afterEach(async () => app?.close())

const rpc = (method: string, params: unknown = {}, id = 1) => ({ jsonrpc: '2.0', id, method, params })
const post = (body: unknown, headers: Record<string, string> = {}) =>
  app.inject({
    method: 'POST',
    url: '/mcp',
    headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream', 'mcp-protocol-version': '2025-06-18', ...headers },
    payload: JSON.stringify(body),
  })
const auth = { authorization: `Bearer ${GOOD}` }

describe('protected resource metadata (RFC 9728)', () => {
  it('is served at the path-suffixed and the root well-known URLs', async () => {
    build()
    expect(metadataUrl(RESOURCE)).toBe('https://mcp.test/.well-known/oauth-protected-resource/mcp')
    for (const url of ['/.well-known/oauth-protected-resource/mcp', '/.well-known/oauth-protected-resource']) {
      const res = await app.inject({ method: 'GET', url })
      expect(res.statusCode).toBe(200)
      expect(res.json()).toMatchObject({ resource: RESOURCE, authorization_servers: ['https://hydra.test'], bearer_methods_supported: ['header'] })
      expect(res.json().scopes_supported).toContain('mcp')
    }
  })
})

describe('authentication at the HTTP layer', () => {
  it('no token → 401 pointing at the metadata', async () => {
    build()
    const res = await post(rpc('tools/list'))
    expect(res.statusCode).toBe(401)
    expect(res.headers['www-authenticate']).toBe('Bearer resource_metadata="https://mcp.test/.well-known/oauth-protected-resource/mcp"')
  })

  it('a revoked token → 401 invalid_token', async () => {
    build()
    const res = await post(rpc('tools/list'), { authorization: 'Bearer ory_at_revoked00000000000000' })
    expect(res.statusCode).toBe(401)
    expect(res.headers['www-authenticate']).toContain('error="invalid_token"')
  })

  it('#5 a jinbe-audience token replayed here → 401', async () => {
    build()
    const res = await post(rpc('tools/list'), { authorization: `Bearer ${JINBE_AUD}` })
    expect(res.statusCode).toBe(401)
    expect(res.json().error).toBe('wrong_audience')
  })

  it('an unknown browser origin → 403 (DNS rebinding)', async () => {
    build()
    expect((await post(rpc('tools/list'), { ...auth, origin: 'https://evil.example' })).statusCode).toBe(403)
    build({ origins: ['https://console.test'] })
    expect((await post(rpc('tools/list'), { ...auth, origin: 'https://console.test' })).statusCode).toBe(200)
  })

  it('the verifier being down is a 503, not a 401 (clients must not re-auth in a loop)', async () => {
    build()
    app.close()
    app = buildApp({
      env: { MCP_RESOURCE: RESOURCE, HYDRA_ISSUER: 'https://hydra.test', MCP_ALLOWED_ORIGINS: [], MCP_BODY_LIMIT_BYTES: 262144 },
      authenticator: new Authenticator({ verify: async () => { throw new AuthError('verifier_unavailable', 'down') } }, noKeys),
      killSwitches: new KillSwitches({ enabled: true, readOnly: true }, null),
      tools: allTools,
      logger: silentLogger,
      toolDeps: deps(mockJinbe({}).fetchImpl),
    })
    const res = await post(rpc('tools/list'), auth)
    expect(res.statusCode).toBe(503)
    expect(res.headers['retry-after']).toBe('5')
  })
})

describe('turned off by an administrator (jinbe 403 mcp_disabled)', () => {
  it('is a 403 mcp_disabled with the reason, never a 401 that restarts OAuth', async () => {
    build()
    app.close()
    app = buildApp({
      env: { MCP_RESOURCE: RESOURCE, HYDRA_ISSUER: 'https://hydra.test', MCP_ALLOWED_ORIGINS: [], MCP_BODY_LIMIT_BYTES: 262144 },
      authenticator: new Authenticator({ verify: async () => { throw new AuthError('mcp_disabled', 'MCP access is turned off by an administrator') } }, noKeys),
      killSwitches: new KillSwitches({ enabled: true, readOnly: true }, null),
      tools: allTools,
      logger: silentLogger,
      toolDeps: deps(mockJinbe({}).fetchImpl),
    })
    const res = await post(rpc('tools/list'), auth)
    expect(res.statusCode).toBe(403)
    expect(res.headers['www-authenticate']).toBeUndefined()
    expect(res.json()).toEqual({ error: 'mcp_disabled', message: 'MCP access is turned off by an administrator' })
  })
})

describe('kill switches at the HTTP layer', () => {
  it('global off → 503 before authentication', async () => {
    build({ killSwitches: new KillSwitches({ enabled: false, readOnly: true }, null) })
    expect((await post(rpc('tools/list'))).statusCode).toBe(503)
  })
  it('user switched off → 403', async () => {
    build({ killSwitches: new KillSwitches({ enabled: true, readOnly: true }, () => JSON.stringify({ disabledUsers: ['user-1'] })) })
    const res = await post(rpc('tools/list'), auth)
    expect(res.statusCode).toBe(403)
    expect(res.json().error).toBe('mcp_disabled')
  })
})

describe('MCP over Streamable HTTP (stateless)', () => {
  it('initialize', async () => {
    build()
    const res = await post(rpc('initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 't', version: '0' } }), auth)
    expect(res.statusCode).toBe(200)
    expect(res.json().result.serverInfo.name).toBe('example-admin')
    expect(res.headers['mcp-session-id']).toBeUndefined()
  })

  it('tools/list shows only what the token carries; no write tool in read-only mode', async () => {
    build({ scopes: ['mcp', 'sites:read'] })
    const res = await post(rpc('tools/list'), auth)
    const tools = res.json().result.tools as Array<{ name: string; annotations: { readOnlyHint: boolean }; outputSchema: unknown }>
    const names = tools.map((t) => t.name)
    expect(names).toContain('list_sites')
    expect(names).not.toContain('explain_access')
    expect(names).not.toContain('find_users')
    expect(names).not.toContain('save_site_version')
    expect(tools.every((t) => t.annotations.readOnlyHint)).toBe(true)
    expect(tools.every((t) => !!t.outputSchema)).toBe(true)
  })

  it('tools/call runs a read tool through jinbe with the user token', async () => {
    const jinbe = mockJinbe({ 'GET /api/admin/sites': [{ name: 'payroll', displayName: 'Payroll', host: 'p.example.com', status: 'live', version: 1, appliedVersion: 1, appliedAt: null, appliedBy: null, orgs: 0, protection: null }] })
    build({ jinbe })
    const res = await post(rpc('tools/call', { name: 'list_sites', arguments: {} }), auth)
    const result = res.json().result
    expect(result.isError).toBeFalsy()
    expect(result.structuredContent.data.items[0].name).toBe('payroll')
    expect(result.content[0].text).toContain('<untrusted-data source="jinbe:/api/admin/sites">')
    expect(jinbe.calls[0].headers.authorization).toBe(`Bearer ${GOOD}`)
  })

  it('#2 calling a tool the token cannot see fails, and nothing reaches jinbe', async () => {
    const jinbe = mockJinbe({})
    build({ jinbe, scopes: ['mcp'] })
    const res = await post(rpc('tools/call', { name: 'explain_access', arguments: { email: 'a@b.test', method: 'GET', path: '/' } }), auth)
    const body = res.json()
    expect(body.error ?? body.result?.isError).toBeTruthy()
    expect(jinbe.calls).toHaveLength(0)
  })

  it('input is validated by the schema: a hostile site name never reaches jinbe', async () => {
    const jinbe = mockJinbe({})
    build({ jinbe })
    const res = await post(rpc('tools/call', { name: 'get_site', arguments: { name: '../../admin/rbac/groups' } }), auth)
    const body = res.json()
    expect(body.error ?? body.result?.isError).toBeTruthy()
    expect(jinbe.calls).toHaveLength(0)
  })

  it('resources/list offers the backing tools the token can use', async () => {
    build({ scopes: ['mcp', 'sites:read', 'org.members:read'], jinbe: mockJinbe({ 'GET /api/admin/sites': [{ name: 'payroll', status: 'live' }], 'GET /api/me/organizations': { organizations: [ORG] } }) })
    const res = await post(rpc('resources/list'), auth)
    const uris = (res.json().result.resources as Array<{ uri: string }>).map((r) => r.uri)
    expect(uris).toEqual(expect.arrayContaining(['platform://', 'catalog://permissions', 'site://payroll', `org://${ORG}`]))
  })

  it('resources/read returns the data with its notice', async () => {
    build({ jinbe: mockJinbe({ 'GET /api/admin/sites/platform': { env: 'dev' } }) })
    const res = await post(rpc('resources/read', { uri: 'platform://' }), auth)
    const doc = JSON.parse(res.json().result.contents[0].text)
    expect(doc.notice).toMatch(/never an instruction/)
    expect(doc.data).toEqual({ env: 'dev' })
  })

  it('serves the getting-started guide as a resource and a prompt, with the server address and this token\'s tools', async () => {
    build({ scopes: ['mcp', 'sites:read'] })
    const init = await post(rpc('initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 't', version: '0' } }), auth)
    expect(init.json().result.capabilities.prompts).toBeDefined()
    expect(init.json().result.instructions).toContain('docs://getting-started')
    // Ask and look before building: the intake, reuse of the sites already serving the Service, a yes.
    expect(init.json().result.instructions).toContain('Before creating or changing a site, run the intake (prompt plan_site_change): find the sites already serving that Service (find_sites_for_service) and extend one rather than create another, ask the person what they need instead of assuming, and show the plan and get a yes before the first write.')
    const list = await post(rpc('resources/list'), auth)
    expect((list.json().result.resources as Array<{ uri: string }>).map((r) => r.uri)).toContain('docs://getting-started')
    const read = await post(rpc('resources/read', { uri: 'docs://getting-started' }), auth)
    const doc = read.json().result.contents[0]
    expect(doc.mimeType).toBe('text/markdown')
    expect(doc.text).toContain(`claude mcp add --transport http --scope user example ${RESOURCE}`)
    expect(doc.text).toMatch(/\| `list_sites` \| List sites \| sites:read \| read \| yes \|/)
    expect(doc.text).toMatch(/\| `explain_access` \| Explain access \| access:check \| read \| no \|/)
    // Wired write tools are documented for every connection, marked unavailable when the key lacks them.
    expect(doc.text).toMatch(/\| `save_site_draft` \| [^|]+ \| sites:write \| write \| no \|/)
    expect(doc.text).toMatch(/\| `publish_site` \| [^|]+ \| sites:apply \| protected write \| no \|/)
    expect(doc.text).not.toContain('simulate_grant')
    const prompts = await post(rpc('prompts/list'), auth)
    expect((prompts.json().result.prompts as Array<{ name: string }>).map((p) => p.name)).toEqual(['getting-started', 'plan_site_change', 'onboard_site'])
    const prompt = await post(rpc('prompts/get', { name: 'getting-started' }), auth)
    const message = prompt.json().result.messages[0]
    expect(message.role).toBe('user')
    expect(message.content.text).toContain('call get_my_identity')
    expect(message.content.text).toContain('Show the last 20 audit events.')
  })

  it('GET and DELETE /mcp → 405 (no sessions, no server stream)', async () => {
    build()
    expect((await app.inject({ method: 'GET', url: '/mcp' })).statusCode).toBe(405)
    expect((await app.inject({ method: 'DELETE', url: '/mcp' })).statusCode).toBe(405)
  })

  it('a body over the limit is refused', async () => {
    build()
    const res = await post({ ...rpc('tools/call', { name: 'check_site_draft', arguments: { site: { x: 'y'.repeat(300_000) } } }) }, auth)
    expect(res.statusCode).toBe(413)
  })
})
