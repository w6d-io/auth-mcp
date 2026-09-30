import { describe, expect, it } from 'vitest'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'
import { buildMcpServer } from '../mcp/server.js'
import { allTools } from '../mcp/tools/index.js'
import { KillSwitches } from '../safety/kill-switch.js'
import { ORG, deps, principal } from './helpers/fixtures.js'
import type { AuthenticatedPrincipal } from '../auth/types.js'
import type { ToolDeps } from '../mcp/registry.js'

/**
 * The e2e run found write tools whose error results broke the client: the SDK's Client validates
 * structuredContent against the tool's output schema even when isError is set. Every tool goes through
 * a real Client here — success and error — so a result shape the client rejects fails this test.
 */

const USER = '0f0e0d0c-0b0a-4908-8706-050403020100'
const HASH = 'a'.repeat(64)
const EVENT = '11111111-2222-4333-8444-555555555555'
const route = { id: 'list', methods: ['GET'], path: '/api/items', gate: 'api', access: { kind: 'signed-in' } }

/** Valid arguments for every tool (the test fails if a tool is missing here). */
const ARGS: Record<string, Record<string, unknown>> = {
  get_my_identity: {}, get_my_permissions: {}, list_orgs: {}, get_second_factor_map: {}, can_i: { tool: 'publish_site', arguments: { name: 'billing' } },
  list_sites: {}, get_site: { name: 'billing' }, site_versions: { name: 'billing' }, blast_radius: { name: 'billing' }, get_platform: {},
  check_site_draft: { site: { name: 'billing' } }, match_request: { method: 'GET', url: 'https://billing.example.com/x' },
  render_template: { template: '{{ .Subject }}', kind: 'header', sample: { method: 'GET', url: 'https://billing.example.com/x' } },
  list_groups: {}, list_services: {}, list_roles: { service: 'billing' }, get_permission_catalog: { service: 'billing' },
  explain_access: { email: 'bob@example.com', method: 'GET', path: '/x' }, get_user_access: { userId: USER }, find_users: { query: 'bob' },
  search_audit: {}, get_audit_event: { eventId: EVENT }, explain_admin_access: { method: 'GET', path: '/api/admin/users' },
  get_org: { org: ORG }, list_org_users: { org: ORG }, list_org_grants: { org: ORG },
  create_site: { name: 'fresh', displayName: 'Fresh', host: 'fresh.example.com', upstream: { service: 'fresh', namespace: 'fresh', port: 80 } },
  save_site_draft: { name: 'billing', site: { name: 'billing' } },
  update_site_routes: { name: 'billing', add: [{ ...route, id: 'added' }] },
  diff_site: { name: 'billing' }, save_site_version: { name: 'billing' },
  set_site_gates: { name: 'billing', gates: [{ id: 'api', label: 'API', who: 'tokens', fails: 'api' }] },
  set_site_access: { name: 'billing', groups: { devs: ['editor'] }, twoFactor: 'writes' },
  verify_site: { name: 'billing' },
  extend_site_ttl: { name: 'billing', ttl: '12h' },
  request_site_deletion: { name: 'billing', reason: 'retired' },
  list_deletion_requests: { state: 'pending' },
  import_openapi: { name: 'billing', spec: '{"openapi":"3.0.0"}' },
  publish_site: { name: 'billing', version: 2 }, request_site_apply: { name: 'billing', version: 2 },
  pause_site: { name: 'billing' }, resume_site: { name: 'billing' }, rollback_site: { name: 'billing', toVersion: 1 },
  invite_user: { email: 'bob@example.com' }, send_recovery_email: { userId: USER }, send_login_link: { userId: USER },
  resend_verification_email: { userId: USER }, change_user_email: { userId: USER, newEmail: 'bob@new.example.com' },
  add_user_to_groups: { email: 'bob@example.com', groups: ['support'] },
  create_group: { name: 'billing_support', services: { billing: ['viewer'] } },
  update_group: { name: 'billing_support', services: { billing: ['editor'] } },
  set_site_roles: { service: 'billing', roles: { viewer: ['billing:read'] } },
  plan_bulk: { op: 'users.verification', items: [{ user: 'bob@example.com' }] },
  execute_bulk: { op: 'users.verification', planId: '6f1d2c3b-4a59-4e6f-8a7b-9c0d1e2f3a4b', planHash: HASH },
  get_bulk_job: { jobId: 'job-00001-aaaa' },
  revoke_my_key: {},
  simulate_grant: { userId: USER, addGroups: ['g'] },
}

const site = { name: 'billing', displayName: 'B', gates: [{ id: 'api' }], routes: { items: [route], catchAll: { gate: 'api', access: { kind: 'signed-in' } } } }

/** A jinbe that answers every route with a plausible body. */
function happyJinbe(): typeof fetch {
  const bodies: Array<[RegExp, unknown]> = [
    [/^GET \/api\/admin\/sites\/fresh(\/draft)?$/, { __status: 404, body: { error: 'not_found' } }],
    [/^GET \/api\/admin\/sites$/, []],
    [/^GET \/api\/admin\/sites\/[^/]+\/versions$/, []],
    [/^GET \/api\/admin\/sites\/[^/]+\/draft$/, { site, baseVersion: 2 }],
    [/^GET \/api\/admin\/sites\/[^/]+$/, { site, version: 2, etag: 'e2', status: 'live', savedAt: 't', applied: null }],
    [/^POST \/api\/admin\/sites\/preview$/, { checks: [], risk: { flags: [] }, words: [] }],
    [/^GET \/api\/admin\/rbac\/groups$/, { groups: [{ name: 'billing_support', services: { billing: ['viewer'] } }] }],
    [/^GET \/api\/admin\/rbac\/services$/, { services: [] }],
    [/^GET \/api\/me\/permissions$/, { groups: [], roles: [], permissions: [] }],
    [/^GET \/api\/me\/organizations$/, { organizations: [ORG], names: {} }],
    [/^GET \/api\/organizations\/[^/]+\/assignable-groups$/, { groups: [] }],
    [/^GET \/api\/organizations\/[^/]+\/users$/, { data: [] }],
    [/^GET \/api\/organizations\/[^/]+\/grants$/, { grants: {} }],
    [/^GET \/api\/admin\/users\/lookup$/, { match: 'none', data: [] }],
    [/^GET \/api\/admin\/users\/[^/]+\/groups$/, { groups: [] }],
    [/^GET \/api\/audit\/events$/, { events: [], nextCursor: null, scope: null, range: { from: 't', to: 't' }, truncated: false }],
    [/^POST \/api\/admin\/rbac\/access-check$/, { allow: true, reason: 'ok' }],
    [/^DELETE /, { __status: 204 }],
  ]
  return (async (input: string | URL, init?: RequestInit) => {
    const key = `${init?.method ?? 'GET'} ${new URL(String(input)).pathname}`
    const hit = bodies.find(([re]) => re.test(key))?.[1]
    const special = hit && typeof hit === 'object' && '__status' in (hit as object) ? (hit as { __status: number; body?: unknown }) : null
    const status = special?.__status ?? 200
    const body = special ? special.body : (hit ?? { ok: true })
    return new Response(body === undefined ? null : JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })
  }) as typeof fetch
}

const failingJinbe = (async () =>
  new Response(JSON.stringify({ error: 'Forbidden', code: 'delegation_refused', reason: 'delegation_ineligible:delete' }), {
    status: 403,
    headers: { 'content-type': 'application/json' },
  })) as typeof fetch

const everything = principal({
  scopes: [
    'mcp', 'sites:read', 'groups:read', 'access:read', 'access:check', 'users:read', 'audit:read', 'org.members:read', 'sites:write', 'sites:apply', 'users:create',
    'users:recovery', 'users:send_login_link', 'users:verify', 'users:update_email', 'groups.members:write', 'groups:write',
  ],
  kind: 'personal',
  keyId: 'key-1',
})

async function connect(p: AuthenticatedPrincipal, d: ToolDeps) {
  const { server } = buildMcpServer(p, d, allTools, 'https://mcp.test/mcp')
  const [clientSide, serverSide] = InMemoryTransport.createLinkedPair()
  const client = new Client({ name: 'test', version: '0' })
  await Promise.all([server.connect(serverSide), client.connect(clientSide)])
  const listed = (await client.listTools()).tools.map((t) => t.name)
  return { client, listed }
}

describe('every tool result passes the SDK client output-schema validation', () => {
  it('has arguments for every tool', () => {
    expect(allTools.map((t) => t.name).filter((n) => !ARGS[n])).toEqual([])
  })

  it('success: each tool answers without the client rejecting its structuredContent', async () => {
    const { client, listed } = await connect(everything, deps(happyJinbe()))
    const failures: string[] = []
    for (const name of listed) {
      const r = await client.callTool({ name, arguments: ARGS[name] })
      const sc = r.structuredContent as { untrusted?: boolean; error?: { code: string } }
      expect(sc.untrusted, name).toBe(true)
      if (r.isError && name !== 'simulate_grant') failures.push(`${name}: ${sc.error?.code}`)
    }
    expect(failures).toEqual([])
  })

  it('errors: jinbe refusals, local refusals and read-only mode are all valid envelopes', async () => {
    const refused = await connect(everything, deps(failingJinbe))
    for (const name of refused.listed) {
      const r = await refused.client.callTool({ name, arguments: ARGS[name] })
      // Answered locally, or a partial result by design (the lint stands without the preview).
      if (['get_my_identity', 'can_i', 'check_site_draft'].includes(name)) continue
      expect(r.isError, name).toBe(true)
      expect((r.structuredContent as { error: { code: string } }).error.code, name).toMatch(/never_via_mcp|not_wired|conflict|invalid_request/)
    }
    // A self-change refused locally (A6) and read-only mode.
    const self = await refused.client.callTool({ name: 'send_recovery_email', arguments: { userId: 'user-1' } })
    expect((self.structuredContent as { error: { code: string } }).error.code).toBe('self_target_refused')
    const ro = await connect(everything, deps(failingJinbe, { killSwitches: new KillSwitches({ enabled: true, readOnly: true }, null) }))
    const w = await ro.client.callTool({ name: 'revoke_my_key', arguments: {} })
    expect((w.structuredContent as { error: { code: string } }).error.code).toBe('read_only')
  })
})

describe('a tool hidden by scope answers insufficient_scope, not tool_not_found', () => {
  it('is not listed, but calling it says which permission the key lacks', async () => {
    const developer = principal({ scopes: ['mcp', 'sites:write'], kind: 'personal', keyId: 'key-2' })
    const { client, listed } = await connect(developer, deps(happyJinbe()))
    expect(listed).toContain('save_site_draft')
    expect(listed).not.toContain('publish_site')
    const r = await client.callTool({ name: 'publish_site', arguments: { name: 'billing', version: 2 } })
    expect(r.isError).toBe(true)
    const err = (r.structuredContent as { error: { code: string; message: string } }).error
    expect(err.code).toBe('insufficient_scope')
    expect(err.message).toContain('sites:apply')
    // A tool that does not exist at all is still unknown.
    const none = await client.callTool({ name: 'delete_site', arguments: {} })
    expect(none.isError).toBe(true)
    expect(JSON.stringify(none.content)).toMatch(/not found/)
  })
})
