import { existsSync, readFileSync } from 'node:fs'
import { execFileSync } from 'node:child_process'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import { allTools } from '../../mcp/tools/index.js'
import { BULK_SPEC } from '../../mcp/tools/bulk.js'
import { CATALOG_PERMISSIONS, P, SCOPES_SUPPORTED } from '../../mcp/permissions.js'

/**
 * Keys carry jinbe catalogue permissions only. A tool gated on anything else (the retired admin:read
 * alias, R-O1) is refused locally for every key and never reaches jinbe.
 */

/**
 * jinbe's catalogue: JINBE_REPO, else the jinbe clone beside this repo — beside the main clone when
 * this runs in a git worktree (its common dir names the main clone).
 */
function jinbeCatalog(): string {
  const rel = 'src/policy/catalog.ts'
  const candidates = [process.env.JINBE_REPO ? join(process.env.JINBE_REPO, rel) : null, fileURLToPath(new URL(`../../../../jinbe/${rel}`, import.meta.url))]
  try {
    const common = execFileSync('git', ['rev-parse', '--path-format=absolute', '--git-common-dir'], { cwd: dirname(fileURLToPath(import.meta.url)), encoding: 'utf8' }).trim()
    candidates.push(join(dirname(dirname(common)), 'jinbe', rel))
  } catch {
    // not in git: the other candidates only
  }
  return candidates.find((c): c is string => !!c && existsSync(c)) ?? ''
}
const JINBE_CATALOG = jinbeCatalog()

describe('tool permissions', () => {
  it('every tool requires only real catalogue permissions (or the mcp baseline)', () => {
    const bad = allTools.flatMap((t) => t.scopes.filter((s) => s !== P.MCP && !CATALOG_PERMISSIONS.has(s)).map((s) => `${t.name}: ${s}`))
    expect(bad).toEqual([])
    for (const spec of Object.values(BULK_SPEC)) expect(CATALOG_PERMISSIONS.has(spec.permission)).toBe(true)
  })

  it('no retired alias is advertised or required', () => {
    for (const legacy of ['admin:read', 'admin:write', 'org:manage_users', 'admin.membership:write', 'users:assign_group']) {
      expect(SCOPES_SUPPORTED).not.toContain(legacy)
      expect(allTools.filter((t) => t.scopes.includes(legacy)).map((t) => t.name)).toEqual([])
    }
  })

  it.skipIf(!JINBE_CATALOG)('the catalogue snapshot matches jinbe policy/catalog.ts', () => {
    const src = readFileSync(JINBE_CATALOG, 'utf8')
    const body = src.slice(src.indexOf('export const CATALOG = {'), src.indexOf('} as const'))
    const names = [...body.matchAll(/^\s+'([a-z][a-z0-9_.-]*:[a-z][a-z0-9_-]*)':/gm)].map((m) => m[1])
    expect(names.length).toBeGreaterThan(20)
    expect([...CATALOG_PERMISSIONS].sort()).toEqual([...new Set(names)].sort())
  })

  it('site reads are sites:read, as jinbe declares GET /api/admin/sites/:name', () => {
    const byName = Object.fromEntries(allTools.map((t) => [t.name, t.scopes]))
    for (const n of ['list_sites', 'get_site', 'site_versions', 'blast_radius', 'get_platform', 'match_request', 'render_template', 'list_services', 'list_roles', 'get_permission_catalog']) {
      expect(byName[n], n).toEqual(['sites:read'])
    }
    expect(byName.list_groups).toEqual(['groups:read'])
    expect(byName.explain_access).toEqual(['access:check'])
    expect(byName.get_user_access).toEqual(['access:read'])
    expect(byName.list_org_users).toEqual(['org.members:read'])
  })
})
