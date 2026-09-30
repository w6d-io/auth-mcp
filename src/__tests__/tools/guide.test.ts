import { describe, expect, it } from 'vitest'
import { EXAMPLES, RECIPES, gettingStarted } from '../../mcp/guide.js'
import { allTools, readTools } from '../../mcp/tools/index.js'
import { deps, mockJinbe, principal } from '../helpers/fixtures.js'

describe('getting-started guide', () => {
  const d = deps(mockJinbe({}).fetchImpl, { exposeUnwired: false })

  it('lists every wired tool once, with the permission it needs and whether this connection has it', () => {
    const md = gettingStarted(allTools, principal({ scopes: ['mcp', 'audit:read'] }), d, 'https://mcp.example.com/mcp')
    for (const t of readTools) expect(md.split('\n').filter((l) => l.startsWith(`| \`${t.name}\` |`))).toHaveLength(1)
    expect(md).toMatch(/\| `search_audit` \| Search the audit trail \| audit:read \| read \| yes \|/)
    expect(md).toMatch(/\| `get_my_identity` \| [^|]+ \| any connection \| read \| yes \|/)
    expect(md).toMatch(/\| `list_sites` \| [^|]+ \| sites:read \| read \| no \|/)
    expect(md).toContain('`https://mcp.example.com/mcp`')
    expect(md).not.toContain('simulate_grant')
  })

  it('shows the stubs, marked, only when they are exposed', () => {
    const md = gettingStarted(allTools, principal(), deps(mockJinbe({}).fetchImpl, { exposeUnwired: true }))
    expect(md).toContain('| `simulate_grant` | Simulate a grant (stub, always refuses) |')
    expect(md).toContain('https://mcp.<your platform>/mcp')
  })

  it('every example names tools that exist', () => {
    const names = new Set(allTools.map((t) => t.name))
    for (const e of [...EXAMPLES, ...RECIPES]) for (const n of e.tools) expect(names.has(n)).toBe(true)
  })

  it('says what is never allowed and what each refusal means, and never carries a key', () => {
    const md = gettingStarted(allTools, principal(), d)
    expect(md).toContain('Delete anything')
    expect(md).toContain('protected actions')
    expect(md).toContain('403 mcp_disabled, "not enabled for your groups"')
    expect(md).toContain('503 retry_later')
    expect(md).not.toMatch(/stk_mcp_[A-Za-z0-9]/)
  })

  it('has the write recipes, each naming tools in order, and marks protected writes', () => {
    const md = gettingStarted(allTools, principal({ scopes: ['mcp', 'sites:write'] }), d)
    for (const title of ['New site from an OpenAPI document', 'Map routes in bulk', "Change a user's email", 'Invite a user', 'Publish a site']) {
      expect(md).toContain(`### ${title}`)
    }
    expect(md.indexOf('`create_site`')).toBeLessThan(md.indexOf('`import_openapi` again with `commit`'))
    expect(md).toMatch(/\| `save_site_draft` \| [^|]+ \| sites:write \| write \| yes \|/)
    expect(md).toMatch(/\| `change_user_email` \|[^\n]*\| protected write \| no \|/)
    expect(md).toContain('tool error protected_actions_off')
    expect(md).toContain('tool error use_apply_request')
    expect(md).toContain('tool error never_via_mcp')
  })
})
