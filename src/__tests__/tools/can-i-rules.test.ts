import { describe, expect, it } from 'vitest'
import { allTools, writeTools } from '../../mcp/tools/index.js'
import { CAN_I_RULES } from '../../mcp/tools/can-i.js'

describe('can_i covers every write tool', () => {
  it('every write tool has a can_i rule (add one when adding a write tool)', () => {
    const missing = allTools.filter((t) => t.write && t.wired !== false && !CAN_I_RULES[t.name]).map((t) => t.name)
    expect(missing).toEqual([])
  })

  it('no rule names a tool that does not exist or is not a write', () => {
    const writes = new Set(allTools.filter((t) => t.write).map((t) => t.name))
    expect(Object.keys(CAN_I_RULES).filter((n) => !writes.has(n))).toEqual([])
  })

  it('every rule list starts with the base checks', () => {
    for (const [name, rules] of Object.entries(CAN_I_RULES)) expect(rules[0], name).toBe('base')
  })

  it('the write tools that change what the gateway serves in production carry the production rule', () => {
    expect(CAN_I_RULES.publish_site).toContain('production')
    expect(CAN_I_RULES.rollback_site).toContain('production')
    expect(CAN_I_RULES.publish_site).toContain('publish_gate')
    expect(CAN_I_RULES.request_site_apply).toContain('publish_gate')
    expect(writeTools.length).toBeGreaterThan(20)
  })
})
