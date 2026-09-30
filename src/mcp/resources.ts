import { McpServer, ResourceTemplate } from '@modelcontextprotocol/sdk/server/mcp.js'
import { ErrorCode, McpError, type CallToolResult, type ReadResourceResult } from '@modelcontextprotocol/sdk/types.js'
import type { AuthenticatedPrincipal } from '../auth/types.js'
import { execute, isVisible, type ToolDeps, type ToolDef } from './registry.js'
import { getPlatform, getSite, listSites } from './tools/sites.js'
import { getOrg, listOrgs } from './tools/orgs.js'
import { getMyPermissions } from './tools/iam.js'
import { DATA_NOTICE, SITE_NAME } from '../safety/untrusted.js'

/**
 * Read-only resources. Each one is a tool call underneath (same pipeline: kill switches, scopes, rate
 * limit, redaction, sanitising, size cap), rendered as a JSON document that carries the data notice.
 * A resource is listed only when its backing tool is visible to this principal.
 */

const MIME = 'application/json'
const ORG_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

async function read(def: ToolDef, args: Record<string, unknown>, uri: URL, principal: AuthenticatedPrincipal, deps: ToolDeps): Promise<ReadResourceResult> {
  const result: CallToolResult = await execute(def, args, principal, deps)
  if (result.isError) {
    const err = (result.structuredContent as { error?: { code?: string; message?: string } } | undefined)?.error
    throw new McpError(ErrorCode.InvalidRequest, `${err?.code ?? 'error'}: ${err?.message ?? 'refused'}`)
  }
  // `<` escaped as in the tool fence: the document cannot smuggle markup either.
  const text = JSON.stringify({ notice: DATA_NOTICE, ...(result.structuredContent as object) }, null, 2).replace(/</g, '\\u003c')
  return { contents: [{ uri: uri.href, mimeType: MIME, text }] }
}

export function registerResources(server: McpServer, principal: AuthenticatedPrincipal, deps: ToolDeps): string[] {
  const registered: string[] = []

  if (isVisible(getPlatform, principal, deps)) {
    server.registerResource('platform', 'platform://', { title: 'Platform settings for sites', mimeType: MIME }, (uri) =>
      read(getPlatform, {}, uri, principal, deps)
    )
    registered.push('platform://')
  }

  if (isVisible(getMyPermissions, principal, deps)) {
    server.registerResource('my-permissions', 'catalog://permissions', { title: 'My effective permissions', mimeType: MIME }, (uri) =>
      read(getMyPermissions, {}, uri, principal, deps)
    )
    registered.push('catalog://permissions')
  }

  if (isVisible(getOrg, principal, deps)) {
    // No org is bound to the token: one resource per organisation the person administers, jinbe
    // deciding on each read whether they may see it.
    const template = new ResourceTemplate('org://{id}', {
      list: async () => {
        const result = await execute(listOrgs, {}, principal, deps)
        if (result.isError) return { resources: [] }
        const items = ((result.structuredContent as { data?: { items?: Array<{ id: string }> } }).data?.items ?? []).filter((o) =>
          ORG_ID.test(o.id)
        )
        return { resources: items.map((o) => ({ uri: `org://${o.id}`, name: o.id, mimeType: MIME })) }
      },
    })
    server.registerResource('org', template, { title: 'An organisation', mimeType: MIME }, (uri, vars) => {
      const id = Array.isArray(vars.id) ? vars.id[0] : vars.id
      if (typeof id !== 'string' || !ORG_ID.test(id)) throw new McpError(ErrorCode.InvalidParams, 'Not an organisation id')
      return read(getOrg, { org: id }, uri, principal, deps)
    })
    registered.push('org://{id}')
  }

  if (isVisible(getSite, principal, deps)) {
    const template = new ResourceTemplate('site://{name}', {
      list: async () => {
        const result = await execute(listSites, { limit: 100 }, principal, deps)
        if (result.isError) return { resources: [] }
        const items = ((result.structuredContent as { data?: { items?: Array<{ name: string }> } }).data?.items ?? []).filter((s) =>
          SITE_NAME.test(s.name)
        )
        return { resources: items.map((s) => ({ uri: `site://${s.name}`, name: s.name, mimeType: MIME })) }
      },
    })
    server.registerResource('site', template, { title: 'A site', mimeType: MIME }, (uri, vars) => {
      const name = Array.isArray(vars.name) ? vars.name[0] : vars.name
      if (typeof name !== 'string' || !SITE_NAME.test(name)) throw new McpError(ErrorCode.InvalidParams, 'Not a site name')
      return read(getSite, { name }, uri, principal, deps)
    })
    registered.push('site://{name}')
  }

  return registered
}
