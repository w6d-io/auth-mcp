/**
 * Scope arithmetic. Scopes ARE jinbe permissions (plan §3.6), plus two pseudo-scopes.
 *
 * This is a UX pre-filter and a narrowing, never a grant: a tool the token cannot carry is hidden and
 * refused here, and everything else is still decided by jinbe → OPA on the call itself.
 */

/** Baseline scope every MCP token carries (the edge checks it). */
export const MCP_SCOPE = 'mcp'
export const OFFLINE_SCOPE = 'offline_access'

const PERMISSION = /^[a-z][a-z0-9_.-]*:[a-z][a-z0-9_-]*$/

/**
 * The twin of jinbe's `covers` (services/authorization-resolution.ts): equal verbs, and the held
 * resource is the required one or a dotted ancestor of it. `admin.member` does not cover
 * `admin.membership`.
 */
export function covers(held: string, required: string): boolean {
  if (held === required) return true
  const [heldResource, heldVerb] = held.split(':')
  const [requiredResource, requiredVerb] = required.split(':')
  if (!heldVerb || !requiredVerb || heldVerb !== requiredVerb) return false
  return requiredResource.startsWith(`${heldResource}.`)
}

/**
 * The scopes of a token that are usable here. `*` and verb wildcards are dropped: a delegated token
 * never carries super-admin power by wildcard (plan §3.2), so one arriving is a misconfiguration to
 * ignore, not honour.
 */
export function usableScopes(scopes: readonly string[]): string[] {
  return scopes.filter((s) => s === MCP_SCOPE || s === OFFLINE_SCOPE || PERMISSION.test(s))
}

export function parseScopeString(scope: string | undefined | null): string[] {
  if (!scope) return []
  return [...new Set(scope.split(/\s+/).filter(Boolean))]
}

/** Whether the token's scopes carry `required` (a permission or the `mcp` baseline). */
export function hasScope(scopes: readonly string[], required: string): boolean {
  const usable = usableScopes(scopes)
  if (!usable.includes(MCP_SCOPE)) return false
  if (required === MCP_SCOPE) return true
  return usable.some((held) => held !== MCP_SCOPE && held !== OFFLINE_SCOPE && covers(held, required))
}

/** At least one of `accepted` is carried (a tool reachable through either of two permissions). */
export function hasAnyScope(scopes: readonly string[], accepted: readonly string[]): boolean {
  return accepted.length > 0 && accepted.some((r) => hasScope(scopes, r))
}

/** Whether a scope set holds any write verb — refused wholesale in read-only mode. */
export function isWriteScope(scope: string): boolean {
  const verb = scope.split(':')[1]
  return !!verb && verb !== 'read'
}
