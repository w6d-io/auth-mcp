import { sanitizeString } from './untrusted.js'
import { redactString } from './redact.js'

/**
 * One error shape for every tool: `isError: true` + `{code, message, hint, retryable, …}` (plan §4).
 * Codes are stable and machine-readable; `upstream` keeps jinbe's own code when it differs.
 */
export type ToolErrorCode =
  | 'unauthenticated'
  | 'forbidden'
  | 'insufficient_scope'
  | 'org_out_of_scope'
  | 'reauth_required'
  | 'second_factor_required'
  | 'needs_human_approval'
  | 'not_found'
  | 'conflict'
  | 'invalid_request'
  | 'invalid_spec'
  | 'invalid_cursor'
  | 'rate_limited'
  | 'retry_later'
  | 'organisation_directory_unavailable'
  | 'upstream_unavailable'
  | 'mcp_disabled'
  | 'read_only'
  | 'self_target_refused'
  | 'not_wired'
  | 'never_via_mcp'
  | 'use_apply_request'
  | 'protected_actions_off'
  | 'idempotency_key_reused'
  | 'unconfirmed_findings'
  | 'route_not_declared'
  | 'grant_exceeds_own'
  | 'staff_group_super_admin_only'
  | 'internal_error'

export interface ToolErrorBody {
  code: ToolErrorCode
  message: string
  hint?: string
  retryable: boolean
  retryAfterSec?: number
  upstream?: string
  status?: number
  details?: unknown
}

export class ToolError extends Error {
  constructor(readonly body: ToolErrorBody) {
    super(body.message)
    this.name = 'ToolError'
  }
}

export const toolError = (code: ToolErrorCode, message: string, extra: Partial<ToolErrorBody> = {}) =>
  new ToolError({ code, message, retryable: false, ...extra })

const HINTS: Partial<Record<ToolErrorCode, string>> = {
  unauthenticated: 'The connection is no longer valid (expired, revoked or disconnected). Reconnect the MCP client.',
  forbidden: 'Your account does not hold the permission this needs in this organisation. Ask an administrator; do not retry.',
  insufficient_scope: 'The connection was not granted this scope. Reconnect and grant it, if your account holds it.',
  org_out_of_scope: 'Your account may not act in that organisation. Pick one of yours (list_orgs); do not retry.',
  reauth_required: 'This needs a second factor proven in the last 15 minutes, in the browser. Finish it in the console.',
  second_factor_required: 'Your account must use two-step sign-in. Set it up in the browser, then retry.',
  needs_human_approval: 'This change is published by a person in the console, after a second factor. Open the approve link.',
  conflict: 'Somebody changed it since you read it. Read it again, then retry with the new etag.',
  rate_limited: 'Too many calls. Wait and retry.',
  retry_later: 'The policy engine could not answer. Retry shortly.',
  organisation_directory_unavailable: 'The organisation directory could not be read. Retry shortly.',
  upstream_unavailable: 'The platform API did not answer. Retry shortly.',
  mcp_disabled: 'MCP access is switched off for this account, client or organisation.',
  read_only: 'MCP is in read-only mode: no write tool can run.',
  not_wired: 'This tool is a stub until the platform supports it.',
  never_via_mcp: 'This action is never allowed through MCP: do it in the console. Do not retry.',
  use_apply_request: 'In production a key does not publish directly: call request_site_apply, and a person approves it in the console.',
  protected_actions_off:
    'This is a protected action (publish, change an email, add to groups, edit groups and roles). A personal key: create a new key with protected actions allowed. A browser sign-in: /mcp → example → Re-authenticate and tick "Allow protected actions" (they last 12 hours). get_my_identity says which applies.',
  idempotency_key_reused: 'This idempotencyKey was used for a different request. Use a new key (or omit it) for a new change.',
  grant_exceeds_own:
    'You may only hand out what you hold yourself. details.missing lists what this grant exceeds, details.grantedBy the groups that hold it: ask an administrator.',
  staff_group_super_admin_only: 'Staff groups and super_admins are changed by a super admin only. Ask one; do not retry.',
  route_not_declared:
    'Likely a version mismatch between this MCP server and the platform, or a route not deployed yet. Not a permanent ban: tell the person, and retry after the platform is updated.',
  unconfirmed_findings:
    'Not published. Fix every error finding (see details.findings, each with its fix), show the person each confirm finding, and publish again with acknowledge listing the codes they accept.',
}

/** jinbe's `error` values that name the same thing under another spelling. */
const UPSTREAM_CODES: Record<string, ToolErrorCode> = {
  // Through a key, a step-up is satisfied only by a key created with protected actions allowed
  // (jinbe delegated-step-up.ts): both answers mean "use such a key", never "go prove a factor".
  reauth_required: 'protected_actions_off',
  step_up_unavailable: 'protected_actions_off',
  second_factor_required: 'second_factor_required',
  use_apply_request: 'use_apply_request',
  idempotency_key_reused: 'idempotency_key_reused',
  idempotency_in_progress: 'retry_later',
  invalid_idempotency_key: 'invalid_request',
  // Addresses (jinbe user-address.routes.ts).
  address_unavailable: 'conflict',
  address_unchanged: 'invalid_request',
  own_address: 'self_target_refused',
  outranked: 'forbidden',
  already_verified: 'conflict',
  unknown_address: 'invalid_request',
  use_email_endpoint: 'invalid_request',
  // Onboarding (jinbe publish gate, verify).
  unconfirmed_findings: 'unconfirmed_findings',
  verify_rate_limited: 'rate_limited',
  gate_without_authenticator: 'invalid_spec',
  // Bulk (jinbe bulk/engine.ts).
  plan_hash_mismatch: 'conflict',
  plan_changed: 'conflict',
  plan_not_found: 'not_found',
  approval_required: 'needs_human_approval',
  second_approver_required: 'needs_human_approval',
  org_out_of_scope: 'org_out_of_scope',
  organisation_directory_unavailable: 'organisation_directory_unavailable',
  organisation_directory_not_configured: 'organisation_directory_unavailable',
  policy_unavailable: 'retry_later',
  audit_store_unavailable: 'upstream_unavailable',
  kubernetes_unavailable: 'upstream_unavailable',
  kubernetes_rate_limited: 'rate_limited',
  trace_store_unavailable: 'upstream_unavailable',
  invalid_spec: 'invalid_spec',
  invalid_site: 'invalid_spec',
  invalid_draft: 'invalid_spec',
  checks_failed: 'invalid_spec',
  invalid_request: 'invalid_request',
  invalid_range: 'invalid_request',
  range_too_large: 'invalid_request',
  name_mismatch: 'invalid_request',
  version_mismatch: 'conflict',
  not_found: 'not_found',
  organisation_not_found: 'not_found',
  insufficient_scope: 'insufficient_scope',
  // Grant guard (jinbe services/permission-refusal.ts, rbac-escalation-guard.ts).
  permission_required: 'forbidden',
  grant_exceeds_own: 'grant_exceeds_own',
  staff_group_super_admin_only: 'staff_group_super_admin_only',
  privilege_escalation_blocked: 'forbidden',
}

/** Codes whose hint is jinbe's own when it sends one: it names the groups that grant what is missing. */
const JINBE_HINTED = new Set<ToolErrorCode>(['forbidden', 'insufficient_scope', 'grant_exceeds_own', 'staff_group_super_admin_only'])

const RETRYABLE = new Set<ToolErrorCode>(['rate_limited', 'retry_later', 'organisation_directory_unavailable', 'upstream_unavailable'])

function byStatus(status: number): ToolErrorCode {
  if (status === 400) return 'invalid_request'
  if (status === 401) return 'unauthenticated'
  if (status === 403) return 'forbidden'
  if (status === 404) return 'not_found'
  if (status === 409 || status === 412) return 'conflict'
  if (status === 422) return 'invalid_spec'
  if (status === 429) return 'rate_limited'
  if (status === 502 || status === 503 || status === 504) return 'upstream_unavailable'
  return 'internal_error'
}

const CODE = /^[a-z][a-z0-9_]{1,63}$/

/**
 * jinbe's code: `error` when it is a snake_case code, else `code` — refusals answer
 * `{error: 'Forbidden', code: 'permission_required'}` (a status text in `error`).
 */
function upstreamCode(body: unknown): string | undefined {
  const b = body as { error?: unknown; code?: unknown } | null
  if (typeof b?.error === 'string' && CODE.test(b.error)) return b.error
  return typeof b?.code === 'string' && CODE.test(b.code) ? b.code : undefined
}

/** jinbe's hint (who to ask, which groups grant it): somebody else's text, so sanitised and capped. */
function upstreamHint(body: unknown): string | undefined {
  const h = (body as { hint?: unknown } | null)?.hint
  return typeof h === 'string' && h.trim() ? sanitizeString(redactString(h), 400) : undefined
}

function upstreamMessage(body: unknown): string | undefined {
  const m = (body as { message?: unknown } | null)?.message
  return typeof m === 'string' ? sanitizeString(redactString(m), 300) : undefined
}

/** Details worth passing on: validation checks, refusal lists, the current etag. Data, so sanitised by the caller. */
function upstreamDetails(body: unknown): unknown {
  if (!body || typeof body !== 'object') return undefined
  const b = body as Record<string, unknown>
  const picked: Record<string, unknown> = {}
  for (const k of [
    'checks', 'issues', 'details', 'refused', 'ties', 'sites', 'stepUp', 'etag', 'approve_url', 'plan', 'findings',
    // A permission refusal: what is missing and which groups grant it (group names, never members).
    'permission', 'missing', 'missingByScope', 'grantedBy', 'blockingGroup',
  ]) {
    if (b[k] !== undefined) picked[k] = b[k]
  }
  return Object.keys(picked).length ? picked : undefined
}

/**
 * jinbe's delegation gate answers 403 `{error: 'Forbidden', code, reason}` where `reason` is
 * `delegation_ineligible:<why>` (never through a key), `scope_missing:<permission>`,
 * `delegation_refused:use_apply_request` (prod publish) or `delegation_no_scope_for_write`.
 */
const REASON = /^(delegation_ineligible|scope_missing|delegation_refused|delegation_no_scope_for_write|delegation_missing)(?::([a-z*][a-z0-9_.:*-]{0,127}))?$/

/** The gate's fixed message: on routes whose 403 schema strips `code` and `reason`, all that is left. */
const GATE_MESSAGE = /^This credential acts for a user through a client and may not use this route\.?$/

function delegationError(status: number, body: unknown): ToolError | null {
  const reason = (body as { reason?: unknown } | null)?.reason
  if (status === 403 && typeof reason !== 'string' && GATE_MESSAGE.test(String((body as { message?: unknown } | null)?.message ?? ''))) {
    return new ToolError({
      code: 'forbidden',
      message: 'This key may not do this: it lacks the permission, or the action is never allowed through MCP (then do it in the console)',
      hint: 'Check get_my_identity for the key\'s scopes; if the permission is there, the action is console-only. Do not retry.',
      retryable: false,
      upstream: 'delegation_refused',
      status,
    })
  }
  if (status !== 403 || typeof reason !== 'string') return null
  const m = REASON.exec(reason)
  if (!m) return null
  const [, kind, detail] = m
  const details = upstreamDetails(body)
  const make = (code: ToolErrorCode, message: string) =>
    new ToolError({
      code,
      message,
      hint: (JINBE_HINTED.has(code) && upstreamHint(body)) || HINTS[code],
      retryable: false,
      upstream: reason,
      status,
      ...(details !== undefined ? { details } : {}),
    })
  if (kind === 'scope_missing') return make('insufficient_scope', `Your key lacks ${detail ?? 'the permission this needs'}`)
  if (kind === 'delegation_refused' && detail === 'use_apply_request') {
    return make('use_apply_request', 'In production, publishing through a key goes through an apply request: call request_site_apply')
  }
  if (kind === 'delegation_ineligible' && detail === 'self_change') {
    return make('self_target_refused', 'A key cannot change its own holder\'s account or groups; ask another administrator')
  }
  // A write to a route jinbe declares no permission for: usually jinbe older than this server (the
  // route does not exist there yet), never a decision that the action is banned.
  if (kind === 'delegation_no_scope_for_write') {
    return make('route_not_declared', 'jinbe declares no permission for this endpoint — it may be older than this MCP server (a version mismatch), or the route is new and not yet deployed')
  }
  if (kind === 'delegation_missing') return make('forbidden', 'The platform could not read this key\'s delegation; reconnect, or create a new key')
  // never_via_mcp only for the gate's real "never": delegation_ineligible (the catalogue's delegable
  // 'never', deletes, infrastructure, credentials) and the prod redirect handled above.
  if (kind === 'delegation_ineligible') return make('never_via_mcp', 'This action is never allowed through MCP: do it in the console')
  return make('forbidden', 'This key may not use this route')
}

/** A jinbe HTTP error → the tool error the model sees. */
/** jinbe before `kubernetes_rate_limited`: the API server's 429 came back as an outage, "(list zones: 429)". */
const KUBE_THROTTLED = /: 429\)$/

export function fromJinbe(status: number, body: unknown, retryAfter?: string | null): ToolError {
  const delegated = delegationError(status, body)
  if (delegated) return delegated
  const upstream = upstreamCode(body)
  let code = (upstream && UPSTREAM_CODES[upstream]) || byStatus(status)
  // A 503 whose code we do not know is still an outage, never "internal".
  if (code === 'internal_error' && status >= 500 && status !== 500) code = 'upstream_unavailable'
  let message = upstreamMessage(body)
  if (upstream === 'kubernetes_unavailable' && message && KUBE_THROTTLED.test(message)) {
    code = 'rate_limited'
    message = 'The Kubernetes API is temporarily rate-limited, nothing was changed; retry in a few seconds'
  }
  if (code === 'protected_actions_off') {
    // jinbe's text says "prove it in a browser", which a key-holder cannot act on from here.
    message = 'This is a protected action and this connection may not do it now: create a new key with protected actions allowed, or (browser sign-in) sign in again and allow them'
  }
  const bodyRetry = (body as { retryAfter?: unknown } | null)?.retryAfter
  const retryAfterSec =
    retryAfter && /^\d{1,5}$/.test(retryAfter)
      ? Number(retryAfter)
      : typeof bodyRetry === 'number' && Number.isInteger(bodyRetry) && bodyRetry >= 0 && bodyRetry < 100000
        ? bodyRetry
        : undefined
  return new ToolError({
    code,
    message: message ?? defaultMessage(code),
    hint: (JINBE_HINTED.has(code) && upstreamHint(body)) || HINTS[code],
    retryable: RETRYABLE.has(code),
    ...(retryAfterSec !== undefined ? { retryAfterSec } : {}),
    ...(upstream && upstream !== code ? { upstream } : {}),
    status,
    ...(upstreamDetails(body) !== undefined ? { details: upstreamDetails(body) } : {}),
  })
}

function defaultMessage(code: ToolErrorCode): string {
  return code.replace(/_/g, ' ')
}

export function withHint(err: ToolError): ToolErrorBody {
  return { ...err.body, hint: err.body.hint ?? HINTS[err.body.code] }
}
