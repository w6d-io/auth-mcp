/**
 * The shapes jinbe answers with (develop, read from its routes and services). Only fields auth-mcp
 * reads are typed; everything else passes through the redaction and sanitising filters untouched.
 */

export type SiteStatus = 'draft' | 'live' | 'attention' | 'paused'

/** GET /api/admin/sites — sites/sites.service.ts listSites. */
export interface SiteSummary {
  name: string
  displayName: string
  host: string | null
  status: SiteStatus
  version: number
  appliedVersion: number | null
  appliedAt: string | null
  appliedBy: string | null
  orgs: number
  protection: unknown
  draft?: { by: string; at: string }
}

/** GET /api/admin/sites/:name — getSite. */
export interface SiteDetail {
  site: Record<string, unknown>
  version: number
  etag: string
  status: SiteStatus
  savedAt: string
  savedBy: string
  applied: { version: number; at: string; by: string; rules: string[] } | null
}

export interface SiteCheck {
  level: 'error' | 'warn'
  code: string
  message: string
  path?: string
}

export interface RiskFlag {
  code: string
  level: 'low' | 'medium' | 'high'
  message: string
}

/** A security finding of the preview (jinbe onboarding): confirm ones must be acknowledged at publish. */
export interface SiteFinding {
  code: string
  level: 'error' | 'warn' | 'confirm'
  message: string
  fix: string
  path?: string
}

/** POST /api/admin/sites/preview. */
export interface SitePreview {
  artefacts: Record<string, unknown>
  checks: SiteCheck[]
  risk: { flags: RiskFlag[] } & Record<string, unknown>
  words: string[]
  suggestedZone?: unknown
  findings?: SiteFinding[]
  /** blocked: any error finding; acknowledge: the distinct codes of the confirm findings. */
  publish?: { blocked: boolean; acknowledge: string[] }
}

/** GET /api/admin/sites/:name/blast-radius — apply.service.ts blastRadius. */
export interface BlastRadius {
  groups: string[]
  orgGrantableGroups: string[]
  orgs: Array<{ id: string; grants: number }>
  rules: number
  routes: number
  people: number | null
  apiKeys: number | null
  requests24h: number | null
}

/** POST /api/admin/rbac/access-check. */
export interface AccessCheck {
  allow: boolean
  reason: 'ok' | 'not_found' | 'forbidden' | 'forbidden_org' | 'needs_2fa' | string
  app: string | null
  owners: string[]
  matchingRules: Array<{ method: string; path: string; permission: string }>
  groups: string[]
  roles: string[]
  permissions: string[]
  superAdmin: boolean
  /** The level asked at (jinbe with aal support). */
  aal?: 'aal1' | 'aal2'
  /** Only with reason needs_2fa: the sign-in level is the failing condition. */
  stepUp?: { requiredAal: 'aal2'; allowedAtAal2: boolean; requiredBy: Array<'site' | 'platform_group'> }
}

/** GET /api/admin/users/:id/access. */
export interface UserAccess {
  site: { groups: string[]; byService: Record<string, string[]> }
  orgs: Array<{ orgId: string; name: string; admin: boolean; grants: string[] }>
}

/** GET /api/admin/users/lookup. */
export interface UserLookup {
  match: 'id' | 'email' | 'prefix' | 'contains' | 'none'
  data: Array<{
    id: string
    email: string
    name: string | null
    active: boolean
    groups: string[] | null
    organizations: string[] | null
    mfa: boolean | null
  }>
}

/** GET /api/organizations/:org/users — Kratos identities. */
export interface OrgUsers {
  data: Array<{ id: string; state?: string; traits?: Record<string, unknown>; created_at?: string; updated_at?: string }>
  total?: number
}

/** GET /api/me/organizations. */
export interface MyOrganizations {
  organizations: string[]
  names?: Record<string, string>
  scope?: string
}

/** GET /api/me/permissions. */
export interface MyPermissions {
  subject?: string
  groups: string[]
  roles: string[]
  permissions: string[]
  actions?: Record<string, boolean>
}

/** GET /api/admin/rbac/groups. */
export interface GroupDefinition {
  name: string
  services: Record<string, string[]>
}

/** GET /api/organizations/:org/assignable-groups. */
export interface AssignableGroups {
  groups: Array<{ name: string; roles?: Record<string, string[]> } & Record<string, unknown>>
}

/** GET /api/audit/events — audit/v1 lines. */
export interface AuditPage {
  events: Array<Record<string, unknown>>
  nextCursor: string | null
  scope: unknown
  range: { from: string; to: string }
  truncated: boolean
}
