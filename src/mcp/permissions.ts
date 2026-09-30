/**
 * The jinbe catalogue permission each tool relies on: the one its jinbe route declares (jinbe
 * policy/catalog.ts and the generated route map). Keys carry catalogue permissions only — never the
 * retired `admin:read` / `admin:write` aliases — so a tool gated on anything else would be refused
 * here for every key without ever reaching jinbe. A tool is listed when the token carries one of its
 * permissions; jinbe decides the call.
 */
import { MCP_SCOPE } from '../auth/scopes.js'
import { PROTECTED_PERMISSIONS } from '../auth/protected-actions.js'

export const P = {
  MCP: MCP_SCOPE,
  SITES_READ: 'sites:read',
  SITES_WRITE: 'sites:write',
  /** Protected: works only with a key created with protected actions allowed. */
  SITES_APPLY: 'sites:apply',
  GROUPS_READ: 'groups:read',
  /** Protected: create and edit groups and service roles (never delete). */
  GROUPS_WRITE: 'groups:write',
  /** Protected. */
  GROUPS_MEMBERS_WRITE: 'groups.members:write',
  ACCESS_READ: 'access:read',
  ACCESS_CHECK: 'access:check',
  USERS_READ: 'users:read',
  USERS_CREATE: 'users:create',
  USERS_RECOVERY: 'users:recovery',
  USERS_LOGIN_LINK: 'users:send_login_link',
  USERS_VERIFY: 'users:verify',
  /** Protected. */
  USERS_UPDATE_EMAIL: 'users:update_email',
  ORG_MEMBERS_READ: 'org.members:read',
  AUDIT_READ: 'audit:read',
} as const

/** Permissions a key may use only when it was created with protected actions allowed (jinbe KEY_STEP_UP_PERMISSIONS). */
export const PROTECTED: ReadonlySet<string> = new Set<string>(PROTECTED_PERMISSIONS)

/**
 * jinbe's catalogue (policy/catalog.ts CATALOG keys), for the test that every tool's permission is a
 * real one. Kept in step by that test when the jinbe repo sits beside this one.
 */
export const CATALOG_PERMISSIONS: ReadonlySet<string> = new Set([
  'users:read', 'users:create', 'users:update', 'users:update_email', 'users.metadata:write', 'users:disable', 'users:delete',
  'users:recovery', 'users:verify', 'users:send_login_link', 'users:reset_second_factor', 'sessions:read', 'sessions:revoke',
  'access:read', 'access:check', 'groups:read', 'groups:write', 'groups.members:write', 'groups.members:revoke', 'groups.mfa:write',
  'org:read', 'org:write', 'org:delete', 'org.members:read', 'org.members:write', 'org.admins:write', 'org.keys:read',
  'org.keys:write', 'org.keys:revoke', 'sites:read', 'sites:write', 'sites:apply', 'sites:delete', 'sites.requests:approve',
  'zones:read', 'zones:write', 'zones:delete', 'gateway:read', 'gateway:apply', 'settings:read', 'settings.signin:write',
  'settings.mcp:write', 'policy.bundle:read', 'policy.bundle:write', 'audit:read', 'audit:export', 'recert:read',
  'recert:manage', 'recert:delete', 'stats:read',
])

/** Catalogue permissions a delegated token may never use (jinbe `delegable: 'never'`), kept in step by the same test. */
export const CATALOG_NEVER: ReadonlySet<string> = new Set([
  'users:delete', 'users:reset_second_factor', 'groups.members:revoke', 'groups.mfa:write', 'org:delete', 'org.admins:write', 'org.keys:write',
  'sites:delete', 'sites.requests:approve', 'zones:write', 'zones:delete', 'gateway:apply', 'settings.signin:write',
  'settings.mcp:write', 'policy.bundle:read', 'policy.bundle:write', 'audit:export', 'recert:manage', 'recert:delete',
])

/**
 * The scopes advertised in the protected-resource metadata: the baseline and every permission a
 * delegated token may carry. An OAuth client requests exactly this list (no `scope` in the 401), and
 * Hydra grants only what was requested, so a permission missing here could never be consented to.
 */
export const SCOPES_SUPPORTED = [MCP_SCOPE, 'offline_access', ...[...CATALOG_PERMISSIONS].filter((s) => !CATALOG_NEVER.has(s))]
