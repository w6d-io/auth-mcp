import { z } from 'zod'
import { defineTool, type ToolDef } from '../registry.js'
import { P } from '../permissions.js'
import { seg } from '../../jinbe/client.js'
import { IDENTITY_ID, SERVICE_NAME } from '../../safety/untrusted.js'
import type { AccessCheck, UserAccess, UserLookup } from '../../jinbe/types.js'

export const explainAccess = defineTool({
  name: 'explain_access',
  title: 'Explain access',
  description:
    'Can this person call METHOD PATH, and why: the gateway verdict plus the owning service, the route rules that matched, and the groups, roles and permissions that applied. ' +
    'The answer depends on the sign-in level: pass `aal` = "aal1" (signed in with a password, the default) or "aal2" (with a second factor). ' +
    'A site or group that requires a second factor answers needs_2fa at aal1; the result then says whether aal2 would be allowed. Check both levels when it matters.',
  scopes: [P.ACCESS_CHECK],
  input: {
    email: z.string().trim().email().max(320),
    method: z.enum(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']),
    path: z.string().max(2048).regex(/^\/[^\s?#]*$/, 'an absolute path with no query or fragment'),
    aal: z
      .enum(['aal1', 'aal2'])
      .default('aal1')
      .describe('Sign-in level the person browses at: aal1 = password only (default), aal2 = with a second factor'),
    app: z.string().max(63).regex(SERVICE_NAME).optional().describe('Pin the service instead of letting the policy resolve the owner'),
  },
  async run(args, { jinbe, call }) {
    const data = await jinbe.post<AccessCheck>(call, '/api/admin/rbac/access-check', args)
    const notes = data.reason === 'needs_2fa' && args.aal !== 'aal2' ? [stepUpNote(data)] : []
    return { data, source: 'jinbe:/api/admin/rbac/access-check', notes }
  },
})

const REQUIRED_BY: Record<string, string> = {
  site: 'this site requires a second factor for everyone',
  platform_group: 'a platform group this person is in requires a second factor',
}

/**
 * needs_2fa is "granted, but not at this sign-in level" (rbac.rego): never a missing permission. Said
 * in words, so a refusal at aal1 on a 2FA site does not read as a broken grant. A jinbe without
 * `stepUp` still gets the sentence, from the reason alone.
 */
function stepUpNote(data: AccessCheck): string {
  const by = (data.stepUp?.requiredBy ?? []).map((k) => REQUIRED_BY[k]).filter(Boolean)
  const why = by.length ? by.join('; ') : 'the site or one of this person\'s groups requires a second factor'
  if (data.stepUp && !data.stepUp.allowedAtAal2) {
    return `Denied at ${data.aal ?? 'aal1'} for want of a second factor (${why}), and still refused at aal2: check the groups and permissions too.`
  }
  return `Would be allowed at aal2 (second factor): ${why}. The only failing condition is the sign-in level, not a permission. Call again with aal "aal2" to confirm.`
}

export const getUserAccess = defineTool({
  name: 'get_user_access',
  title: "A person's access",
  description: "One person's access, both layers: site groups and roles per service, and per organisation the admin flag and groups granted there.",
  scopes: [P.ACCESS_READ],
  input: { userId: z.string().regex(IDENTITY_ID, 'an identity id (find_users gives it)') },
  async run(args, { jinbe, call }) {
    const data = await jinbe.get<UserAccess>(call, `/api/admin/users/${seg(args.userId)}/access`)
    return { data, source: 'jinbe:/api/admin/users/:id/access' }
  },
})

export const findUsers = defineTool({
  name: 'find_users',
  title: 'Find people',
  description:
    'Quick find by identity id, whole email, start of an email, or a substring of email or name. At most 10 hits with id, email, name, active, groups, organisations and 2FA status.',
  scopes: [P.USERS_READ],
  input: {
    query: z.string().min(1).max(320),
    limit: z.number().int().min(1).max(10).optional(),
  },
  async run(args, { jinbe, call }) {
    const res = await jinbe.get<UserLookup>(call, '/api/admin/users/lookup', { q: args.query, limit: args.limit })
    // Only the documented fields: a Kratos identity carries more than anybody asking needs.
    const items = res.data.map(({ id, email, name, active, groups, organizations, mfa }) => ({ id, email, name, active, groups, organizations, mfa }))
    return { data: { match: res.match, items }, source: 'jinbe:/api/admin/users/lookup' }
  },
})

export const accessTools: ToolDef[] = [explainAccess, getUserAccess, findUsers] as ToolDef[]
