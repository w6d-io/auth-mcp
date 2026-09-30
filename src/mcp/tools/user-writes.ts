import { z } from 'zod'
import { defineTool, type ToolDef } from '../registry.js'
import { P } from '../permissions.js'
import { seg } from '../../jinbe/client.js'
import { toolError } from '../../safety/errors.js'
import { GROUP_NAME } from '../../safety/untrusted.js'
import { USERS, idempotencyKey, obj, refuseSelfTarget, userId } from './write-common.js'

/**
 * People: DIRECT through a key, each on its own catalogue permission. Never the caller's own account
 * (refused here and in jinbe). Changing an address and adding to groups are PROTECTED (a key created
 * with protected actions allowed). Links and codes are mailed by Kratos and never come back to jinbe,
 * so no tool can return one.
 */

const JINBE_W17 = 'wave17/mcp-endpoints'
const email = z.string().email().max(254)

export const inviteUser = defineTool({
  name: 'invite_user',
  title: 'Invite a user',
  description:
    'Create a user with an email and optional name, and (by default) mail them an invitation (also needs users:recovery). Optional groups go through the same checks as add_user_to_groups (groups.members:write, protected).',
  scopes: [P.USERS_CREATE],
  write: true,
  input: {
    email,
    name: z.string().min(1).max(120).optional(),
    groups: z.array(z.string().regex(GROUP_NAME)).max(20).optional(),
    sendInvite: z.boolean().default(true),
    idempotencyKey,
  },
  async run(args, ctx) {
    const res = await ctx.jinbe.write<Record<string, unknown>>(ctx.call, 'POST', USERS, {
      body: { email: args.email, ...(args.name ? { name: args.name } : {}), ...(args.groups?.length ? { groups: args.groups } : {}), sendInvite: args.sendInvite },
      idempotencyKey: args.idempotencyKey,
    })
    const u = obj(res.body)
    const traits = obj(u.traits)
    return {
      data: { id: u.id, email: traits.email ?? args.email, name: traits.name ?? null, state: u.state ?? null, invited: args.sendInvite, groups: args.groups ?? [] },
      source: `jinbe:${USERS}`,
    }
  },
})

export const sendRecoveryEmail = defineTool({
  name: 'send_recovery_email',
  title: 'Send a recovery email',
  description: "Mail a user a Kratos recovery message, to get back into their account. The link goes only to their address.",
  scopes: [P.USERS_RECOVERY],
  write: true,
  input: { userId, idempotencyKey },
  guard: (args, ctx) => refuseSelfTarget(args.userId, ctx),
  async run(args, ctx) {
    await ctx.jinbe.write(ctx.call, 'POST', `${USERS}/${seg(args.userId)}/recovery-email`, { body: {}, idempotencyKey: args.idempotencyKey })
    return { data: { userId: args.userId, sent: true }, source: `jinbe:${USERS}/:id/recovery-email` }
  },
})

export const sendLoginLink = defineTool({
  name: 'send_login_link',
  title: 'Send a sign-in link',
  description: 'Mail a user a one-click sign-in link (rate limited per user). The link is never returned.',
  scopes: [P.USERS_LOGIN_LINK],
  write: true,
  input: {
    userId,
    returnTo: z.string().url().max(2048).refine((u) => /^https?:\/\//.test(u), 'an http(s) URL').optional().describe('Where they land after signing in'),
    idempotencyKey,
  },
  guard: (args, ctx) => refuseSelfTarget(args.userId, ctx),
  async run(args, ctx) {
    const res = await ctx.jinbe.write<Record<string, unknown>>(ctx.call, 'POST', `${USERS}/${seg(args.userId)}/login-link`, {
      body: args.returnTo ? { return_to: args.returnTo } : {},
      idempotencyKey: args.idempotencyKey,
    })
    const b = obj(res.body)
    return { data: { userId: args.userId, sent: b.sent ?? true, expiresAt: b.expiresAt ?? null }, source: `jinbe:${USERS}/:id/login-link` }
  },
})

/** requires jinbe ≥ wave17/mcp-endpoints: POST /api/admin/users/:id/verification. */
export const resendVerificationEmail = defineTool({
  name: 'resend_verification_email',
  title: 'Resend a verification email',
  description:
    "Mail a verification link to a user's unverified address (3 per user per 15 minutes). Refused when the address is already verified (conflict) or is not one of theirs.",
  scopes: [P.USERS_VERIFY],
  write: true,
  requiresJinbe: JINBE_W17,
  input: { userId, address: email.optional().describe("Which of the user's addresses; default: the sign-in one"), idempotencyKey },
  guard: (args, ctx) => refuseSelfTarget(args.userId, ctx),
  async run(args, ctx) {
    const res = await ctx.jinbe.write<Record<string, unknown>>(ctx.call, 'POST', `${USERS}/${seg(args.userId)}/verification`, {
      body: args.address ? { address: args.address } : {},
      idempotencyKey: args.idempotencyKey,
    })
    return { data: { userId: args.userId, sent: obj(res.body).sent ?? true }, source: `jinbe:${USERS}/:id/verification` }
  },
})

/**
 * requires jinbe ≥ wave17/mcp-endpoints: POST /api/admin/users/:id/email {email} → {id, email,
 * verified: false, verificationSent, verificationError?, oldAddressNotice}. jinbe refuses your own
 * address (own_address), a target holding admin rights you lack (outranked), a taken address
 * (address_unavailable, generic) and the same address (address_unchanged).
 */
export const changeUserEmail = defineTool({
  name: 'change_user_email',
  title: "Change a user's email",
  description:
    "Change another user's sign-in address. The new address starts unverified and is sent a verification link; the change is recorded in the audit trail. Never your own, never someone holding admin rights you lack. Protected: needs a connection allowed protected actions (get_my_identity says; can_i checks).",
  scopes: [P.USERS_UPDATE_EMAIL],
  write: true,
  destructive: true,
  protectedAction: true,
  requiresJinbe: JINBE_W17,
  input: { userId, newEmail: email, idempotencyKey },
  guard: (args, ctx) => refuseSelfTarget(args.userId, ctx),
  async run(args, ctx) {
    const res = await ctx.jinbe.write<Record<string, unknown>>(ctx.call, 'POST', `${USERS}/${seg(args.userId)}/email`, {
      body: { email: args.newEmail },
      idempotencyKey: args.idempotencyKey,
    })
    const b = obj(res.body)
    const notes = b.verificationSent === false ? ['The verification email could not be sent: retry with resend_verification_email.'] : []
    return {
      data: {
        userId: b.id ?? args.userId,
        email: b.email ?? args.newEmail,
        verified: b.verified ?? false,
        verificationSent: b.verificationSent ?? null,
        ...(b.verificationError ? { verificationError: b.verificationError } : {}),
        oldAddressNotice: b.oldAddressNotice ?? null,
      },
      source: `jinbe:${USERS}/:id/email`,
      notes,
    }
  },
})

export const addUserToGroups = defineTool({
  name: 'add_user_to_groups',
  title: 'Add a user to groups',
  description:
    'Add a user (by email) to platform groups; their other groups are kept. Never removes a group (removal is done in the console). Protected: needs a connection allowed protected actions (get_my_identity says; can_i checks).',
  scopes: [P.GROUPS_MEMBERS_WRITE],
  write: true,
  protectedAction: true,
  input: {
    email: email.describe("The user's email"),
    groups: z.array(z.string().regex(GROUP_NAME)).min(1).max(20),
    idempotencyKey,
  },
  guard: (args, ctx) => refuseSelfTarget(args.email, ctx),
  async run(args, ctx) {
    const path = `${USERS}/${seg(args.email.toLowerCase())}/groups`
    const current = await ctx.jinbe.get<{ groups?: unknown }>(ctx.call, path)
    const held = Array.isArray(current.groups) ? current.groups.map(String) : null
    if (!held) throw toolError('upstream_unavailable', "The user's current groups could not be read; nothing was changed", { retryable: true })
    const wanted = [...new Set(args.groups)]
    const added = wanted.filter((g) => !held.includes(g))
    const alreadyMember = wanted.filter((g) => held.includes(g))
    if (!added.length) {
      // Nothing written: said so, not reported as a successful change.
      return {
        data: { email: args.email, status: 'unchanged', changed: false, added: [], already_member: alreadyMember, groups: held },
        source: `jinbe:${USERS}/:email/groups`,
        notes: ['No change: the user already holds every requested group, so nothing was written.'],
      }
    }
    // PUT replaces the set: always a superset of what was read, so this tool can only add.
    const res = await ctx.jinbe.write<Record<string, unknown>>(ctx.call, 'PUT', path, { body: { groups: [...held, ...added] }, idempotencyKey: args.idempotencyKey })
    const out = obj(res.body)
    return {
      data: { email: args.email, status: 'added', changed: true, added, already_member: alreadyMember, groups: out.groups ?? [...held, ...added] },
      source: `jinbe:${USERS}/:email/groups`,
    }
  },
})

export const revokeMyKey = defineTool({
  name: 'revoke_my_key',
  title: 'Revoke one of my keys',
  description:
    'Revoke one of your own personal keys, by default the one this connection uses: it stops working at once. The only removal a key may make.',
  scopes: [P.MCP],
  write: true,
  destructive: true,
  input: {
    keyId: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/).optional().describe('Default: the key of this connection'),
  },
  async run(args, ctx) {
    const keyId = args.keyId ?? ctx.principal.keyId
    if (!keyId) throw toolError('invalid_request', 'This connection is not a personal key: name the keyId to revoke')
    await ctx.jinbe.write(ctx.call, 'DELETE', `/api/me/api-keys/${seg(keyId)}`)
    // Refused on this replica from now on, and its cached token and principal dropped.
    ctx.revocations?.revoke(keyId)
    return {
      data: { keyId, revoked: true, thisConnection: keyId === ctx.principal.keyId },
      source: 'jinbe:/api/me/api-keys/:clientId',
      ...(keyId === ctx.principal.keyId ? { notes: ['This connection stops working now: create a new key to connect again.'] } : {}),
    }
  },
})

export const userWriteTools: ToolDef[] = [
  inviteUser,
  sendRecoveryEmail,
  sendLoginLink,
  resendVerificationEmail,
  changeUserEmail,
  addUserToGroups,
  revokeMyKey,
] as ToolDef[]
