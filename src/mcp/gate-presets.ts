import { z } from 'zod'

/**
 * A gate's four questions, answered by preset name — the same radios as kuma's Gates tab
 * (kuma src/lib/sites/presets.ts; keep the handler lists in step). A gate built from presets is the
 * secure, reviewed path; raw handlers go only through an explicit `expert_gate`, which the lint flags.
 */

type Handler = { handler: string; config?: Record<string, unknown> }

const SESSION_TOKEN: Handler = {
  handler: 'bearer_token',
  config: { token_from: { header: 'X-Session-Token' }, forward_http_headers: ['X-Session-Token'] },
}

export const WHO = {
  'signed-in': [{ handler: 'cookie_session' }],
  'signed-in-or-tokens': [{ handler: 'cookie_session' }, SESSION_TOKEN, { handler: 'oauth2_introspection' }],
  tokens: [{ handler: 'oauth2_introspection' }, SESSION_TOKEN],
  machines: [{ handler: 'oauth2_introspection' }],
  anyone: [{ handler: 'noop' }],
  optional: [{ handler: 'cookie_session' }, { handler: 'anonymous' }],
} satisfies Record<string, Handler[]>

export const PASS = {
  policy: 'policy',
  everyone: { handler: 'allow' },
  nobody: { handler: 'deny' },
} satisfies Record<string, 'policy' | Handler>

export const GETS = {
  identity: [{ handler: 'header' }],
  nothing: [{ handler: 'noop' }],
  enrich: [{ handler: 'hydrator' }, { handler: 'header' }],
} satisfies Record<string, Handler[]>

export const FAILS = ['website', 'api', 'platform'] as const

export type WhoPreset = keyof typeof WHO
export type PassPreset = keyof typeof PASS
export type GetsPreset = keyof typeof GETS

const gateId = z.string().regex(/^[a-z]([a-z0-9-]{0,20}[a-z0-9])?$/, 'lowercase letters, digits and dashes, at most 22 characters')
const method = z.enum(['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'])

/** A gate by preset (the normal way). */
export const presetGate = z
  .object({
    id: gateId,
    label: z.string().min(1).max(80),
    who: z.enum(Object.keys(WHO) as [WhoPreset, ...WhoPreset[]]).describe('Who comes in: signed-in people, tokens, machines, anyone, optional sign-in'),
    pass: z.enum(Object.keys(PASS) as [PassPreset, ...PassPreset[]]).default('policy').describe('Who may pass: policy checks permissions per route (recommended)'),
    gets: z.enum(Object.keys(GETS) as [GetsPreset, ...GetsPreset[]]).default('identity').describe('What the service receives'),
    fails: z.enum(FAILS).default('platform').describe('How refusals look: website (sign-in page), api (JSON), platform default'),
    methods: z.array(method).min(1).optional(),
    preflight: z.boolean().optional(),
  })
  .strict()

const handler = z.object({ handler: z.string().regex(/^[a-z][a-z0-9_]{1,40}$/), config: z.record(z.unknown()).optional() }).strict()

/** Raw handlers: only here, explicitly, and flagged by check_site_draft. */
export const expertGate = z
  .object({
    id: gateId,
    label: z.string().min(1).max(80),
    authenticators: z.array(handler).min(1).max(8),
    authorizer: z.union([z.literal('policy'), handler]),
    mutators: z.array(handler).min(1).max(8),
    errors: z.union([z.enum(FAILS), z.array(handler).min(1).max(8)]),
    methods: z.array(method).min(1).optional(),
    preflight: z.boolean().optional(),
    reason: z.string().min(3).max(280).describe('Why no preset fits: echoed in the answer for the person to review (not stored)'),
  })
  .strict()

export type PresetGate = z.infer<typeof presetGate>

/**
 * A preset gate as the Site intent stores it. As in kuma's withPreset: with "anyone" there is no
 * subject for the policy to check, so pass becomes everyone (unless nobody) and gets becomes nothing.
 */
export function buildGate(g: PresetGate): Record<string, unknown> {
  const anyone = g.who === 'anyone'
  const pass = anyone && g.pass === 'policy' ? 'everyone' : g.pass
  const gets = anyone ? 'nothing' : g.gets
  return {
    id: g.id,
    label: g.label,
    authenticators: WHO[g.who],
    authorizer: PASS[pass],
    mutators: GETS[gets],
    errors: g.fails,
    ...(g.methods ? { methods: g.methods } : {}),
    ...(g.preflight !== undefined ? { preflight: g.preflight } : {}),
  }
}

/** An expert gate as stored (its reason is not part of the intent). */
export function buildExpertGate(g: z.infer<typeof expertGate>): Record<string, unknown> {
  const gate: Record<string, unknown> = { ...g }
  delete gate.reason
  return gate
}

const same = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b)
const find = <T>(table: Record<string, T>, value: unknown) => Object.keys(table).find((k) => same(table[k], value)) ?? null

/** A stored gate read back into presets; null for each answer that is not exactly a preset (kuma's "custom"). */
export function presetsOf(gate: Record<string, unknown>) {
  return {
    who: find(WHO, gate.authenticators),
    pass: find(PASS, gate.authorizer),
    gets: find(GETS, gate.mutators),
    fails: typeof gate.errors === 'string' && (FAILS as readonly string[]).includes(gate.errors) ? gate.errors : null,
  }
}

/** Whether a stored gate is hand-built: any answer not a preset, or a raw match URL. */
export function isExpertGate(gate: Record<string, unknown>): boolean {
  const p = presetsOf(gate)
  const expert = gate.expert as { matchUrl?: unknown } | undefined
  return Object.values(p).includes(null) || !!expert?.matchUrl
}
