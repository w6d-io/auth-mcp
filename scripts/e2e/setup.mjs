// Fixtures and cleanup. Role holders are made the way a person would be: a Kratos identity, a recovery
// link opened in a cookie jar, an authenticator app enrolled with a secret only this process knows, a
// step-up to aal2, a staff group set by the owner, and then the holder mints their own key in
// jinbe (POST /api/me/api-keys needs a second factor proven in the last 15 minutes: they just did).
import { CFG, Jar, State, http, owner, kratosAdmin, hydraAdmin, fixtureEmail, isFixtureEmail, groupName, totp, totpWindow, sleep, log } from './lib.mjs'

export const HOLDERS = [
  { role: 'support', group: 'staff-support' },
  { role: 'developer', group: 'staff-developers' },
  { role: 'ops', group: 'staff-ops' },
  { role: 'security', group: 'staff-security' },
]
export const TARGETS = ['t1', 't2', 't3', 't4']

/** The owner, from their own session: id, email, and how long ago they proved a second factor. */
export async function whoOwner(ownerJar) {
  const r = await http('GET', `${CFG.kratosUrl}/sessions/whoami`, { jar: ownerJar })
  if (r.status !== 200) throw new Error(`E2E_OWNER_COOKIE is not a valid sandbox session (whoami ${r.status})`)
  const s = r.body
  const second = (s.authentication_methods ?? []).filter((m) => ['totp', 'webauthn', 'lookup_secret', 'passkey'].includes(m.method))
  const last = second.map((m) => Date.parse(m.completed_at)).filter(Number.isFinite).sort().pop()
  return {
    id: s.identity.id,
    email: String(s.identity.traits?.email ?? '').toLowerCase(),
    aal: s.authenticator_assurance_level,
    secondFactorAgeSec: last ? Math.round((Date.now() - last) / 1000) : null,
  }
}

async function createIdentity(email, name, verified) {
  const r = await kratosAdmin('POST', '/admin/identities', {
    schema_id: 'default',
    traits: { email, name },
    state: 'active',
    verifiable_addresses: [{ value: email, via: 'email', verified, status: verified ? 'completed' : 'pending' }],
  })
  if (r.status !== 201) throw new Error(`create identity ${email}: Kratos ${r.status} ${JSON.stringify(r.body).slice(0, 200)}`)
  return r.body.id
}

/** Adds groups as the owner (jinbe PUT replaces the set: always a superset of what was read). */
async function addGroups(ownerJar, email, groups) {
  const cur = await owner('GET', `/api/admin/users/${encodeURIComponent(email)}/groups`, undefined, ownerJar)
  if (cur.status !== 200) throw new Error(`read groups of ${email}: jinbe ${cur.status}`)
  const held = (cur.body.groups ?? []).map(String)
  const r = await owner('PUT', `/api/admin/users/${encodeURIComponent(email)}/groups`, { groups: [...new Set([...held, ...groups])] }, ownerJar)
  if (r.status !== 200) throw new Error(`add ${email} to ${groups}: jinbe ${r.status} ${JSON.stringify(r.body).slice(0, 200)} (a second factor older than 15 min? groups_precondition_failed?)`)
}

const node = (flow, id) => (flow.ui?.nodes ?? []).find((n) => n.attributes?.id === id || n.attributes?.name === id)
const csrf = (flow) => node(flow, 'csrf_token')?.attributes?.value

/** Recovery link → session → TOTP enrolled → aal2. Returns the jar holding the aal2 session. */
async function holderSession(identityId) {
  const link = await kratosAdmin('POST', '/admin/recovery/link', { identity_id: identityId, expires_in: '10m' })
  if (link.status !== 200) throw new Error(`recovery link: Kratos ${link.status}`)
  const jar = new Jar()
  let url = link.body.recovery_link
  const K = url.slice(0, url.indexOf('/self-service')) // Kratos public, as Kratos itself names it
  let flowId = null
  for (let hop = 0; hop < 6 && url; hop++) {
    const r = await http('GET', url, { jar, headers: { accept: 'text/html' } })
    const next = r.location ? new URL(r.location, url) : null
    if (next?.searchParams.get('flow') && /settings/.test(next.pathname)) flowId = next.searchParams.get('flow')
    url = next && next.href.startsWith(`${K}/self-service`) ? next.href : null
  }
  if (!flowId) throw new Error('recovery link did not land on a settings flow (link method enabled? step 13)')

  const flow = await http('GET', `${K}/self-service/settings/flows?id=${flowId}`, { jar })
  const secret = node(flow.body, 'totp_secret_key')?.attributes?.text?.text
  if (!secret) throw new Error('settings flow offers no TOTP secret (totp method enabled?)')
  const enrolled = totpWindow()
  const set = await http('POST', `${K}/self-service/settings?flow=${flowId}`, { jar, body: { method: 'totp', totp_code: totp(secret), csrf_token: csrf(flow.body) } })
  if (set.status !== 200) throw new Error(`TOTP enrolment: Kratos ${set.status} ${JSON.stringify(set.body?.ui?.messages ?? set.body?.error ?? '').slice(0, 200)}`)

  while (totpWindow() === enrolled) await sleep(1000) // a fresh code for the step-up
  const login = await http('GET', `${K}/self-service/login/browser?aal=aal2&refresh=true`, { jar })
  if (login.status !== 200) throw new Error(`aal2 login flow: Kratos ${login.status}`)
  const done = await http('POST', `${K}/self-service/login?flow=${login.body.id}`, { jar, body: { method: 'totp', totp_code: totp(secret), csrf_token: csrf(login.body) } })
  if (done.status !== 200) throw new Error(`aal2 step-up: Kratos ${done.status}`)
  const who = await http('GET', `${K}/sessions/whoami`, { jar })
  if (who.body?.authenticator_assurance_level !== 'aal2') throw new Error(`holder session is ${who.body?.authenticator_assurance_level}, not aal2`)
  return jar
}

/** A personal key, minted by its holder (session jar). Returns {clientId, key}. */
async function mintKey(jar, label, allowStepUp = true) {
  const r = await owner('POST', '/api/me/api-keys', { label, expires_in_days: 1, allow_step_up_actions: allowStepUp }, jar)
  if (r.status !== 201) throw new Error(`mint key ${label}: jinbe ${r.status} ${r.body?.error ?? ''} ${r.body?.message ?? ''}`.trim())
  return { clientId: r.body.client_id, key: r.body.key }
}

/**
 * Builds every fixture. Returns {holders: {role: {id, email, clientId, key}}, admin, adminNoProtect,
 * targets: {t1: {id, email}}, owner}. Keys are returned, never stored.
 */
export async function setup(state, ownerJar) {
  const o = await whoOwner(ownerJar)
  state.data.owner = { id: o.id, email: o.email }
  state.save()
  log(`owner ${o.email} (${o.aal}, second factor ${o.secondFactorAgeSec ?? '?'}s ago)`)
  if (o.aal !== 'aal2') throw new Error('the owner session is not aal2: sign in to kuma with your second factor, then copy the cookie')
  if (o.secondFactorAgeSec !== null && o.secondFactorAgeSec > 600) throw new Error(`the owner's second factor is ${o.secondFactorAgeSec}s old: step up again (setup needs < 10 min, holder group adds need < 15)`)

  // Owner keys first: they need the owner's second factor to be recent, so a stale cookie fails here,
  // before any fixture exists.
  const adminKeys = {}
  for (const [name, allow, envVar] of [['admin', true, 'E2E_KEY_ADMIN'], ['admin-noprotect', false, 'E2E_KEY_ADMIN_NOPROTECT']]) {
    if (process.env[envVar]) {
      adminKeys[name] = { key: process.env[envVar], clientId: process.env[envVar].replace(/^stk_mcp_/, '').split('.')[0], id: o.id, email: o.email }
      continue
    }
    const k = await mintKey(ownerJar, `${CFG.run}-${name}`, allow)
    state.add('keys', { clientId: k.clientId, holder: o.id, role: name, ownerKey: true })
    adminKeys[name] = { ...k, id: o.id, email: o.email }
  }
  log('owner keys ready: admin (protected actions allowed), admin-noprotect (not allowed)')

  // Holders: identity, then a second factor and aal2 (jinbe refuses a staff group to anybody without
  // one: 422 mfa_required), then the group, then the key. Sessions run in parallel (TOTP windows).
  const holders = {}
  const jars = {}
  for (const h of HOLDERS) {
    const email = fixtureEmail(h.role)
    const id = await createIdentity(email, `E2E ${h.role}`, true)
    state.add('identities', { id, email, kind: 'holder', role: h.role })
    holders[h.role] = { id, email, group: h.group }
  }
  await Promise.all(HOLDERS.map(async (h) => (jars[h.role] = await holderSession(holders[h.role].id))))
  log('holders enrolled a second factor and are at aal2')
  for (const [i, h] of HOLDERS.entries()) {
    if (i) await sleep(1000) // each add triggers a policy push; spaced so the edge is not caught mid-reload
    await addGroups(ownerJar, holders[h.role].email, [h.group])
  }
  log(`holders in ${HOLDERS.map((h) => h.group).join(', ')}`)

  // Targets while the policy push lands (the key's scopes are the holder's groups at mint time).
  const pushed = Date.now() + 5000
  const targets = {}
  for (const t of TARGETS) {
    const email = fixtureEmail(t)
    const id = await createIdentity(email, `E2E ${t}`, false)
    state.add('identities', { id, email, kind: 'target' })
    targets[t] = { id, email }
  }
  log(`targets: ${TARGETS.join(', ')} (unverified)`)
  if (Date.now() < pushed) await sleep(pushed - Date.now())

  await Promise.all(
    HOLDERS.map(async (h) => {
      const k = await mintKey(jars[h.role], `${CFG.run}-${h.role}`)
      state.add('keys', { clientId: k.clientId, holder: holders[h.role].id, role: h.role, ownerKey: false })
      Object.assign(holders[h.role], k)
    }),
  )
  log('holder keys minted (1 day, all of the holder\'s permissions, protected actions allowed)')
  return { holders, targets, owner: o, admin: adminKeys.admin, adminNoProtect: adminKeys['admin-noprotect'] }
}

/**
 * Removes everything the state file lists: keys, then identities (Kratos admin, no second factor
 * needed, so they go even when the owner's step-up has expired), then groups and sites (as
 * the owner: a second factor < 15 min old). Idempotent: a second run after a partial failure removes
 * what is left. Identities are deleted only when Kratos still says their address is one of this
 * run's fixtures (never the owner, never anybody else).
 */
export async function cleanup(state, ownerJar) {
  const left = []
  const d = state.data
  const ownerOk = ownerJar ? (await http('GET', `${CFG.kratosUrl}/sessions/whoami`, { jar: ownerJar })).status === 200 : false

  for (const k of d.keys.filter((x) => !x.revoked)) {
    let gone = false
    if (k.ownerKey && ownerOk) gone = [204, 404].includes((await owner('DELETE', `/api/me/api-keys/${encodeURIComponent(k.clientId)}`, undefined, ownerJar)).status)
    if (!gone) gone = [204, 404].includes((await hydraAdmin('DELETE', `/admin/clients/${encodeURIComponent(k.clientId)}`)).status)
    if (gone) k.revoked = true
    else left.push(`key ${k.role} ${k.clientId}`)
  }
  state.save()

  for (const i of d.identities.filter((x) => !x.deleted)) {
    const cur = await kratosAdmin('GET', `/admin/identities/${i.id}`)
    if (cur.status === 404) { i.deleted = true; continue }
    const email = cur.body?.traits?.email
    if (cur.status !== 200 || !isFixtureEmail(email) || i.id === d.owner?.id) { left.push(`identity ${i.id} (${cur.status}, not deleted: address ${isFixtureEmail(email) ? 'ok' : 'is not a fixture'})`); continue }
    const r = await kratosAdmin('DELETE', `/admin/identities/${i.id}`)
    if ([204, 404].includes(r.status)) i.deleted = true
    else left.push(`identity ${i.id} (${r.status})`)
  }
  state.save()

  for (const g of d.groups.filter((x) => !x.deleted)) {
    if (!ownerOk) { left.push(`group ${g.name} (no valid owner session)`); continue }
    const r = await owner('DELETE', `/api/admin/rbac/groups/${g.name}`, undefined, ownerJar)
    if ([200, 204, 404].includes(r.status)) g.deleted = true
    else left.push(`group ${g.name} (${r.status} ${r.body?.error ?? ''})`)
  }
  for (const s of d.sites.filter((x) => !x.deleted)) {
    if (!ownerOk) { left.push(`site ${s.name} (no valid owner session)`); continue }
    const del = await owner('DELETE', `/api/admin/sites/${s.name}`, undefined, ownerJar)
    const draft = await owner('DELETE', `/api/admin/sites/${s.name}/draft`, undefined, ownerJar)
    if ([200, 202, 204, 404].includes(del.status) && [200, 204, 404].includes(draft.status)) s.deleted = true
    else left.push(`site ${s.name} (delete ${del.status} ${del.body?.error ?? ''}, draft ${draft.status}; a second factor older than 15 min → re-run --cleanup-only with a fresh cookie)`)
  }
  state.save()

  d.cleanedAt = new Date().toISOString()
  d.leftovers = left
  state.save()
  return left
}

export const ownerJarFromEnv = () => (process.env.E2E_OWNER_COOKIE ? new Jar(process.env.E2E_OWNER_COOKIE) : null)
export { State, groupName }
