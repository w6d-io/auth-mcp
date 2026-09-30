#!/usr/bin/env node
// The MCP end-to-end test's client. Run through scripts/mcp-e2e.sh, which checks the kube context and
// the sandbox marker first and always runs `cleanup` afterwards.
//
//   node scripts/mcp-e2e-client.mjs plan       print every step and case; calls nothing
//   node scripts/mcp-e2e-client.mjs run        fixtures → recipes → adversarial → audit → report
//   node scripts/mcp-e2e-client.mjs cleanup    remove what state.json lists (idempotent)
//
// Env: E2E_RUN_ID, E2E_STATE_DIR, E2E_REPORT_DIR, E2E_OWNER_COOKIE, E2E_BINDINGS (JSON), and the
// optional overrides in e2e/lib.mjs (CFG).
import { CFG, State, Mcp, leaks, log, sleep, groupName } from './e2e/lib.mjs'
import { setup, cleanup, ownerJarFromEnv, HOLDERS, TARGETS } from './e2e/setup.mjs'
import { CASES, FINAL_CASES } from './e2e/cases.mjs'
import { writeReport } from './e2e/report.mjs'

const cmd = process.argv[2]
const need = (v, name) => {
  if (!v) {
    console.error(`missing ${name}`)
    process.exit(2)
  }
  return v
}

function plan() {
  const line = (id, actor, title, expect) => console.log(`  ${id.padEnd(6)} ${actor.padEnd(18)} ${title}\n  ${''.padEnd(6)} ${''.padEnd(18)} → ${expect}`)
  console.log(`Setup (owner session cookie + kubectl exec in ${CFG.ns}; nothing through the MCP yet)`)
  console.log('  S1  owner keys first (fails fast on a stale second factor): admin (protected actions allowed) and admin-noprotect, minted with the owner cookie unless E2E_KEY_ADMIN[_NOPROTECT] are set')
  console.log(`  S2  holders ${HOLDERS.map((h) => h.role).join(', ')}: Kratos admin (exec in jinbe) → recovery link → session → TOTP enrolled (secret in memory) → aal2`)
  console.log(`  S3  owner adds each holder to its group (${HOLDERS.map((h) => `${h.role}→${h.group}`).join(', ')}): jinbe PUT groups; needs the holder's second factor`)
  console.log(`  S4  targets ${TARGETS.join(', ')}: Kratos admin, unverified, ${CFG.run || 'e2e-<ts>'}-t*@${CFG.emailDomain} (covers the policy push), then each holder mints its own key (1 day)`)
  console.log('\nCases')
  for (const c of CASES) line(c.id, c.actor, c.title, c.expect)
  line('AU-*', 'admin (MCP)', 'search_audit for every passing write: actor = holder, auth.method delegated, act.via, act.client_id = key', `one AU row per recipe with an audit event (act.via=${CFG.actVia})`)
  for (const c of FINAL_CASES) line(c.id, c.actor, `${c.title}${c.optional ? ' [optional, skipped unless E2E_RATE_LIMIT=on]' : ''}`, c.expect)
  line('A9', 'every result', 'leak scan over every tool result', 'no stk_mcp_, PEM, ory_* token, JWT or self-service link with a token')
  console.log('\nCleanup (always, trap): keys (owner: DELETE /api/me/api-keys; holders: Hydra admin), identities (Kratos admin, only if the address is still a run fixture), groups and sites (DELETE site + draft) as the owner')
}

async function run() {
  need(CFG.run, 'E2E_RUN_ID')
  const state = new State(`${need(CFG.stateDir, 'E2E_STATE_DIR')}/state.json`)
  const ownerJar = ownerJarFromEnv()
  need(ownerJar, 'E2E_OWNER_COOKIE')
  const bindings = process.env.E2E_BINDINGS ? JSON.parse(process.env.E2E_BINDINGS) : null
  state.data.bindings = bindings
  state.save()
  const startedAt = new Date().toISOString()
  const rows = []
  let fatal = null
  let c = null
  try {
    const fx = await setup(state, ownerJar)
    const keys = { ...Object.fromEntries(HOLDERS.map((h) => [h.role, fx.holders[h.role]])), admin: fx.admin, noprotect: fx.adminNoProtect }
    const mcp = {}
    for (const [role, k] of Object.entries(keys)) mcp[role] = await new Mcp(role, k.key).connect()
    const adminTools = (await mcp.admin.tools()).map((t) => t.name)
    if (!adminTools.includes('create_site')) throw new Error('the admin key sees no write tool: auth-mcp is in read-only mode (MCP_READ_ONLY) or the kill switch is on')
    c = { mcp, keys, holders: fx.holders, targets: fx.targets, owner: fx.owner, admin: fx.admin, site: CFG.run, group: groupName(), state, store: {}, ownerJar }
    log(`site ${c.site}, group ${c.group}; ${CASES.length} cases`)

    const exec = async (list) => {
      for (const k of list) {
        const t0 = Date.now()
        let r
        try {
          r = await k.run(c)
        } catch (e) {
          r = { pass: false, got: `exception: ${String(e?.message ?? e).slice(0, 300)}` }
        }
        rows.push({ id: k.id, actor: k.actor, title: k.title, expect: k.expect, ...r, ms: Date.now() - t0 })
        log(`${String(r.pass === true ? 'PASS' : r.pass === false ? 'FAIL' : String(r.pass).toUpperCase()).padEnd(12)} ${k.id} ${r.got}`)
      }
    }
    await exec(CASES)
    rows.push(...(await auditRows(c, rows, startedAt)))
    await exec(FINAL_CASES)
  } catch (e) {
    fatal = String(e?.message ?? e)
    log(`ABORTED: ${fatal}`)
  } finally {
    rows.push({ id: 'A9', actor: 'every result', title: 'leak scan over every tool result', expect: 'no secret-shaped string', pass: leaks.length === 0, got: leaks.length ? `matched ${[...new Set(leaks)].join(', ')}` : 'clean' })
    for (const m of Object.values(c?.mcp ?? {})) await m.close()
  }
  const finishedAt = new Date().toISOString()
  const file = `${need(CFG.reportDir, 'E2E_REPORT_DIR')}/mcp-e2e-report-${CFG.run}.md`
  const t = writeReport(file, { rows, bindings, state, startedAt, finishedAt, fatal, serviceVersions: c?.store.serviceVersions, gate: c?.store.gate })
  state.data.results = rows.map(({ id, pass, got }) => ({ id, pass, got }))
  state.save()
  console.log(`\nreport: ${file}\n${t.PASS} pass, ${t.FAIL} fail, ${t.INCONCLUSIVE} inconclusive, ${t.SKIP} skipped${fatal ? ' — ABORTED' : ''}`)
  process.exitCode = fatal || t.FAIL ? 1 : 0
}

/** One AU row per passing write: the event is in the trail with the right actor, method, client and path. */
async function auditRows(c, rows, since) {
  const want = rows.filter((r) => r.pass === true && r.audit)
  if (!want.length) return []
  const actorOf = (holder) => (holder === 'admin' ? c.admin : c.keys[holder])
  const found = new Map()
  const versions = new Set()
  const deadline = Date.now() + 120000 // Loki ingestion lag
  while (Date.now() < deadline) {
    for (const actorId of new Set(want.map((r) => actorOf(r.audit.holder).id))) {
      let cursor
      for (let page = 0; page < 5; page++) {
        const r = await c.mcp.admin.call('search_audit', { from: since, actor: actorId, limit: 100, ...(cursor ? { cursor } : {}) })
        if (!r.ok) break
        for (const e of r.data?.items ?? []) {
          if (e.service_version) versions.add(e.service_version)
          for (const w of want) {
            const a = actorOf(w.audit.holder)
            const prev = found.get(w.id)
            if (prev?.actor?.act?.client_id === a.clientId || a.id !== e.actor?.id || !w.audit.events.includes(e.event)) continue
            // An event from this key wins over one from another path (e.g. the owner's browser).
            if (!prev || e.actor?.act?.client_id === a.clientId) found.set(w.id, e)
          }
        }
        cursor = r.raw?.structuredContent?.nextCursor
        if (!cursor) break
      }
    }
    if (want.every((w) => found.get(w.id)?.actor?.act?.client_id === actorOf(w.audit.holder).clientId)) break
    await sleep(15000)
  }
  c.store.serviceVersions = [...versions]
  return want.map((w) => {
    const e = found.get(w.id)
    const a = actorOf(w.audit.holder)
    const act = e?.actor?.act ?? {}
    const checks = e ? { method: e.actor?.auth?.method === 'delegated', via: act.via === CFG.actVia, client: act.client_id === a.clientId, kind: act.kind === 'personal', success: e.result === 'success' } : {}
    const bad = Object.entries(checks).filter(([, v]) => !v).map(([k]) => k)
    return {
      id: `AU-${w.id}`,
      actor: `${w.audit.holder} (${a.id})`,
      title: `audit of ${w.id}`,
      expect: `${w.audit.events.join(' | ')}; delegated; via ${CFG.actVia}; client ${a.clientId}`,
      pass: !!e && bad.length === 0,
      got: e ? `${e.event} ${e.event_id} method=${e.actor?.auth?.method} via=${act.via} client=${act.client_id} kind=${act.kind}${bad.length ? ` — wrong: ${bad.join(', ')}` : ''}` : 'no event within 120s',
    }
  })
}

async function doCleanup() {
  need(CFG.run, 'E2E_RUN_ID')
  const state = new State(`${need(CFG.stateDir, 'E2E_STATE_DIR')}/state.json`)
  const left = await cleanup(state, ownerJarFromEnv())
  if (left.length) {
    console.error(`cleanup left ${left.length} object(s):`)
    for (const l of left) console.error(`  - ${l}`)
    console.error(`re-run with a fresh owner cookie: scripts/mcp-e2e.sh --cleanup-only ${CFG.run}`)
    process.exitCode = 1
  } else {
    console.error('cleanup: nothing left')
  }
}

if (cmd === 'plan') plan()
else if (cmd === 'run') await run()
else if (cmd === 'cleanup') await doCleanup()
else {
  console.error('usage: mcp-e2e-client.mjs plan|run|cleanup')
  process.exit(2)
}
