// The run's evidence: a markdown report bound to what was running (image digests from the pods,
// the repositories' HEADs, jinbe's service_version from the audit lines) and every result row.
import { writeFileSync, mkdirSync } from 'node:fs'
import { CFG } from './lib.mjs'

const mark = (p) => (p === true ? 'PASS' : p === false ? 'FAIL' : p === 'inconclusive' ? 'INCONCLUSIVE' : 'SKIP')
const cell = (s) => String(s ?? '').replace(/\|/g, '\\|').replace(/\n/g, ' ').slice(0, 400)

export function tally(rows) {
  const t = { PASS: 0, FAIL: 0, INCONCLUSIVE: 0, SKIP: 0 }
  for (const r of rows) t[mark(r.pass)] += 1
  return t
}

export function writeReport(file, { rows, bindings, state, startedAt, finishedAt, fatal, serviceVersions, gate }) {
  const t = tally(rows)
  const b = bindings ?? {}
  const img = (k) => b.images?.[k] ?? {}
  const repo = (k) => b.repos?.[k] ?? {}
  const table = (list) => ['| ID | Actor | Case | Expected | Got | Result |', '|---|---|---|---|---|---|', ...list.map((r) => `| ${r.id} | ${cell(r.actor)} | ${cell(r.title)} | ${cell(r.expect)} | ${cell(r.got)} | **${mark(r.pass)}** |`)].join('\n')
  const section = (prefix) => rows.filter((r) => r.id.startsWith(prefix))
  const d = state?.data ?? {}
  const md = `# MCP end-to-end report — ${CFG.run}

${fatal ? `> **Run aborted:** ${cell(fatal)}\n\n` : ''}**Result:** ${t.PASS} pass, ${t.FAIL} fail, ${t.INCONCLUSIVE} inconclusive, ${t.SKIP} skipped. Started ${startedAt}, finished ${finishedAt} (${Math.round((Date.parse(finishedAt) - Date.parse(startedAt)) / 1000)} s).
Context \`${CFG.ctx}\`, namespace \`${CFG.ns}\` (sandbox marker checked), MCP \`${CFG.mcpUrl}\`, jinbe \`${CFG.jinbeUrl}\`.

## What ran (bindings)

| Component | Image | Digest (pod imageID) | Repo HEAD (local, for reference) |
|---|---|---|---|
| auth-mcp | \`${img('mcp').image ?? '?'}\` | \`${img('mcp').imageID ?? '?'}\` | \`${repo('auth-mcp').head ?? '?'}\`${repo('auth-mcp').dirty ? ' (dirty)' : ''} ${repo('auth-mcp').branch ?? ''} |
| jinbe | \`${img('jinbe').image ?? '?'}\` | \`${img('jinbe').imageID ?? '?'}\` | \`${repo('jinbe').head ?? '?'}\`${repo('jinbe').dirty ? ' (dirty)' : ''} ${repo('jinbe').branch ?? ''} |
| kuma | \`${img('kuma').image ?? '?'}\` | \`${img('kuma').imageID ?? '?'}\` | \`${repo('kuma').head ?? '?'}\`${repo('kuma').dirty ? ' (dirty)' : ''} ${repo('kuma').branch ?? ''} |

Image revisions (OCI label, when the script could read it): auth-mcp \`${img('mcp').revision ?? 'n/a'}\`, jinbe \`${img('jinbe').revision ?? 'n/a'}\`, kuma \`${img('kuma').revision ?? 'n/a'}\`.
jinbe \`service_version\` seen in this run's audit lines: ${serviceVersions?.length ? serviceVersions.map((v) => `\`${v}\``).join(', ') : 'none'}.
auth-mcp env: ${Object.entries(b.mcpEnv ?? {}).map(([k, v]) => `\`${k}=${v}\``).join(', ') || 'n/a'}.

The repo HEADs are the workstation's checkouts; the deployed code is the image digest. A result applies to the digests above.

## Recipes (R) — each role, through the MCP, with its own key

${table(section('R-'))}

## Audit (AU) — each successful write names the holder, \`auth.method=delegated\`, \`act.via=${CFG.actVia}\`, the key's client id

${table(section('AU-'))}

## Adversarial (A)

${table(rows.filter((r) => /^A\d/.test(r.id)))}
${gate?.length ? `
### A3 detail — jinbe's delegation gate, called from the auth-mcp pod with the admin key's delegated token

| Probe | Request | Want | Status | Reason / error | Verdict |
|---|---|---|---|---|---|
${gate.map((g) => `| ${g.id} | \`${g.method} ${cell(g.path)}\` | \`${g.want}\` | ${g.status} | \`${cell(g.reason ?? g.error ?? '')}\` | ${g.verdict} |`).join('\n')}

INCONCLUSIVE = jinbe validated the body before the gate ran (400/422): the refusal is not proven by this probe.
` : ''}
## Fixtures and cleanup

Run id \`${CFG.run}\`; every identity is \`${CFG.run}-*@${CFG.emailDomain}\`, the site \`${CFG.run}\`, groups \`mcpe_*\`.
Identities ${d.identities?.length ?? 0}, keys ${d.keys?.length ?? 0}, sites ${d.sites?.length ?? 0}, groups ${d.groups?.length ?? 0}.
Cleanup runs after this report (trap in mcp-e2e.sh); its outcome is in \`state.json\` (\`leftovers\`) and the script's last lines.
`
  mkdirSync(file.replace(/\/[^/]+$/, ''), { recursive: true })
  writeFileSync(file, md)
  return t
}
