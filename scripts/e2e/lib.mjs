// Shared plumbing for the MCP end-to-end test (scripts/mcp-e2e.sh): configuration, the run state
// file, HTTP with a cookie jar, the in-cluster admin calls (through kubectl exec, never a
// port-forward), TOTP, and the MCP client wrapper. No secret is ever written to disk or printed:
// keys, cookies, recovery links and TOTP secrets live in this process's memory only.
import { spawn } from 'node:child_process'
import { createHmac } from 'node:crypto'
import { mkdirSync, readFileSync, writeFileSync, existsSync } from 'node:fs'
import { dirname } from 'node:path'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js'

const env = process.env

export const CFG = {
  ctx: env.E2E_CONTEXT || 'example/dev-aws-1',
  ns: env.E2E_NAMESPACE || 'auth-dev',
  run: env.E2E_RUN_ID || '',
  mcpUrl: env.E2E_MCP_URL || 'https://mcp.authdev.dev.example.com/mcp',
  // Byte-equal to auth-mcp's HYDRA_ISSUER and jinbe's MCP_OAUTH_ISSUER (trailing slash included).
  issuer: env.E2E_OAUTH_ISSUER || 'https://hydra.authdev.dev.example.com/',
  jinbeUrl: (env.E2E_JINBE_URL || 'https://kuma.authdev.dev.example.com').replace(/\/$/, ''),
  kratosUrl: (env.E2E_KRATOS_URL || 'https://auth.authdev.dev.example.com').replace(/\/$/, ''),
  emailDomain: env.E2E_EMAIL_DOMAIN || 'example.com',
  siteDomain: env.E2E_SITE_DOMAIN || 'dev.example.com',
  upstream: (env.E2E_UPSTREAM || 'echo:auth-dev:80').split(':'),
  actVia: env.E2E_ACT_VIA || 'auth-mcp',
  jinbeTarget: env.E2E_JINBE_TARGET || 'deploy/auth-jinbe',
  jinbeContainer: env.E2E_JINBE_CONTAINER || 'jinbe',
  mcpTarget: env.E2E_MCP_TARGET || 'deploy/auth-mcp',
  mcpContainer: env.E2E_MCP_CONTAINER || 'mcp',
  stateDir: env.E2E_STATE_DIR || '',
  reportDir: env.E2E_REPORT_DIR || '',
  rateLimit: env.E2E_RATE_LIMIT === 'on',
}

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms))
export const log = (...a) => console.error(`[${new Date().toISOString().slice(11, 19)}]`, ...a)

/** Everything created, by id and name only: what cleanup (possibly another process) must remove. */
export class State {
  constructor(file) {
    this.file = file
    this.data = existsSync(file)
      ? JSON.parse(readFileSync(file, 'utf8'))
      : { run: CFG.run, startedAt: new Date().toISOString(), identities: [], keys: [], groups: [], sites: [], owner: null, bindings: null }
  }
  save() {
    mkdirSync(dirname(this.file), { recursive: true, mode: 0o700 })
    writeFileSync(this.file, JSON.stringify(this.data, null, 2), { mode: 0o600 })
  }
  add(kind, entry) {
    this.data[kind].push(entry)
    this.save()
  }
}

/** Names every fixture carries: e2e-<ts>-<suffix>, lowercase. */
export const fixtureEmail = (suffix) => `${CFG.run}-${suffix}@${CFG.emailDomain}`.toLowerCase()
export const isFixtureEmail = (email) => typeof email === 'string' && email.toLowerCase().startsWith(`${CFG.run}-`) && CFG.run.startsWith('e2e-')
/** Group names allow [a-z_] only (create_group): the run's digits as letters. */
export const groupName = () => `mcpe_${CFG.run.replace(/^e2e-/, '').replace(/\d/g, (d) => 'abcdefghij'[Number(d)])}`

// ── HTTP with a cookie jar ────────────────────────────────────────────────────────────────────────

export class Jar {
  constructor(header = '') {
    this.cookies = new Map()
    for (const part of header.split(';')) {
      const i = part.indexOf('=')
      if (i > 0) this.cookies.set(part.slice(0, i).trim(), part.slice(i + 1).trim())
    }
  }
  take(res) {
    for (const c of res.headers.getSetCookie?.() ?? []) {
      const [pair] = c.split(';')
      const i = pair.indexOf('=')
      if (i > 0) this.cookies.set(pair.slice(0, i).trim(), pair.slice(i + 1).trim())
    }
  }
  header() {
    return [...this.cookies].map(([k, v]) => `${k}=${v}`).join('; ')
  }
}

/** fetch → {status, body, headers, location}. JSON in and out; redirects are never followed. */
export async function http(method, url, { jar, body, headers = {}, timeoutMs = 20000 } = {}) {
  const h = { accept: 'application/json', ...headers }
  if (jar) h.cookie = jar.header()
  if (body !== undefined) h['content-type'] = 'application/json'
  const res = await fetch(url, { method, headers: h, body: body === undefined ? undefined : JSON.stringify(body), redirect: 'manual', signal: AbortSignal.timeout(timeoutMs) })
  jar?.take(res)
  const text = await res.text()
  let parsed = text
  try {
    parsed = text ? JSON.parse(text) : null
  } catch {
    /* not JSON */
  }
  return { status: res.status, body: parsed, headers: res.headers, location: res.headers.get('location') }
}

/**
 * jinbe through the gateway with a session jar (the owner's, or a holder's). A 302/401/403 that is
 * not jinbe's JSON (a redirect or an HTML page: the edge authorizer, e.g. while OPAL reloads OPA
 * data) is retried up to 5 times with backoff; a JSON refusal from jinbe is the answer, never retried.
 */
const EDGE_BACKOFF_MS = [250, 500, 1000, 2000, 4000]
const fromEdge = (r) => [302, 401, 403].includes(r.status) && (!!r.location || r.body === null || typeof r.body !== 'object')
export async function owner(method, path, body, jar) {
  for (let attempt = 0; ; attempt++) {
    const r = await http(method, `${CFG.jinbeUrl}${path}`, { jar, body })
    if (!fromEdge(r) || attempt >= EDGE_BACKOFF_MS.length) return r
    log(`  edge answered ${r.status}${r.location ? ` → ${new URL(r.location, CFG.jinbeUrl).pathname}` : ''} to ${method} ${path}; retry ${attempt + 1}/${EDGE_BACKOFF_MS.length} in ${EDGE_BACKOFF_MS[attempt]} ms`)
    await sleep(EDGE_BACKOFF_MS[attempt])
  }
}

// ── In-cluster admin calls (kubectl exec; the admin tokens never leave the pod) ─────────────────

function kexec(target, container, script, input) {
  return new Promise((resolve, reject) => {
    const p = spawn('kubectl', ['--context', CFG.ctx, '-n', CFG.ns, 'exec', '-i', target, '-c', container, '--', 'node', '-e', script], { stdio: ['pipe', 'pipe', 'pipe'] })
    let out = ''
    let err = ''
    p.stdout.on('data', (d) => (out += d))
    p.stderr.on('data', (d) => (err += d))
    p.on('error', reject)
    p.on('close', (code) => {
      if (code !== 0) return reject(new Error(`kubectl exec ${target} exited ${code}: ${err.trim().slice(0, 300)}`))
      try {
        resolve(JSON.parse(out))
      } catch {
        reject(new Error(`kubectl exec ${target}: not JSON: ${out.slice(0, 200)}`))
      }
    })
    p.stdin.end(JSON.stringify(input))
  })
}

// Runs inside jinbe's container with jinbe's own resolved env (PID 1, after vault-env).
const ADMIN_SCRIPT = `
let s='';process.stdin.on('data',d=>s+=d).on('end',async()=>{
  const env=Object.fromEntries(require('fs').readFileSync('/proc/1/environ','utf8').split('\\0').filter(Boolean).map(l=>[l.slice(0,l.indexOf('=')),l.slice(l.indexOf('=')+1)]))
  const {urlVar,tokVar,method,path,body}=JSON.parse(s)
  const headers={accept:'application/json'}
  if(env[tokVar])headers.authorization='Bearer '+env[tokVar]
  if(body!==undefined)headers['content-type']='application/json'
  try{const r=await fetch(env[urlVar].replace(/\\/$/,'')+path,{method,headers,body:body===undefined?undefined:JSON.stringify(body),signal:AbortSignal.timeout(10000)})
    const t=await r.text();let b=t;try{b=t?JSON.parse(t):null}catch{}
    console.log(JSON.stringify({status:r.status,body:b}))}catch(e){console.log(JSON.stringify({status:0,body:{error:String(e.cause?.code||e.name)}}))}
})`

export const kratosAdmin = (method, path, body) =>
  kexec(CFG.jinbeTarget, CFG.jinbeContainer, ADMIN_SCRIPT, { urlVar: 'KRATOS_ADMIN_URL', tokVar: 'KRATOS_ADMIN_TOKEN', method, path, body })
export const hydraAdmin = (method, path, body) =>
  kexec(CFG.jinbeTarget, CFG.jinbeContainer, ADMIN_SCRIPT, { urlVar: 'HYDRA_ADMIN_URL', tokVar: 'HYDRA_ADMIN_TOKEN', method, path, body })

// Runs inside auth-mcp's container: exchanges a key exactly as auth-mcp does, then calls jinbe
// directly with the delegated token + auth-mcp's actor token. It tests jinbe's delegation gate with
// the MCP's own local refusals out of the way. Returns status and error codes only, never bodies.
const GATE_SCRIPT = `
let s='';process.stdin.on('data',d=>s+=d).on('end',async()=>{
  const {key,probes}=JSON.parse(s);const J=process.env.JINBE_URL.replace(/\\/$/,'')
  const actor=require('fs').readFileSync(process.env.ACTOR_TOKEN_PATH,'utf8').trim()
  const x=await fetch(J+'/api/mcp/personal-keys/exchange',{method:'POST',headers:{authorization:'Bearer '+key,'x-actor-token':actor,accept:'application/json'}})
  if(!x.ok){console.log(JSON.stringify({exchange:x.status,results:[]}));return}
  const tok=(await x.json()).access_token;const results=[]
  for(const p of probes){const headers={authorization:'Bearer '+tok,'x-actor-token':actor,accept:'application/json'}
    if(p.body!==undefined)headers['content-type']='application/json'
    try{const r=await fetch(J+p.path,{method:p.method,headers,body:p.body===undefined?undefined:JSON.stringify(p.body)});let b={};try{b=await r.json()}catch{}
      results.push({id:p.id,status:r.status,error:typeof b.error==='string'?b.error:null,code:typeof b.code==='string'?b.code:null,reason:typeof b.reason==='string'?b.reason:null})
    }catch(e){results.push({id:p.id,status:0,error:String(e.cause?.code||e.name)})}}
  console.log(JSON.stringify({exchange:200,results}))
})`

export const gateProbe = (key, probes) => kexec(CFG.mcpTarget, CFG.mcpContainer, GATE_SCRIPT, { key, probes })

// ── TOTP (RFC 6238: SHA-1, 6 digits, 30 s) ──────────────────────────────────────────────────────

function base32(s) {
  const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  let bits = ''
  for (const c of s.replace(/=+$/, '').toUpperCase().replace(/\s/g, '')) {
    const v = A.indexOf(c)
    if (v < 0) throw new Error('not base32')
    bits += v.toString(2).padStart(5, '0')
  }
  const bytes = []
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2))
  return Buffer.from(bytes)
}

export const totpWindow = (t = Date.now()) => Math.floor(t / 30000)
export function totp(secret, t = Date.now()) {
  const counter = Buffer.alloc(8)
  counter.writeBigUInt64BE(BigInt(totpWindow(t)))
  const h = createHmac('sha1', base32(secret)).update(counter).digest()
  const o = h[h.length - 1] & 0xf
  return String(((h.readUInt32BE(o) & 0x7fffffff) % 1_000_000)).padStart(6, '0')
}

// ── MCP ─────────────────────────────────────────────────────────────────────────────────────────

/** What must never appear in any tool result. */
const LEAKS = [/stk_mcp_/, /-----BEGIN/, /ory_(st|ht|at|rt|ac)_[A-Za-z0-9]/, /self-service\/(recovery|verification|login)[^"\s]*[?&](token|code|flow)=/, /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\./]
export const leaks = []

/** An SDK-level failure (no tool error body): an unknown tool, arguments refused on the wire, HTTP 401. */
function transportCode(text) {
  if (/Tool [\w-]+ not found|-32601/i.test(text)) return 'tool_not_found'
  if (/-32602|validation|Invalid arguments/i.test(text)) return 'invalid_request'
  if (/\b401\b|unauthori[sz]ed|invalid_token|invalid_key/i.test(text)) return 'unauthenticated'
  return 'transport_error'
}

/** A tool result → {ok, code, data, text, raw}. `code` is the tool error code, or a transport class. */
export function classify(res) {
  const text = (res?.content ?? []).map((c) => c.text ?? '').join('\n')
  for (const re of LEAKS) if (re.test(text) || re.test(JSON.stringify(res?.structuredContent ?? {}))) leaks.push(String(re))
  if (!res?.isError) return { ok: true, code: 'ok', data: res?.structuredContent?.data, text, raw: res }
  const err = res?.structuredContent?.error
  const code = err?.code ?? transportCode(text)
  return { ok: false, code, error: err ?? null, text, raw: res }
}

/** One MCP connection per key. Rate-limited calls are retried after retryAfterSec unless told not to. */
export class Mcp {
  constructor(role, key) {
    this.role = role
    this.key = key
    this.client = null
  }
  async connect() {
    this.client = new Client({ name: `mcp-e2e-${this.role}`, version: '1.0.0' })
    const transport = new StreamableHTTPClientTransport(new URL(CFG.mcpUrl), { requestInit: { headers: { authorization: `Bearer ${this.key}` } } })
    await this.client.connect(transport)
    return this
  }
  async tools() {
    const out = []
    let cursor
    do {
      const page = await this.client.listTools(cursor ? { cursor } : {})
      out.push(...page.tools)
      cursor = page.nextCursor
    } while (cursor)
    return out
  }
  async call(name, args = {}, { retry = true, timeoutMs } = {}) {
    for (let attempt = 0; ; attempt++) {
      let r
      try {
        // The SDK's default request timeout is 60 s; verify_site's worst case is close to it.
        r = classify(await this.client.callTool({ name, arguments: args }, undefined, timeoutMs ? { timeout: timeoutMs } : undefined))
      } catch (e) {
        const msg = String(e?.message ?? e)
        r = { ok: false, code: transportCode(msg), text: msg.slice(0, 300) }
      }
      if (r.code === 'rate_limited' && retry && attempt < 3) {
        const wait = Math.min(65, Number(r.error?.retryAfterSec ?? 30) + 1)
        log(`  ${this.role}: rate limited on ${name}, waiting ${wait}s`)
        await sleep(wait * 1000)
        continue
      }
      return r
    }
  }
  async close() {
    await this.client?.close().catch(() => {})
  }
}
