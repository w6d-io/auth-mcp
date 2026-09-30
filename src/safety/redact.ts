/**
 * The last filter before anything leaves auth-mcp (plan §4 "No secrets in outputs, ever").
 *
 * jinbe already keeps secrets out of its answers; this is the second line, for the day one slips
 * through (a template body with a pasted token, a site description with a key). Two passes:
 *   1. keys: a value under a secret-named key is replaced whatever it looks like;
 *   2. values: token-shaped strings are replaced wherever they appear, inside longer text too.
 */

export const REDACTED = '[REDACTED]'

const SECRET_KEY =
  /^(?:.*[_-])?(?:password|passwd|secret|client_secret|api[_-]?key|apikey|access[_-]?token|refresh[_-]?token|id[_-]?token|token|private[_-]?key|session[_-]?(?:id|token)|sessionid|cookie|set-cookie|authorization|x-actor-token|credentials?)$/i
// camelCase spellings the regex above misses once lowercased boundaries are gone.
const SECRET_KEY_CAMEL = /(?:Secret|Password|Token|PrivateKey|ApiKey|SessionId)$/

/** Keys whose values are not secrets even though their name ends like one. */
const ALLOWED_KEYS = new Set(['tokenHash', 'token_type', 'tokenType', 'token_use', 'nextCursor'])

const VALUE_PATTERNS: Array<[RegExp, string]> = [
  // PEM blocks, whole.
  [/-----BEGIN [A-Z0-9 ]+-----[\s\S]*?(?:-----END [A-Z0-9 ]+-----|$)/g, REDACTED],
  // Our own personal keys and any stk_ prefixed secret.
  [/\bstk_[A-Za-z0-9_]*[A-Za-z0-9][._-][A-Za-z0-9_\-~.]{8,}/g, REDACTED],
  // Ory tokens: access, refresh, authorize code, session tokens.
  [/\bory_(?:at|rt|ac|st|ht|pat)_[A-Za-z0-9_\-.]{8,}/g, REDACTED],
  // JWTs (three base64url segments, header starting eyJ).
  [/\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}/g, REDACTED],
  // Bearer/Basic credentials in free text.
  [/\b(Bearer|Basic)\s+[A-Za-z0-9\-._~+/]{12,}=*/gi, `$1 ${REDACTED}`],
  // Cloud keys.
  [/\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g, REDACTED],
  [/\bgh[pousr]_[A-Za-z0-9]{30,}\b/g, REDACTED],
  [/\bglpat-[A-Za-z0-9_-]{20,}\b/g, REDACTED],
  [/\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g, REDACTED],
  // Vault references (bank-vaults `vault:secret/data/...#key`) and Vault tokens.
  [/\bvault:[A-Za-z0-9_\-/]+(?:#[A-Za-z0-9_-]+)?/g, REDACTED],
  [/\bhvs\.[A-Za-z0-9_-]{20,}/g, REDACTED],
  // user:password@ in URLs.
  [/(\b[a-z][a-z0-9+.-]*:\/\/)[^\s:/@]+:[^\s@/]+@/gi, `$1${REDACTED}@`],
]

export function isSecretKey(key: string): boolean {
  if (ALLOWED_KEYS.has(key)) return false
  return SECRET_KEY.test(key) || SECRET_KEY_CAMEL.test(key)
}

export function redactString(value: string): string {
  let out = value
  for (const [pattern, replacement] of VALUE_PATTERNS) out = out.replace(pattern, replacement)
  return out
}

/** A deep copy with secrets replaced. Cycles and depth beyond 32 are cut, never followed. */
export function redact<T>(value: T, depth = 0, seen = new WeakSet<object>()): T {
  if (typeof value === 'string') return redactString(value) as T
  if (value === null || typeof value !== 'object') return value
  if (depth > 32 || seen.has(value as object)) return REDACTED as T
  seen.add(value as object)
  if (Array.isArray(value)) return value.map((v) => redact(v, depth + 1, seen)) as T
  const out: Record<string, unknown> = {}
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    out[k] = isSecretKey(k) && v !== null && v !== undefined && v !== '' ? REDACTED : redact(v, depth + 1, seen)
  }
  return out as T
}

/** Whether a serialised output still contains something secret-shaped (used by the leak tests). */
export function containsSecret(text: string): boolean {
  return VALUE_PATTERNS.some(([pattern]) => {
    pattern.lastIndex = 0
    const hit = pattern.test(text)
    pattern.lastIndex = 0
    return hit
  })
}
