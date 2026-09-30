/**
 * The OAuth issuer must be ONE exact string everywhere: HYDRA_ISSUER, the protected-resource metadata's
 * `authorization_servers[0]`, and the `issuer` of the authorization server's RFC 8414 document (live
 * Hydra: `https://hydra.authdev.dev.example.com/`, trailing slash included). Clients key stored
 * credentials by that string, and RFC 8414 §3.3 clients refuse a mismatch. Checked once at startup;
 * a mismatch is logged, never fatal (keys keep working without OAuth).
 */

type Fetch = typeof fetch

export type IssuerCheck =
  | { ok: true; url: string }
  | { ok: false; url: string; problem: 'unreachable' | 'not_found' | 'no_issuer' | 'mismatch'; found?: string }

/** RFC 8414 §3: the metadata of issuer `https://h/` (or `https://h`) is at `https://h/.well-known/oauth-authorization-server`. */
export function authorizationServerMetadataUrl(issuer: string): string {
  const u = new URL(issuer)
  const path = u.pathname === '/' ? '' : u.pathname.replace(/\/$/, '')
  return `${u.origin}/.well-known/oauth-authorization-server${path}`
}

export async function checkIssuer(issuer: string, fetchImpl: Fetch = fetch, timeoutMs = 5000): Promise<IssuerCheck> {
  const url = authorizationServerMetadataUrl(issuer)
  let res: Response
  try {
    res = await fetchImpl(url, { headers: { accept: 'application/json' }, signal: AbortSignal.timeout(timeoutMs) })
  } catch {
    return { ok: false, url, problem: 'unreachable' }
  }
  if (!res.ok) return { ok: false, url, problem: 'not_found' }
  let body: { issuer?: unknown }
  try {
    body = (await res.json()) as { issuer?: unknown }
  } catch {
    return { ok: false, url, problem: 'no_issuer' }
  }
  if (typeof body.issuer !== 'string') return { ok: false, url, problem: 'no_issuer' }
  // Byte-equal on purpose: a trailing slash is a different issuer to an RFC 8414 client.
  return body.issuer === issuer ? { ok: true, url } : { ok: false, url, problem: 'mismatch', found: body.issuer }
}
