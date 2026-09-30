import { z } from 'zod'
import dotenv from 'dotenv'

dotenv.config()

const bool = (fallback: 'true' | 'false') =>
  z
    .enum(['true', 'false'])
    .default(fallback)
    .transform((v) => v === 'true')

const list = z
  .string()
  .default('')
  .transform((s) =>
    s
      .split(',')
      .map((x) => x.trim())
      .filter(Boolean)
  )

const int = (fallback: string) => z.string().default(fallback).transform(Number).pipe(z.number().int().positive())

/**
 * Everything auth-mcp is configured with. No credential of its own lives here: the only secret the
 * pod reads is its projected ServiceAccount token (ACTOR_TOKEN_PATH), which proves "this is auth-mcp"
 * to jinbe and is worth nothing without a user's token beside it.
 */
export const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'production', 'test']).default('production'),
  PORT: int('3100'),
  HOST: z.string().default('0.0.0.0'),
  LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace']).default('info'),

  // The public URL of this resource server: the token audience (RFC 8707) and the PRM `resource`.
  MCP_RESOURCE: z.string().url().default('https://mcp.authdev.dev.example.com/mcp'),
  // Origins a browser-based client may call from (DNS-rebinding defence). Empty = no Origin allowed;
  // native clients send none.
  MCP_ALLOWED_ORIGINS: list,
  MCP_BODY_LIMIT_BYTES: int('262144'),
  MCP_RESPONSE_LIMIT_BYTES: int('65536'),

  // The authorization server (Hydra): issuer for PRM, public URL for personal-key exchange, admin URL
  // for introspection when TOKEN_VERIFIER=hydra.
  // Byte-equal to the authorization server's issuer, trailing slash included (auth/issuer-check.ts).
  HYDRA_ISSUER: z.string().url().default('https://hydra.authdev.dev.example.com/'),
  HYDRA_PUBLIC_URL: z.string().url().default('http://auth-hydra-public:4444'),
  HYDRA_ADMIN_URL: z.string().url().default('http://auth-hydra-admin:4445'),

  // hydra: introspect at hydra-admin (needs a NetworkPolicy hole to hydra-admin).
  // jinbe: ask jinbe's token-info endpoint (preferred once it exists: hydra-admin stays closed).
  // dev:   a fixed principal, NODE_ENV=development only.
  TOKEN_VERIFIER: z.enum(['hydra', 'jinbe', 'dev']).default('jinbe'),
  TOKEN_CACHE_TTL_MS: int('30000'),

  JINBE_URL: z.string().url().default('http://jinbe:3000'),
  JINBE_TIMEOUT_MS: int('10000'),
  // Projected ServiceAccount token (audience jinbe), sent as X-Actor-Token. Rotated by the kubelet.
  ACTOR_TOKEN_PATH: z.string().default('/var/run/secrets/tokens/jinbe/token'),

  // Kill switches. The file (a mounted ConfigMap) is re-read at most every KILL_SWITCH_TTL_MS.
  MCP_ENABLED: bool('true'),
  MCP_READ_ONLY: bool('true'),
  KILL_SWITCH_FILE: z.string().optional(),
  KILL_SWITCH_TTL_MS: int('10000'),

  // Per (subject, client) budgets.
  RATE_READS_PER_MIN: int('60'),
  RATE_WRITES_PER_MIN: int('10'),

  // W4 write tools are stubs until jinbe change requests land. Listing them is opt-in.
  MCP_EXPOSE_UNWIRED_TOOLS: bool('false'),

  // TOKEN_VERIFIER=dev only.
  DEV_SUBJECT: z.string().default('dev-user-id'),
  DEV_EMAIL: z.string().default('dev@localhost'),
  // Informational only (tokens are not org-bound); unset = none.
  DEV_ORG: z.string().optional(),
  DEV_SCOPES: z.string().default('mcp sites:read groups:read users:read audit:read'),
})

export type Env = z.infer<typeof envSchema>

export function loadEnv(source: NodeJS.ProcessEnv = process.env): Env {
  const parsed = envSchema.safeParse(source)
  if (!parsed.success) {
    const issues = parsed.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('; ')
    throw new Error(`Invalid configuration: ${issues}`)
  }
  const env = parsed.data
  if (env.TOKEN_VERIFIER === 'dev' && env.NODE_ENV !== 'development') {
    throw new Error('TOKEN_VERIFIER=dev is refused outside NODE_ENV=development')
  }
  return env
}
