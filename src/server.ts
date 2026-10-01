import { loadEnv, type Env } from './config/env.js'
import { createLogger } from './telemetry/logger.js'
import { buildApp } from './app.js'
import { Authenticator } from './auth/authenticator.js'
import { FileActorTokenSource, StaticActorTokenSource, type ActorTokenSource } from './auth/actor-token.js'
import { CachingVerifier, DevVerifier, HydraIntrospectionVerifier, JinbeTokenInfoVerifier, type TokenVerifier } from './auth/verifier.js'
import { CachingKeyExchanger, JinbeKeyExchanger } from './auth/personal-key.js'
import { KeyRevocations } from './auth/revocations.js'
import { checkIssuer } from './auth/issuer-check.js'
import { withAccessToken } from './auth/types.js'
import { parseScopeString } from './auth/scopes.js'
import { JinbeClient } from './jinbe/client.js'
import { KillSwitches } from './safety/kill-switch.js'
import { SlidingWindowRateLimiter } from './safety/rate-limit.js'
import { allTools } from './mcp/tools/index.js'

function actorSource(env: Env): ActorTokenSource {
  // Local development has no projected token; jinbe then runs with DEV_BYPASS_AUTH and ignores it.
  if (env.TOKEN_VERIFIER === 'dev') return new StaticActorTokenSource('dev-actor')
  return new FileActorTokenSource(env.ACTOR_TOKEN_PATH)
}

function verifier(env: Env, actor: ActorTokenSource): TokenVerifier {
  switch (env.TOKEN_VERIFIER) {
    case 'hydra':
      return new HydraIntrospectionVerifier(env.HYDRA_ADMIN_URL, env.MCP_RESOURCE)
    case 'jinbe':
      return new JinbeTokenInfoVerifier(env.JINBE_URL, env.MCP_RESOURCE, actor)
    case 'dev':
      return new DevVerifier({
        subject: env.DEV_SUBJECT,
        email: env.DEV_EMAIL,
        org: env.DEV_ORG ?? null,
        scopes: parseScopeString(env.DEV_SCOPES),
        clientId: 'dev-client',
        kind: 'oauth',
        keyId: null,
      })
  }
}

async function main() {
  const env = loadEnv()
  const logger = createLogger(env.LOG_LEVEL, env.NODE_ENV === 'development')
  const actor = actorSource(env)
  const revocations = new KeyRevocations()
  const cachingVerifier = new CachingVerifier(verifier(env, actor), env.TOKEN_CACHE_TTL_MS)
  const cachingKeys = new CachingKeyExchanger(new JinbeKeyExchanger(env.JINBE_URL, actor))
  revocations.onRevoke((keyId) => {
    cachingKeys.forgetKey(keyId)
    cachingVerifier.forgetKey(keyId)
  })
  const authenticator = new Authenticator(cachingVerifier, cachingKeys, revocations)
  const killSwitches = KillSwitches.fromFile(
    env.KILL_SWITCH_FILE,
    { enabled: env.MCP_ENABLED, readOnly: env.MCP_READ_ONLY },
    env.KILL_SWITCH_TTL_MS,
    (err) => logger.error({ err: (err as Error).message }, 'kill-switch file unreadable: MCP switched off until fixed')
  )
  const app = buildApp({
    env,
    authenticator,
    killSwitches,
    tools: allTools,
    logger,
    toolDeps: {
      jinbe: new JinbeClient(env.JINBE_URL, actor, env.JINBE_TIMEOUT_MS),
      killSwitches,
      rateLimiter: new SlidingWindowRateLimiter({ read: env.RATE_READS_PER_MIN, write: env.RATE_WRITES_PER_MIN }),
      logger,
      responseLimitBytes: env.MCP_RESPONSE_LIMIT_BYTES,
      exposeUnwired: env.MCP_EXPOSE_UNWIRED_TOOLS,
      revocations,
      // Bypasses the ≤30 s token cache, once per call, before a protected action is refused for an old proof.
      reverify: async (p) => withAccessToken(await cachingVerifier.verifyFresh(p.accessToken), p.accessToken),
    },
  })

  const shutdown = async (signal: string) => {
    logger.info({ signal }, 'shutting down')
    await app.close()
    process.exit(0)
  }
  process.on('SIGTERM', () => void shutdown('SIGTERM'))
  process.on('SIGINT', () => void shutdown('SIGINT'))

  await app.listen({ port: env.PORT, host: env.HOST })
  logger.info({ resource: env.MCP_RESOURCE, verifier: env.TOKEN_VERIFIER, readOnly: env.MCP_READ_ONLY }, 'auth-mcp listening')
  // OAuth discovery depends on one exact issuer string; checked in the background, never fatal.
  void checkIssuer(env.HYDRA_ISSUER).then((r) => {
    if (r.ok) logger.info({ issuer: env.HYDRA_ISSUER }, 'OAuth issuer matches the authorization server metadata')
    else logger.warn({ issuer: env.HYDRA_ISSUER, metadata: r.url, problem: r.problem, found: r.found }, 'OAuth issuer check failed: browser sign-in may not work (keys are unaffected)')
  })
}

main().catch((err) => {
  console.error('auth-mcp failed to start:', (err as Error).message)
  process.exit(1)
})
