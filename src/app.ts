import Fastify, { type FastifyBaseLogger, type FastifyInstance, type FastifyReply, type FastifyRequest } from 'fastify'
import type { Logger } from 'pino'
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js'
import type { Env } from './config/env.js'
import { AuthError, type AuthenticatedPrincipal } from './auth/types.js'
import type { Authenticator } from './auth/authenticator.js'
import type { KillSwitches } from './safety/kill-switch.js'
import type { ToolDeps, ToolDef } from './mcp/registry.js'
import { buildMcpServer } from './mcp/server.js'
import { SCOPES_SUPPORTED } from './mcp/permissions.js'

export interface AppDeps {
  env: Pick<Env, 'MCP_RESOURCE' | 'HYDRA_ISSUER' | 'MCP_ALLOWED_ORIGINS' | 'MCP_BODY_LIMIT_BYTES'>
  authenticator: Authenticator
  killSwitches: KillSwitches
  toolDeps: ToolDeps
  tools: readonly ToolDef[]
  logger: Logger
}

/** RFC 9728 §3: the metadata of `https://host/mcp` lives at `https://host/.well-known/oauth-protected-resource/mcp`. */
export function metadataUrl(resource: string): string {
  const u = new URL(resource)
  const path = u.pathname === '/' ? '' : u.pathname.replace(/\/$/, '')
  return `${u.origin}/.well-known/oauth-protected-resource${path}`
}

export function protectedResourceMetadata(env: AppDeps['env']) {
  return {
    resource: env.MCP_RESOURCE,
    authorization_servers: [env.HYDRA_ISSUER],
    scopes_supported: SCOPES_SUPPORTED,
    bearer_methods_supported: ['header'],
    resource_name: 'example admin MCP',
    resource_documentation: 'https://docs.example.com/mcp',
  }
}

const quote = (s: string) => s.replace(/["\\]/g, '')

function unauthorized(reply: FastifyReply, env: AppDeps['env'], err?: AuthError) {
  const params = [`resource_metadata="${metadataUrl(env.MCP_RESOURCE)}"`]
  if (err && err.code !== 'missing_token') params.push('error="invalid_token"', `error_description="${quote(err.message)}"`)
  return reply
    .status(401)
    .header('www-authenticate', `Bearer ${params.join(', ')}`)
    .send({ error: err?.code ?? 'missing_token', message: err?.message ?? 'Authentication required' })
}

export function buildApp(deps: AppDeps): FastifyInstance {
  const { env } = deps
  const app = Fastify({ loggerInstance: deps.logger as FastifyBaseLogger, bodyLimit: env.MCP_BODY_LIMIT_BYTES })

  app.get('/healthz', async () => ({ status: 'ok' }))

  const prm = protectedResourceMetadata(env)
  const prmPath = new URL(metadataUrl(env.MCP_RESOURCE)).pathname
  app.get('/.well-known/oauth-protected-resource', async () => prm)
  if (prmPath !== '/.well-known/oauth-protected-resource') app.get(prmPath, async () => prm)

  const mcpPath = new URL(env.MCP_RESOURCE).pathname || '/mcp'

  /** Everything a request must pass before an MCP server is built for it. */
  async function admit(request: FastifyRequest, reply: FastifyReply): Promise<AuthenticatedPrincipal | null> {
    if (!deps.killSwitches.current().enabled) {
      reply.status(503).send({ error: 'mcp_disabled', message: 'MCP is switched off' })
      return null
    }
    // DNS-rebinding defence: a browser always sends Origin; native clients send none.
    const origin = request.headers.origin
    if (origin && !env.MCP_ALLOWED_ORIGINS.includes(origin)) {
      reply.status(403).send({ error: 'origin_not_allowed', message: 'This origin may not call the MCP server' })
      return null
    }
    let principal: AuthenticatedPrincipal
    try {
      principal = await deps.authenticator.authenticate(request.headers.authorization)
    } catch (err) {
      if (err instanceof AuthError && err.code === 'verifier_unavailable') {
        reply.status(503).header('retry-after', '5').send({ error: 'retry_later', message: 'Credentials cannot be verified right now' })
        return null
      }
      if (err instanceof AuthError && err.code === 'mcp_disabled') {
        // Turned off by an administrator in the console: re-authenticating cannot help, so not a 401.
        reply.status(403).send({ error: 'mcp_disabled', message: err.message })
        return null
      }
      if (err instanceof AuthError) {
        unauthorized(reply, env, err)
        return null
      }
      throw err
    }
    const refusal = deps.killSwitches.check(principal)
    if (refusal.refused) {
      reply.status(403).send({ error: 'mcp_disabled', message: `MCP access is switched off (${refusal.reason})` })
      return null
    }
    return principal
  }

  app.post(mcpPath, async (request, reply) => {
    const principal = await admit(request, reply)
    if (!principal) return reply
    const { server } = buildMcpServer(principal, deps.toolDeps, deps.tools, env.MCP_RESOURCE)
    // Stateless: no Mcp-Session-Id, one server and transport per request; JSON answers, no SSE stream.
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true })
    reply.raw.on('close', () => {
      void transport.close()
      void server.close()
    })
    await server.connect(transport)
    reply.hijack()
    await transport.handleRequest(request.raw, reply.raw, request.body)
    return reply
  })

  // Stateless mode has no server-initiated stream and no session to end.
  const notAllowed = async (_request: FastifyRequest, reply: FastifyReply) =>
    reply.status(405).header('allow', 'POST').send({ jsonrpc: '2.0', error: { code: -32000, message: 'Method not allowed' }, id: null })
  app.get(mcpPath, notAllowed)
  app.delete(mcpPath, notAllowed)

  return app
}
