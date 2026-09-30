import { readFile } from 'node:fs/promises'

/**
 * auth-mcp's own identity toward jinbe: the projected ServiceAccount token (audience `jinbe`), sent
 * as `X-Actor-Token`. jinbe accepts an MCP-audience user token only together with a TokenReview-
 * verified actor `system:serviceaccount:auth:auth-mcp` (plan §2). On its own it grants nothing.
 *
 * The kubelet rotates the file; it is re-read at most every `ttlMs`. The value is never logged.
 */
export interface ActorTokenSource {
  get(): Promise<string>
}

export class FileActorTokenSource implements ActorTokenSource {
  private cached: { value: string; at: number } | null = null

  constructor(
    private readonly path: string,
    private readonly ttlMs = 60_000,
    private readonly now: () => number = Date.now
  ) {}

  async get(): Promise<string> {
    if (this.cached && this.now() - this.cached.at < this.ttlMs) return this.cached.value
    let value: string
    try {
      value = (await readFile(this.path, 'utf8')).trim()
    } catch {
      throw new ActorTokenUnavailableError()
    }
    if (!value) throw new ActorTokenUnavailableError()
    this.cached = { value, at: this.now() }
    return value
  }
}

/** Local development: no ServiceAccount, and jinbe runs with DEV_BYPASS_AUTH. */
export class StaticActorTokenSource implements ActorTokenSource {
  constructor(private readonly value: string) {}
  async get(): Promise<string> {
    return this.value
  }
}

export class ActorTokenUnavailableError extends Error {
  constructor() {
    super('The actor token (projected ServiceAccount token) could not be read')
    this.name = 'ActorTokenUnavailableError'
  }
}
