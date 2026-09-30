import { readFileSync } from 'node:fs'
import { z } from 'zod'
import type { Principal } from '../auth/types.js'

/**
 * Kill switches (plan §5), checked on every call and never cached longer than `ttlMs` (10 s):
 *   - global: MCP_ENABLED=false, or `enabled: false` in the file → every request 503;
 *   - read-only: MCP_READ_ONLY=true, or `readOnly: true` → write tools hidden and refused;
 *   - per user / client / key → that principal refused; per org only for a token that still names one
 *     (`ext.org`, informational — tokens are no longer org-bound);
 *   - `personalKeysDisabledOrgs` → legacy: personal keys are not org-bound any more, so it only matches a
 *     key token that still names an org.
 * The file is a mounted ConfigMap, so flipping one is a GitOps change or a `kubectl edit`, no
 * restart. The env values are floors: the file can switch MCP off or to read-only, never back on.
 */

const fileSchema = z
  .object({
    enabled: z.boolean().optional(),
    readOnly: z.boolean().optional(),
    disabledOrgs: z.array(z.string()).default([]),
    disabledUsers: z.array(z.string()).default([]),
    disabledClients: z.array(z.string()).default([]),
    disabledKeys: z.array(z.string()).default([]),
    personalKeysDisabledOrgs: z.array(z.string()).default([]),
  })
  .strict()

export type KillSwitchFile = z.infer<typeof fileSchema>

export interface KillSwitchState {
  enabled: boolean
  readOnly: boolean
  disabledOrgs: ReadonlySet<string>
  disabledUsers: ReadonlySet<string>
  disabledClients: ReadonlySet<string>
  disabledKeys: ReadonlySet<string>
  personalKeysDisabledOrgs: ReadonlySet<string>
}

export type Refusal = { refused: false } | { refused: true; reason: 'disabled' | 'org' | 'user' | 'client' | 'key' | 'personal_keys' }

export class KillSwitches {
  private state: KillSwitchState | null = null
  private loadedAt = 0

  constructor(
    private readonly env: { enabled: boolean; readOnly: boolean },
    private readonly read: (() => string | null) | null,
    private readonly ttlMs = 10_000,
    private readonly now: () => number = Date.now,
    private readonly onError: (err: unknown) => void = () => undefined
  ) {}

  static fromFile(path: string | undefined, env: { enabled: boolean; readOnly: boolean }, ttlMs: number, onError?: (err: unknown) => void) {
    return new KillSwitches(env, path ? () => readFileSync(path, 'utf8') : null, ttlMs, Date.now, onError)
  }

  current(): KillSwitchState {
    if (this.state && this.now() - this.loadedAt < this.ttlMs) return this.state
    this.state = this.load()
    this.loadedAt = this.now()
    return this.state
  }

  private load(): KillSwitchState {
    let file: KillSwitchFile = fileSchema.parse({})
    if (this.read) {
      try {
        const raw = this.read()
        if (raw && raw.trim()) file = fileSchema.parse(JSON.parse(raw))
      } catch (err) {
        // An unreadable or malformed switch file fails CLOSED: off. A typo must not reopen a kill.
        this.onError(err)
        return { ...emptySets(), enabled: false, readOnly: true }
      }
    }
    return {
      enabled: this.env.enabled && file.enabled !== false,
      readOnly: this.env.readOnly || file.readOnly === true,
      disabledOrgs: new Set(file.disabledOrgs),
      disabledUsers: new Set(file.disabledUsers),
      disabledClients: new Set(file.disabledClients),
      disabledKeys: new Set(file.disabledKeys),
      personalKeysDisabledOrgs: new Set(file.personalKeysDisabledOrgs),
    }
  }

  check(principal: Principal): Refusal {
    const s = this.current()
    if (!s.enabled) return { refused: true, reason: 'disabled' }
    if (principal.org && s.disabledOrgs.has(principal.org)) return { refused: true, reason: 'org' }
    if (s.disabledUsers.has(principal.subject)) return { refused: true, reason: 'user' }
    if (s.disabledClients.has(principal.clientId)) return { refused: true, reason: 'client' }
    if (principal.keyId && s.disabledKeys.has(principal.keyId)) return { refused: true, reason: 'key' }
    if (principal.kind === 'personal' && principal.org !== null && s.personalKeysDisabledOrgs.has(principal.org)) return { refused: true, reason: 'personal_keys' }
    return { refused: false }
  }
}

function emptySets() {
  return {
    disabledOrgs: new Set<string>(),
    disabledUsers: new Set<string>(),
    disabledClients: new Set<string>(),
    disabledKeys: new Set<string>(),
    personalKeysDisabledOrgs: new Set<string>(),
  }
}
