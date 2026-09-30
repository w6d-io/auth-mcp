import { pino, type Logger } from 'pino'

/**
 * Logs never carry a credential: the Authorization, actor-token and cookie headers are censored at
 * the logger, whatever a call site passes. Tool arguments are logged by key only (see mcp/registry).
 */
export const LOG_REDACT_PATHS = [
  'req.headers.authorization',
  'req.headers["x-actor-token"]',
  'req.headers.cookie',
  'headers.authorization',
  'headers["x-actor-token"]',
  'accessToken',
  'token',
  '*.accessToken',
  '*.token',
  '*.secret',
]

export function createLogger(level: string, pretty = false): Logger {
  return pino({
    level,
    base: { service: 'auth-mcp' },
    redact: { paths: LOG_REDACT_PATHS, censor: '[REDACTED]' },
    ...(pretty ? { transport: { target: 'pino-pretty', options: { colorize: true } } } : {}),
  })
}
