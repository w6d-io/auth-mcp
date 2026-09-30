import { parseAuthorization } from './bearer.js'
import { AuthError, withAccessToken, type AuthenticatedPrincipal } from './types.js'
import type { TokenVerifier } from './verifier.js'
import type { KeyExchanger } from './personal-key.js'
import type { KeyRevocations } from './revocations.js'

/**
 * Authorization header → principal. The only way a principal comes to exist in this service.
 */
export class Authenticator {
  constructor(
    private readonly verifier: TokenVerifier,
    private readonly keys: KeyExchanger,
    private readonly revocations?: KeyRevocations
  ) {}

  async authenticate(header: string | string[] | undefined): Promise<AuthenticatedPrincipal> {
    const credential = parseAuthorization(header)
    if (!credential) {
      throw new AuthError(header ? 'invalid_token' : 'missing_token', header ? 'Malformed credential' : 'Authentication required')
    }
    if (credential.kind === 'token') {
      const principal = await this.verifier.verify(credential.token)
      if (this.revocations?.isRevoked(principal.keyId)) throw new AuthError('invalid_token', 'This key was revoked')
      return withAccessToken(principal, credential.token)
    }
    if (this.revocations?.isRevoked(credential.keyId)) throw new AuthError('invalid_key', 'This key was revoked')
    const { accessToken } = await this.keys.exchange(credential.keyId, credential.secret)
    const principal = await this.verifier.verify(accessToken)
    // The token minted from a key must say it is that key's: a mismatch means the exchange or the
    // token hook is wrong, and acting on it would attribute calls to somebody else's key.
    if (principal.kind !== 'personal' || principal.keyId !== credential.keyId) {
      throw new AuthError('invalid_key', 'The personal key did not yield a token of its own')
    }
    return withAccessToken(principal, accessToken)
  }
}
