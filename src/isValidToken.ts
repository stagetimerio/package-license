import jwt from 'jsonwebtoken'
import parseRSAKey from './parseRSAKey'
import type { Algorithm } from './types'

/**
 * Checks if a JWT token is valid (signature verifies and token is not expired).
 *
 * Unlike {@link parseToken}, this does **not** ignore expiration — an expired
 * token returns `false`.
 *
 * @param tokenString - The JWT string to verify.
 * @param key - Public key (RS256) or secret (HS256) used for verification.
 * @param algorithm - The algorithm used (`'RS256'` or `'HS256'`, default `'RS256'`).
 * @returns `true` if the token signature is valid and it has not expired.
 */
export default function isValidToken(
  tokenString: string,
  key: string,
  algorithm: Algorithm = 'RS256',
): boolean {
  try {
    const sanitizedKey = algorithm === 'RS256' ? parseRSAKey(key) : key
    jwt.verify(tokenString, sanitizedKey, { algorithms: [algorithm] })
    return true
  } catch {
    return false
  }
}
