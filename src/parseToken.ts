import jwt from 'jsonwebtoken'
import parseRSAKey from './parseRSAKey'
import type { Algorithm, ParsedToken } from './types'

/**
 * Parse and verify a JWT token, returning its decoded payload with validity info.
 *
 * **Important: does not throw for expired tokens.** Instead, it returns the full
 * decoded payload with `isValid: false`. This is by design so that callers can
 * inspect expired token data (e.g. to show renewal prompts or grace-period logic).
 *
 * **Throws** `JsonWebTokenError` for invalid signatures or malformed tokens.
 *
 * @example
 * ```ts
 * const parsed = parseToken(token, publicKey)
 * if (!parsed.isValid) {
 *   // Token is expired — but you can still read parsed.exp, parsed.foo, etc.
 * }
 * ```
 *
 * @param tokenString - The JWT string to parse.
 * @param key - Public key (RS256) or secret (HS256) used for verification.
 * @param algorithm - The algorithm used (`'RS256'` or `'HS256'`, default `'RS256'`).
 * @returns The decoded token payload with `iat`, `exp` as `Date | null` and `isValid` boolean.
 */
export default function parseToken(
  tokenString: string,
  key: string,
  algorithm: Algorithm = 'RS256',
): ParsedToken {
  const sanitizedKey = algorithm === 'RS256' ? parseRSAKey(key) : key
  const parsed = jwt.verify(tokenString, sanitizedKey, { algorithms: [algorithm], ignoreExpiration: true }) as Record<string, unknown>
  const exp = typeof parsed.exp === 'number' ? new Date(parsed.exp * 1000) : null
  const iat = typeof parsed.iat === 'number' ? new Date(parsed.iat * 1000) : null
  const isValid = exp === null || new Date() <= exp

  return { ...parsed, exp, iat, isValid }
}
