import jwt from 'jsonwebtoken'
import parseRSAKey from './parseRSAKey'
import type { Algorithm, TokenPayload } from './types'

/**
 * Signs a payload with the provided key to create a JSON Web Token (JWT).
 *
 * @param payload - The payload to be signed.
 * @param key - The private key (RS256) or secret (HS256) used for signing.
 * @param expiresIn - When the token expires. Pass a `Date` for an absolute time,
 *   a string like `"30d"` for a relative duration, or `null` for no expiration.
 * @param algorithm - The algorithm to use (`'RS256'` or `'HS256'`, default `'RS256'`).
 * @returns The signed JWT string.
 */
export default function signToken(
  payload: TokenPayload,
  key: string,
  expiresIn: string | Date | null = null,
  algorithm: Algorithm = 'RS256',
): string {
  const options: jwt.SignOptions = { algorithm }
  if (expiresIn instanceof Date) options.expiresIn = Math.floor((expiresIn.getTime() - Date.now()) / 1000)
  if (typeof expiresIn === 'string') options.expiresIn = expiresIn as jwt.SignOptions['expiresIn']

  const sanitizedKey = algorithm === 'RS256' ? parseRSAKey(key) : key
  return jwt.sign(payload, sanitizedKey, options)
}
