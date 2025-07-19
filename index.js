/*!
 * @stagetimerio/license
 * © Lukas Hermann <hey@lukashermann.dev>
 * All rights reserved.
 */

const jwt = require('jsonwebtoken')

/**
 * type TokenPayload = Record<string, any>
 */

/**
 * type ParsedToken = TokenPayload & {
 *   iat: Date | null
 *   exp: Date | null
 *   isValid: boolean
 * }
 */

/**
 * Signs a payload with the provided key to create a JSON Web Token (JWT).
 *
 * @param {TokenPayload} payload - The payload to be signed.
 * @param {string} key - The private key (RS256) or secret (HS256) used for signing.
 * @param {string|Date|null} expiresIn - The duration for which the token is valid (default is null).
 * @param {string} algorithm - The algorithm to use ('RS256' or 'HS256', default is 'RS256').
 * @return {string} - The signed JWT.
 */
function signToken (payload, key, expiresIn = null, algorithm = 'RS256') {
  const options = { algorithm }
  if (expiresIn instanceof Date ) options.expiresIn = Math.floor((expiresIn.getTime() - Date.now()) / 1000)
  if (typeof expiresIn === 'string') options.expiresIn = expiresIn

  const sanitizedKey = algorithm === 'RS256' ? _parseRSAKey(key) : key
  return jwt.sign(payload, sanitizedKey, options)
}

/**
 * Parse JWT Token
 * @param  {string} tokenString
 * @param  {string} key - Public key (RS256) or secret (HS256)
 * @param  {string} algorithm - The algorithm used ('RS256' or 'HS256', default is 'RS256')
 * @return {ParsedToken}
 */
function parseToken (tokenString, key, algorithm = 'RS256') {
  const sanitizedKey = algorithm === 'RS256' ? _parseRSAKey(key) : key
  const parsed = jwt.verify(tokenString, sanitizedKey, { algorithms: [algorithm], ignoreExpiration: true })
  parsed.exp = parsed.exp ? new Date(parsed.exp * 1000) : null
  parsed.iat = parsed.iat ? new Date(parsed.iat * 1000) : null
  parsed.isValid = parsed.exp === null || new Date() <= parsed.exp
  return parsed
}

/**
 * Checks if a JWT token is valid (signature validates and is not expired)
 * @param  {string} tokenString
 * @param  {string} key - Public key (RS256) or secret (HS256)
 * @param  {string} algorithm - The algorithm used ('RS256' or 'HS256', default is 'RS256')
 * @return {boolean}
 */
function isValidToken (tokenString, key, algorithm = 'RS256') {
  try {
    const sanitizedKey = algorithm === 'RS256' ? _parseRSAKey(key) : key
    jwt.verify(tokenString, sanitizedKey, { algorithms: [algorithm] })
    return true
  } catch (err) {
    return false
  }
}

/**
 * Check if the parsed token's expiration date is identical to the given date within a tolerance
 *
 * Note: The tolerance is 2000 (2s) because JWT timestamps are in seconds, not milliseconds, and still seem to apply
 *       some rounding on top of that.
 *
 * @param  {ParsedToken} parsedToken
 * @param  {Date} date
 * @return {boolean}
 */
function isTokenExpDateMatching (parsedToken, date) {
  const tolerance = 2000

  if (!parsedToken.exp) return false

  const tokenExpTime = parsedToken.exp.getTime()
  const dateToCompareTime = new Date(date).getTime()

  return Math.abs(tokenExpTime - dateToCompareTime) <= tolerance
}

/**
 * Parse a private or public key, making sure that \n or spaces are turned into newlines
 * @param  {String} key [private or public key string]
 * @return {String}     [properly formatted key]
 */
function _parseRSAKey (key) {
  let keyType = null
  if (key.startsWith('-----BEGIN PUBLIC KEY-----')) keyType = 'PUBLIC KEY'
  if (key.startsWith('-----BEGIN RSA PRIVATE KEY-----')) keyType = 'RSA PRIVATE KEY'


  const coreStr = key
    .replace(`-----BEGIN ${keyType}-----`, '')
    .replace(`-----END ${keyType}-----`, '')
    .replace(/\\n|\s/g, '\n')
    .replace(/\n\n/g, '\n')
    .trim()

  const formattedKey = `-----BEGIN ${keyType}-----\n` + coreStr + `\n-----END ${keyType}-----`
  return formattedKey
}

module.exports = {
  signToken,
  parseToken,
  isValidToken,
  isTokenExpDateMatching,
  _parseRSAKey,
}

