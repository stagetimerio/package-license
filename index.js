const jwt = require('jsonwebtoken')

/**
 * type TokenPayload = Record<string, any>
 */

/**
 * type ParsedToken = TokenPayload & {
 *   iat: Date
 *   exp: Date
 *   isValid: boolean
 * }
 */

/**
 * Signs a payload with the provided private key to create a JSON Web Token (JWT).
 *
 * @param {TokenPayload} payload - The payload to be signed.
 * @param {string} privateKey - The private key used for signing the token.
 * @param {string|Date} expiresIn - The duration for which the token is valid (default is '1 month').
 * @return {string} - The signed JWT.
 */
function signToken (payload, privateKey, expiresIn = '1m') {
  if (expiresIn instanceof Date ) expiresIn = Math.floor((expiresIn.getTime() - Date.now()) / 1000)
  return jwt.sign(
    payload,
    _parseKey(privateKey),
    { algorithm: 'RS256', expiresIn },
  )
}

/**
 * Parse JWT Token
 * @param  {string} tokenString
 * @param  {string} publicKey
 * @return {ParsedToken}
 */
function parseToken (tokenString, publicKey) {
  const parsed = jwt.verify(tokenString, _parseKey(publicKey), { algorithms: ['RS256'], ignoreExpiration: true })
  parsed.exp = new Date(parsed.exp * 1000)
  parsed.iat = new Date(parsed.iat * 1000)
  parsed.isValid = new Date() <= parsed.exp
  return parsed
}

/**
 * Checks if a JWT token is valid (signature validates and is note expired)
 * @param  {string} tokenString
 * @param  {string} publicKey
 * @return {boolean}
 */
function isValidToken (tokenString, publicKey) {
  try {
    jwt.verify(tokenString, _parseKey(publicKey), { algorithms: ['RS256'] })
    return true
  } catch (err) {
    return false
  }
}

/**
 * Validates a JSON Web Token (JWT) using the provided public key.
 *
 * @param {string} tokenString - The JWT string to be validated.
 * @param {string} publicKey - The public key used to verify the token.
 * @return {any} - An object representing the decoded token, including a 'valid' flag indicating the token's validity.
 */
function validateToken_DEPRECATED (tokenString, publicKey) {
  let decoded

  try {
    decoded = jwt.verify(tokenString, _parseKey(publicKey), { algorithms: ['RS256'] })
    decoded.exp = new Date(decoded.exp * 1000)
    decoded.valid = true
  } catch (err) {
    if (!err.message.includes('jwt must be provided')) console.error(`[${process.env.npm_package_name}]`, err.message)
    decoded = { exp: err.expiredAt || null }
    decoded.valid = false
  }

  return {
    ...decoded,
    token: tokenString,
  }
}

/**
 * Parse a private or public key, making sure that \n or spaces are turned into newlines
 * @param  {String} key [private or public key string]
 * @return {String}     [properly formatted key]
 */
function _parseKey (key) {
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
  validateToken: validateToken_DEPRECATED,
  _parseKey,
}

