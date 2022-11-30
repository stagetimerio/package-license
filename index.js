const jwt = require('jsonwebtoken')
const { subscriptionHandler } = require('@stagetimer/shared')

const schema = {
  planId: { type: Number, default: 0 },
  email: { type: String, default: null },
  uid: { type: String, default: null },
}

function signToken (payload, privateKey, expiresIn = '1 month') {
  return jwt.sign(_applySchema(payload), _parseKey(privateKey), { algorithm: 'RS256', expiresIn })
}

function validateToken (tokenString, publicKey) {
  let decoded, valid

  try {
    decoded = jwt.verify(tokenString, _parseKey(publicKey), { algorithms: ['RS256'] })
    decoded.exp = new Date(decoded.exp * 1000)
    valid = true
  } catch (err) {
    if (!err.message.includes('jwt must be provided')) console.error('[@stagetimer/license]', err.message)
    decoded = { exp: err.expiredAt || null }
    valid = false
  }

  return {
    ..._applySchema(decoded),
    exp: decoded.exp,
    plan: subscriptionHandler.getPlanById(decoded.planId),
    token: tokenString,
    valid,
    active: new Date() < decoded.exp,
  }
}

function _applySchema (payload = {}) {
  const result = {}
  for (const key in schema) {
    result[key] = payload[key] || schema[key].default
  }
  return result
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
    .replace(/\\n|\s/g, '\n').trim()

  const formattedKey = `-----BEGIN ${keyType}-----\n` + coreStr + `\n-----END ${keyType}-----`
  return formattedKey
}

exports.signToken = signToken
exports.validateToken = validateToken
exports._applySchema = _applySchema
exports._parseKey = _parseKey

module.exports = {
  signToken,
  validateToken,
  _applySchema,
  _parseKey,
}

