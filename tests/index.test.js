const { expect } = require('chai')
const { _parseKey } = require('../index.js')

describe('_parseKey', () => {
  const mockPublicKey = `-----BEGIN PUBLIC KEY-----
MIIBojANBgkqh
a5LPDfJneQHEi
vceYTMfN
-----END PUBLIC KEY-----`
  const mockPrivateKey = `-----BEGIN RSA PRIVATE KEY-----
MIIBojANBgkqh
a5LPDfJneQHEi
vceYTMfN
-----END RSA PRIVATE KEY-----`

  test('public key string with spaces', () => {
    const key = '-----BEGIN PUBLIC KEY----- MIIBojANBgkqh a5LPDfJneQHEi vceYTMfN -----END PUBLIC KEY-----'
    expect(_parseKey(key)).to.equal(mockPublicKey)
  })

  test('public key string with newlines', () => {
    const key = '-----BEGIN PUBLIC KEY-----\nMIIBojANBgkqh\na5LPDfJneQHEi\nvceYTMfN\n-----END PUBLIC KEY-----'
    expect(_parseKey(key)).to.equal(mockPublicKey)
  })

  test('public key string with escaped newlines', () => {
    const key = '-----BEGIN PUBLIC KEY-----\\nMIIBojANBgkqh\\na5LPDfJneQHEi\\nvceYTMfN\\n-----END PUBLIC KEY-----'
    expect(_parseKey(key)).to.equal(mockPublicKey)
  })

  test('public key string correctly formatted', () => {
    expect(_parseKey(mockPublicKey)).to.equal(mockPublicKey)
  })

  test('private key string with spaces', () => {
    const key = '-----BEGIN RSA PRIVATE KEY----- MIIBojANBgkqh a5LPDfJneQHEi vceYTMfN -----END RSA PRIVATE KEY-----'
    expect(_parseKey(key)).to.equal(mockPrivateKey)
  })

  test('private key string with newlines', () => {
    const key = '-----BEGIN RSA PRIVATE KEY-----\nMIIBojANBgkqh\na5LPDfJneQHEi\nvceYTMfN\n-----END RSA PRIVATE KEY-----'
    expect(_parseKey(key)).to.equal(mockPrivateKey)
  })

  test('private key string correctly formatted', () => {
    expect(_parseKey(mockPrivateKey)).to.equal(mockPrivateKey)
  })
})

// describe('signToken', () => {
// })

// describe('validateToken', () => {
// })
