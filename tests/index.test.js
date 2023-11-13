const { expect } = require('chai')
const { _parseKey, signToken, parseToken } = require('../index.js')
const { readFileSync } = require('fs')

const JWT_PRIVATE_KEY = readFileSync(__dirname + '/jwt-fixture-2048-RS256.key', { encoding: 'utf8' })
const JWT_PUBLIC_KEY = readFileSync(__dirname + '/jwt-fixture-2048-RS256.key.pub', { encoding: 'utf8' })

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

describe('signToken', () => {
  test('sign with future date', () => {
    const future = new Date(new Date().setMonth(new Date().getMonth() + 1))
    const token = signToken({ foo: 'bar' }, JWT_PRIVATE_KEY, future)
    expect(typeof token).to.equal('string')
  })

  test('sign with past date', () => {
    const past = new Date(new Date().setMonth(new Date().getMonth() - 1))
    const token = signToken({ foo: 'bar' }, JWT_PRIVATE_KEY, past)
    expect(typeof token).to.equal('string')
  })

  test('sign with null date', () => {
    const token = signToken({ foo: 'bar' }, JWT_PRIVATE_KEY, null)
    expect(typeof token).to.equal('string')
  })

  test('sign without date', () => {
    const token = signToken({ foo: 'bar' }, JWT_PRIVATE_KEY)
    expect(typeof token).to.equal('string')
  })
})

describe('parseToken', () => {
  test('parse valid token', () => {
    const future = new Date(new Date().setMonth(new Date().getMonth() + 1))
    const token = signToken({ foo: 'bar' }, JWT_PRIVATE_KEY, future)
    const parsedToken = parseToken(token, JWT_PUBLIC_KEY)
    expect(typeof parsedToken).to.equal('object')
    expect(parsedToken.foo).to.equal('bar')
    expect(parsedToken.exp.getTime()).to.equal(future.setMilliseconds(0))
    expect(parsedToken.isValid).to.equal(true)
  })

  test('parse expired token', () => {
    const past = new Date(new Date().setMonth(new Date().getMonth() - 1))
    const token = signToken({ foo: 'bar' }, JWT_PRIVATE_KEY, past)
    const parsedToken = parseToken(token, JWT_PUBLIC_KEY)
    expect(typeof parsedToken).to.equal('object')
    expect(parsedToken.foo).to.equal('bar')
    expect(parsedToken.exp.getTime()).to.equal(past.setMilliseconds(0))
    expect(parsedToken.isValid).to.equal(false)
  })

  test('parse token without expiration date', () => {
    const token = signToken({ foo: 'bar' }, JWT_PRIVATE_KEY, null)
    const parsedToken = parseToken(token, JWT_PUBLIC_KEY)
    expect(typeof parsedToken).to.equal('object')
    expect(parsedToken.foo).to.equal('bar')
    expect(parsedToken.exp).to.equal(null)
    expect(parsedToken.isValid).to.equal(true)
  })

  test('parse token with invalid signature', () => {
    const token = signToken({ foo: 'bar' }, JWT_PRIVATE_KEY)
    const fn = () => parseToken(token + 'XXX', JWT_PUBLIC_KEY)
    expect(fn).to.throw()
  })
})
