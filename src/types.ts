export type Algorithm = 'RS256' | 'HS256'

export type TokenPayload = Record<string, unknown>

export interface ParsedToken extends TokenPayload {
  iat: Date | null
  exp: Date | null
  isValid: boolean
}
