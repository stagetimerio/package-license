import type { ParsedToken } from './types'

/**
 * Check if the parsed token's expiration date matches the given date within a tolerance.
 *
 * The tolerance is 2000ms (2s) because JWT timestamps are in seconds, not milliseconds,
 * and still seem to apply some rounding on top of that.
 *
 * @param parsedToken - A parsed token object (from {@link parseToken}).
 * @param date - The date to compare against.
 * @returns `true` if the expiration dates match within tolerance.
 */
export default function isTokenExpDateMatching(
  parsedToken: Pick<ParsedToken, 'exp'>,
  date: Date,
): boolean {
  const tolerance = 2000

  if (!parsedToken.exp) return false

  const tokenExpTime = parsedToken.exp.getTime()
  const dateToCompareTime = new Date(date).getTime()

  return Math.abs(tokenExpTime - dateToCompareTime) <= tolerance
}
