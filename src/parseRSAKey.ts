/**
 * Parse a private or public RSA key, normalizing whitespace into proper newlines.
 *
 * Handles keys where newlines have been replaced with spaces or escaped `\\n`
 * characters (common when keys are stored in environment variables).
 *
 * @private Internal helper — not part of the public API.
 * @param key - Private or public RSA key string.
 * @returns Properly formatted PEM key string.
 */
export default function parseRSAKey(key: string): string {
  let keyType: string | null = null
  if (key.startsWith('-----BEGIN PUBLIC KEY-----')) keyType = 'PUBLIC KEY'
  if (key.startsWith('-----BEGIN RSA PRIVATE KEY-----')) keyType = 'RSA PRIVATE KEY'

  const coreStr = key
    .replace(`-----BEGIN ${keyType}-----`, '')
    .replace(`-----END ${keyType}-----`, '')
    .replace(/\\n|\s/g, '\n')
    .replace(/\n\n/g, '\n')
    .trim()

  return `-----BEGIN ${keyType}-----\n${coreStr}\n-----END ${keyType}-----`
}
