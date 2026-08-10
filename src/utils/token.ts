import crypto from 'crypto';

/**
 * 192 bits of randomness, base64url-encoded. The shared shape behind every
 * bearer secret this service hands out (stats tokens, requester cookies) —
 * generated once, never stored raw, only its hash is kept server-side.
 */
export function generateSecureToken(): string {
  return crypto.randomBytes(24).toString('base64url');
}

/** Raw bearer token handed to the client once, at creation time. Never stored. */
export function generateStatsToken(): string {
  return generateSecureToken();
}

export function hashToken(token: string): string {
  return crypto.createHash('sha256').update(token).digest('hex');
}

export function timingSafeEqualHex(a: string, b: string): boolean {
  const bufA = Buffer.from(a, 'hex');
  const bufB = Buffer.from(b, 'hex');
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

/** "Same visitor" key for unique-click counting: IP + full user agent string. */
export function fingerprintVisitor(ip: string, userAgent: string): string {
  return crypto.createHash('sha256').update(`${ip}|${userAgent}`).digest('hex');
}
