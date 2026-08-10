import { customAlphabet } from 'nanoid';

// Unambiguous base62-ish alphabet — no 0/O/1/l/I confusion pairs.
const ALPHABET = '23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

export const generateShortCode = customAlphabet(ALPHABET, 7);

const ALIAS_RE = /^[a-zA-Z0-9-]{3,30}$/;

export const RESERVED_CODES = new Set([
  'api',
  'health',
  'favicon.ico',
  'robots.txt',
  'sitemap.xml',
  'admin',
  'static',
  'assets',
  '_next',
]);

export function isValidAlias(alias: string): boolean {
  return ALIAS_RE.test(alias) && !RESERVED_CODES.has(alias.toLowerCase());
}
