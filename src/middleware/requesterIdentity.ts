import type { NextFunction, Request, Response } from 'express';
import requesterRepository from '../repository/requester.repository.js';
import { generateSecureToken, hashToken } from '../utils/token.js';
import { logger } from '../utils/logger.js';
import ApiResponse from '../utils/ApiResponse.js';
import config from '../config/config.js';

const COOKIE_NAME = config.requester.cookieName;

/**
 * Client and server run on different origins (different ports in dev, and
 * possibly different hosts in production), so this cookie is inherently
 * cross-site. Browsers only send a cross-site cookie on programmatic
 * requests (fetch/XHR — what the SPA uses) when it's `SameSite=None`, and
 * `SameSite=None` is only accepted by browsers alongside `Secure`. `Secure`
 * in turn requires HTTPS — except browsers special-case plain `localhost`
 * as trustworthy. `req.secure` honours the `trust proxy` setting already
 * configured in app.ts, so this is correct behind a TLS-terminating proxy
 * too. Net effect: works in production (HTTPS) and over http://localhost;
 * degrades to a same-site-only cookie (won't reach cross-origin XHR) if
 * something is served over plain HTTP from a non-localhost host — that's a
 * browser security rule, not a gap in this code.
 */
function cookieOptions(req: Request) {
  const secure = req.secure;
  return {
    httpOnly: true,
    secure,
    sameSite: (secure ? 'none' : 'lax') as 'none' | 'lax',
    maxAge: config.requester.maxAgeMs,
    path: '/',
  };
}

/**
 * Assigns every requester a durable anonymous identity — no login. Mounted
 * on /api only (not the public redirect route, which is hit by whoever
 * clicks a shared link, not by someone "using the app").
 *
 * First touch: mint a random token, store only its sha256 (same
 * never-store-the-raw-secret pattern as statsTokenHash), set it as an
 * HttpOnly cookie. Return visit, any network: look the presented cookie's
 * hash up by unique index; a match reuses that identity regardless of IP —
 * that's the actual point. A missing, forged, or stale (e.g. wiped dev DB)
 * cookie can't be trusted, so it mints a fresh identity rather than
 * adopting an unverifiable one.
 */
export async function requesterIdentity(req: Request, res: Response, next: NextFunction) {
  try {
    const presented = req.cookies?.[COOKIE_NAME] as string | undefined;

    if (presented) {
      const existing = await requesterRepository.findByTokenHash(hashToken(presented));
      if (existing) {
        req.requester = { id: existing.id };
        void requesterRepository.touchLastSeen(existing.id);
        next();
        return;
      }
    }

    const token = generateSecureToken();
    const created = await requesterRepository.create({
      id: crypto.randomUUID(),
      tokenHash: hashToken(token),
    });
    req.requester = { id: created.id };
    res.cookie(COOKIE_NAME, token, cookieOptions(req));
    next();
  } catch (err) {
    logger.logError('Failed to resolve requester identity', err as Error);
    ApiResponse.internal(res);
  }
}
