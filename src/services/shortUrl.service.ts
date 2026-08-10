import { UAParser } from 'ua-parser-js';
import { Prisma } from '@prisma/client';
import shortUrlRepository, { ShortUrlStatus } from '../repository/shortUrl.repository.js';
import { filterUrlSubmission, logContentFilterDecision } from '../lib/contentFilter.js';
import { generateShortCode, isValidAlias, RESERVED_CODES } from '../utils/shortCode.js';
import { generateStatsToken, hashToken, timingSafeEqualHex, fingerprintVisitor } from '../utils/token.js';
import { getGeoIp } from '../utils/geoIp.js';
import { logger } from '../utils/logger.js';
import config from '../config/config.js';
import type {
  ClickRequestMeta,
  CreateShortUrlParams,
  CreateShortUrlResult,
  GetAnalyticsResult,
  MyLink,
  ResolveResult,
  ShortUrlStats,
} from '../interface/ShortUrlInterface.js';

const MAX_CODE_GENERATION_ATTEMPTS = 5;

function toShortUrl(shortCode: string): string {
  return `${config.app.url}/${shortCode}`;
}

/**
 * True for a database unique-constraint violation on `shortCode` specifically
 * (Prisma error P2002). This is the race-condition backstop: the app-level
 * `isShortCodeTaken` check and this insert aren't atomic, so two requests for
 * the same brand-new alias can both pass the check before either commits.
 * The database catches what the check couldn't; this just recognizes that
 * failure and reports it the same way as the normal case.
 *
 * `@prisma/adapter-mariadb` doesn't populate the classic `meta.target` field
 * P2002 has on the engine-based client — its column info lives at
 * `meta.driverAdapterError.cause.constraint.index`, an adapter-internal shape
 * not worth depending on directly. `err.message` (e.g. "Unique constraint
 * failed on the constraint: `ShortUrl_shortCode_key`") is the stable,
 * public-facing field, so that's what's checked here, scoped to the
 * ShortUrl model via `meta.modelName` to rule out unrelated P2002s.
 */
function isDuplicateShortCodeError(err: unknown): boolean {
  if (!(err instanceof Prisma.PrismaClientKnownRequestError) || err.code !== 'P2002') return false;
  const meta = err.meta as { modelName?: string } | undefined;
  return meta?.modelName === 'ShortUrl' && err.message.includes('shortCode');
}

/** True when `url` points back at this shortener's own host — no shortening a shortener of itself. */
function isSelfReferential(url: string): boolean {
  try {
    const target = new URL(url).hostname.toLowerCase().replace(/^www\./, '');
    const own = new URL(config.app.url).hostname.toLowerCase().replace(/^www\./, '');
    const frontend = new URL(config.app.frontendUrl).hostname.toLowerCase().replace(/^www\./, '');
    return target === own || target === frontend;
  } catch {
    return false;
  }
}

class ShortUrlService {
  async createShortUrl(params: CreateShortUrlParams): Promise<CreateShortUrlResult> {
    const { url, alias, expiresInDays, requesterId, identifier, ip } = params;

    if (isSelfReferential(url)) {
      return { ok: false, reason: 'SELF_REFERENTIAL' };
    }

    const filtered = filterUrlSubmission(`${alias ?? ''} ${url}`.trim(), { identifier });
    logContentFilterDecision(filtered.audit!, { ip, endpoint: 'POST /api/shorten' });

    if (filtered.result.decision === 'BLOCK') {
      return {
        ok: false,
        reason: 'CONTENT_REJECTED',
        message: filtered.response!.error,
        category: filtered.result.category,
        riskScore: filtered.result.riskScore,
      };
    }

    let shortCode: string;
    let isCustomAlias = false;

    if (alias) {
      if (!isValidAlias(alias)) return { ok: false, reason: 'ALIAS_RESERVED' };
      if (await shortUrlRepository.isShortCodeTaken(alias)) {
        return { ok: false, reason: 'ALIAS_TAKEN' };
      }
      shortCode = alias;
      isCustomAlias = true;
    } else {
      shortCode = await this.generateUniqueShortCode();
    }

    const statsToken = generateStatsToken();
    const expiresAt = expiresInDays
      ? new Date(Date.now() + expiresInDays * 24 * 60 * 60 * 1000)
      : undefined;

    let record;
    try {
      record = await shortUrlRepository.create({
        id: crypto.randomUUID(),
        shortCode,
        originalUrl: url,
        isCustomAlias,
        statsTokenHash: hashToken(statsToken),
        requesterId,
        expiresAt,
        createdByIp: ip,
      });
    } catch (err) {
      if (isCustomAlias && isDuplicateShortCodeError(err)) {
        return { ok: false, reason: 'ALIAS_TAKEN' };
      }
      throw err;
    }

    return {
      ok: true,
      shortCode: record.shortCode,
      shortUrl: toShortUrl(record.shortCode),
      originalUrl: record.originalUrl,
      createdAt: record.createdAt,
      expiresAt: record.expiresAt,
      statsToken,
    };
  }

  private async generateUniqueShortCode(): Promise<string> {
    for (let attempt = 0; attempt < MAX_CODE_GENERATION_ATTEMPTS; attempt++) {
      const candidate = generateShortCode();
      if (RESERVED_CODES.has(candidate.toLowerCase())) continue;
      if (!(await shortUrlRepository.isShortCodeTaken(candidate))) return candidate;
    }
    throw new Error('Could not generate a unique short code after several attempts');
  }

  /** Public redirect handler — no auth. Resolves a short code and logs the click (non-blocking geo lookup). */
  async resolveAndRecordClick(shortCode: string, meta: ClickRequestMeta): Promise<ResolveResult> {
    const record = await shortUrlRepository.findByShortCode(shortCode);
    if (!record) return { ok: false, reason: 'NOT_FOUND' };
    if (record.status === ShortUrlStatus.DISABLED) return { ok: false, reason: 'DISABLED' };

    const isExpired = record.expiresAt !== null && record.expiresAt.getTime() <= Date.now();
    if (isExpired || record.status === ShortUrlStatus.EXPIRED) {
      if (record.status !== ShortUrlStatus.EXPIRED) void shortUrlRepository.markExpired(record.id);
      return { ok: false, reason: 'EXPIRED' };
    }

    void this.recordClickDetails(record.id, meta);
    await shortUrlRepository.recordClick(record.id);

    return { ok: true, redirectUrl: record.originalUrl };
  }

  /** Runs off the request/response path — a slow or failed geo lookup must never delay a redirect. */
  private async recordClickDetails(shortUrlId: string, meta: ClickRequestMeta): Promise<void> {
    try {
      const ip = meta.ip ?? 'unknown';
      const userAgent = meta.userAgent ?? '';
      const { browser, os, device } = UAParser(userAgent);

      const click = await shortUrlRepository.createClick({
        id: crypto.randomUUID(),
        shortUrlId,
        ipAddress: meta.ip,
        userAgent: meta.userAgent,
        browser: browser.name,
        os: os.name,
        device: device.type ?? 'desktop',
        referrer: meta.referrer,
        fingerprint: fingerprintVisitor(ip, userAgent),
      });

      if (meta.ip) {
        const geo = await getGeoIp(meta.ip);
        if (geo?.country) {
          await shortUrlRepository.updateClickGeo(click.id, geo.country, geo.countryCode);
        }
      }
    } catch (err) {
      logger.logError('Failed to record click details', err as Error, { shortUrlId });
    }
  }

  /**
   * The calling requester's own links — the only "list" endpoint in this
   * service, and it's IDOR-safe by construction: `requesterId` is never
   * accepted as a parameter from a route/query, only ever passed down from
   * `req.requester.id`, which the identity middleware derives from the
   * verified cookie. There's no ID here a client could substitute.
   */
  async listMyLinks(requesterId: string): Promise<MyLink[]> {
    const records = await shortUrlRepository.findByRequesterId(requesterId);
    return records.map((r) => ({
      shortCode: r.shortCode,
      shortUrl: toShortUrl(r.shortCode),
      originalUrl: r.originalUrl,
      clickCount: r.clickCount,
      createdAt: r.createdAt,
      expiresAt: r.expiresAt,
      status: r.status,
    }));
  }

  async getStats(shortCode: string): Promise<ShortUrlStats | null> {
    const record = await shortUrlRepository.findByShortCode(shortCode);
    if (!record) return null;
    return {
      shortCode: record.shortCode,
      originalUrl: record.originalUrl,
      shortUrl: toShortUrl(record.shortCode),
      clickCount: record.clickCount,
      lastClickedAt: record.lastClickedAt,
      createdAt: record.createdAt,
      expiresAt: record.expiresAt,
    };
  }

  /** Detailed per-click analytics — gated behind the stats token handed out at creation. */
  async getAnalytics(shortCode: string, token: string | undefined): Promise<GetAnalyticsResult> {
    const record = await shortUrlRepository.findByShortCode(shortCode);
    if (!record) return { ok: false, reason: 'NOT_FOUND' };
    if (!token || !timingSafeEqualHex(hashToken(token), record.statsTokenHash)) {
      return { ok: false, reason: 'UNAUTHORIZED' };
    }

    const [uniqueClicks, breakdowns, recent] = await Promise.all([
      shortUrlRepository.countUniqueClicks(record.id),
      shortUrlRepository.getBreakdowns(record.id),
      shortUrlRepository.getRecentClicks(record.id),
    ]);

    return {
      ok: true,
      analytics: {
        shortCode: record.shortCode,
        originalUrl: record.originalUrl,
        totalClicks: record.clickCount,
        uniqueClicks,
        createdAt: record.createdAt,
        ...breakdowns,
        recentClicks: recent.map((c) => ({
          ipAddress: c.ipAddress,
          device: c.device,
          browser: c.browser,
          os: c.os,
          country: c.country,
          countryCode: c.countryCode,
          referrer: c.referrer,
          clickedAt: c.clickedAt,
        })),
      },
    };
  }
}

export default new ShortUrlService();
