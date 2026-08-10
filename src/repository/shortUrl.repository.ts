import { ShortUrlStatus, type ShortUrl, type ShortUrlClick } from '@prisma/client';
import { DBClient, prisma } from '../config/prisma.js';
import type { AnalyticsBreakdownEntry } from '../interface/ShortUrlInterface.js';

const RECENT_CLICKS_LIMIT = 50;
const BREAKDOWN_LIMIT = 5;

/**
 * Repository layer — the only place that talks to Prisma for this feature.
 * Services depend on this interface, never on PrismaClient directly.
 */
class ShortUrlRepository {
  async findByShortCode(shortCode: string, tx?: DBClient): Promise<ShortUrl | null> {
    const client = tx ?? prisma;
    return client.shortUrl.findUnique({ where: { shortCode } });
  }

  async isShortCodeTaken(shortCode: string, tx?: DBClient): Promise<boolean> {
    const client = tx ?? prisma;
    const existing = await client.shortUrl.findUnique({
      where: { shortCode },
      select: { id: true },
    });
    return existing !== null;
  }

  async create(
    params: {
      id: string;
      shortCode: string;
      originalUrl: string;
      isCustomAlias: boolean;
      statsTokenHash: string;
      requesterId: string;
      expiresAt?: Date | undefined;
      createdByIp?: string | undefined;
    },
    tx?: DBClient,
  ): Promise<ShortUrl> {
    const client = tx ?? prisma;
    return client.shortUrl.create({
      data: {
        id: params.id,
        shortCode: params.shortCode,
        originalUrl: params.originalUrl,
        isCustomAlias: params.isCustomAlias,
        statsTokenHash: params.statsTokenHash,
        requesterId: params.requesterId,
        expiresAt: params.expiresAt ?? null,
        createdByIp: params.createdByIp ?? null,
      },
    });
  }

  /** Own-data listing for GET /api/me/links — requesterId always comes from the verified cookie, never from client input. */
  async findByRequesterId(requesterId: string, tx?: DBClient): Promise<ShortUrl[]> {
    const client = tx ?? prisma;
    return client.shortUrl.findMany({
      where: { requesterId },
      orderBy: { createdAt: 'desc' },
    });
  }

  async recordClick(id: string, tx?: DBClient): Promise<void> {
    const client = tx ?? prisma;
    await client.shortUrl.update({
      where: { id },
      data: { clickCount: { increment: 1 }, lastClickedAt: new Date() },
    });
  }

  /** Lazily flips a link to EXPIRED once its validity window has passed. */
  async markExpired(id: string, tx?: DBClient): Promise<void> {
    const client = tx ?? prisma;
    await client.shortUrl.update({ where: { id }, data: { status: ShortUrlStatus.EXPIRED } });
  }

  async createClick(
    params: {
      id: string;
      shortUrlId: string;
      ipAddress?: string | undefined;
      userAgent?: string | undefined;
      device?: string | undefined;
      browser?: string | undefined;
      os?: string | undefined;
      referrer?: string | undefined;
      fingerprint: string;
    },
    tx?: DBClient,
  ): Promise<ShortUrlClick> {
    const client = tx ?? prisma;
    return client.shortUrlClick.create({
      data: {
        id: params.id,
        shortUrlId: params.shortUrlId,
        ipAddress: params.ipAddress ?? null,
        userAgent: params.userAgent ?? null,
        device: params.device ?? null,
        browser: params.browser ?? null,
        os: params.os ?? null,
        referrer: params.referrer ?? null,
        fingerprint: params.fingerprint,
      },
    });
  }

  /** Patches in geo data once the (async, non-blocking) lookup resolves. */
  async updateClickGeo(clickId: string, country: string, countryCode: string): Promise<void> {
    await prisma.shortUrlClick.update({
      where: { id: clickId },
      data: { country, countryCode },
    });
  }

  async countUniqueClicks(shortUrlId: string): Promise<number> {
    const groups = await prisma.shortUrlClick.groupBy({
      by: ['fingerprint'],
      where: { shortUrlId },
    });
    return groups.length;
  }

  private async breakdown(
    shortUrlId: string,
    column: 'browser' | 'os' | 'device' | 'country' | 'referrer',
  ): Promise<AnalyticsBreakdownEntry[]> {
    const groups = await prisma.shortUrlClick.groupBy({
      by: [column],
      where: { shortUrlId, [column]: { not: null } },
      _count: { _all: true },
      orderBy: { _count: { [column]: 'desc' } },
      take: BREAKDOWN_LIMIT,
    });
    return groups
      .map((g) => ({ label: (g[column] as string | null) ?? 'Unknown', count: g._count._all }))
      .filter((entry) => entry.count > 0);
  }

  async getBreakdowns(shortUrlId: string) {
    const [byBrowser, byOs, byDevice, byCountry, byReferrer] = await Promise.all([
      this.breakdown(shortUrlId, 'browser'),
      this.breakdown(shortUrlId, 'os'),
      this.breakdown(shortUrlId, 'device'),
      this.breakdown(shortUrlId, 'country'),
      this.breakdown(shortUrlId, 'referrer'),
    ]);
    return { byBrowser, byOs, byDevice, byCountry, byReferrer };
  }

  async getRecentClicks(shortUrlId: string): Promise<ShortUrlClick[]> {
    return prisma.shortUrlClick.findMany({
      where: { shortUrlId },
      orderBy: { clickedAt: 'desc' },
      take: RECENT_CLICKS_LIMIT,
    });
  }
}

export { ShortUrlStatus };
export default new ShortUrlRepository();
