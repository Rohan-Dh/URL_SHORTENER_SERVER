export type ResolveResult =
  | { ok: true; redirectUrl: string }
  | { ok: false; reason: 'NOT_FOUND' | 'DISABLED' | 'EXPIRED' };

export interface ClickRequestMeta {
  ip?: string | undefined;
  userAgent?: string | undefined;
  referrer?: string | undefined;
}

export interface CreateShortUrlParams {
  url: string;
  alias?: string | undefined;
  /** Days until the link stops working. Undefined/null = never expires. */
  expiresInDays?: number | undefined;
  /** The anonymous requester creating this link (see requesterIdentity middleware). */
  requesterId: string;
  identifier: string;
  ip?: string | undefined;
}

export type CreateShortUrlResult =
  | {
      ok: true;
      shortCode: string;
      shortUrl: string;
      originalUrl: string;
      createdAt: Date;
      expiresAt: Date | null;
      /** Shown once — required to view this link's detailed analytics later. */
      statsToken: string;
    }
  | {
      ok: false;
      reason: 'CONTENT_REJECTED';
      message: string;
      category: string | null;
      riskScore: number | null;
    }
  | { ok: false; reason: 'ALIAS_TAKEN' }
  | { ok: false; reason: 'ALIAS_RESERVED' }
  | { ok: false; reason: 'SELF_REFERENTIAL' };

export interface ShortUrlStats {
  shortCode: string;
  originalUrl: string;
  shortUrl: string;
  clickCount: number;
  lastClickedAt: Date | null;
  createdAt: Date;
  expiresAt: Date | null;
}

export interface AnalyticsBreakdownEntry {
  label: string;
  count: number;
}

export interface RecentClick {
  ipAddress: string | null;
  device: string | null;
  browser: string | null;
  os: string | null;
  country: string | null;
  countryCode: string | null;
  referrer: string | null;
  clickedAt: Date;
}

export interface ShortUrlAnalytics {
  shortCode: string;
  originalUrl: string;
  totalClicks: number;
  uniqueClicks: number;
  createdAt: Date;
  byBrowser: AnalyticsBreakdownEntry[];
  byOs: AnalyticsBreakdownEntry[];
  byDevice: AnalyticsBreakdownEntry[];
  byCountry: AnalyticsBreakdownEntry[];
  byReferrer: AnalyticsBreakdownEntry[];
  recentClicks: RecentClick[];
}

export type GetAnalyticsResult =
  | { ok: true; analytics: ShortUrlAnalytics }
  | { ok: false; reason: 'NOT_FOUND' | 'UNAUTHORIZED' };

/** One row in the calling requester's own link list — GET /api/me/links. */
export interface MyLink {
  shortCode: string;
  shortUrl: string;
  originalUrl: string;
  clickCount: number;
  createdAt: Date;
  expiresAt: Date | null;
  status: string;
}
