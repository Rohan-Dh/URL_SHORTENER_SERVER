import { Request, Response } from 'express';
import BaseController from './base.controller.js';
import ApiResponse from '../utils/ApiResponse.js';
import shortUrlService from '../services/shortUrl.service.js';
import { createShortUrlSchema } from '../validators/shortUrl.schema.js';

/**
 * Controller layer — translates HTTP <-> service calls. No business logic
 * or Prisma calls live here; everything is delegated to ShortUrlService.
 */
class ShortUrlController extends BaseController {
  /** POST /api/shorten — public, no auth. */
  create = async (req: Request, res: Response) => {
    try {
      const parsed = createShortUrlSchema.safeParse(req.body);
      if (!parsed.success) {
        return ApiResponse.error(
          res,
          parsed.error.issues[0]?.message ?? 'Invalid request',
          'VALIDATION_ERROR',
          400,
        );
      }

      // Guaranteed by requesterIdentity middleware on every /api route — this
      // check is defensive (wrong route wiring), not a real auth gate here.
      if (!req.requester) return ApiResponse.internal(res);

      const identifier = req.ip ?? 'unknown';
      const result = await shortUrlService.createShortUrl({
        url: parsed.data.url,
        alias: parsed.data.alias,
        expiresInDays: parsed.data.expiresInDays,
        requesterId: req.requester.id,
        identifier,
        ip: req.ip,
      });

      if (!result.ok) {
        switch (result.reason) {
          case 'CONTENT_REJECTED':
            return ApiResponse.error(res, result.message, 'CONTENT_POLICY_VIOLATION', 422, undefined, {
              category: result.category,
              riskScore: result.riskScore,
            });
          case 'ALIAS_TAKEN':
            return ApiResponse.conflict(res, 'That custom alias is already taken', 'ALIAS_TAKEN');
          case 'ALIAS_RESERVED':
            return ApiResponse.error(
              res,
              'That alias is reserved or contains invalid characters',
              'ALIAS_RESERVED',
              400,
            );
          case 'SELF_REFERENTIAL':
            return ApiResponse.error(
              res,
              "You can't shorten a link that points back at this shortener",
              'SELF_REFERENTIAL',
              400,
            );
          default:
            return ApiResponse.internal(res);
        }
      }

      return ApiResponse.created(res, {
        shortCode: result.shortCode,
        shortUrl: result.shortUrl,
        originalUrl: result.originalUrl,
        createdAt: result.createdAt,
        expiresAt: result.expiresAt,
        statsToken: result.statsToken,
      });
    } catch (err) {
      return this.sendError(res, err, 'ShortUrlController.create');
    }
  };

  /** GET /api/shorten/:shortCode — public click-count lookup for the result card. */
  stats = async (req: Request, res: Response) => {
    try {
      const shortCode = req.params['shortCode'] as string;
      const stats = await shortUrlService.getStats(shortCode);
      if (!stats) return ApiResponse.notFound(res, 'Short link not found');
      return ApiResponse.success(res, stats);
    } catch (err) {
      return this.sendError(res, err, 'ShortUrlController.stats');
    }
  };

  /**
   * GET /api/shorten/:shortCode/analytics — per-click log (IP, device,
   * location) behind the stats token issued at creation. Never public.
   */
  analytics = async (req: Request, res: Response) => {
    try {
      const shortCode = req.params['shortCode'] as string;
      const token = req.get('x-stats-token');
      const result = await shortUrlService.getAnalytics(shortCode, token);

      if (!result.ok) {
        if (result.reason === 'NOT_FOUND') return ApiResponse.notFound(res, 'Short link not found');
        return ApiResponse.unauthorized(res, 'Missing or invalid stats token', 'UNAUTHORIZED');
      }

      return ApiResponse.success(res, result.analytics);
    } catch (err) {
      return this.sendError(res, err, 'ShortUrlController.analytics');
    }
  };

  /**
   * GET /api/me/links — the calling requester's own links, identified
   * solely by their requester cookie. No ID is ever read from the request
   * itself, so there's nothing here for one requester to substitute to see
   * another's data.
   */
  myLinks = async (req: Request, res: Response) => {
    try {
      if (!req.requester) return ApiResponse.internal(res);
      const links = await shortUrlService.listMyLinks(req.requester.id);
      return ApiResponse.success(res, links);
    } catch (err) {
      return this.sendError(res, err, 'ShortUrlController.myLinks');
    }
  };

  /** GET /:shortCode — public redirect, no auth, no org scoping. */
  redirect = async (req: Request, res: Response) => {
    try {
      const shortCode = req.params['shortCode'] as string;
      const result = await shortUrlService.resolveAndRecordClick(shortCode, {
        ip: req.ip,
        userAgent: req.get('user-agent'),
        referrer: req.get('referer'),
      });

      if (!result.ok) {
        const statusByReason: Record<string, number> = { NOT_FOUND: 404, DISABLED: 410, EXPIRED: 410 };
        return ApiResponse.error(
          res,
          'Short URL could not be resolved',
          result.reason,
          statusByReason[result.reason] ?? 400,
        );
      }

      return res.redirect(302, result.redirectUrl);
    } catch (err) {
      return this.sendError(res, err, 'ShortUrlController.redirect');
    }
  };
}

export default new ShortUrlController();
