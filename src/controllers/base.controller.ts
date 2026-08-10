import type { Response } from 'express';

import { AppError } from '../utils/AppError.js';
import ApiResponse from '../utils/ApiResponse.js';
import { logger } from '../utils/logger.js';

abstract class BaseController {
  protected sendError(
    res: Response,
    error: unknown,
    context: string,
    message = 'Internal server error',
    code = 'INTERNAL_ERROR',
  ): Response {
    if (error instanceof AppError) {
      logger.error(`[${context}] ${error.message}`, {
        code: error.code,
        statusCode: error.statusCode,
      });
      const extra =
        error.details && typeof error.details === 'object'
          ? (error.details as Record<string, unknown>)
          : {};
      return ApiResponse.error(res, error.message, error.code, error.statusCode, undefined, extra);
    }
    const err = error as Error;
    logger.error(`[${context}] ${err?.message ?? String(error)}`);
    return ApiResponse.internal(res, message, code);
  }
}

export default BaseController;
