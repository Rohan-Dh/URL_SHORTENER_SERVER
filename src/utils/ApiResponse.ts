import type { Response } from 'express';

export interface SuccessPayload {
  success: true;
  message?: string;
  data?: unknown;
  [key: string]: unknown;
}

export interface ErrorPayload {
  success: false;
  error: string;
  code: string;
  message?: string;
  [key: string]: unknown;
}

class ApiResponse {
  static success(
    res: Response,
    data?: unknown,
    message?: string,
    status = 200,
    extra: Record<string, unknown> = {},
  ): Response {
    const body: SuccessPayload = {
      success: true,
      ...(message !== undefined && { message }),
      ...(data !== undefined && { data }),
      ...extra,
    };
    return res.status(status).json(body);
  }

  static error(
    res: Response,
    error: string,
    code: string,
    status = 400,
    message?: string,
    extra: Record<string, unknown> = {},
  ): Response {
    const body: ErrorPayload = {
      success: false,
      error,
      code,
      ...(message !== undefined && { message }),
      ...extra,
    };
    return res.status(status).json(body);
  }

  static created(
    res: Response,
    data?: unknown,
    message?: string,
    extra: Record<string, unknown> = {},
  ): Response {
    return ApiResponse.success(res, data, message, 201, extra);
  }

  static notFound(res: Response, message = 'Not found', code = 'NOT_FOUND'): Response {
    return ApiResponse.error(res, message, code, 404);
  }

  static unauthorized(res: Response, message = 'Unauthorized', code = 'UNAUTHORIZED'): Response {
    return ApiResponse.error(res, message, code, 401);
  }

  static conflict(res: Response, message: string, code = 'CONFLICT'): Response {
    return ApiResponse.error(res, message, code, 409);
  }

  static internal(
    res: Response,
    message = 'Internal server error',
    code = 'INTERNAL_ERROR',
  ): Response {
    return ApiResponse.error(res, message, code, 500);
  }
}

export default ApiResponse;
