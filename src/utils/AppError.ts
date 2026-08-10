export class AppError extends Error {
  readonly statusCode: number;
  readonly code: string;
  readonly details?: unknown;

  constructor(message: string, statusCode: number, code: string, details?: unknown) {
    super(message);
    this.name = 'AppError';
    this.statusCode = statusCode;
    this.code = code;
    this.details = details;
    Object.setPrototypeOf(this, new.target.prototype);
  }

  static badRequest(message: string, code = 'BAD_REQUEST', details?: unknown) {
    return new AppError(message, 400, code, details);
  }

  static notFound(message = 'Not found', code = 'NOT_FOUND') {
    return new AppError(message, 404, code);
  }

  static conflict(message: string, code = 'CONFLICT', details?: unknown) {
    return new AppError(message, 409, code, details);
  }

  static unprocessable(message: string, code = 'UNPROCESSABLE', details?: unknown) {
    return new AppError(message, 422, code, details);
  }

  static tooManyRequests(message = 'Too many requests', code = 'RATE_LIMITED') {
    return new AppError(message, 429, code);
  }

  static internal(message = 'Internal server error', code = 'INTERNAL_ERROR') {
    return new AppError(message, 500, code);
  }
}
