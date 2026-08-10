import fs from 'fs';
import path from 'path';

import winston from 'winston';
import DailyRotateFile from 'winston-daily-rotate-file';

import config from '../config/config.js';
import { getGeoIp } from './geoIp.js';

// ─── Types ────────────────────────────────────────────────────────────────────

interface BaseError {
  message: string;
  stack?: string;
  code?: string | number;
}

type LogContext = Record<string, unknown>;

interface ExtendedLogger extends winston.Logger {
  logError: (message: string, error: BaseError, context?: LogContext) => void;
}

// ─── Directories ──────────────────────────────────────────────────────────────

const LOG_DIR = config.logging.dir || path.join(process.cwd(), 'storage', 'logs');
const LOG_SUBDIRS = {
  general: path.join(LOG_DIR, 'general'),
  contentFilter: path.join(LOG_DIR, 'content-filter'),
} as const;

Object.values(LOG_SUBDIRS).forEach((dir) => {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

// ─── Formats ─────────────────────────────────────────────────────────────────

const detailedFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  winston.format.errors({ stack: true }),
  winston.format.metadata(),
  winston.format.json(),
);

const consoleFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  winston.format.colorize(),
  winston.format.printf(({ timestamp, level, message, ...meta }) => {
    let msg = `${String(timestamp)} [${String(level)}]: ${String(message)}`;
    if (Object.keys(meta).length > 0) msg += ` ${JSON.stringify(meta)}`;
    return msg;
  }),
);

const contentFilterFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  winston.format.printf(({ level, message, timestamp, service, environment, ...rest }) => {
    const { event, request, filter, content } = rest as Record<string, unknown>;
    return JSON.stringify(
      { timestamp, level, event: event ?? message, service, environment, request, filter, content },
      null,
      2,
    );
  }),
);

// ─── Transports ───────────────────────────────────────────────────────────────

const errorFileTransport = new DailyRotateFile({
  filename: path.join(LOG_SUBDIRS.general, 'error-%DATE%.log'),
  datePattern: 'YYYY-MM-DD',
  maxFiles: '10d',
  level: 'error',
  format: detailedFormat,
});

const combinedFileTransport = new DailyRotateFile({
  filename: path.join(LOG_SUBDIRS.general, 'combined-%DATE%.log'),
  datePattern: 'YYYY-MM-DD',
  maxFiles: '10d',
  format: detailedFormat,
});

const contentFilterTransport = new DailyRotateFile({
  filename: path.join(LOG_SUBDIRS.contentFilter, 'content-filter-%DATE%.log'),
  datePattern: 'YYYY-MM-DD',
  maxFiles: '10d',
  format: contentFilterFormat,
});

errorFileTransport.handleExceptions = true;
errorFileTransport.handleRejections = true;
[errorFileTransport, combinedFileTransport, contentFilterTransport].forEach((t) =>
  t.setMaxListeners(20),
);

// ─── Geo enrichment ───────────────────────────────────────────────────────────

/**
 * Wraps a logger so any call carrying `meta.request.ip` fetches geo data and
 * inlines country/countryCode/lat/lon/isp into the request block before the
 * entry is written. Callers never touch geoIp directly.
 */
function withGeoEnrichment(instance: ExtendedLogger): ExtendedLogger {
  const levels = ['error', 'warn', 'info', 'http', 'verbose', 'debug'] as const;

  for (const lvl of levels) {
    const original = (instance[lvl] as (...a: unknown[]) => ExtendedLogger).bind(instance);

    (instance as unknown as Record<string, unknown>)[lvl] = (
      message: unknown,
      meta?: Record<string, unknown>,
      ...rest: unknown[]
    ): void => {
      const request = meta?.['request'] as Record<string, unknown> | undefined;
      const ip = request?.['ip'];

      if (!ip || typeof ip !== 'string') {
        original(message, meta, ...rest);
        return;
      }

      getGeoIp(ip)
        .then((geo) => {
          const enrichedRequest = geo
            ? {
                ...request,
                country: geo.country,
                countryCode: geo.countryCode,
                lat: geo.lat,
                lon: geo.lon,
                isp: geo.isp,
              }
            : request;
          original(message, { ...meta, request: enrichedRequest }, ...rest);
        })
        .catch(() => original(message, meta, ...rest));
    };
  }

  return instance;
}

// ─── Logger factory ───────────────────────────────────────────────────────────

const isDev = config.app.env !== 'production' || config.logging.consoleLogs;

function makeLogger(service: string, level: string, transports: winston.transport[]): ExtendedLogger {
  const instance = winston.createLogger({
    level,
    defaultMeta: { service, environment: config.app.env },
    transports,
    exitOnError: false,
  }) as ExtendedLogger;

  if (isDev) instance.add(new winston.transports.Console({ format: consoleFormat }));

  instance.logError = (message, error, context = {}) => {
    instance.error(message, { error, ...context });
  };

  return instance;
}

// ─── Loggers ─────────────────────────────────────────────────────────────────

const logger = makeLogger('nest-sms-url-server', config.logging.level, [
  errorFileTransport,
  combinedFileTransport,
]);
if (isDev) {
  logger.add(
    new winston.transports.Console({
      format: consoleFormat,
      handleExceptions: true,
      handleRejections: true,
    }),
  );
}

const contentFilterLogger = withGeoEnrichment(
  makeLogger('content-filter', 'info', [contentFilterTransport]),
);

export { logger, contentFilterLogger, LOG_DIR, LOG_SUBDIRS };
export type { BaseError, LogContext, ExtendedLogger };
export default { logger, contentFilterLogger, LOG_DIR, LOG_SUBDIRS };
