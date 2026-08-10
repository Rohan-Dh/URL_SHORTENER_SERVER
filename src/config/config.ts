import 'dotenv/config';

function env(key: string, fallback: string): string;
function env(key: string): string | undefined;
function env(key: string, fallback?: string): string | undefined {
  return process.env[key] ?? fallback;
}

const envNumber = (key: string, fallback: number) => Number(process.env[key] ?? fallback);

export default {
  app: {
    name: env('APP_NAME', 'NestSMS URL Shortener'),
    env: env('NODE_ENV', 'development'),
    port: envNumber('PORT', 8081),
    url: env('APP_URL', 'http://localhost:8081'),
    frontendUrl: env('FRONTEND_URL', 'http://localhost:3002'),
    // Extra allowed CORS origins beyond `frontendUrl` (comma-separated) — e.g.
    // both a localhost and a LAN-IP origin while testing from another device.
    corsOrigins: (env('CORS_ORIGINS', '') as string)
      .split(',')
      .map((o) => o.trim())
      .filter(Boolean),
  },

  database: {
    host: env('DATABASE_HOST', 'localhost'),
    port: envNumber('DATABASE_PORT', 3306),
    user: env('DATABASE_USER', 'root'),
    password: env('DATABASE_PASSWORD', ''),
    name: env('DATABASE_NAME', 'nestsms_url_shortener'),
    connectionLimit: envNumber('DB_CONNECTION_LIMIT', 20),
  },

  logging: {
    level: env('LOG_LEVEL', 'debug'),
    dir: env('LOG_DIR'),
    consoleLogs: env('CONSOLE_LOGS', 'true') === 'true',
  },

  shortUrl: {
    codeLength: envNumber('SHORT_URL_CODE_LENGTH', 7),
  },

  requester: {
    cookieName: env('REQUESTER_COOKIE_NAME', 'nsms_rid'),
    // 1 year — this cookie *is* the anonymous identity, so it should
    // outlive a normal session rather than expire like one.
    maxAgeMs: envNumber('REQUESTER_COOKIE_MAX_AGE_MS', 365 * 24 * 60 * 60 * 1000),
  },
};
