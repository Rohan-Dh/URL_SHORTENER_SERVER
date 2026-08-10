import 'dotenv/config';

function env(key: string, fallback: string): string;
function env(key: string): string | undefined;
function env(key: string, fallback?: string): string | undefined {
  return process.env[key] ?? fallback;
}

const envNumber = (key: string, fallback: number) => Number(process.env[key] ?? fallback);
const envBool = (key: string, fallback: boolean) =>
  process.env[key] === undefined ? fallback : process.env[key] === 'true';

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
    // Off by default — matches unencrypted local/Docker MySQL. Turn on for
    // any DB reached over the public internet (e.g. Railway's public proxy).
    ssl: envBool('DATABASE_SSL', false),
    // Verifies the server's cert by default when SSL is on. Only disable this
    // if you hit a self-signed-cert connection error from your specific
    // provider — that trades "encrypted" for "encrypted but not authenticated"
    // (blocks passive eavesdropping, not an active MITM), so it's opt-in, not
    // a default I'll silently pick for you.
    sslRejectUnauthorized: envBool('DATABASE_SSL_REJECT_UNAUTHORIZED', true),
    // The `mariadb` driver defaults this to 1000ms, which is tuned for a
    // local/LAN MySQL and is too tight for a real TLS handshake to a remote
    // host over the public internet — that combination reliably times out
    // creating new pool connections against a hosted DB (Railway, PlanetScale,
    // etc.) even though the DB itself is reachable and healthy.
    connectTimeoutMs: envNumber('DATABASE_CONNECT_TIMEOUT_MS', 10_000),
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
