/**
 * Express application configuration and middleware setup for the
 * NestSMS URL Shortener API.
 */
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';

import config from './config/config.js';
import shortUrlRoutes from './routes/shortUrl.routes.js';
import shortUrlController from './controllers/shortUrl.controller.js';
import { requesterIdentity } from './middleware/requesterIdentity.js';
import ApiResponse from './utils/ApiResponse.js';

const app = express();

app.disable('x-powered-by');
app.set('trust proxy', 1);

const allowedOrigins = new Set([config.app.frontendUrl, ...config.app.corsOrigins]);

app.use(helmet());
app.use(
  cors({
    origin(origin, callback) {
      // No Origin header (curl, server-to-server, same-origin) — allow.
      // An origin outside the allow-list is denied, not errored: the request
      // still completes, it just comes back without CORS headers, so the
      // browser (not this server) is what blocks the page from reading it.
      callback(null, !origin || allowedOrigins.has(origin));
    },
    // Required for the requester-identity cookie to flow at all: browsers
    // strip Set-Cookie from cross-origin responses and won't attach cookies
    // to cross-origin requests unless the server opts in. Safe alongside a
    // specific origin allow-list (never used with a wildcard origin).
    credentials: true,
  }),
);
app.use(express.json({ limit: '16kb' }));
app.use(cookieParser());

// ─── Health & root ───────────────────────────────────────────────────────────
app.get('/health', (_req, res) => res.status(200).json({ status: 'OK', timestamp: new Date().toISOString() }));
app.get('/', (_req, res) => res.json({ message: 'NestSMS URL Shortener API' }));

// ─── API ─────────────────────────────────────────────────────────────────────
app.use('/api', requesterIdentity, shortUrlRoutes);

// ─── Public redirect — must stay last, it's a catch-all on /:shortCode ───────
app.get('/:shortCode', shortUrlController.redirect);

// ─── 404 for anything else (e.g. POST to an unknown path) ────────────────────
app.use((_req, res) => ApiResponse.notFound(res, 'Not found'));

export default app;
