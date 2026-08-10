import 'dotenv/config';

import app from './src/app.js';
import { connectDB } from './src/config/prisma.js';
import config from './src/config/config.js';
import { logger } from './src/utils/logger.js';

const PORT = config.app.port;

process.on('uncaughtException', (err: Error) => {
  logger.logError('Uncaught exception — shutting down', err);
  process.exit(1);
});

void connectDB();

const server = app.listen(PORT, '0.0.0.0');

server.on('listening', () => {
  console.log(`NestSMS URL Shortener API running on http://localhost:${PORT}`);
});

server.on('error', (err: NodeJS.ErrnoException) => {
  console.error('Server failed to start:', err);
  if (err.code === 'EADDRINUSE') console.error(`Port ${PORT} is already in use.`);
  process.exit(1);
});

function gracefulShutdown(signal: string) {
  console.log(`\n[${signal}] Shutting down gracefully...`);
  server.close(() => process.exit(0));
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

process.on('unhandledRejection', (err: Error) => {
  logger.logError('Unhandled promise rejection — shutting down', err);
  server.close(() => process.exit(1));
});
