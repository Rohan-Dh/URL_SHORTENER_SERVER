import 'dotenv/config';
import { PrismaClient, Prisma } from '@prisma/client';
import { PrismaMariaDb } from '@prisma/adapter-mariadb';

import config from './config.js';

const globalForPrisma = globalThis as unknown as {
  prisma: PrismaClient | undefined;
};

const adapter = new PrismaMariaDb({
  host: config.database.host,
  port: config.database.port,
  user: config.database.user,
  password: config.database.password,
  database: config.database.name,
  connectionLimit: config.database.connectionLimit,
});

export const prisma =
  globalForPrisma.prisma ??
  new PrismaClient({
    adapter,
    log: config.app.env === 'development' ? ['error', 'warn'] : ['error'],
  });

if (config.app.env !== 'production') {
  globalForPrisma.prisma = prisma;
}

export const connectDB = async () => {
  try {
    await prisma.$connect();
    console.log('✅ Database connected');
  } catch (error) {
    console.error('❌ Database connection failed:', error);
    process.exit(1);
  }
};

export const disconnectDB = async () => {
  await prisma.$disconnect();
  console.log('🔌 Database disconnected');
};

export type DBClient = PrismaClient | Prisma.TransactionClient;
