// Prisma configuration for v7.x
import 'dotenv/config';
import { defineConfig } from 'prisma/config';

export default defineConfig({
  schema: 'prisma/schema.prisma',
  datasource: {
    ...(process.env['DATABASE_URL'] && { url: process.env['DATABASE_URL'] }),
  },
});
