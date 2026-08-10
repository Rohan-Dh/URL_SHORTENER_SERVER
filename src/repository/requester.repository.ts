import type { Requester } from '@prisma/client';
import { DBClient, prisma } from '../config/prisma.js';

/**
 * Repository layer for the anonymous Requester identity — the only place
 * that talks to Prisma for this feature. `tokenHash` is a unique indexed
 * column, so `findByTokenHash` is a direct equality lookup, not a
 * fetch-then-compare — there's no secret comparison to time here (unlike
 * `statsTokenHash` verification, which compares an already-fetched row's
 * hash against a presented token and needs `timingSafeEqualHex` for that).
 */
class RequesterRepository {
  async findByTokenHash(tokenHash: string, tx?: DBClient): Promise<Requester | null> {
    const client = tx ?? prisma;
    return client.requester.findUnique({ where: { tokenHash } });
  }

  async create(params: { id: string; tokenHash: string }, tx?: DBClient): Promise<Requester> {
    const client = tx ?? prisma;
    return client.requester.create({ data: { id: params.id, tokenHash: params.tokenHash } });
  }

  async touchLastSeen(id: string, tx?: DBClient): Promise<void> {
    const client = tx ?? prisma;
    await client.requester.update({ where: { id }, data: { lastSeenAt: new Date() } });
  }
}

export default new RequesterRepository();
