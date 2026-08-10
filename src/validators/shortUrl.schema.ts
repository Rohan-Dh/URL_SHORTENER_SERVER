import { z } from 'zod';

function isHttpUrl(value: string): boolean {
  try {
    const parsed = new URL(value);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:';
  } catch {
    return false;
  }
}

export const createShortUrlSchema = z.object({
  url: z
    .string()
    .trim()
    .min(1, 'URL is required')
    .max(2048, 'URL is too long')
    .refine(isHttpUrl, 'Must be a valid http(s) URL'),
  // Custom aliases are temporarily disabled — uncomment to re-enable.
  // alias: z
  //   .string()
  //   .trim()
  //   .min(3, 'Alias must be at least 3 characters')
  //   .max(30, 'Alias must be at most 30 characters')
  //   .regex(/^[a-zA-Z0-9-]+$/, 'Alias may only contain letters, numbers and hyphens')
  //   .optional(),
  // How many days the link stays valid for. Omitted/undefined = never expires.
  expiresInDays: z
    .number()
    .int('Must be a whole number of days')
    .min(1, 'Validity must be at least 1 day')
    .max(3650, 'Validity can be at most 10 years')
    .optional(),
});

export type CreateShortUrlInput = z.infer<typeof createShortUrlSchema>;
