import { createHash, createHmac, randomInt, timingSafeEqual } from 'node:crypto';

export const sha256 = (v: string): string => createHash('sha256').update(String(v)).digest('hex');

export const hmac = (secret: string, v: string): string =>
  createHmac('sha256', secret).update(String(v)).digest('hex');

export function generateOtp(length = 6): string {
  return String(randomInt(0, 10 ** length)).padStart(length, '0');
}

export function safeEqual(a: string, b: string): boolean {
  const ba = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ba.length !== bb.length) return false;
  return timingSafeEqual(ba, bb);
}
