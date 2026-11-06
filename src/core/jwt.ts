import { createHmac, timingSafeEqual } from 'node:crypto';
import { toSeconds } from '../utils/duration';

/** JWT HS256 buatan sendiri (RFC 7519) memakai HMAC-SHA256 bawaan Node. */

export type JwtFailure = 'expired' | 'invalid';

export class JwtError extends Error {
  readonly reason: JwtFailure;
  constructor(reason: JwtFailure, message?: string) {
    super(message ?? reason);
    this.name = 'JwtError';
    this.reason = reason;
  }
}

export interface JwtPayload {
  sub?: string;
  jti?: string;
  iat?: number;
  exp?: number;
  nbf?: number;
  [claim: string]: unknown;
}

export interface SignJwtOptions {
  expiresIn: string | number;
  subject?: string;
  jwtid?: string;
}

const B64URL = /^[A-Za-z0-9_-]+$/;
const encode = (v: unknown): string => Buffer.from(JSON.stringify(v)).toString('base64url');
const HEADER = encode({ alg: 'HS256', typ: 'JWT' });
const mac = (data: string, secret: string): Buffer => createHmac('sha256', secret).update(data).digest();

export function signJwt(payload: Record<string, unknown>, secret: string, opts: SignJwtOptions): string {
  const iat = Math.floor(Date.now() / 1000);
  const body: JwtPayload = { ...payload, iat, exp: iat + toSeconds(opts.expiresIn) };
  if (opts.subject) body.sub = opts.subject;
  if (opts.jwtid) body.jti = opts.jwtid;
  const data = `${HEADER}.${encode(body)}`;
  return `${data}.${mac(data, secret).toString('base64url')}`;
}

function parseSegment(segment: string): Record<string, unknown> {
  if (!B64URL.test(segment)) throw new JwtError('invalid');
  let value: unknown;
  try {
    value = JSON.parse(Buffer.from(segment, 'base64url').toString('utf8'));
  } catch {
    throw new JwtError('invalid');
  }
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new JwtError('invalid');
  return value as Record<string, unknown>;
}

/** Verifikasi tanda tangan + masa berlaku. Hanya menerima HS256 (menolak "none" & algoritma lain). */
export function verifyJwt(token: unknown, secret: string): JwtPayload {
  if (typeof token !== 'string' || token.length > 4096) throw new JwtError('invalid');
  const parts = token.split('.');
  if (parts.length !== 3) throw new JwtError('invalid');
  const [h, p, s] = parts;

  const header = parseSegment(h);
  if (header.alg !== 'HS256' || header.typ !== 'JWT') throw new JwtError('invalid');
  if (!B64URL.test(s)) throw new JwtError('invalid');

  const given = Buffer.from(s, 'base64url');
  const expected = mac(`${h}.${p}`, secret);
  if (given.length !== expected.length || !timingSafeEqual(given, expected)) throw new JwtError('invalid');

  const payload = parseSegment(p) as JwtPayload;
  const now = Math.floor(Date.now() / 1000);
  if (typeof payload.exp !== 'number' || !Number.isFinite(payload.exp) || payload.exp <= 0) {
    throw new JwtError('invalid');
  }
  if (now >= payload.exp) throw new JwtError('expired');
  if (payload.nbf !== undefined && (typeof payload.nbf !== 'number' || !Number.isFinite(payload.nbf))) {
    throw new JwtError('invalid');
  }
  if (typeof payload.nbf === 'number' && now < payload.nbf) throw new JwtError('invalid');
  return payload;
}

export function decodeJwtUnsafe(token: string): JwtPayload | null {
  try {
    return parseSegment(token.split('.')[1] ?? '') as JwtPayload;
  } catch {
    return null;
  }
}
