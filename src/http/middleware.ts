import { HttpError } from '../errors';
import type { Context, Handler } from './context';

// ---------------- CORS ----------------
export interface CorsOptions {
  /** Daftar origin yang diizinkan, atau '*'. */
  origins: string[] | '*';
  methods?: string[];
  headers?: string[];
  /** Detik. Default 600. */
  maxAge?: number;
}

export function cors(options: CorsOptions): Handler {
  const methods = (options.methods ?? ['GET', 'POST', 'PUT', 'PATCH', 'DELETE']).join(', ');
  const headers = (options.headers ?? ['Content-Type', 'Authorization']).join(', ');
  const maxAge = String(options.maxAge ?? 600);

  return (ctx, next) => {
    const origin = ctx.header('origin');
    if (!origin) return next();
    const allowed = options.origins === '*' || options.origins.includes(origin);
    if (!allowed) return next();

    ctx.setHeader('Access-Control-Allow-Origin', options.origins === '*' ? '*' : origin);
    ctx.setHeader('Vary', 'Origin');

    if (ctx.method === 'OPTIONS' && ctx.header('access-control-request-method')) {
      ctx.setHeader('Access-Control-Allow-Methods', methods);
      ctx.setHeader('Access-Control-Allow-Headers', headers);
      ctx.setHeader('Access-Control-Max-Age', maxAge);
      ctx.res.writeHead(204);
      ctx.res.end();
      return;
    }
    return next();
  };
}

// ---------------- Rate limit ----------------
export interface RateLimitOptions {
  /** Default 60000 (1 menit). */
  windowMs?: number;
  /** Maksimal request per window per key. Default 10. */
  max?: number;
  /** Default: IP client. */
  key?: (ctx: Context) => string;
}

/** Rate limiter in-memory (per proses). Untuk banyak server/instance gunakan limiter terpusat (mis. di gateway/Redis). */
export function rateLimit(options: RateLimitOptions = {}): Handler {
  const windowMs = options.windowMs ?? 60_000;
  const max = options.max ?? 10;
  if (!Number.isFinite(windowMs) || windowMs < 1 || !Number.isInteger(max) || max < 1) {
    throw new Error('rateLimit: windowMs harus positif dan max harus integer minimal 1');
  }
  const maxKeys = 50_000;
  const hits = new Map<string, { count: number; reset: number }>();

  const sweep = setInterval(() => {
    const now = Date.now();
    for (const [k, v] of hits) if (v.reset <= now) hits.delete(k);
  }, Math.min(windowMs, 60_000));
  sweep.unref();

  return (ctx, next) => {
    const key = options.key ? options.key(ctx) : ctx.ip;
    const now = Date.now();
    let entry = hits.get(key);
    if (!entry || entry.reset <= now) {
      if (hits.size >= maxKeys) hits.delete(hits.keys().next().value as string);
      entry = { count: 0, reset: now + windowMs };
      hits.set(key, entry);
    }
    entry.count += 1;
    ctx.setHeader('RateLimit-Limit', String(max));
    ctx.setHeader('RateLimit-Remaining', String(Math.max(0, max - entry.count)));

    if (entry.count > max) {
      throw new HttpError('Terlalu banyak permintaan, coba lagi nanti', 429, 'RATE_LIMITED', {
        'Retry-After': String(Math.ceil((entry.reset - now) / 1000)),
      });
    }
    return next();
  };
}
