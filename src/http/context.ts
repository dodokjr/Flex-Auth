import type { IncomingMessage, ServerResponse } from 'node:http';
import { HttpError } from '../errors';
import type { AuthContext, PublicUser } from '../types';

export interface State {
  auth?: AuthContext;
  user?: PublicUser;
  [key: string]: unknown;
}

export interface ContextOptions {
  maxBodyBytes: number;
  trustProxy: boolean;
}

export type Next = () => Promise<void>;
export type Handler = (ctx: Context, next: Next) => Promise<void> | void;

// BigInt (mis. dari Prisma) tidak bisa di-JSON.stringify secara bawaan
const replacer = (_k: string, v: unknown): unknown =>
  typeof v === 'bigint' ? (Number.isSafeInteger(Number(v)) ? Number(v) : v.toString()) : v;

export class Context {
  readonly req: IncomingMessage;
  readonly res: ServerResponse;
  readonly method: string;
  readonly path: string;
  readonly query: URLSearchParams;
  readonly badUrl: boolean;
  params: Record<string, string> = {};
  readonly state: State = {};
  private readonly opts: ContextOptions;
  private bodyCache: Record<string, unknown> | undefined;

  constructor(req: IncomingMessage, res: ServerResponse, opts: ContextOptions) {
    this.req = req;
    this.res = res;
    this.opts = opts;
    this.method = (req.method ?? 'GET').toUpperCase();

    let path = '/';
    let query = new URLSearchParams();
    let bad = false;
    try {
      const url = new URL(req.url ?? '/', 'http://localhost');
      path = url.pathname.length > 1 ? url.pathname.replace(/\/+$/, '') || '/' : url.pathname;
      query = url.searchParams;
    } catch {
      bad = true;
    }
    this.path = path;
    this.query = query;
    this.badUrl = bad;
  }

  /** Nilai header (huruf kecil/besar bebas). */
  header(name: string): string | undefined {
    const v = this.req.headers[name.toLowerCase()];
    return Array.isArray(v) ? v[0] : v;
  }

  /** IP client. X-Forwarded-For hanya dipercaya jika trustProxy aktif. */
  get ip(): string {
    if (this.opts.trustProxy) {
      const xff = this.header('x-forwarded-for');
      if (xff) return xff.split(',')[0].trim();
    }
    return this.req.socket.remoteAddress ?? 'unknown';
  }

  setHeader(name: string, value: string): void {
    if (!this.res.headersSent) this.res.setHeader(name, value);
  }

  /** Baca body JSON (harus object). Dibatasi ukurannya & wajib Content-Type: application/json. */
  async readJson(): Promise<Record<string, unknown>> {
    if (this.bodyCache) return this.bodyCache;
    const max = this.opts.maxBodyBytes;

    const declared = Number(this.header('content-length') ?? 0);
    if (declared > max) {
      this.setHeader('Connection', 'close');
      throw new HttpError('Body request terlalu besar', 413, 'PAYLOAD_TOO_LARGE');
    }

    const chunks: Buffer[] = [];
    let size = 0;
    for await (const chunk of this.req) {
      const buf = chunk as Buffer;
      size += buf.length;
      if (size > max) {
        this.setHeader('Connection', 'close');
        throw new HttpError('Body request terlalu besar', 413, 'PAYLOAD_TOO_LARGE');
      }
      chunks.push(buf);
    }

    if (size === 0) return (this.bodyCache = {});

    if (!/^application\/json\b/i.test(this.header('content-type') ?? '')) {
      throw new HttpError('Content-Type harus application/json', 415, 'UNSUPPORTED_MEDIA_TYPE');
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    } catch {
      throw new HttpError('Body request bukan JSON yang valid', 400, 'INVALID_JSON');
    }
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new HttpError('Body request harus berupa object JSON', 400, 'INVALID_JSON');
    }
    return (this.bodyCache = parsed as Record<string, unknown>);
  }

  /** Kirim respons JSON. Token tidak boleh di-cache, jadi selalu no-store. */
  json(status: number, data: unknown): void {
    if (this.res.headersSent) return;
    const body = JSON.stringify(data, replacer);
    this.res.writeHead(status, {
      'Content-Type': 'application/json; charset=utf-8',
      'Content-Length': Buffer.byteLength(body),
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
    });
    this.res.end(body);
  }
}
