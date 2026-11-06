import http, { type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { HttpError } from '../errors';
import { Context, type Handler, type Next } from './context';
import type { Router } from './router';

export function compose(handlers: Handler[]): Handler {
  return (ctx, next) => {
    let index = -1;
    const dispatch = async (i: number): Promise<void> => {
      if (i <= index) throw new Error('next() dipanggil lebih dari sekali');
      index = i;
      const h = handlers[i];
      if (!h) return next();
      await h(ctx, () => dispatch(i + 1));
    };
    return dispatch(0);
  };
}

export interface AppOptions {
  /** Batas ukuran body JSON. Default 16 KB. */
  maxBodyBytes?: number;
  /** Percayai header X-Forwarded-For (aktifkan hanya di belakang reverse proxy tepercaya). */
  trustProxy?: boolean;
  /** Dipanggil untuk error tak terduga (500). Default: console.error. */
  logger?: (err: unknown, ctx: Context) => void;
}

const defaultLogger = (err: unknown, ctx: Context): void =>
  console.error(`[flex-auth] ${ctx.method} ${ctx.path}`, err);

export class App {
  private readonly handlers: Handler[] = [];
  private readonly maxBodyBytes: number;
  private readonly trustProxy: boolean;
  private readonly logger: (err: unknown, ctx: Context) => void;

  constructor(options: AppOptions = {}) {
    this.maxBodyBytes = options.maxBodyBytes ?? 16 * 1024;
    this.trustProxy = options.trustProxy ?? false;
    this.logger = options.logger ?? defaultLogger;
  }

  use(handler: Handler): this;
  use(prefix: string, router: Router): this;
  use(a: Handler | string, b?: Router): this {
    if (typeof a === 'string') {
      if (!b) throw new Error('use(prefix, router): router wajib diisi');
      this.handlers.push(b.handler(a));
    } else {
      this.handlers.push(a);
    }
    return this;
  }

  /** Fungsi (req, res) yang bisa dipasang ke http.createServer / https.createServer. */
  callback(): (req: IncomingMessage, res: ServerResponse) => void {
    const run = compose(this.handlers);
    return (req, res) => {
      const ctx = new Context(req, res, { maxBodyBytes: this.maxBodyBytes, trustProxy: this.trustProxy });
      // Jika respons sudah selesai tapi body belum terbaca penuh (mis. 413), tutup koneksi
      res.once('finish', () => { if (!req.complete) req.destroy(); });

      const notFound: Next = async () => {
        throw new HttpError(`Route ${ctx.method} ${ctx.path} tidak ditemukan`, 404, 'NOT_FOUND');
      };
      Promise.resolve()
        .then(() => {
          if (ctx.badUrl) throw new HttpError('URL tidak valid', 400, 'BAD_REQUEST');
          return run(ctx, notFound);
        })
        .catch((err) => this.handleError(err, ctx));
    };
  }

  private handleError(err: unknown, ctx: Context): void {
    if (ctx.res.headersSent) {
      this.logger(err, ctx);
      ctx.res.destroy();
      return;
    }
    if (err instanceof HttpError) {
      if (err.headers) for (const [k, v] of Object.entries(err.headers)) ctx.setHeader(k, v);
      ctx.json(err.status, { success: false, code: err.code, message: err.message });
      return;
    }
    this.logger(err, ctx);
    ctx.json(500, { success: false, code: 'INTERNAL_ERROR', message: 'Terjadi kesalahan server' });
  }

  /** Jalankan server HTTP. Resolve setelah server benar-benar listening (port 0 = acak). */
  listen(port = 3000, host?: string): Promise<Server> {
    const server = http.createServer(this.callback());
    return new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(port, host, () => {
        server.off('error', reject);
        resolve(server);
      });
    });
  }
}
