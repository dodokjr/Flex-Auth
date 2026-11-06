import { HttpError } from '../errors';
import type { Handler } from './context';

interface Route {
  method: string;
  segments: string[];
  handlers: Handler[];
}

const split = (p: string): string[] => p.split('/').filter(Boolean);

function matchSegments(pattern: string[], actual: string[]): Record<string, string> | null {
  if (pattern.length !== actual.length) return null;
  const params: Record<string, string> = {};
  for (let i = 0; i < pattern.length; i++) {
    if (pattern[i].startsWith(':')) {
      try {
        params[pattern[i].slice(1)] = decodeURIComponent(actual[i]);
      } catch {
        throw new HttpError('Parameter URL tidak valid', 400, 'BAD_REQUEST');
      }
    } else if (pattern[i] !== actual[i]) {
      return null;
    }
  }
  return params;
}

export class Router {
  private readonly routes: Route[] = [];
  private readonly middleware: Handler[] = [];

  /** Middleware yang dijalankan sebelum handler route milik router ini. */
  use(...handlers: Handler[]): this {
    this.middleware.push(...handlers);
    return this;
  }

  get(path: string, ...handlers: Handler[]): this { return this.add('GET', path, handlers); }
  post(path: string, ...handlers: Handler[]): this { return this.add('POST', path, handlers); }
  put(path: string, ...handlers: Handler[]): this { return this.add('PUT', path, handlers); }
  patch(path: string, ...handlers: Handler[]): this { return this.add('PATCH', path, handlers); }
  delete(path: string, ...handlers: Handler[]): this { return this.add('DELETE', path, handlers); }

  private add(method: string, path: string, handlers: Handler[]): this {
    if (!path.startsWith('/')) throw new Error(`Path route harus diawali "/": ${path}`);
    if (!handlers.length) throw new Error(`Route ${method} ${path} butuh minimal 1 handler`);
    this.routes.push({ method, segments: split(path), handlers });
    return this;
  }

  /** Dipanggil App.use(prefix, router). */
  handler(prefix = ''): Handler {
    const base = prefix.replace(/\/+$/, '');
    return async (ctx, next) => {
      if (base && ctx.path !== base && !ctx.path.startsWith(`${base}/`)) return next();
      const actual = split(ctx.path.slice(base.length));

      const allowed = new Set<string>();
      for (const route of this.routes) {
        const params = matchSegments(route.segments, actual);
        if (!params) continue;
        if (route.method !== ctx.method) {
          allowed.add(route.method);
          continue;
        }
        ctx.params = params;
        return run([...this.middleware, ...route.handlers], ctx, next);
      }
      if (allowed.size) {
        throw new HttpError('Method tidak diizinkan', 405, 'METHOD_NOT_ALLOWED', {
          Allow: [...allowed].join(', '),
        });
      }
      return next();
    };
  }
}

function run(handlers: Handler[], ctx: Parameters<Handler>[0], done: Parameters<Handler>[1]): Promise<void> {
  let index = -1;
  const dispatch = async (i: number): Promise<void> => {
    if (i <= index) throw new Error('next() dipanggil lebih dari sekali');
    index = i;
    const h = handlers[i];
    if (!h) return done();
    await h(ctx, () => dispatch(i + 1));
  };
  return dispatch(0);
}
