import { AuthError } from '../errors';
import type { AuthService } from '../core/AuthService';
import type { PublicUser, UserRecord } from '../types';
import type { Handler } from './context';

export interface AuthenticateOptions {
  /** true = ambil data user dari storage dan taruh di ctx.state.user */
  loadUser?: boolean;
}

export function createAuthenticate<U extends UserRecord>(
  auth: AuthService<U>,
  options: AuthenticateOptions = {},
): Handler {
  return async (ctx, next) => {
    const match = /^Bearer\s+([^\s]+)$/i.exec(ctx.header('authorization') ?? '');
    const token = match?.[1];
    if (!token) throw new AuthError('Token tidak ditemukan', 401, 'NO_TOKEN');

    const payload = auth.verifyAccessToken(token);
    ctx.state.auth = { userId: payload.sub, email: payload.email, role: payload.role };
    if (options.loadUser) ctx.state.user = (await auth.getProfile(payload.sub)) as unknown as PublicUser;
    await next();
  };
}

export function createAuthorize(...roles: string[]): Handler {
  return async (ctx, next) => {
    const role = ctx.state.auth?.role;
    if (!role || (roles.length > 0 && !roles.includes(role))) {
      throw new AuthError('Akses ditolak', 403, 'FORBIDDEN');
    }
    await next();
  };
}
