import type { AuthService } from '../core/AuthService';
import type { PublicUser, UserRecord } from '../types';
import type { Context } from './context';
import { rateLimit, type RateLimitOptions } from './middleware';
import { Router } from './router';

export interface AuthRouterOptions<U extends UserRecord> {
  /** Isi data dashboard Anda sendiri. */
  dashboard?: (user: PublicUser<U>, ctx: Context) => Promise<unknown> | unknown;
  /**
   * Rate limit bawaan per IP. false = matikan semua (mis. jika sudah ada di gateway).
   * Default: 10 request/menit untuk register, login, dan otp (verify/resend).
   */
  rateLimit?: false | {
    register?: RateLimitOptions | false;
    login?: RateLimitOptions | false;
    otp?: RateLimitOptions | false;
    refresh?: RateLimitOptions | false;
  };
}

export function createAuthRouter<U extends UserRecord>(
  auth: AuthService<U>,
  options: AuthRouterOptions<U> = {},
): Router {
  const router = new Router();
  const rl = options.rateLimit;
  const limiter = (kind: 'register' | 'login' | 'otp' | 'refresh') => {
    if (rl === false) return [];
    const cfg = rl?.[kind];
    return cfg === false ? [] : [rateLimit(cfg ?? {})];
  };

  const dashboardHandler =
    options.dashboard ??
    ((user: PublicUser<U>) => ({ message: `Selamat datang, ${user.name ?? user.email}!` }));

  router.post('/register', ...limiter('register'), async (ctx) => {
    ctx.json(201, { success: true, data: await auth.register(await ctx.readJson()) });
  });

  router.post('/login', ...limiter('login'), async (ctx) => {
    ctx.json(200, { success: true, data: await auth.login(await ctx.readJson()) });
  });

  const otpLimit = limiter('otp');
  router.post('/verify-otp', ...otpLimit, async (ctx) => {
    ctx.json(200, { success: true, data: await auth.verifyOtp(await ctx.readJson()) });
  });

  router.post('/resend-otp', ...limiter('otp'), async (ctx) => {
    ctx.json(200, { success: true, data: await auth.resendOtp(await ctx.readJson()) });
  });

  router.post('/refresh', ...limiter('refresh'), async (ctx) => {
    ctx.json(200, { success: true, data: await auth.refresh(await ctx.readJson()) });
  });

  router.post('/logout', async (ctx) => {
    ctx.json(200, { success: true, data: await auth.logout(await ctx.readJson()) });
  });

  router.post('/logout-all', auth.authenticate(), async (ctx) => {
    ctx.json(200, { success: true, data: await auth.logoutAll(ctx.state.auth!.userId) });
  });

  router.get('/me', auth.authenticate({ loadUser: true }), (ctx) => {
    ctx.json(200, { success: true, data: ctx.state.user });
  });

  router.get('/dashboard', auth.authenticate({ loadUser: true }), async (ctx) => {
    const data = await dashboardHandler(ctx.state.user as unknown as PublicUser<U>, ctx);
    ctx.json(200, { success: true, data });
  });

  return router;
}
