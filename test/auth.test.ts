import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import type { Server } from 'node:http';
import { App, Router, adapters, createAuth, createAuthRouter, cors } from '../src';

const JWT = { accessSecret: 'A'.repeat(40), refreshSecret: 'B'.repeat(40), accessExpiresIn: 900 };

let server: Server;
let base: string;
let lastOtp = '';
const auth = createAuth({
  adapter: adapters.createMemoryAdapter(),
  jwt: JWT,
  password: { cost: 4096 },
  otp: { resendCooldownSeconds: 0, send: ({ code }) => { lastOtp = code; } },
});

before(async () => {
  const app = new App();
  app.use(cors({ origins: ['http://front.test'] }));
  app.use('/auth', createAuthRouter(auth, { rateLimit: false }));
  const admin = new Router();
  admin.get('/', auth.authenticate(), auth.authorize('admin'), (ctx) => ctx.json(200, { ok: true }));
  admin.get('/items/:id', (ctx) => ctx.json(200, { id: ctx.params.id }));
  app.use('/admin', admin);
  server = await app.listen(0, '127.0.0.1');
  base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
});
after(() => { server.closeAllConnections(); server.close(); });

async function call(method: string, path: string, body?: unknown, token?: string, extra: Record<string, string> = {}) {
  const res = await fetch(base + path, {
    method,
    headers: {
      ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...extra,
    },
    body: body === undefined ? undefined : typeof body === 'string' ? body : JSON.stringify(body),
  });
  const json = (await res.json().catch(() => null)) as any;
  return { status: res.status, json, headers: res.headers };
}

const user = { email: 'Budi@Example.com', password: 'rahasia123', name: 'Budi' };
let tokens: { accessToken: string; refreshToken: string };

test('register -> 201 + OTP dikirim, password tidak bocor', async () => {
  const r = await call('POST', '/auth/register', user);
  assert.equal(r.status, 201);
  assert.equal(r.json.data.otpRequired, true);
  assert.equal(r.json.data.user.email, 'budi@example.com');
  assert.equal(r.json.data.user.passwordHash, undefined);
  assert.equal(r.json.data.user.isVerified, false);
  assert.match(lastOtp, /^\d{6}$/);
  assert.equal(r.headers.get('cache-control'), 'no-store');
});

test('register ganda -> 409, validasi -> 400', async () => {
  assert.equal((await call('POST', '/auth/register', user)).json.code, 'EMAIL_EXISTS');
  assert.equal((await call('POST', '/auth/register', { ...user, email: 'x' })).json.code, 'INVALID_EMAIL');
  assert.equal((await call('POST', '/auth/register', { email: 'z@z.com', password: '123' })).json.code, 'WEAK_PASSWORD');
  assert.equal((await call('POST', '/auth/register', { email: 'z@z.com', password: 'x'.repeat(200) })).json.code, 'PASSWORD_TOO_LONG');
});

test('login sebelum verifikasi -> minta OTP lagi (tanpa token)', async () => {
  const r = await call('POST', '/auth/login', { email: user.email, password: user.password });
  assert.equal(r.status, 200);
  assert.equal(r.json.data.otpRequired, true);
  assert.equal(r.json.data.accessToken, undefined);
});

test('OTP salah -> 400, format salah -> 400, OTP benar -> token', async () => {
  const wrong = lastOtp === '000000' ? '111111' : '000000';
  assert.equal((await call('POST', '/auth/verify-otp', { email: user.email, code: wrong })).json.code, 'OTP_INVALID');
  assert.equal((await call('POST', '/auth/verify-otp', { email: user.email, code: 'abc' })).json.code, 'INVALID_OTP_FORMAT');
  const ok = await call('POST', '/auth/verify-otp', { email: user.email, code: lastOtp });
  assert.equal(ok.status, 200);
  assert.equal(ok.json.data.user.isVerified, true);
  tokens = ok.json.data;
  // OTP sekali pakai
  assert.equal((await call('POST', '/auth/verify-otp', { email: user.email, code: lastOtp })).json.code, 'OTP_NOT_FOUND');
});

test('login benar -> token; salah -> 401', async () => {
  const ok = await call('POST', '/auth/login', { email: user.email, password: user.password });
  assert.equal(ok.status, 200);
  assert.ok(ok.json.data.accessToken);
  assert.equal(ok.json.data.tokenType, 'Bearer');
  const bad = await call('POST', '/auth/login', { email: user.email, password: 'salah-banget' });
  assert.equal(bad.status, 401);
  assert.equal(bad.json.code, 'INVALID_CREDENTIALS');
  const none = await call('POST', '/auth/login', { email: 'nope@x.com', password: 'whatever123' });
  assert.equal(none.json.code, 'INVALID_CREDENTIALS');
});

test('dashboard & me: 200 dengan token, 401 tanpa/invalid token', async () => {
  const d = await call('GET', '/auth/dashboard', undefined, tokens.accessToken);
  assert.equal(d.status, 200);
  assert.match(d.json.data.message, /Budi/);
  const me = await call('GET', '/auth/me', undefined, tokens.accessToken);
  assert.equal(me.json.data.email, 'budi@example.com');
  assert.equal(me.json.data.passwordHash, undefined);
  assert.equal((await call('GET', '/auth/me')).json.code, 'NO_TOKEN');
  assert.equal((await call('GET', '/auth/me', undefined, 'abc.def.ghi')).json.code, 'INVALID_TOKEN');
  // refresh token tidak boleh dipakai sebagai access token
  assert.equal((await call('GET', '/auth/me', undefined, tokens.refreshToken)).status, 401);
});

test('403 untuk role yang tidak cocok; params route', async () => {
  assert.equal((await call('GET', '/admin', undefined, tokens.accessToken)).status, 403);
  assert.equal((await call('GET', '/admin/items/a%20b')).json.id, 'a b');
});

test('refresh: rotasi, pemakaian ulang mencabut semua sesi', async () => {
  const r1 = await call('POST', '/auth/refresh', { refreshToken: tokens.refreshToken });
  assert.equal(r1.status, 200);
  const next = r1.json.data;
  assert.notEqual(next.refreshToken, tokens.refreshToken);

  const reuse = await call('POST', '/auth/refresh', { refreshToken: tokens.refreshToken });
  assert.equal(reuse.status, 401);
  assert.equal(reuse.json.code, 'REFRESH_TOKEN_REUSED');

  // token "baru" ikut tercabut
  assert.equal((await call('POST', '/auth/refresh', { refreshToken: next.refreshToken })).json.code, 'REFRESH_TOKEN_REUSED');
  assert.equal((await call('POST', '/auth/refresh', { refreshToken: 'ngawur' })).json.code, 'INVALID_REFRESH_TOKEN');
});

test('logout & logout-all', async () => {
  const login = (await call('POST', '/auth/login', { email: user.email, password: user.password })).json.data;
  assert.equal((await call('POST', '/auth/logout', { refreshToken: login.refreshToken })).status, 200);
  assert.equal((await call('POST', '/auth/refresh', { refreshToken: login.refreshToken })).json.code, 'REFRESH_TOKEN_REUSED');

  const a = (await call('POST', '/auth/login', { email: user.email, password: user.password })).json.data;
  const b = (await call('POST', '/auth/login', { email: user.email, password: user.password })).json.data;
  assert.equal((await call('POST', '/auth/logout-all', undefined, a.accessToken)).status, 200);
  assert.equal((await call('POST', '/auth/refresh', { refreshToken: b.refreshToken })).status, 401);
});

test('status HTTP: 404, 405, 400 JSON rusak, 415, 413', async () => {
  const nf = await call('GET', '/tidak/ada');
  assert.equal(nf.status, 404);
  assert.equal(nf.json.code, 'NOT_FOUND');

  const mna = await call('GET', '/auth/login');
  assert.equal(mna.status, 405);
  assert.equal(mna.headers.get('allow'), 'POST');

  assert.equal((await call('POST', '/auth/login', '{rusak')).json.code, 'INVALID_JSON');
  assert.equal((await call('POST', '/auth/login', '[1,2]')).json.code, 'INVALID_JSON');

  const ct = await fetch(`${base}/auth/login`, { method: 'POST', headers: { 'Content-Type': 'text/plain' }, body: 'halo' });
  assert.equal(ct.status, 415);

  const big = await call('POST', '/auth/login', { email: 'a@b.com', password: 'x'.repeat(40_000) });
  assert.equal(big.status, 413);
  assert.equal(big.json.code, 'PAYLOAD_TOO_LARGE');
});

test('CORS: origin diizinkan/tidak, preflight 204', async () => {
  const pre = await fetch(`${base}/auth/login`, {
    method: 'OPTIONS',
    headers: { Origin: 'http://front.test', 'Access-Control-Request-Method': 'POST' },
  });
  assert.equal(pre.status, 204);
  assert.equal(pre.headers.get('access-control-allow-origin'), 'http://front.test');

  const evil = await fetch(`${base}/auth/me`, { headers: { Origin: 'http://evil.test' } });
  assert.equal(evil.headers.get('access-control-allow-origin'), null);
});

test('2FA saat login (requireOnLogin) dan tanpa OTP', async () => {
  let code = '';
  const a2 = createAuth({
    adapter: adapters.createMemoryAdapter(), jwt: JWT, password: { cost: 4096 },
    otp: { requireOnLogin: true, send: (p) => { code = p.code; } },
  });
  await a2.register({ email: 'a@a.com', password: 'password123' });
  await a2.verifyOtp({ email: 'a@a.com', code });
  const step1 = await a2.login({ email: 'a@a.com', password: 'password123' });
  assert.ok('otpRequired' in step1 && step1.purpose === 'login');
  const step2 = await a2.verifyOtp({ email: 'a@a.com', code, purpose: 'login' });
  assert.ok(step2.accessToken);

  const a3 = createAuth({ adapter: adapters.createMemoryAdapter(), jwt: JWT, password: { cost: 4096 }, otp: { enabled: false } });
  const reg = await a3.register({ email: 'b@b.com', password: 'password123' });
  assert.ok('accessToken' in reg && reg.user.isVerified === true);
});

test('OTP: percobaan dibatasi, kedaluwarsa ditolak', async () => {
  let code = '';
  const a = createAuth({
    adapter: adapters.createMemoryAdapter(), jwt: JWT, password: { cost: 4096 },
    otp: { maxAttempts: 2, send: (p) => { code = p.code; } },
  });
  await a.register({ email: 'c@c.com', password: 'password123' });
  const wrong = code === '123456' ? '654321' : '123456';
  for (let i = 0; i < 2; i++) await assert.rejects(a.verifyOtp({ email: 'c@c.com', code: wrong }), { code: 'OTP_INVALID' });
  await assert.rejects(a.verifyOtp({ email: 'c@c.com', code }), { code: 'OTP_TOO_MANY_ATTEMPTS' });
});

test('konfigurasi tidak aman ditolak saat startup', () => {
  const mem = adapters.createMemoryAdapter();
  assert.throws(() => createAuth({ adapter: mem, jwt: { accessSecret: 'pendek', refreshSecret: 'pendek2' } }), /32/);
  assert.throws(() => createAuth({ adapter: mem, jwt: { accessSecret: 'A'.repeat(40), refreshSecret: 'A'.repeat(40) } }), /berbeda/);
  assert.throws(() => createAuth({ adapter: mem, jwt: JWT, userFields: ['role'] }), /field sistem/);
  assert.throws(() => createAuth({ adapter: mem, jwt: { ...JWT, accessExpiresIn: 'sebentar' } }), /tidak valid/);
});

test('rate limit bawaan: 429 + Retry-After', async () => {
  const a = createAuth({ adapter: adapters.createMemoryAdapter(), jwt: JWT, password: { cost: 4096 }, otp: { send: () => {} } });
  const app = new App();
  app.use('/auth', createAuthRouter(a, { rateLimit: { login: { max: 3, windowMs: 60_000 } } }));
  const s = await app.listen(0, '127.0.0.1');
  const url = `http://127.0.0.1:${(s.address() as { port: number }).port}/auth/login`;
  const statuses: number[] = [];
  let retryAfter: string | null = null;
  for (let i = 0; i < 5; i++) {
    const r = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email: 'x@x.com', password: 'whatever123' }) });
    statuses.push(r.status);
    if (r.status === 429) retryAfter = r.headers.get('retry-after');
    await r.arrayBuffer();
  }
  s.closeAllConnections(); s.close();
  assert.deepEqual(statuses, [401, 401, 401, 429, 429]);
  assert.ok(Number(retryAfter) > 0);
});
