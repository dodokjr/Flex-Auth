import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { signJwt, verifyJwt, JwtError } from '../src/core/jwt';
import { PasswordHasher } from '../src/core/password';
import { toSeconds } from '../src/utils/duration';

const SECRET = 'a'.repeat(40);

test('JWT: sign & verify', () => {
  const t = signJwt({ email: 'a@b.c' }, SECRET, { expiresIn: '15m', subject: 'u1', jwtid: 'j1' });
  const p = verifyJwt(t, SECRET);
  assert.equal(p.sub, 'u1');
  assert.equal(p.jti, 'j1');
  assert.equal(p.email, 'a@b.c');
  assert.ok((p.exp as number) - (p.iat as number) === 900);
});

test('JWT: secret salah, payload diubah, alg none, dan token rusak ditolak', () => {
  const t = signJwt({ role: 'user' }, SECRET, { expiresIn: 60, subject: 'u1' });
  assert.throws(() => verifyJwt(t, 'b'.repeat(40)), (e) => e instanceof JwtError && e.reason === 'invalid');

  const [h, p, s] = t.split('.');
  const evil = Buffer.from(JSON.stringify({ ...JSON.parse(Buffer.from(p, 'base64url').toString()), role: 'admin' })).toString('base64url');
  assert.throws(() => verifyJwt(`${h}.${evil}.${s}`, SECRET), JwtError);

  const none = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
  assert.throws(() => verifyJwt(`${none}.${p}.`, SECRET), JwtError);
  assert.throws(() => verifyJwt(`${none}.${p}.${s}`, SECRET), JwtError);

  const wrongTyp = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'NOT-JWT' })).toString('base64url');
  const wrongTypSig = createHmac('sha256', SECRET).update(`${wrongTyp}.${p}`).digest('base64url');
  assert.throws(() => verifyJwt(`${wrongTyp}.${p}.${wrongTypSig}`, SECRET), JwtError);

  // alg lain (HS512) dengan tanda tangan "benar" tetap ditolak
  const h512 = Buffer.from(JSON.stringify({ alg: 'HS512', typ: 'JWT' })).toString('base64url');
  const sig = createHmac('sha512', SECRET).update(`${h512}.${p}`).digest('base64url');
  assert.throws(() => verifyJwt(`${h512}.${p}.${sig}`, SECRET), JwtError);

  for (const bad of ['', 'abc', 'a.b', 'a.b.c.d', null, undefined, 123]) {
    assert.throws(() => verifyJwt(bad, SECRET), JwtError);
  }
});

test('JWT: kedaluwarsa dibedakan dari tidak valid', async () => {
  const t = signJwt({}, SECRET, { expiresIn: 1, subject: 'u' });
  await new Promise((r) => setTimeout(r, 2100));
  assert.throws(() => verifyJwt(t, SECRET), (e) => e instanceof JwtError && e.reason === 'expired');
});

test('Password: hash, verify, salt unik, parameter rusak ditolak', async () => {
  const h = new PasswordHasher({ cost: 4096 });
  const a = await h.hash('rahasia-banget');
  const b = await h.hash('rahasia-banget');
  assert.notEqual(a, b);
  assert.ok(a.startsWith('scrypt$4096$8$1$'));
  assert.equal(await h.verify('rahasia-banget', a), true);
  assert.equal(await h.verify('salah', a), false);
  assert.equal(await h.verify('x', 'bukan-hash'), false);
  assert.equal(await h.verify('x', 'scrypt$999999999$8$1$AAAAAAAAAAA=$AAAAAAAAAAAAAAAAAAAAAA=='), false);
  assert.throws(() => new PasswordHasher({ cost: 1000 }));
  const bounded = new PasswordHasher({ cost: 4096, maxLength: 8 });
  await assert.rejects(() => bounded.hash('password-terlalu-panjang'));
  assert.equal(await bounded.verify('password-terlalu-panjang', a), false);
});

test('Durasi', () => {
  assert.equal(toSeconds('15m'), 900);
  assert.equal(toSeconds('7d'), 604800);
  assert.equal(toSeconds(30), 30);
  assert.throws(() => toSeconds('abc'));
  assert.throws(() => toSeconds(-1));
  assert.throws(() => toSeconds(0.5));
});
