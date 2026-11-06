import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { adapters, createAuth, type UserRecord } from '../src';
import { startMockGoogle, type MockGoogle } from './helpers/mockGoogle';

const EMAIL = 'svc@proyek.iam.gserviceaccount.com';
const { publicKey, privateKey } = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});

let mock: MockGoogle;
before(async () => { mock = await startMockGoogle(publicKey, EMAIL); });
after(() => mock.close());

const jwt = { accessSecret: 'A'.repeat(40), refreshSecret: 'B'.repeat(40) };

test('Google Sheets: tab dibuat otomatis + alur register/verify/login/refresh/logout-all', async () => {
  // private key ala .env: satu baris dengan literal \n dan tanda kutip
  const envStyleKey = `"${privateKey.replace(/\n/g, '\\n')}"`;
  const adapter = adapters.createSheetsAdapter({
    spreadsheetId: 'sheet-ID_123', clientEmail: EMAIL, privateKey: envStyleKey,
    apiBase: mock.url, tokenUrl: `${mock.url}/token`,
  });
  let code = '';
  const auth = createAuth({ adapter, jwt, password: { cost: 4096 }, otp: { send: (p) => { code = p.code; } } });

  const reg = await auth.register({ email: 'sheet@x.com', password: 'password123', name: "O'Brien" });
  assert.ok('otpRequired' in reg);

  // tab & header dibuat otomatis
  assert.deepEqual([...mock.sheets.keys()].sort(), ['otps', 'refresh_tokens', 'users']);
  assert.deepEqual(mock.sheets.get('users')!.rows[0], ['id', 'email', 'name', 'passwordHash', 'role', 'isVerified', 'createdAt', 'updatedAt']);
  const row = mock.sheets.get('users')!.rows[1];
  assert.equal(row[1], 'sheet@x.com');
  assert.match(String(row[3]), /^scrypt\$/); // hash, bukan password asli
  assert.equal(row[5], false);

  const verified = await auth.verifyOtp({ email: 'sheet@x.com', code });
  assert.equal(verified.user.isVerified, true);
  assert.equal(mock.sheets.get('users')!.rows[1][5], true); // update tertulis ke sheet
  assert.equal(mock.sheets.get('otps')!.rows.length, 1); // OTP sekali pakai: tersisa header saja
  assert.equal(mock.sheets.get('refresh_tokens')!.rows.length, 2);

  const login = await auth.login({ email: 'sheet@x.com', password: 'password123' });
  assert.ok('accessToken' in login);
  const profile = await auth.getProfile(verified.user.id);
  assert.equal(profile.name, "O'Brien");
  assert.equal(profile.isVerified, true);
  assert.equal(typeof profile.createdAt, 'number');

  // refresh + deteksi pemakaian ulang bekerja di atas Sheets
  const r1 = await auth.refresh({ refreshToken: verified.refreshToken });
  await assert.rejects(auth.refresh({ refreshToken: verified.refreshToken }), { code: 'REFRESH_TOKEN_REUSED' });
  await assert.rejects(auth.refresh({ refreshToken: r1.refreshToken }), { code: 'REFRESH_TOKEN_REUSED' });

  // logout-all menghapus banyak baris sekaligus
  const a = await auth.login({ email: 'sheet@x.com', password: 'password123' });
  const b = await auth.login({ email: 'sheet@x.com', password: 'password123' });
  assert.ok('accessToken' in a && 'accessToken' in b);
  assert.ok(mock.sheets.get('refresh_tokens')!.rows.length >= 3);
  await auth.logoutAll(verified.user.id);
  assert.equal(mock.sheets.get('refresh_tokens')!.rows.length, 1);
});

test('Google Sheets: kolom tambahan (phone) dan field yang tidak terdaftar ditolak', async () => {
  mock.sheets.clear(); // spreadsheet baru
  interface MyUser extends UserRecord { phone?: string }
  const adapter = adapters.createSheetsAdapter<MyUser>({
    spreadsheetId: 'sheet2', clientEmail: EMAIL, privateKey,
    apiBase: mock.url, tokenUrl: `${mock.url}/token`,
    columns: { users: ['id', 'email', 'name', 'phone', 'passwordHash', 'role', 'isVerified', 'createdAt', 'updatedAt'] },
  });
  const auth = createAuth<MyUser>({ adapter, jwt, password: { cost: 4096 }, otp: { enabled: false }, userFields: ['name', 'phone'] });
  const r = await auth.register({ email: 'p@x.com', password: 'password123', phone: '0812' });
  assert.ok('user' in r && r.user?.phone === '0812');
  assert.equal((await auth.getProfile((r as { user: { id: string } }).user.id)).phone, '0812'); // dibaca ulang dari sheet

  mock.sheets.clear();
  const noCol = createAuth({ adapter: adapters.createSheetsAdapter({
    spreadsheetId: 'sheet3', clientEmail: EMAIL, privateKey, apiBase: mock.url, tokenUrl: `${mock.url}/token`,
  }), jwt, password: { cost: 4096 }, otp: { enabled: false }, userFields: ['name', 'phone'] });
  await assert.rejects(noCol.register({ email: 'q@x.com', password: 'password123', phone: '1' }), /Kolom \[phone\]/);
});

test('Google Sheets: kredensial dan konfigurasi salah ditolak', async () => {
  const base = { apiBase: mock.url, tokenUrl: `${mock.url}/token` };
  assert.throws(() => adapters.createSheetsAdapter({ spreadsheetId: 'x', clientEmail: EMAIL, privateKey: 'bukan-pem', ...base }), /PEM/);
  assert.throws(() => adapters.createSheetsAdapter({ spreadsheetId: '../hack', clientEmail: EMAIL, privateKey, ...base }), /tidak valid/);
  assert.throws(() => adapters.createSheetsAdapter({ spreadsheetId: 'x', clientEmail: EMAIL, privateKey, ...base, columns: { users: ['id', 'id'] } }), /duplikat/);

  // service account yang tidak dikenal -> OAuth ditolak dengan pesan jelas
  const bad = adapters.createSheetsAdapter({ spreadsheetId: 'x', clientEmail: 'lain@x.iam', privateKey, ...base });
  const auth = createAuth({ adapter: bad, jwt, password: { cost: 4096 }, otp: { enabled: false } });
  await assert.rejects(auth.register({ email: 'z@x.com', password: 'password123' }), /OAuth gagal/);
});
