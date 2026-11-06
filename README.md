# flex-auth v2 — zero dependency

Framework auth Node.js + TypeScript yang **tidak memakai library/framework lain**. Semuanya dibangun di atas modul bawaan Node.js.

| Dulu (v1) | Sekarang (v2, buatan sendiri) |
|---|---|
| Express | `App`, `Router`, `Context` di atas `node:http` |
| jsonwebtoken | JWT HS256 sendiri (`node:crypto` HMAC) |
| bcryptjs | `scrypt` (`node:crypto`) |
| googleapis | Sheets REST API lewat `fetch` + tanda tangan RS256 service account |
| dotenv | `process.loadEnvFile()` |
| express-rate-limit | `rateLimit()` bawaan |

`package.json` hanya punya devDependencies: `typescript` dan `@types/node`. Butuh **Node >= 20.6**.

Fitur: register, login, OTP, JWT access token, refresh token (rotasi + deteksi pemakaian ulang), logout, dashboard terproteksi, CORS, dan rate limit. Storage bebas: Database atau Google Sheets.

## Jalankan

```bash
npm install            # hanya typescript + @types/node
# Atur AuthPage/Jwt.ts: pilih mode 'import' atau 'env'
npm test               # build + 23 tes (JWT, password, HTTP, OTP, Google Sheets tiruan)
npm start              # build + jalankan example/server.ts
# Mode env: isi .env, pilih 'env' di AuthPage/Jwt.ts; file dimuat tanpa dotenv
```

## Konfigurasi JWT: Import atau ENV (tanpa dotenv)

Atur `JWT_SECRET_SOURCE` di `AuthPage/Jwt.ts`:

- `import`: isi `IMPORT_JWT_ACCESS` dan `IMPORT_JWT_REFRESH` dengan secret acak minimal 32 karakter. Jika masih placeholder saat development, contoh server membuat secret sementara acak agar `npm start` bisa dicoba; token tidak berlaku setelah restart. Dalam `NODE_ENV=production`, placeholder tetap ditolak.
- `env`: set `JWT_SECRET_SOURCE` ke `'env'`, lalu isi `JWT_ACCESS_SECRET` dan `JWT_REFRESH_SECRET` pada environment deployment atau `.env`. Modul mencoba memuat `.env` memakai `process.loadEnvFile()` bawaan Node (Node >=20.12) jika tersedia; tidak memakai `dotenv`. Pada platform deployment, isi environment variables langsung di dashboard platform.

Kedua mode mengekspor nama yang sama sehingga kode aplikasi tetap: `import { JWT_Access, JWT_Refresh } from '../AuthPage/Jwt'`. Access dan refresh secret wajib berbeda. Jangan pernah commit secret asli ke repository publik. File `AuthPage/Jwt.ts` dalam ZIP ini hanya berisi placeholder; sebelum mengisi secret sungguhan, siapkan file lokal yang tidak dilacak Git atau pilih mode `env`.

## Pemakaian

```ts
import { App, createAuth, createAuthRouter, adapters } from 'flex-auth';
import { JWT_Access, JWT_Refresh } from './AuthPage/Jwt';

const auth = createAuth({
  adapter: adapters.memoryAdapter(),              // ganti sesuai storage (lihat bawah)
  jwt: {
    accessSecret: JWT_Access,   // dari AuthPage/Jwt.ts
    refreshSecret: JWT_Refresh, // dari AuthPage/Jwt.ts
    accessExpiresIn: '15m',
    refreshExpiresIn: '7d',
  },
  otp: { send: async ({ email, code }) => { /* kirim email / WhatsApp / SMS */ } },
});

const app = new App();
app.use('/auth', createAuthRouter(auth, {
  dashboard: async (user) => ({ message: `Halo ${user.name}` }),
}));
await app.listen(3000);
```

## Storage — pilih adapter tanpa `create*`

Pilih adapter berdasarkan database yang sudah Anda siapkan. Tidak perlu memanggil `createSheetsAdapter()` atau `createDatabaseAdapter()` lagi:

```ts
import { adapters } from 'flex-auth';
import { getGoogleSheetsConfig } from './AuthPage/GoogleSheets';

// Google Sheets
const sheets = adapters.googleSheetsAdapter(getGoogleSheetsConfig());

// Database SQL / ORM: berikan repository dari Sequelize, Prisma, atau driver Anda
const mysql = adapters.dbMysqlAdapter({ users, refreshTokens, otps });
const postgres = adapters.dbPostgreSQL({ users, refreshTokens, otps });

// MongoDB: berikan repository dari Mongoose / MongoDB driver Anda
const mongo = adapters.dbMongoDB({ users, refreshTokens, otps });

// Adapter database generik
const customDb = adapters.dbAdapter({ users, refreshTokens, otps });
```

`dbMysqlAdapter`, `dbPostgreSQL`, `dbMongoDB`, dan `dbAdapter` menerima tiga repository (`users`, `refreshTokens`, `otps`) yang sudah terhubung ke database. Nama adapter tersebut adalah pemilih/validator kontrak Flex Auth, **bukan driver database otomatis**; instal dan konfigurasi driver/ORM database yang Anda pilih. Helper `fromSequelize`, `fromPrisma`, dan `fromMongoose` membantu mengubah model ORM menjadi repository. Alias lama `createMemoryAdapter`, `createSheetsAdapter`, dan `createDatabaseAdapter` tetap tersedia demi kompatibilitas.

## Storage

### Google Sheets

Google Sheets membutuhkan tiga nilai: `spreadsheetId`, `clientEmail` (Service Account), dan `privateKey` (PEM). Ketiganya diberikan sekaligus pada `googleSheetsAdapter` melalui `getGoogleSheetsConfig()`:

```ts
import { getGoogleSheetsConfig } from './AuthPage/GoogleSheets';

const adapter = adapters.googleSheetsAdapter(getGoogleSheetsConfig());
```

Konfigurasi ada di `AuthPage/GoogleSheets.ts` dan mendukung dua mode:

**Mode import (tanpa `.env`)** — biarkan `GOOGLE_SHEETS_SOURCE = 'import'`, lalu isi `IMPORT_SPREADSHEET_ID`, `IMPORT_CLIENT_EMAIL`, dan `IMPORT_PRIVATE_KEY` di file tersebut.

**Mode ENV** — ubah `GOOGLE_SHEETS_SOURCE = 'env'`, lalu isi:

```env
GOOGLE_SPREADSHEET_ID=ID_SPREADSHEET_ANDA
GOOGLE_CLIENT_EMAIL=service-account@project-id.iam.gserviceaccount.com
GOOGLE_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\nISI_KEY_ANDA\n-----END PRIVATE KEY-----\n"
```

Tidak membutuhkan `dotenv`; pada Node yang mendukung `process.loadEnvFile()`, file `.env` dimuat otomatis. Bisa juga jalankan Node dengan `--env-file=.env`.

1. Google Cloud Console → aktifkan **Google Sheets API** → buat **Service Account** → buat key JSON.
2. Ambil `client_email` dan `private_key` dari file JSON.
3. Buat spreadsheet kosong, lalu **Share** ke email Service Account sebagai **Editor**.
4. ID spreadsheet adalah bagian URL: `docs.google.com/spreadsheets/d/<ID>/edit`.

`getGoogleSheetsConfig()` hanya dipanggil ketika `STORAGE=sheets`, jadi mode memory tidak memerlukan kredensial Google. Jangan commit private key atau kredensial asli ke repository publik.

Tab `users`, `refresh_tokens`, `otps` + header dibuat otomatis. Nilai ditulis dengan mode `RAW` sehingga tidak bisa jadi formula. Access token Google di-cache dan diperbarui otomatis, dan request 429/5xx di-retry.

> Cocok untuk prototipe / skala kecil: ada kuota API Google dan tidak ada transaksi.

### Database

Model harus punya `id` bertipe string dan timestamp **epoch milidetik** (`BIGINT`).

| Tabel | Kolom |
|---|---|
| users | id, email (unique), name, passwordHash, role, isVerified, createdAt, updatedAt |
| refresh_tokens | id, userId, tokenHash, expiresAt, createdAt |
| otps | id, email, purpose, codeHash, attempts, expiresAt, createdAt |

```ts
const adapter = adapters.dbMysqlAdapter({ // atau dbPostgreSQL / dbMongoDB / dbAdapter
  users: adapters.fromSequelize(User),
  refreshTokens: adapters.fromSequelize(RefreshToken),
  otps: adapters.fromSequelize(Otp),
});
```

Helper ORM tidak menambah dependency (parameter bertipe `any`). Untuk knex / SQL mentah, implementasikan `Repository<T>`:

```ts
import type { Repository, UserRecord } from 'flex-auth';

const usersRepo: Repository<UserRecord> = {
  async create(data) { /* insert, return row */ return data; },
  async findOne(where) { /* where = { email: '...' } -> row | null */ return null; },
  async update(where, data) { /* update semua yang cocok */ },
  async delete(where) { /* hapus semua yang cocok */ },
};
```

### Field tambahan di user

```ts
interface MyUser extends UserRecord { phone?: string }

const adapter = adapters.googleSheetsAdapter<MyUser>({
  spreadsheetId,
  columns: { users: ['id','email','name','phone','passwordHash','role','isVerified','createdAt','updatedAt'] },
});
const auth = createAuth<MyUser>({ adapter, jwt, userFields: ['name', 'phone'] });
```

## Endpoint

| Method | Path | Body | Keterangan |
|---|---|---|---|
| POST | /auth/register | email, password, name | Buat akun, kirim OTP |
| POST | /auth/verify-otp | email, code, purpose? | Verifikasi OTP → token |
| POST | /auth/resend-otp | email | Kirim ulang OTP register |
| POST | /auth/login | email, password | Token, atau `otpRequired` bila belum verifikasi / 2FA |
| POST | /auth/refresh | refreshToken | Token baru (refresh token dirotasi) |
| POST | /auth/logout | refreshToken | Cabut 1 sesi |
| POST | /auth/logout-all | – (Bearer) | Cabut semua sesi |
| GET | /auth/me | – (Bearer) | Profil |
| GET | /auth/dashboard | – (Bearer) | Data dashboard (kustom) |

Alur: `register → verify-otp (dapat token) → login → dashboard dengan Authorization: Bearer <accessToken> → saat code TOKEN_EXPIRED panggil /refresh`.

## Status HTTP & kode error

Respons: `{ success: true, data }` atau `{ success: false, code, message }`. Semua respons `no-store`.

| Status | Kapan | `code` |
|---|---|---|
| 200 / 201 | Berhasil / register berhasil | – |
| 400 | Input tidak valid, OTP salah/kedaluwarsa, JSON rusak | INVALID_EMAIL, WEAK_PASSWORD, PASSWORD_TOO_LONG, OTP_INVALID, INVALID_OTP_FORMAT, OTP_EXPIRED, OTP_NOT_FOUND, INVALID_JSON |
| 401 | Kredensial salah, token tidak ada/invalid/kedaluwarsa, refresh dipakai ulang | INVALID_CREDENTIALS, NO_TOKEN, INVALID_TOKEN, TOKEN_EXPIRED, INVALID_REFRESH_TOKEN, REFRESH_TOKEN_REUSED |
| 403 | Role tidak punya akses | FORBIDDEN |
| 404 | Route/user tidak ada | NOT_FOUND, USER_NOT_FOUND |
| 405 | Method salah (header `Allow` disertakan) | METHOD_NOT_ALLOWED |
| 409 | Email sudah terdaftar | EMAIL_EXISTS |
| 413 / 415 | Body > 16 KB / bukan `application/json` | PAYLOAD_TOO_LARGE, UNSUPPORTED_MEDIA_TYPE |
| 429 | Rate limit / terlalu banyak percobaan OTP | RATE_LIMITED, OTP_TOO_MANY_ATTEMPTS, OTP_COOLDOWN |
| 500 | Error tak terduga (detail hanya di log server) | INTERNAL_ERROR |

301/302 tidak dipakai karena ini API JSON.

## Membuat route sendiri

```ts
import { App, Router, HttpError } from 'flex-auth';

const api = new Router();
api.get('/orders/:id', auth.authenticate(), async (ctx) => {
  const { userId } = ctx.state.auth!;          // dari token
  if (ctx.params.id === '0') throw new HttpError('Order tidak ditemukan', 404, 'ORDER_NOT_FOUND');
  ctx.json(200, { success: true, data: { id: ctx.params.id, userId } });
});
api.post('/orders', auth.authenticate(), auth.authorize('admin'), async (ctx) => {
  const body = await ctx.readJson();           // object JSON, dibatasi ukurannya
  ctx.json(201, { success: true, data: body });
});
app.use('/api', api);
```

`Context`: `ctx.req`, `ctx.res`, `ctx.method`, `ctx.path`, `ctx.query`, `ctx.params`, `ctx.state`, `ctx.ip`, `ctx.header(name)`, `ctx.readJson()`, `ctx.json(status, data)`.
Middleware bentuknya `(ctx, next) => ...`, dipasang dengan `app.use(fn)`. Bawaan: `cors({ origins })` dan `rateLimit({ windowMs, max })`.

Untuk HTTPS: `https.createServer(opts, app.callback())`.

## Opsi `createAuth`

| Opsi | Default | Keterangan |
|---|---|---|
| adapter | – | Wajib. Memory / Database / Sheets |
| jwt.accessSecret, jwt.refreshSecret | – | Wajib, min 32 karakter, harus berbeda |
| jwt.accessExpiresIn / refreshExpiresIn | 15m / 7d | Angka detik atau `'15m'`, `'7d'`, dst. |
| otp.enabled | true | false = tanpa OTP |
| otp.requireOnLogin | false | true = OTP tiap login (2FA) |
| otp.length / ttlMinutes / maxAttempts | 6 / 5 / 5 | length 4–10 |
| otp.resendCooldownSeconds | 60 | |
| otp.send | development-only console | **Wajib di production** bila OTP aktif |
| password.minLength / maxLength | 8 / 128 | maxLength dalam byte |
| password.cost | 32768 | Biaya scrypt (pangkat 2) |
| userFields | ['name'] | Tidak boleh berisi field sistem |
| defaultRole | 'user' | |

`createAuthRouter(auth, { rateLimit })`: default 10 request/menit per IP untuk register, login, dan OTP. `rateLimit: false` untuk mematikan, atau atur per endpoint `{ login: { max: 5, windowMs: 60000 } }`.

## Keamanan

- Password: scrypt + salt acak per user, perbandingan timing-safe, parameter hash tersimpan divalidasi. Waktu respons login tidak membocorkan keberadaan email.
- JWT: hanya HS256 (menolak `alg: none` dan algoritma lain), signature diperiksa sebelum masa berlaku.
- Refresh token dirotasi dan disimpan sebagai hash SHA-256. Jika token lama dipakai lagi, semua sesi user dicabut. Record refresh juga harus cocok dengan `jti`, `sub`, dan waktu kedaluwarsa token.
- OTP di-hash (HMAC), sekali pakai, dengan batas percobaan.
- Production: gunakan database persisten (**bukan** `createMemoryAdapter()`), konfigurasikan `otp.send`, pakai HTTPS, dan set `trustProxy: true` hanya jika berada di belakang reverse proxy tepercaya. Contoh server tidak lagi mencetak OTP dengan sender buatan sendiri; tanpa provider OTP, startup production akan ditolak.
- `rateLimit` bersifat in-memory per proses. Dengan banyak instance, pasang limiter terpusat di gateway.

## Migrasi dari v1

Hash password v1 (bcrypt) **tidak kompatibel** dengan v2 (scrypt), jadi user lama harus reset password atau mendaftar ulang. Token v1 juga tidak berlaku lagi karena secret minimal sekarang 32 karakter.


### Catatan keamanan production (wajib dibaca)

- Buat unique index/constraint pada `users.email`, `refresh_tokens.tokenHash`, dan ID primary key. Cek-lalu-buat pada service tidak menggantikan constraint database saat ada request bersamaan.
- Rate limiter bawaan bersifat in-memory per proses. Di deployment multi-instance/serverless, gunakan rate limiter terpusat (gateway/Redis) untuk membatasi login, register, OTP, dan refresh secara global.
- OTP dan refresh kini diserialisasi per key dalam satu instance proses. Namun Google Sheets dan kontrak repository generik belum menyediakan atomic consume lintas instance. Untuk deployment multi-instance/serverless, race/replay lintas instance masih mungkin; gunakan database dengan transaksi/conditional delete/atomic `find-and-delete` sebelum production sensitif.
- `trustProxy: true` hanya aman jika proxy tepercaya menghapus lalu menulis ulang `X-Forwarded-For`. Jangan aktifkan jika klien dapat mengirim header tersebut langsung.
- Jangan pernah commit `.env`, service-account JSON/private key, JWT secret, token, atau file kredensial. Jika pernah ter-commit/terunggah, revoke/rotate di provider; menghapus file dari commit terbaru tidak menghapus riwayat Git.
- Simpan refresh token di cookie `HttpOnly`, `Secure`, `SameSite` yang sesuai bila arsitektur web memungkinkan. Jika memakai cookie, terapkan perlindungan CSRF. Hindari menyimpan token jangka panjang di `localStorage`.
- Tambahkan unique constraint dan backup untuk database. Gunakan TLS, secret manager, monitoring, dependency scanning, dan rotasi secret berkala.
