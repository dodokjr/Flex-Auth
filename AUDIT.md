# Flex Auth Zero — Audit & Perbaikan

Tanggal audit: 2026-11-06  
Cakupan: source TypeScript, konfigurasi package, contoh server, dokumentasi, dan 23 test yang disertakan.

## Ringkasan

- TypeScript typecheck: **lulus**.
- Build TypeScript: **lulus**.
- Test otomatis: **23/23 lulus**.
- Secret scan pada arsip: **tidak menemukan private key/token/credential live**. Satu-satunya pola private-key adalah placeholder `ISI_KEY_ANDA` di `.env.example`.
- Audit ini bukan pentest eksternal, bukan verifikasi deployment, dan bukan jaminan bebas seluruh bug.

## Temuan yang diperbaiki

| Prioritas | Area | Temuan | Perbaikan |
|---|---|---|---|
| Critical | Example / OTP | Contoh server memasang callback OTP yang selalu `console.log` kode OTP, termasuk jika `NODE_ENV=production`. Ini dapat membocorkan OTP ke log produksi. | Hapus sender demo dari contoh. Sender bawaan hanya mencetak OTP pada development dan menolak penggunaan di production. Production wajib mengonfigurasi provider OTP sendiri. |
| High | Google Sheets | Retry otomatis pada seluruh request `POST` setelah 429/5xx dapat mengulang operasi non-idempotent seperti append user/token/OTP dan membuat baris duplikat. | Retry 429/5xx hanya untuk GET dan PUT. POST tidak diulang otomatis. |
| High | Google Sheets | Header sheet yang tidak sesuai hanya menghasilkan warning, padahal pembacaan/penulisan memakai urutan kolom konfigurasi. Ini dapat membaca atau menulis data pada kolom yang salah. | Startup gagal secara eksplisit jika header yang ada tidak cocok. |
| High | Google Sheets | Konfigurasi kolom custom dapat menghilangkan kolom sistem yang wajib sehingga adapter berjalan dengan data tidak lengkap. | Validasi kolom wajib users, refreshTokens, dan OTP saat adapter dibuat. |
| High | Refresh token | Validasi record refresh sebelumnya hanya mencari hash token. Record tidak dicek ulang terhadap `jti`, `sub`/userId, dan `expiresAt` yang tersimpan. | Validasi semua binding tersebut sebelum rotasi. Operasi refresh juga diserialisasi per token dalam satu instance. |
| High | Password hashing | Pemanggilan `PasswordHasher` secara langsung tidak memiliki batas panjang input dan hash tersimpan dapat meminta output key dengan ukuran arbitrer. | Batasi panjang password di hasher; salt dan output hash harus memiliki panjang tepat; parameter scrypt tetap dibatasi. |
| Medium | JWT | Verifier hanya memeriksa `alg`; tipe header `typ` tidak divalidasi dan nilai `exp`/`nbf` tidak sepenuhnya divalidasi sebagai angka finite. | Wajib `alg=HS256`, `typ=JWT`; `exp` finite dan positif; `nbf` jika ada harus finite. |
| Medium | Durasi JWT | Nilai durasi numerik pecahan di bawah satu detik dapat dibulatkan menjadi nol detik. | Durasi numerik sekarang minimal satu detik dan hasil parsing harus safe integer. |
| Medium | OTP delivery | Jika provider OTP gagal setelah record dibuat, OTP lama tertinggal dan cooldown dapat menghambat percobaan ulang meskipun pesan tidak terkirim. | Hapus record OTP jika pengiriman gagal. |
| Medium | Rate limit | `windowMs` dan `max` tidak divalidasi; interval sweep sangat besar dapat memicu perilaku timer yang tidak diharapkan. | Validasi konfigurasi dan batasi interval pembersihan maksimal 60 detik. |
| Medium | Auth endpoints | Endpoint refresh belum memakai rate limiter bawaan seperti register/login/OTP. | Tambahkan opsi rate limit `refresh` pada auth router. |
| Medium | Konfigurasi password | Konfigurasi `minLength`/`maxLength` yang tidak masuk akal tidak ditolak sejak startup. | Validasi rentang dan hubungan kedua konfigurasi; batas max 1024 byte. |
| Low | Repository hygiene | Tidak ada `.gitignore`, sehingga `.env`, `node_modules`, dan hasil build mudah ikut ter-commit. | Tambahkan `.gitignore` dengan pengecualian `.env.example`. |

## Risiko yang masih harus ditangani sebelum production

1. **Atomicity lintas instance:** lock OTP/refresh hanya berlaku dalam satu instance proses. Repository generik dan Google Sheets belum menyediakan atomic consume/conditional delete. Pada deployment multi-instance/serverless, dua proses dapat memproses OTP atau refresh token bersamaan. Gunakan database transaksional dengan operasi atomic consume.
2. **Unique constraint:** `findOne(email)` lalu `create()` tidak menjamin bebas race saat register bersamaan. Wajib pasang unique index/constraint pada `users.email`, `refresh_tokens.tokenHash`, dan primary key terkait di database.
3. **Rate limiting:** limiter bawaan hanya in-memory per proses. Untuk serverless/multi-instance, gunakan Redis/API gateway atau limiter terpusat. Terapkan juga pembatasan berdasarkan akun/email dan proteksi brute-force sesuai kebutuhan.
4. **Google Sheets:** tidak cocok sebagai database autentikasi production yang membutuhkan transaksi, konsistensi, dan anti-replay kuat. Gunakan database yang mendukung transaksi.
5. **Proxy trust:** `trustProxy: true` hanya aman jika reverse proxy tepercaya menghapus lalu menulis ulang `X-Forwarded-For`; jika tidak, alamat IP dapat dipalsukan.
6. **Token browser:** desain penyimpanan token di sisi frontend belum termasuk dalam ZIP. Pertimbangkan refresh token pada cookie `HttpOnly; Secure; SameSite` dan mitigasi CSRF; hindari refresh token di `localStorage`.
7. **Operational secrets:** gunakan secret manager, TLS, rotasi secret, backup, monitoring, dan audit log yang tidak pernah mencatat password, OTP, access token, refresh token, atau private key.
8. **Dependency supply chain:** ZIP tidak menyertakan lockfile. Buat dan commit `package-lock.json` dari environment yang dapat mengakses registry, lalu gunakan `npm ci` dan audit dependency pada pipeline.

## Pemeriksaan secret

Pemindaian pola pada file arsip tidak menemukan credential live. `.env.example` hanya memuat nilai placeholder untuk JWT dan Google private key. Pemeriksaan pola tidak dapat menjamin tidak ada secret yang disamarkan atau disimpan dalam format lain. Jika secret pernah masuk GitHub, log CI, atau deployment, lakukan revoke/rotate pada sumbernya; menghapus file dari commit terbaru tidak menghapus riwayat Git.

## Validasi yang dijalankan

```bash
tsc --noEmit
tsc
node --test 'dist/test/*.test.js'
```

Hasil: **23 tests passed, 0 failed**. Pengujian ini mencakup alur auth, OTP, refresh/logout, HTTP, CORS, rate limit, Google Sheets mock, JWT, password, dan duration. Pengujian Google Sheets menggunakan mock; koneksi live ke Google API dan deployment production tidak diuji.
