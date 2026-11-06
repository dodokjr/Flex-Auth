/**
 * Flex Auth Zero — JWT secret provider.
 *
 * Pilih satu sumber:
 *   'import' : isi IMPORT_JWT_ACCESS dan IMPORT_JWT_REFRESH di bawah.
 *   'env'    : baca JWT_ACCESS_SECRET dan JWT_REFRESH_SECRET dari process.env.
 *
 * Untuk mode env, file .env (jika dipakai) dimuat memakai API bawaan Node.
 * Tidak membutuhkan package dotenv. Alternatif: jalankan Node dengan --env-file.
 */
import { randomBytes } from 'node:crypto';

export type JwtSecretSource = 'import' | 'env';

export const JWT_SECRET_SOURCE: JwtSecretSource = 'import';

// Ganti dengan nilai acak minimal 32 karakter yang berbeda untuk setiap instalasi.
// Jangan publikasikan secret asli ke repository open source.
const IMPORT_JWT_ACCESS = 'REPLACE_WITH_UNIQUE_ACCESS_SECRET_MIN_32_CHARS';
const IMPORT_JWT_REFRESH = 'REPLACE_WITH_DIFFERENT_REFRESH_SECRET_MIN_32_CHARS';

function readEnvironmentFile(): void {
  if (typeof process.loadEnvFile !== 'function') return;
  try {
    process.loadEnvFile();
  } catch (error) {
    // File .env memang opsional. Jangan sembunyikan error selain file tidak ada.
    const code = (error as NodeJS.ErrnoException)?.code;
    if (code !== 'ENOENT') throw error;
  }
}

function validateSecret(name: string, value: string | undefined): string {
  if (typeof value !== 'string' || value.length < 32) {
    throw new Error(
      `[flex-auth] ${name} wajib diisi dengan secret minimal 32 karakter. ` +
      `Periksa AuthPage/Jwt.ts atau konfigurasi environment.`,
    );
  }
  if (/^(CHANGE_ME|REPLACE_WITH|YOUR_SECRET)/i.test(value)) {
    throw new Error(`[flex-auth] ${name} masih menggunakan placeholder.`);
  }
  return value;
}

let accessValue: string | undefined;
let refreshValue: string | undefined;

if (String(JWT_SECRET_SOURCE) === 'env') {
  readEnvironmentFile();
  accessValue = process.env.JWT_ACCESS_SECRET;
  refreshValue = process.env.JWT_REFRESH_SECRET;
} else {
  accessValue = IMPORT_JWT_ACCESS;
  refreshValue = IMPORT_JWT_REFRESH;

  // Biar contoh `npm start` langsung bisa dicoba tanpa secret sungguhan.
  // Secret sementara hanya untuk development dan berubah setiap proses restart.
  const hasPlaceholder = (value: string | undefined): boolean =>
    !value || /^(CHANGE_ME|REPLACE_WITH|YOUR_SECRET|ISI_SECRET)/i.test(value);

  if (hasPlaceholder(accessValue) || hasPlaceholder(refreshValue)) {
    if (process.env.NODE_ENV === 'production') {
      throw new Error(
        '[flex-auth] Secret JWT masih placeholder. Isi AuthPage/Jwt.ts dengan secret acak minimal 32 karakter, ' +
        'atau ubah JWT_SECRET_SOURCE ke \'env\' dan atur JWT_ACCESS_SECRET serta JWT_REFRESH_SECRET.',
      );
    }

    accessValue = randomBytes(48).toString('base64url');
    refreshValue = randomBytes(48).toString('base64url');
    console.warn(
      '[flex-auth] Menggunakan JWT secret sementara untuk DEVELOPMENT. ' +
      'Token akan tidak berlaku setelah server restart. Isi secret sendiri sebelum production.',
    );
  }
}

export const JWT_Access = validateSecret('JWT_ACCESS_SECRET', accessValue);
export const JWT_Refresh = validateSecret('JWT_REFRESH_SECRET', refreshValue);

if (JWT_Access === JWT_Refresh) {
  throw new Error('[flex-auth] JWT access dan refresh secret harus berbeda.');
}
