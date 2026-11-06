/** Template aman untuk konfigurasi JWT Flex Auth Zero. */
export type JwtSecretSource = 'import' | 'env';

// Pilih 'import' atau 'env'.
export const JWT_SECRET_SOURCE: JwtSecretSource = 'import';

const IMPORT_JWT_ACCESS = 'REPLACE_WITH_UNIQUE_ACCESS_SECRET_MIN_32_CHARS';
const IMPORT_JWT_REFRESH = 'REPLACE_WITH_DIFFERENT_REFRESH_SECRET_MIN_32_CHARS';

function validateSecret(name: string, value: string | undefined): string {
  if (!value || value.length < 32 || /^(CHANGE_ME|REPLACE_WITH|YOUR_SECRET)/i.test(value)) {
    throw new Error(`[flex-auth] ${name} wajib berupa secret unik minimal 32 karakter.`);
  }
  return value;
}

if (String(JWT_SECRET_SOURCE) === 'env' && typeof process.loadEnvFile === 'function') {
  try { process.loadEnvFile(); }
  catch (error) {
    if ((error as NodeJS.ErrnoException)?.code !== 'ENOENT') throw error;
  }
}

export const JWT_Access = validateSecret(
  'JWT_ACCESS_SECRET',
  String(JWT_SECRET_SOURCE) === 'env' ? process.env.JWT_ACCESS_SECRET : IMPORT_JWT_ACCESS,
);
export const JWT_Refresh = validateSecret(
  'JWT_REFRESH_SECRET',
  String(JWT_SECRET_SOURCE) === 'env' ? process.env.JWT_REFRESH_SECRET : IMPORT_JWT_REFRESH,
);
if (JWT_Access === JWT_Refresh) throw new Error('[flex-auth] JWT secrets harus berbeda.');
