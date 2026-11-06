/**
 * Flex Auth Zero — Google Sheets credentials.
 *
 * Pilih sumber konfigurasi:
 *   'import' : isi nilai IMPORT_* di file ini.
 *   'env'    : baca GOOGLE_SPREADSHEET_ID, GOOGLE_CLIENT_EMAIL,
 *              GOOGLE_PRIVATE_KEY dari process.env.
 *
 * Jangan commit kredensial asli ke repository publik.
 */
export type GoogleSheetsSecretSource = 'import' | 'env';

export const GOOGLE_SHEETS_SOURCE: GoogleSheetsSecretSource = 'import';

// Isi hanya untuk mode 'import'. Gunakan kredensial Service Account milik sendiri.
const IMPORT_SPREADSHEET_ID = 'ISI_ID_SPREADSHEET_ANDA';
const IMPORT_CLIENT_EMAIL = 'ISI_CLIENT_EMAIL_SERVICE_ACCOUNT';
const IMPORT_PRIVATE_KEY = `-----BEGIN PRIVATE KEY-----
ISI_PRIVATE_KEY_ANDA
-----END PRIVATE KEY-----`;

function loadEnvironmentFile(): void {
  // Native Node.js API; tidak membutuhkan dotenv.
  if (typeof process.loadEnvFile !== 'function') return;
  try {
    process.loadEnvFile();
  } catch (error) {
    const code = (error as NodeJS.ErrnoException)?.code;
    if (code !== 'ENOENT') throw error;
  }
}

function required(name: string, value: string | undefined): string {
  const normalized = value?.trim();
  if (!normalized) {
    throw new Error(`[flex-auth] ${name} wajib diisi pada AuthPage/GoogleSheets.ts atau environment.`);
  }
  if (/^(ISI_|CHANGE_ME|REPLACE_WITH|YOUR_)/i.test(normalized)) {
    throw new Error(`[flex-auth] ${name} masih menggunakan placeholder. Isi kredensial Google milik Anda.`);
  }
  return normalized;
}

/** Dipanggil hanya saat STORAGE=sheets agar mode memory tidak membutuhkan kredensial Google. */
export function getGoogleSheetsConfig(): {
  spreadsheetId: string;
  clientEmail: string;
  privateKey: string;
} {
  let spreadsheetId: string | undefined;
  let clientEmail: string | undefined;
  let privateKey: string | undefined;

  if (GOOGLE_SHEETS_SOURCE === 'env') {
    loadEnvironmentFile();
    spreadsheetId = process.env.GOOGLE_SPREADSHEET_ID;
    clientEmail = process.env.GOOGLE_CLIENT_EMAIL;
    privateKey = process.env.GOOGLE_PRIVATE_KEY;
  } else {
    spreadsheetId = IMPORT_SPREADSHEET_ID;
    clientEmail = IMPORT_CLIENT_EMAIL;
    privateKey = IMPORT_PRIVATE_KEY;
  }

  const safeSpreadsheetId = required('GOOGLE_SPREADSHEET_ID', spreadsheetId);
  const safeClientEmail = required('GOOGLE_CLIENT_EMAIL', clientEmail);
  const safePrivateKey = required('GOOGLE_PRIVATE_KEY', privateKey)
    .replace(/\\n/g, '\n')
    .replace(/^"|"$/g, '');

  if (!/^[A-Za-z0-9_-]+$/.test(safeSpreadsheetId)) {
    throw new Error('[flex-auth] GOOGLE_SPREADSHEET_ID tidak valid. Gunakan ID dari URL Google Sheets.');
  }
  if (!/^[^\s@]+@[^\s@]+\.iam\.gserviceaccount\.com$/i.test(safeClientEmail)) {
    throw new Error('[flex-auth] GOOGLE_CLIENT_EMAIL bukan email Service Account Google yang valid.');
  }
  if (!safePrivateKey.includes('-----BEGIN PRIVATE KEY-----') || !safePrivateKey.includes('-----END PRIVATE KEY-----')) {
    throw new Error('[flex-auth] GOOGLE_PRIVATE_KEY harus berupa private key PEM yang valid.');
  }

  return {
    spreadsheetId: safeSpreadsheetId,
    clientEmail: safeClientEmail,
    privateKey: safePrivateKey,
  };
}
