/** Template publik. Salin sebagai GoogleSheets.ts dan isi kredensial sendiri. */
export type GoogleSheetsSecretSource = 'import' | 'env';
export const GOOGLE_SHEETS_SOURCE: GoogleSheetsSecretSource = 'import';

const IMPORT_SPREADSHEET_ID = 'ISI_ID_SPREADSHEET_ANDA';
const IMPORT_CLIENT_EMAIL = 'ISI_CLIENT_EMAIL_SERVICE_ACCOUNT';
const IMPORT_PRIVATE_KEY = `-----BEGIN PRIVATE KEY-----
ISI_PRIVATE_KEY_ANDA
-----END PRIVATE KEY-----`;

export { IMPORT_SPREADSHEET_ID, IMPORT_CLIENT_EMAIL, IMPORT_PRIVATE_KEY };
