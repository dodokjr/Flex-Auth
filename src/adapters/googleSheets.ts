import type { AuthAdapter, OtpRecord, RefreshTokenRecord, Repository, UserRecord, Where } from '../types';
import { SheetsClient } from './sheetsClient';

export interface SheetsAdapterOptions {
  /** ID spreadsheet (bagian URL setelah /d/). Default: env GOOGLE_SPREADSHEET_ID */
  spreadsheetId?: string;
  /** Default: env GOOGLE_CLIENT_EMAIL */
  clientEmail?: string;
  /** Default: env GOOGLE_PRIVATE_KEY */
  privateKey?: string;
  sheetNames?: Partial<Record<'users' | 'refreshTokens' | 'otps', string>>;
  /** Urutan kolom per tab. Tambahkan kolom sendiri di sini (mis. phone). */
  columns?: Partial<Record<'users' | 'refreshTokens' | 'otps', string[]>>;
  /** Hanya untuk testing / proxy. */
  apiBase?: string;
  tokenUrl?: string;
}

const DEFAULT_COLUMNS = {
  users: ['id', 'email', 'name', 'passwordHash', 'role', 'isVerified', 'createdAt', 'updatedAt'],
  refreshTokens: ['id', 'userId', 'tokenHash', 'expiresAt', 'createdAt'],
  otps: ['id', 'email', 'purpose', 'codeHash', 'attempts', 'expiresAt', 'createdAt'],
};
const DEFAULT_SHEETS = { users: 'users', refreshTokens: 'refresh_tokens', otps: 'otps' };

// Escape apostrophe sesuai notasi A1 Google Sheets.
const quoteSheet = (name: string): string => `'${name.replace(/'/g, "''")}'`;

function colLetter(n: number): string {
  let s = '';
  while (n > 0) {
    const m = (n - 1) % 26;
    s = String.fromCharCode(65 + m) + s;
    n = Math.floor((n - 1) / 26);
  }
  return s;
}

const match = (row: Where, where: Where): boolean =>
  Object.keys(where).every((k) => String(row[k]) === String(where[k]));

interface Located { row: number; record: Where } // row = nomor baris di sheet (1-based)

class SheetTable<T extends object> implements Repository<T> {
  readonly title: string;
  readonly columns: string[];
  readonly lastCol: string;
  sheetId: number | null = null; // diisi saat init
  private readonly adapter: GoogleSheetsAdapter;

  constructor(adapter: GoogleSheetsAdapter, title: string, columns: string[]) {
    this.adapter = adapter;
    this.title = title;
    this.columns = columns;
    this.lastCol = colLetter(columns.length);
  }

  private get client(): SheetsClient { return this.adapter.client; }
  private get spreadsheetId(): string { return this.adapter.spreadsheetId; }

  private async rows(): Promise<Located[]> {
    await this.adapter.ready();
    const res = await this.client.valuesGet(
      this.spreadsheetId, `${quoteSheet(this.title)}!A2:${this.lastCol}`);
    return (res.values ?? []).map((row, i) => {
      const record: Where = {};
      this.columns.forEach((c, idx) => {
        const v = row[idx];
        record[c] = v === undefined || v === '' ? null : v;
      });
      return { row: i + 2, record };
    });
  }

  private toRow(data: Where): unknown[] {
    const unknown = Object.keys(data).filter((k) => !this.columns.includes(k));
    if (unknown.length) {
      throw new Error(
        `Kolom [${unknown.join(', ')}] belum ada di sheet "${this.title}". ` +
        'Tambahkan lewat option columns pada googleSheetsAdapter().',
      );
    }
    return this.columns.map((c) => (data[c] === undefined || data[c] === null ? '' : data[c]));
  }

  async create(data: T): Promise<T> {
    await this.adapter.ready();
    // RAW: nilai tidak diinterpretasi sebagai formula (mencegah formula injection)
    await this.client.valuesAppend(this.spreadsheetId, `${quoteSheet(this.title)}!A:A`, [this.toRow(data as Where)]);
    return { ...data };
  }

  async findOne(where: Where): Promise<T | null> {
    const found = (await this.rows()).find((r) => match(r.record, where));
    return found ? (found.record as T) : null;
  }

  async update(where: Where, data: Record<string, unknown>): Promise<void> {
    const matches = (await this.rows()).filter((r) => match(r.record, where));
    if (!matches.length) return;
    await this.client.valuesBatchUpdate(
      this.spreadsheetId,
      matches.map((m) => ({
        range: `${quoteSheet(this.title)}!A${m.row}:${this.lastCol}${m.row}`,
        values: [this.toRow({ ...m.record, ...data })],
      })),
    );
  }

  async delete(where: Where): Promise<void> {
    const matches = (await this.rows()).filter((r) => match(r.record, where));
    if (!matches.length) return;
    // hapus dari baris paling bawah agar nomor baris lain tidak bergeser
    const requests = matches
      .map((m) => m.row)
      .sort((a, b) => b - a)
      .map((row) => ({
        deleteDimension: {
          range: { sheetId: this.sheetId, dimension: 'ROWS', startIndex: row - 1, endIndex: row },
        },
      }));
    await this.client.batchUpdate(this.spreadsheetId, requests);
  }
}

export class GoogleSheetsAdapter<U extends UserRecord = UserRecord> implements AuthAdapter<U> {
  readonly spreadsheetId: string;
  readonly client: SheetsClient;
  readonly users: SheetTable<U>;
  readonly refreshTokens: SheetTable<RefreshTokenRecord>;
  readonly otps: SheetTable<OtpRecord>;
  private readyPromise: Promise<void> | null = null;

  constructor(opts: SheetsAdapterOptions = {}) {
    const spreadsheetId = opts.spreadsheetId ?? process.env.GOOGLE_SPREADSHEET_ID;
    const clientEmail = opts.clientEmail ?? process.env.GOOGLE_CLIENT_EMAIL;
    const privateKey = (opts.privateKey ?? process.env.GOOGLE_PRIVATE_KEY ?? '')
      .replace(/\\n/g, '\n')
      .replace(/^"|"$/g, '');

    if (!spreadsheetId) throw new Error('Google Sheets: spreadsheetId wajib diisi');
    if (!/^[A-Za-z0-9_-]+$/.test(spreadsheetId)) throw new Error('Google Sheets: spreadsheetId tidak valid');
    if (!clientEmail) throw new Error('Google Sheets: GOOGLE_CLIENT_EMAIL belum diisi');
    if (!privateKey) throw new Error('Google Sheets: GOOGLE_PRIVATE_KEY belum diisi');
    this.spreadsheetId = spreadsheetId;

    this.client = new SheetsClient({ clientEmail, privateKey, apiBase: opts.apiBase, tokenUrl: opts.tokenUrl });

    const names = { ...DEFAULT_SHEETS, ...opts.sheetNames };
    const cols = { ...DEFAULT_COLUMNS, ...opts.columns };
    const requiredColumns: Record<string, string[]> = {
      users: ['id', 'email', 'passwordHash', 'role', 'isVerified', 'createdAt', 'updatedAt'],
      refreshTokens: ['id', 'userId', 'tokenHash', 'expiresAt', 'createdAt'],
      otps: ['id', 'email', 'purpose', 'codeHash', 'attempts', 'expiresAt', 'createdAt'],
    };
    for (const [kind, columns] of Object.entries(cols)) {
      if (!columns.length || new Set(columns).size !== columns.length || columns.some((c) => !c || typeof c !== 'string')) {
        throw new Error(`Google Sheets: konfigurasi kolom ${kind} kosong atau duplikat`);
      }
      const missing = requiredColumns[kind].filter((c) => !columns.includes(c));
      if (missing.length) throw new Error(`Google Sheets: kolom wajib ${kind} hilang: ${missing.join(', ')}`);
    }
    this.users = new SheetTable<U>(this, names.users, cols.users);
    this.refreshTokens = new SheetTable<RefreshTokenRecord>(this, names.refreshTokens, cols.refreshTokens);
    this.otps = new SheetTable<OtpRecord>(this, names.otps, cols.otps);
  }

  ready(): Promise<void> {
    if (!this.readyPromise) {
      this.readyPromise = this.init().catch((e) => { this.readyPromise = null; throw e; });
    }
    return this.readyPromise;
  }

  /** Otomatis membuat tab + header jika belum ada. */
  private async init(): Promise<void> {
    const meta = await this.client.getSpreadsheet(this.spreadsheetId);
    const existing = new Map<string, number>();
    for (const s of meta.sheets ?? []) {
      if (s.properties?.title != null && s.properties.sheetId != null) {
        existing.set(s.properties.title, s.properties.sheetId);
      }
    }
    const tables: SheetTable<object>[] = [this.users, this.refreshTokens, this.otps];

    const missing = tables.filter((t) => !existing.has(t.title));
    if (missing.length) {
      const res = await this.client.batchUpdate(
        this.spreadsheetId,
        missing.map((t) => ({ addSheet: { properties: { title: t.title } } })),
      );
      (res.replies ?? []).forEach((rep, i) => {
        const id = rep.addSheet?.properties?.sheetId;
        if (id != null) existing.set(missing[i].title, id);
      });
    }

    for (const t of tables) {
      t.sheetId = existing.get(t.title) ?? null;
      const range = `${quoteSheet(t.title)}!A1:${t.lastCol}1`;
      const head = await this.client.valuesGet(this.spreadsheetId, range);
      const current: unknown[] = head.values?.[0] ?? [];
      if (!current.length) {
        await this.client.valuesUpdate(this.spreadsheetId, range, [t.columns]);
      } else if (current.join('|') !== t.columns.join('|')) {
        throw new Error(`Google Sheets: header sheet "${t.title}" tidak cocok dengan konfigurasi columns; hentikan agar data tidak salah kolom.`);
      }
      if (t.sheetId === null) throw new Error(`Google Sheets: sheetId untuk tab "${t.title}" tidak ditemukan`);
    }
  }
}

/** Nama adapter langsung: gunakan sebagai pilihan storage Google Sheets. */
export const googleSheetsAdapter = <U extends UserRecord = UserRecord>(
  opts?: SheetsAdapterOptions,
): GoogleSheetsAdapter<U> => new GoogleSheetsAdapter<U>(opts);

/** @deprecated Gunakan googleSheetsAdapter(). */
export const createSheetsAdapter = googleSheetsAdapter;
