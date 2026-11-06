import { createPrivateKey, createSign, type KeyObject } from 'node:crypto';

/** Klien Google Sheets API v4 minimal: OAuth2 service account (JWT RS256) + REST lewat fetch bawaan Node. */

export interface SheetsClientOptions {
  clientEmail: string;
  privateKey: string;
  /** Default https://sheets.googleapis.com (diubah hanya untuk testing). */
  apiBase?: string;
  /** Default https://oauth2.googleapis.com/token */
  tokenUrl?: string;
  timeoutMs?: number;
  /** Jumlah retry untuk 429/5xx. Default 3. */
  retries?: number;
}

export class SheetsApiError extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(`Google Sheets API ${status}: ${message}`);
    this.name = 'SheetsApiError';
    this.status = status;
  }
}

const SCOPE = 'https://www.googleapis.com/auth/spreadsheets';
const b64u = (v: unknown): string => Buffer.from(JSON.stringify(v)).toString('base64url');
const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

async function errorMessage(res: Response): Promise<string> {
  try {
    const data = (await res.json()) as { error?: { message?: string } | string; error_description?: string };
    if (typeof data.error === 'string') return data.error_description ?? data.error;
    return data.error?.message ?? res.statusText;
  } catch {
    return res.statusText;
  }
}

export class SheetsClient {
  private readonly clientEmail: string;
  private readonly key: KeyObject;
  private readonly apiBase: string;
  private readonly tokenUrl: string;
  private readonly timeoutMs: number;
  private readonly retries: number;
  private token: { value: string; expiresAt: number } | null = null;
  private pending: Promise<string> | null = null;

  constructor(opts: SheetsClientOptions) {
    this.clientEmail = opts.clientEmail;
    try {
      this.key = createPrivateKey(opts.privateKey);
    } catch {
      throw new Error('Google Sheets: GOOGLE_PRIVATE_KEY bukan private key PEM yang valid');
    }
    this.apiBase = (opts.apiBase ?? 'https://sheets.googleapis.com').replace(/\/+$/, '');
    this.tokenUrl = opts.tokenUrl ?? 'https://oauth2.googleapis.com/token';
    this.timeoutMs = opts.timeoutMs ?? 15_000;
    this.retries = opts.retries ?? 3;
  }

  private accessToken(force = false): Promise<string> {
    if (!force && this.token && this.token.expiresAt - 60_000 > Date.now()) {
      return Promise.resolve(this.token.value);
    }
    if (!this.pending) {
      this.pending = this.fetchToken().finally(() => { this.pending = null; });
    }
    return this.pending;
  }

  private async fetchToken(): Promise<string> {
    const now = Math.floor(Date.now() / 1000);
    const unsigned = `${b64u({ alg: 'RS256', typ: 'JWT' })}.${b64u({
      iss: this.clientEmail, scope: SCOPE, aud: this.tokenUrl, iat: now, exp: now + 3600,
    })}`;
    const signature = createSign('RSA-SHA256').update(unsigned).sign(this.key).toString('base64url');

    const res = await fetch(this.tokenUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
        assertion: `${unsigned}.${signature}`,
      }),
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    if (!res.ok) throw new SheetsApiError(res.status, `OAuth gagal: ${await errorMessage(res)}`);

    const data = (await res.json()) as { access_token?: string; expires_in?: number };
    if (typeof data.access_token !== 'string' || !data.access_token ||
        typeof data.expires_in !== 'number' || !Number.isFinite(data.expires_in) || data.expires_in <= 0) {
      throw new Error('Google Sheets: respons OAuth tidak valid');
    }
    this.token = { value: data.access_token, expiresAt: Date.now() + data.expires_in * 1000 };
    return data.access_token;
  }

  async request<T>(
    method: string,
    path: string,
    opts: { query?: Record<string, string>; body?: unknown } = {},
  ): Promise<T> {
    const qs = opts.query ? `?${new URLSearchParams(opts.query).toString()}` : '';
    let refreshedToken = false;

    for (let attempt = 0; ; attempt++) {
      const token = await this.accessToken();
      const res = await fetch(`${this.apiBase}${path}${qs}`, {
        method,
        headers: {
          Authorization: `Bearer ${token}`,
          ...(opts.body !== undefined ? { 'Content-Type': 'application/json' } : {}),
        },
        body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
        signal: AbortSignal.timeout(this.timeoutMs),
      });

      if (res.ok) return (await res.json()) as T;
      if (res.status === 401 && !refreshedToken) {
        refreshedToken = true;
        await this.accessToken(true);
        continue;
      }
      // POST dapat bersifat non-idempotent (append/addSheet); retry dapat menggandakan baris.
      if ((method === 'GET' || method === 'PUT') && (res.status === 429 || res.status >= 500) && attempt < this.retries) {
        await sleep(300 * 2 ** attempt);
        continue;
      }
      throw new SheetsApiError(res.status, await errorMessage(res));
    }
  }

  // ---- Endpoint yang dipakai adapter ----
  private id(spreadsheetId: string): string { return `/v4/spreadsheets/${encodeURIComponent(spreadsheetId)}`; }

  getSpreadsheet(spreadsheetId: string) {
    return this.request<{ sheets?: { properties?: { sheetId?: number; title?: string } }[] }>(
      'GET', this.id(spreadsheetId), { query: { fields: 'sheets.properties(sheetId,title)' } });
  }

  batchUpdate(spreadsheetId: string, requests: unknown[]) {
    return this.request<{ replies?: { addSheet?: { properties?: { sheetId?: number } } }[] }>(
      'POST', `${this.id(spreadsheetId)}:batchUpdate`, { body: { requests } });
  }

  valuesGet(spreadsheetId: string, range: string) {
    return this.request<{ values?: unknown[][] }>(
      'GET', `${this.id(spreadsheetId)}/values/${encodeURIComponent(range)}`,
      { query: { valueRenderOption: 'UNFORMATTED_VALUE' } });
  }

  valuesAppend(spreadsheetId: string, range: string, values: unknown[][]) {
    return this.request<unknown>(
      'POST', `${this.id(spreadsheetId)}/values/${encodeURIComponent(range)}:append`,
      { query: { valueInputOption: 'RAW', insertDataOption: 'INSERT_ROWS' }, body: { values } });
  }

  valuesUpdate(spreadsheetId: string, range: string, values: unknown[][]) {
    return this.request<unknown>(
      'PUT', `${this.id(spreadsheetId)}/values/${encodeURIComponent(range)}`,
      { query: { valueInputOption: 'RAW' }, body: { values } });
  }

  valuesBatchUpdate(spreadsheetId: string, data: { range: string; values: unknown[][] }[]) {
    return this.request<unknown>(
      'POST', `${this.id(spreadsheetId)}/values:batchUpdate`,
      { body: { valueInputOption: 'RAW', data } });
  }
}
