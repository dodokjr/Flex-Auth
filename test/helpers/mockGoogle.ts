import http from 'node:http';
import { createPublicKey, createVerify } from 'node:crypto';

/** Server tiruan Google (OAuth token + Sheets v4) untuk menguji adapter tanpa internet. */

export interface MockGoogle {
  url: string;
  sheets: Map<string, { id: number; rows: unknown[][] }>;
  requests: string[];
  close(): Promise<void>;
}

const colIndex = (letters: string): number =>
  letters.split('').reduce((n, ch) => n * 26 + (ch.charCodeAt(0) - 64), 0) - 1;

const RANGE = /^'((?:[^']|'')+)'!([A-Z]+)(\d+)?(?::([A-Z]+)(\d+)?)?$/;

function trimRow(row: unknown[]): unknown[] {
  const r = [...row];
  while (r.length && (r[r.length - 1] === '' || r[r.length - 1] == null)) r.pop();
  return r;
}

export async function startMockGoogle(publicKeyPem: string, clientEmail: string): Promise<MockGoogle> {
  const publicKey = createPublicKey(publicKeyPem);
  const sheets = new Map<string, { id: number; rows: unknown[][] }>();
  const requests: string[] = [];
  let nextId = 100;

  const readBody = async (req: http.IncomingMessage): Promise<string> => {
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    return Buffer.concat(chunks).toString('utf8');
  };
  const send = (res: http.ServerResponse, status: number, body: unknown) => {
    res.writeHead(status, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(body));
  };
  const findSheet = (title: string) => sheets.get(title.replace(/''/g, "'"));

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url ?? '/', 'http://x');
    const path = decodeURIComponent(url.pathname);
    requests.push(`${req.method} ${path}`);
    const raw = await readBody(req);

    // ---- OAuth token: verifikasi assertion JWT RS256 ----
    if (path === '/token') {
      const assertion = new URLSearchParams(raw).get('assertion') ?? '';
      const [h, p, s] = assertion.split('.');
      const ok = createVerify('RSA-SHA256').update(`${h}.${p}`).verify(publicKey, Buffer.from(s ?? '', 'base64url'));
      const claim = JSON.parse(Buffer.from(p ?? '', 'base64url').toString() || '{}');
      if (!ok || claim.iss !== clientEmail || !String(claim.scope).includes('spreadsheets')) {
        return send(res, 400, { error: 'invalid_grant', error_description: 'bad assertion' });
      }
      return send(res, 200, { access_token: 'mock-token', expires_in: 3600 });
    }

    if (req.headers.authorization !== 'Bearer mock-token') {
      return send(res, 401, { error: { message: 'unauthenticated' } });
    }
    const body = raw ? JSON.parse(raw) : {};

    // ---- spreadsheets.get ----
    if (req.method === 'GET' && /^\/v4\/spreadsheets\/[^/:]+$/.test(path)) {
      return send(res, 200, {
        sheets: [...sheets.entries()].map(([title, s]) => ({ properties: { title, sheetId: s.id } })),
      });
    }

    // ---- spreadsheets.batchUpdate (addSheet, deleteDimension) ----
    if (req.method === 'POST' && /^\/v4\/spreadsheets\/[^/:]+:batchUpdate$/.test(path)) {
      const replies: unknown[] = [];
      for (const r of body.requests as Record<string, any>[]) {
        if (r.addSheet) {
          const id = nextId++;
          sheets.set(r.addSheet.properties.title, { id, rows: [] });
          replies.push({ addSheet: { properties: { sheetId: id, title: r.addSheet.properties.title } } });
        } else if (r.deleteDimension) {
          const { sheetId, startIndex, endIndex } = r.deleteDimension.range;
          const sheet = [...sheets.values()].find((s) => s.id === sheetId);
          if (!sheet) return send(res, 400, { error: { message: 'sheet tidak ada' } });
          sheet.rows.splice(startIndex, endIndex - startIndex);
          replies.push({});
        }
      }
      return send(res, 200, { replies });
    }

    // ---- values.batchUpdate ----
    if (req.method === 'POST' && /^\/v4\/spreadsheets\/[^/:]+\/values:batchUpdate$/.test(path)) {
      for (const d of body.data as { range: string; values: unknown[][] }[]) write(d.range, d.values);
      return send(res, 200, {});
    }

    // ---- values.get / append / update ----
    const m = /^\/v4\/spreadsheets\/[^/:]+\/values\/(.+)$/.exec(path);
    if (m) {
      if (req.method === 'POST' && m[1].endsWith(':append')) {
        const rg = RANGE.exec(m[1].slice(0, -':append'.length));
        const sheet = rg && findSheet(rg[1]);
        if (!sheet) return send(res, 400, { error: { message: 'range tidak valid' } });
        sheet.rows.push(...(body.values as unknown[][]));
        return send(res, 200, {});
      }
      if (req.method === 'PUT') {
        return write(m[1], body.values) ? send(res, 200, {}) : send(res, 400, { error: { message: 'range tidak valid' } });
      }
      if (req.method === 'GET') {
        const rg = RANGE.exec(m[1]);
        const sheet = rg && findSheet(rg[1]);
        if (!rg || !sheet) return send(res, 400, { error: { message: 'range tidak valid' } });
        const c1 = colIndex(rg[2]);
        const c2 = rg[4] ? colIndex(rg[4]) : c1;
        const r1 = rg[3] ? Number(rg[3]) : 1;
        const r2 = rg[5] ? Number(rg[5]) : sheet.rows.length;
        const values = sheet.rows.slice(r1 - 1, r2).map((row) => trimRow(row.slice(c1, c2 + 1)));
        while (values.length && values[values.length - 1].length === 0) values.pop();
        return send(res, 200, values.length ? { values } : {});
      }
    }
    return send(res, 404, { error: { message: `tidak dikenal: ${req.method} ${path}` } });
  });

  function write(range: string, values: unknown[][]): boolean {
    const rg = RANGE.exec(range);
    const sheet = rg && findSheet(rg[1]);
    if (!rg || !sheet) return false;
    const c1 = colIndex(rg[2]);
    const r1 = rg[3] ? Number(rg[3]) : 1;
    values.forEach((vals, i) => {
      while (sheet.rows.length < r1 + i) sheet.rows.push([]);
      const row = sheet.rows[r1 - 1 + i];
      vals.forEach((v, j) => { row[c1 + j] = v; });
    });
    return true;
  }

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as { port: number };
  return {
    url: `http://127.0.0.1:${port}`,
    sheets,
    requests,
    close: () => new Promise<void>((resolve) => { server.close(() => resolve()); server.closeAllConnections(); }),
  };
}
