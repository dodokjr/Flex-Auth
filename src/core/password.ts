import { randomBytes, scrypt, timingSafeEqual } from 'node:crypto';

/** Hashing password dengan scrypt (bawaan Node). Format: scrypt$N$r$p$salt$hash (base64). */

const KEY_BYTES = 64;
const SALT_BYTES = 16;

const derive = (password: string, salt: Buffer, N: number, r: number, p: number, keylen: number) =>
  new Promise<Buffer>((resolve, reject) => {
    scrypt(password, salt, keylen, { N, r, p, maxmem: 256 * N * r }, (err, key) =>
      err ? reject(err) : resolve(key));
  });

const isPow2 = (n: number): boolean => Number.isInteger(n) && n > 0 && (n & (n - 1)) === 0;

export class PasswordHasher {
  private readonly N: number;
  private readonly r = 8;
  private readonly p = 1;

  private readonly maxLength: number;

  constructor(options: { cost?: number; maxLength?: number } = {}) {
    this.N = options.cost ?? 32768;
    this.maxLength = options.maxLength ?? 128;
    if (!Number.isInteger(this.maxLength) || this.maxLength < 8 || this.maxLength > 1024) {
      throw new Error('flex-auth: password.maxLength harus bilangan bulat 8–1024 byte');
    }
    if (!isPow2(this.N) || this.N < 4096 || this.N > 262144) {
      throw new Error('flex-auth: password.cost harus pangkat 2 antara 4096 dan 262144');
    }
  }

  async hash(password: string): Promise<string> {
    if (typeof password !== 'string' || Buffer.byteLength(password, 'utf8') > this.maxLength) {
      throw new Error('flex-auth: password melebihi batas panjang');
    }
    const salt = randomBytes(SALT_BYTES);
    const key = await derive(password.normalize('NFKC'), salt, this.N, this.r, this.p, KEY_BYTES);
    return ['scrypt', this.N, this.r, this.p, salt.toString('base64'), key.toString('base64')].join('$');
  }

  async verify(password: string, stored: string): Promise<boolean> {
    if (typeof password !== 'string' || Buffer.byteLength(password, 'utf8') > this.maxLength || typeof stored !== 'string') return false;
    const parts = String(stored).split('$');
    if (parts.length !== 6 || parts[0] !== 'scrypt') return false;
    const N = Number(parts[1]);
    const r = Number(parts[2]);
    const p = Number(parts[3]);
    // Batasi parameter dari data tersimpan agar baris yang dimanipulasi tidak bisa menghabiskan memori/CPU
    if (!isPow2(N) || N < 4096 || N > 262144 || !Number.isInteger(r) || r < 1 || r > 16 ||
        !Number.isInteger(p) || p < 1 || p > 4) return false;
    const salt = Buffer.from(parts[4], 'base64');
    const expected = Buffer.from(parts[5], 'base64');
    if (salt.length !== SALT_BYTES || expected.length !== KEY_BYTES) return false;

    const key = await derive(password.normalize('NFKC'), salt, N, r, p, expected.length);
    return timingSafeEqual(key, expected);
  }
}
