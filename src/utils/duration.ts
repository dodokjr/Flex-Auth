const UNITS: Record<string, number> = { s: 1, m: 60, h: 3600, d: 86400, w: 604800 };

/** 900 -> 900 detik; '15m' -> 900; '7d' -> 604800. */
export function toSeconds(value: string | number, name = 'expiresIn'): number {
  if (typeof value === 'number') {
    if (!Number.isFinite(value) || value < 1) throw new Error(`${name} harus minimal 1 detik`);
    return Math.floor(value);
  }
  const m = /^(\d+)\s*([smhdw])$/i.exec(String(value).trim());
  if (!m) throw new Error(`${name} tidak valid: gunakan angka detik atau format seperti "15m", "1h", "7d"`);
  const seconds = Number(m[1]) * UNITS[m[2].toLowerCase()];
  if (!Number.isSafeInteger(seconds) || seconds <= 0) throw new Error(`${name} harus durasi positif yang valid`);
  return seconds;
}
