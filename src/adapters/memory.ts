import type { AuthAdapter, OtpRecord, RefreshTokenRecord, Repository, UserRecord, Where } from '../types';

const match = (row: object, where: Where): boolean =>
  Object.keys(where).every((k) => String((row as Where)[k]) === String(where[k]));

class MemoryTable<T extends object> implements Repository<T> {
  private rows: T[] = [];

  async create(data: T): Promise<T> {
    this.rows.push({ ...data });
    return { ...data };
  }
  async findOne(where: Where): Promise<T | null> {
    const r = this.rows.find((x) => match(x, where));
    return r ? { ...r } : null;
  }
  async update(where: Where, data: Record<string, unknown>): Promise<void> {
    this.rows.filter((x) => match(x, where)).forEach((x) => Object.assign(x, data));
  }
  async delete(where: Where): Promise<void> {
    this.rows = this.rows.filter((x) => !match(x, where));
  }
}

/** Data hilang saat server restart. Cocok untuk development/testing. */
export function memoryAdapter<U extends UserRecord = UserRecord>(): AuthAdapter<U> {
  return {
    users: new MemoryTable<U>(),
    refreshTokens: new MemoryTable<RefreshTokenRecord>(),
    otps: new MemoryTable<OtpRecord>(),
  };
}

/** @deprecated Gunakan memoryAdapter(). */
export const createMemoryAdapter = memoryAdapter;
