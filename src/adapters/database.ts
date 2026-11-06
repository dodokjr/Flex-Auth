import type { AuthAdapter, OtpRecord, RefreshTokenRecord, Repository, UserRecord } from '../types';

/**
 * Adapter database generik. Beri 3 repository (users, refreshTokens, otps), masing-masing
 * punya 4 fungsi: create, findOne, update, delete (lihat interface Repository).
 */
export function dbAdapter<U extends UserRecord = UserRecord>(repos: {
  users: Repository<U>;
  refreshTokens: Repository<RefreshTokenRecord>;
  otps: Repository<OtpRecord>;
}): AuthAdapter<U> {
  const methods = ['create', 'findOne', 'update', 'delete'] as const;
  for (const [name, repo] of Object.entries(repos ?? {})) {
    if (!repo) throw new Error(`dbAdapter: "${name}" wajib diisi`);
    for (const m of methods) {
      if (typeof (repo as Repository<unknown>)[m] !== 'function') {
        throw new Error(`dbAdapter: ${name}.${m}() belum ada`);
      }
    }
  }
  if (!repos?.users || !repos.refreshTokens || !repos.otps) {
    throw new Error('dbAdapter: users, refreshTokens, dan otps wajib diisi');
  }
  return repos;
}

// ----- Helper siap pakai untuk ORM populer -----
// Parameter bertipe `any` agar tidak memaksa Anda meng-install tipe ORM yang tidak dipakai.
/* eslint-disable @typescript-eslint/no-explicit-any */

export const fromSequelize = <T extends object>(Model: any): Repository<T> => ({
  create: async (data) => (await Model.create(data)).get({ plain: true }) as T,
  findOne: async (where) => {
    const row = await Model.findOne({ where });
    return row ? (row.get({ plain: true }) as T) : null;
  },
  update: async (where, data) => { await Model.update(data, { where }); },
  delete: async (where) => { await Model.destroy({ where }); },
});

export const fromMongoose = <T extends object>(Model: any): Repository<T> => ({
  create: async (data) => (await Model.create(data)).toObject() as T,
  findOne: async (where) => (await Model.findOne(where).lean()) as T | null,
  update: async (where, data) => { await Model.updateMany(where, { $set: data }); },
  delete: async (where) => { await Model.deleteMany(where); },
});

export const fromPrisma = <T extends object>(delegate: any): Repository<T> => ({
  create: async (data) => (await delegate.create({ data })) as T,
  findOne: async (where) => (await delegate.findFirst({ where })) as T | null,
  update: async (where, data) => { await delegate.updateMany({ where, data }); },
  delete: async (where) => { await delegate.deleteMany({ where }); },
});


/**
 * Alias provider SQL. Fungsi ini TIDAK membuka koneksi MySQL/PostgreSQL;
 * berikan repository yang sudah dibuat oleh driver/ORM pilihan Anda.
 */
export const dbMysqlAdapter = <U extends UserRecord = UserRecord>(repos: {
  users: Repository<U>;
  refreshTokens: Repository<RefreshTokenRecord>;
  otps: Repository<OtpRecord>;
}): AuthAdapter<U> => dbAdapter<U>(repos);

/** Alias provider PostgreSQL; gunakan repository dari pg/Prisma/Sequelize/ORM Anda. */
export const dbPostgreSQL = <U extends UserRecord = UserRecord>(repos: {
  users: Repository<U>;
  refreshTokens: Repository<RefreshTokenRecord>;
  otps: Repository<OtpRecord>;
}): AuthAdapter<U> => dbAdapter<U>(repos);

/** Alias provider MongoDB; gunakan repository dari Mongoose/driver MongoDB Anda. */
export const dbMongoDB = <U extends UserRecord = UserRecord>(repos: {
  users: Repository<U>;
  refreshTokens: Repository<RefreshTokenRecord>;
  otps: Repository<OtpRecord>;
}): AuthAdapter<U> => dbAdapter<U>(repos);

/** @deprecated Gunakan dbAdapter(). */
export const createDatabaseAdapter = dbAdapter;
