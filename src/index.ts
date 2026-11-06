import { AuthService } from './core/AuthService';
import { memoryAdapter, createMemoryAdapter } from './adapters/memory';
import { dbAdapter, dbMysqlAdapter, dbPostgreSQL, dbMongoDB, createDatabaseAdapter, fromSequelize, fromMongoose, fromPrisma } from './adapters/database';
import { googleSheetsAdapter, createSheetsAdapter } from './adapters/googleSheets';
import type { AuthOptions, UserRecord } from './types';

export const adapters = {
  memoryAdapter,
  googleSheetsAdapter,
  dbAdapter,
  dbMysqlAdapter,
  dbPostgreSQL,
  dbMongoDB,
  // Alias lama untuk kompatibilitas.
  createMemoryAdapter,
  createDatabaseAdapter,
  createSheetsAdapter,
  fromSequelize,
  fromMongoose,
  fromPrisma,
};

export const createAuth = <U extends UserRecord = UserRecord>(options: AuthOptions<U>): AuthService<U> =>
  new AuthService<U>(options);

export { AuthService };
export type { AccessTokenPayload } from './core/AuthService';

// HTTP (framework buatan sendiri)
export { App, compose } from './http/app';
export type { AppOptions } from './http/app';
export { Router } from './http/router';
export { Context } from './http/context';
export type { Handler, Next, State } from './http/context';
export { cors, rateLimit } from './http/middleware';
export type { CorsOptions, RateLimitOptions } from './http/middleware';
export { createAuthRouter } from './http/authRouter';
export type { AuthRouterOptions } from './http/authRouter';

// Building block yang bisa dipakai terpisah
export { signJwt, verifyJwt, JwtError } from './core/jwt';
export type { JwtPayload } from './core/jwt';
export { PasswordHasher } from './core/password';

export { AuthError, HttpError } from './errors';
export { memoryAdapter, googleSheetsAdapter, dbAdapter, dbMysqlAdapter, dbPostgreSQL, dbMongoDB };
export type { SheetsAdapterOptions } from './adapters/googleSheets';
export * from './types';
