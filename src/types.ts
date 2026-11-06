export type OtpPurpose = 'register' | 'login';

// ---------- Record (baris data) ----------
// Semua timestamp = epoch milidetik (number).
export interface UserRecord {
  id: string;
  email: string;
  passwordHash: string;
  role: string;
  isVerified: boolean;
  createdAt: number;
  updatedAt: number;
  name?: string | null;
}

export interface RefreshTokenRecord {
  id: string;
  userId: string;
  tokenHash: string;
  expiresAt: number;
  createdAt: number;
}

export interface OtpRecord {
  id: string;
  email: string;
  purpose: OtpPurpose;
  codeHash: string;
  attempts: number;
  expiresAt: number;
  createdAt: number;
}

/** User tanpa passwordHash (aman dikirim ke client). */
export type PublicUser<U extends UserRecord = UserRecord> = Omit<U, 'passwordHash'>;

// ---------- Adapter / Repository ----------
export type Where = Record<string, unknown>;

/** Kontrak yang harus dipenuhi storage apa pun (database, sheets, dll). */
export interface Repository<T> {
  /** Simpan baris baru, return baris tersebut. */
  create(data: T): Promise<T>;
  /** Cari 1 baris yang cocok. where = { kolom: nilai }. */
  findOne(where: Where): Promise<T | null>;
  /** Update semua baris yang cocok. */
  update(where: Where, data: Record<string, unknown>): Promise<void>;
  /** Hapus semua baris yang cocok. */
  delete(where: Where): Promise<void>;
}

export interface AuthAdapter<U extends UserRecord = UserRecord> {
  users: Repository<U>;
  refreshTokens: Repository<RefreshTokenRecord>;
  otps: Repository<OtpRecord>;
}

// ---------- Options ----------
export interface JwtOptions {
  /** Minimal 32 karakter. Harus berbeda dari refreshSecret. */
  accessSecret: string;
  /** Minimal 32 karakter. */
  refreshSecret: string;
  /** Angka detik, atau string seperti '15m', '1h', '7d'. Default '15m'. */
  accessExpiresIn?: string | number;
  /** Default '7d'. */
  refreshExpiresIn?: string | number;
}

export interface OtpSendPayload {
  email: string;
  code: string;
  purpose: OtpPurpose;
  expiresInMinutes: number;
}

export interface OtpOptions {
  enabled?: boolean;
  length?: number;
  ttlMinutes?: number;
  maxAttempts?: number;
  resendCooldownSeconds?: number;
  /** true = OTP juga diminta setiap login (2FA). */
  requireOnLogin?: boolean;
  /** Secret untuk HMAC OTP. Default: jwt.accessSecret. */
  secret?: string;
  /** Fungsi pengirim OTP (email / WhatsApp / SMS). Wajib di production. */
  send?: (payload: OtpSendPayload) => Promise<void> | void;
}

export interface PasswordOptions {
  minLength?: number;
  /** Batas panjang (byte UTF-8) agar hashing tidak bisa dipakai untuk DoS. Default 128. */
  maxLength?: number;
  /** Biaya scrypt (N, pangkat 2, 4096 - 262144). Default 32768. */
  cost?: number;
}

export interface AuthOptions<U extends UserRecord = UserRecord> {
  adapter: AuthAdapter<U>;
  jwt: JwtOptions;
  otp?: OtpOptions;
  password?: PasswordOptions;
  /** Field tambahan dari body register yang boleh disimpan. Default ['name']. */
  userFields?: string[];
  defaultRole?: string;
}

// ---------- Input / Output ----------
export interface RegisterInput {
  email: string;
  password: string;
  name?: string;
  [extra: string]: unknown;
}
export interface LoginInput { email: string; password: string }
export interface VerifyOtpInput { email: string; code: string; purpose?: OtpPurpose }

export interface AuthTokens {
  accessToken: string;
  refreshToken: string;
  tokenType: 'Bearer';
  expiresIn: string | number;
}
export type AuthSuccess<U extends UserRecord = UserRecord> = { user: PublicUser<U> } & AuthTokens;
export interface OtpChallenge<U extends UserRecord = UserRecord> {
  otpRequired: true;
  purpose: OtpPurpose;
  user?: PublicUser<U>;
}

export interface AuthContext {
  userId: string;
  email: string;
  role: string;
}
