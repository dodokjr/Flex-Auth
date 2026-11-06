import { randomUUID } from 'node:crypto';
import { AuthError } from '../errors';
import { sha256, hmac, generateOtp, safeEqual } from './crypto';
import { JwtError, signJwt, verifyJwt, decodeJwtUnsafe, type JwtPayload } from './jwt';
import { PasswordHasher } from './password';
import { toSeconds } from '../utils/duration';
import { createAuthenticate, createAuthorize, type AuthenticateOptions } from '../http/authMiddleware';
import type { Handler } from '../http/context';
import type {
  AuthOptions, AuthSuccess, AuthTokens, JwtOptions, LoginInput, OtpChallenge, OtpOptions,
  OtpPurpose, OtpRecord, PasswordOptions, PublicUser, RefreshTokenRecord, RegisterInput,
  Repository, UserRecord, VerifyOtpInput,
} from '../types';

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const OTP_PURPOSES: OtpPurpose[] = ['register', 'login'];
const MIN_SECRET_LENGTH = 32;

const isTrue = (v: unknown): boolean =>
  v === true || v === 1 || v === '1' || String(v).toLowerCase() === 'true';
const normEmail = (e: unknown): string => (typeof e === 'string' ? e.trim().toLowerCase() : '');

// Default pengirim OTP: hanya untuk development.
const defaultSendOtp: NonNullable<OtpOptions['send']> = ({ email, code, purpose, expiresInMinutes }) => {
  if (process.env.NODE_ENV === 'production') {
    throw new Error('flex-auth: Konfigurasikan otp.send di production; OTP tidak boleh dikirim ke log.');
  }
  console.warn(`[flex-auth:development-only] OTP ${purpose} untuk ${email}: ${code} (berlaku ${expiresInMinutes} menit)`);
};

type ResolvedOtp = Required<Omit<OtpOptions, 'secret'>> & { secret?: string };

export interface AccessTokenPayload extends JwtPayload {
  sub: string;
  email: string;
  role: string;
}

export class AuthService<U extends UserRecord = UserRecord> {
  private readonly jwtOpt: Required<JwtOptions>;
  private readonly otpOpt: ResolvedOtp;
  private readonly pwdOpt: Required<Omit<PasswordOptions, 'cost'>>;
  private readonly hasher: PasswordHasher;
  private readonly userFields: string[];
  private readonly defaultRole: string;
  private dummyHash?: Promise<string>;
  private readonly operationLocks = new Map<string, Promise<void>>();

  private readonly users: Repository<U>;
  private readonly refreshTokens: Repository<RefreshTokenRecord>;
  private readonly otps: Repository<OtpRecord>;

  constructor(options: AuthOptions<U>) {
    const { adapter } = options;
    if (!adapter?.users || !adapter.refreshTokens || !adapter.otps) {
      throw new Error('flex-auth: "adapter" wajib punya users, refreshTokens, dan otps');
    }
    const { accessSecret, refreshSecret } = options.jwt ?? ({} as JwtOptions);
    if (!accessSecret || !refreshSecret) {
      throw new Error('flex-auth: jwt.accessSecret dan jwt.refreshSecret wajib diisi');
    }
    if (accessSecret.length < MIN_SECRET_LENGTH || refreshSecret.length < MIN_SECRET_LENGTH) {
      throw new Error(`flex-auth: secret JWT minimal ${MIN_SECRET_LENGTH} karakter`);
    }
    if (accessSecret === refreshSecret) {
      throw new Error('flex-auth: accessSecret dan refreshSecret harus berbeda');
    }
    if (process.env.NODE_ENV === 'production' && options.otp?.enabled !== false && !options.otp?.send) {
      throw new Error('flex-auth: otp.send wajib dikonfigurasi di production; jangan log OTP.');
    }

    this.jwtOpt = { accessExpiresIn: '15m', refreshExpiresIn: '7d', ...options.jwt };
    toSeconds(this.jwtOpt.accessExpiresIn, 'jwt.accessExpiresIn'); // validasi lebih awal
    toSeconds(this.jwtOpt.refreshExpiresIn, 'jwt.refreshExpiresIn');

    this.otpOpt = {
      enabled: true,
      length: 6,
      ttlMinutes: 5,
      maxAttempts: 5,
      resendCooldownSeconds: 60,
      requireOnLogin: false,
      send: defaultSendOtp,
      ...options.otp,
    };
    this.pwdOpt = { minLength: 8, maxLength: 128, ...options.password };
    if (!Number.isInteger(this.pwdOpt.minLength) || this.pwdOpt.minLength < 1 ||
        !Number.isInteger(this.pwdOpt.maxLength) || this.pwdOpt.maxLength < this.pwdOpt.minLength || this.pwdOpt.maxLength > 1024) {
      throw new Error('flex-auth: konfigurasi password.minLength/maxLength tidak valid');
    }
    this.hasher = new PasswordHasher({ cost: options.password?.cost, maxLength: this.pwdOpt.maxLength });
    this.userFields = options.userFields ?? ['name'];
    this.defaultRole = options.defaultRole ?? 'user';

    const reserved = new Set(['id', 'email', 'passwordHash', 'role', 'isVerified', 'createdAt', 'updatedAt']);
    const unsafe = this.userFields.filter((f) => reserved.has(f) || ['__proto__', 'prototype', 'constructor'].includes(f));
    if (unsafe.length) {
      throw new Error(`flex-auth: userFields tidak boleh berisi field sistem: ${unsafe.join(', ')}`);
    }
    if (this.otpOpt.secret !== undefined && this.otpOpt.secret.length < MIN_SECRET_LENGTH) {
      throw new Error(`flex-auth: otp.secret minimal ${MIN_SECRET_LENGTH} karakter`);
    }
    if (!Number.isInteger(this.otpOpt.length) || this.otpOpt.length < 4 || this.otpOpt.length > 10) {
      throw new Error('flex-auth: otp.length harus bilangan bulat antara 4 dan 10');
    }
    if (!Number.isInteger(this.otpOpt.maxAttempts) || this.otpOpt.maxAttempts < 1 ||
        !Number.isFinite(this.otpOpt.ttlMinutes) || this.otpOpt.ttlMinutes <= 0 ||
        !Number.isFinite(this.otpOpt.resendCooldownSeconds) || this.otpOpt.resendCooldownSeconds < 0) {
      throw new Error('flex-auth: konfigurasi OTP tidak valid');
    }

    this.users = adapter.users;
    this.refreshTokens = adapter.refreshTokens;
    this.otps = adapter.otps;
  }

  // ---------- Helpers ----------
  /** Serialisasi operasi sensitif per key dalam satu instance proses.
   * Adapter/database tetap harus menyediakan atomic consume untuk jaminan lintas instance. */
  private async withOperationLock<T>(key: string, operation: () => Promise<T>): Promise<T> {
    const previous = this.operationLocks.get(key) ?? Promise.resolve();
    let release!: () => void;
    const current = new Promise<void>((resolve) => { release = resolve; });
    this.operationLocks.set(key, current);
    await previous;
    try {
      return await operation();
    } finally {
      release();
      if (this.operationLocks.get(key) === current) this.operationLocks.delete(key);
    }
  }

  publicUser(user: U): PublicUser<U> {
    // Jangan pernah serialisasikan field kredensial/rahasia dari custom UserRecord.
    const safe: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(user)) {
      if (/password|secret|token|otp|hash|credential|private|api.?key/i.test(key)) continue;
      safe[key] = value;
    }
    safe.isVerified = isTrue(safe.isVerified);
    return safe as unknown as PublicUser<U>;
  }

  // Hash palsu agar waktu respons login tidak membocorkan apakah email terdaftar.
  private getDummyHash(): Promise<string> {
    return (this.dummyHash ??= this.hasher.hash('dummy-password-flex-auth'));
  }

  // ---------- Register ----------
  async register(input: Partial<RegisterInput> = {}): Promise<AuthSuccess<U> | OtpChallenge<U>> {
    const email = normEmail(input.email);
    const password = typeof input.password === 'string' ? input.password : '';

    if (email.length > 254 || !EMAIL_RE.test(email)) throw new AuthError('Format email tidak valid', 400, 'INVALID_EMAIL');
    if (password.length < this.pwdOpt.minLength) {
      throw new AuthError(`Password minimal ${this.pwdOpt.minLength} karakter`, 400, 'WEAK_PASSWORD');
    }
    if (Buffer.byteLength(password, 'utf8') > this.pwdOpt.maxLength) {
      throw new AuthError(`Password maksimal ${this.pwdOpt.maxLength} byte`, 400, 'PASSWORD_TOO_LONG');
    }
    if (await this.users.findOne({ email })) {
      throw new AuthError('Email sudah terdaftar', 409, 'EMAIL_EXISTS');
    }

    const now = Date.now();
    const extra: Record<string, unknown> = {};
    for (const f of this.userFields) if (input[f] !== undefined) extra[f] = input[f];

    const user = await this.users.create({
      id: randomUUID(),
      email,
      passwordHash: await this.hasher.hash(password),
      role: this.defaultRole,
      isVerified: !this.otpOpt.enabled,
      ...extra,
      createdAt: now,
      updatedAt: now,
    } as unknown as U);

    if (this.otpOpt.enabled) {
      await this.issueOtp(email, 'register');
      return { user: this.publicUser(user), otpRequired: true, purpose: 'register' };
    }
    return { user: this.publicUser(user), ...(await this.issueTokens(user)) };
  }

  // ---------- Login ----------
  async login(input: Partial<LoginInput> = {}): Promise<AuthSuccess<U> | OtpChallenge<U>> {
    const email = normEmail(input.email);
    const password = typeof input.password === 'string' ? input.password : '';
    if (!email || !password || Buffer.byteLength(password, 'utf8') > this.pwdOpt.maxLength) {
      throw new AuthError('Email atau password salah', 401, 'INVALID_CREDENTIALS');
    }

    const user = await this.users.findOne({ email });
    const ok = await this.hasher.verify(password, user ? user.passwordHash : await this.getDummyHash());
    if (!user || !ok) throw new AuthError('Email atau password salah', 401, 'INVALID_CREDENTIALS');

    if (this.otpOpt.enabled && !isTrue(user.isVerified)) {
      await this.issueOtp(email, 'register');
      return { otpRequired: true, purpose: 'register' };
    }
    if (this.otpOpt.enabled && this.otpOpt.requireOnLogin) {
      await this.issueOtp(email, 'login');
      return { otpRequired: true, purpose: 'login' };
    }
    return { user: this.publicUser(user), ...(await this.issueTokens(user)) };
  }

  // ---------- OTP ----------
  async verifyOtp(input: Partial<VerifyOtpInput> = {}): Promise<AuthSuccess<U>> {
    const email = normEmail(input.email);
    const purpose = input.purpose ?? 'register';
    if (!OTP_PURPOSES.includes(purpose)) throw new AuthError('Purpose OTP tidak valid', 400, 'INVALID_PURPOSE');

    const code = String(input.code ?? '');
    if (code.length !== this.otpOpt.length || !/^\d+$/.test(code)) {
      throw new AuthError('Format OTP tidak valid', 400, 'INVALID_OTP_FORMAT');
    }

    return this.withOperationLock(`otp:${email}:${purpose}`, async () => {
      await this.checkOtp(email, purpose, code);

      let user = await this.users.findOne({ email });
      if (!user) throw new AuthError('User tidak ditemukan', 404, 'USER_NOT_FOUND');

      if (!isTrue(user.isVerified)) {
        await this.users.update({ id: user.id }, { isVerified: true, updatedAt: Date.now() });
        user = { ...user, isVerified: true };
      }
      return { user: this.publicUser(user), ...(await this.issueTokens(user)) };
    });
  }

  async resendOtp(input: { email?: string } = {}): Promise<{ ok: true }> {
    const email = normEmail(input.email);
    const user = await this.users.findOne({ email });
    // Respons selalu sama agar tidak membocorkan apakah email terdaftar
    if (!user || isTrue(user.isVerified)) return { ok: true };

    const rec = await this.otps.findOne({ email, purpose: 'register' });
    if (rec && Date.now() - Number(rec.createdAt) < this.otpOpt.resendCooldownSeconds * 1000) {
      throw new AuthError('Tunggu sebentar sebelum meminta OTP lagi', 429, 'OTP_COOLDOWN');
    }
    await this.issueOtp(email, 'register');
    return { ok: true };
  }

  private hashOtp(email: string, purpose: OtpPurpose, code: string): string {
    return hmac(this.otpOpt.secret ?? this.jwtOpt.accessSecret, `${email}:${purpose}:${code}`);
  }

  private async issueOtp(email: string, purpose: OtpPurpose): Promise<void> {
    const code = generateOtp(this.otpOpt.length);
    await this.otps.delete({ email, purpose });
    await this.otps.create({
      id: randomUUID(),
      email,
      purpose,
      codeHash: this.hashOtp(email, purpose, code),
      attempts: 0,
      expiresAt: Date.now() + this.otpOpt.ttlMinutes * 60 * 1000,
      createdAt: Date.now(),
    });
    try {
      await this.otpOpt.send({ email, code, purpose, expiresInMinutes: this.otpOpt.ttlMinutes });
    } catch (error) {
      await this.otps.delete({ email, purpose });
      throw error;
    }
  }

  private async checkOtp(email: string, purpose: OtpPurpose, code: string): Promise<void> {
    const rec = await this.otps.findOne({ email, purpose });
    if (!rec) throw new AuthError('OTP tidak ditemukan, silakan minta ulang', 400, 'OTP_NOT_FOUND');

    if (Number(rec.expiresAt) < Date.now()) {
      await this.otps.delete({ id: rec.id });
      throw new AuthError('OTP sudah kedaluwarsa', 400, 'OTP_EXPIRED');
    }
    if (Number(rec.attempts) >= this.otpOpt.maxAttempts) {
      await this.otps.delete({ id: rec.id });
      throw new AuthError('Terlalu banyak percobaan, minta OTP baru', 429, 'OTP_TOO_MANY_ATTEMPTS');
    }
    if (!safeEqual(this.hashOtp(email, purpose, code), rec.codeHash)) {
      await this.otps.update({ id: rec.id }, { attempts: Number(rec.attempts) + 1 });
      throw new AuthError('Kode OTP salah', 400, 'OTP_INVALID');
    }
    await this.otps.delete({ id: rec.id }); // sekali pakai
  }

  // ---------- Token ----------
  private async issueTokens(user: U): Promise<AuthTokens> {
    const accessToken = signJwt({ email: user.email, role: user.role }, this.jwtOpt.accessSecret, {
      subject: String(user.id),
      expiresIn: this.jwtOpt.accessExpiresIn,
    });

    const jti = randomUUID();
    const refreshToken = signJwt({}, this.jwtOpt.refreshSecret, {
      subject: String(user.id),
      jwtid: jti,
      expiresIn: this.jwtOpt.refreshExpiresIn,
    });
    const exp = decodeJwtUnsafe(refreshToken)?.exp as number;

    // Yang disimpan hanya HASH refresh token, bukan token aslinya
    await this.refreshTokens.create({
      id: jti,
      userId: String(user.id),
      tokenHash: sha256(refreshToken),
      expiresAt: exp * 1000,
      createdAt: Date.now(),
    });

    return { accessToken, refreshToken, tokenType: 'Bearer', expiresIn: this.jwtOpt.accessExpiresIn };
  }

  verifyAccessToken(token: string): AccessTokenPayload {
    try {
      const p = verifyJwt(token, this.jwtOpt.accessSecret);
      if (typeof p.sub !== 'string' || typeof p.email !== 'string' || typeof p.role !== 'string') {
        throw new JwtError('invalid');
      }
      return p as AccessTokenPayload;
    } catch (e) {
      if (e instanceof JwtError && e.reason === 'expired') {
        throw new AuthError('Access token kedaluwarsa', 401, 'TOKEN_EXPIRED');
      }
      throw new AuthError('Access token tidak valid', 401, 'INVALID_TOKEN');
    }
  }

  /** Rotasi refresh token: token lama dihapus, token baru dibuat. */
  async refresh(input: { refreshToken?: string } = {}): Promise<AuthSuccess<U>> {
    const refreshToken = typeof input.refreshToken === 'string' ? input.refreshToken : '';
    let payload: JwtPayload;
    try {
      payload = verifyJwt(refreshToken, this.jwtOpt.refreshSecret);
    } catch {
      throw new AuthError('Refresh token tidak valid atau kedaluwarsa', 401, 'INVALID_REFRESH_TOKEN');
    }
    if (!payload.sub || !payload.jti) throw new AuthError('Refresh token tidak valid', 401, 'INVALID_REFRESH_TOKEN');
    const userId = String(payload.sub);

    return this.withOperationLock(`refresh:${sha256(refreshToken)}`, async () => {
      const stored = await this.refreshTokens.findOne({ tokenHash: sha256(refreshToken) });
      if (!stored || stored.id !== payload.jti || stored.userId !== userId || Number(stored.expiresAt) <= Date.now()) {
        // Token valid tapi sudah tidak ada di store = kemungkinan dipakai ulang/dicuri
        await this.refreshTokens.delete({ userId });
        throw new AuthError('Refresh token sudah dipakai, silakan login ulang', 401, 'REFRESH_TOKEN_REUSED');
      }

      await this.refreshTokens.delete({ id: stored.id });
      const user = await this.users.findOne({ id: userId });
      if (!user) throw new AuthError('User tidak ditemukan', 401, 'USER_NOT_FOUND');

      return { user: this.publicUser(user), ...(await this.issueTokens(user)) };
    });
  }

  async logout(input: { refreshToken?: string } = {}): Promise<{ ok: true }> {
    if (typeof input.refreshToken === 'string' && input.refreshToken) {
      await this.refreshTokens.delete({ tokenHash: sha256(input.refreshToken) });
    }
    return { ok: true };
  }

  async logoutAll(userId: string): Promise<{ ok: true }> {
    await this.refreshTokens.delete({ userId: String(userId) });
    return { ok: true };
  }

  // ---------- Dashboard / Profile ----------
  async getProfile(userId: string): Promise<PublicUser<U>> {
    const user = await this.users.findOne({ id: userId });
    if (!user) throw new AuthError('User tidak ditemukan', 404, 'USER_NOT_FOUND');
    return this.publicUser(user);
  }

  // ---------- Middleware ----------
  authenticate(opts?: AuthenticateOptions): Handler {
    return createAuthenticate(this, opts);
  }
  authorize(...roles: string[]): Handler {
    return createAuthorize(...roles);
  }
}
