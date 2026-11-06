/** Error yang otomatis diubah menjadi respons JSON dengan status HTTP yang sesuai. */
export class HttpError extends Error {
  readonly status: number;
  readonly code: string;
  readonly headers?: Record<string, string>;

  constructor(message: string, status = 500, code = 'HTTP_ERROR', headers?: Record<string, string>) {
    super(message);
    this.name = 'HttpError';
    this.status = status;
    this.code = code;
    this.headers = headers;
  }
}

export class AuthError extends HttpError {
  constructor(message: string, status = 400, code = 'AUTH_ERROR') {
    super(message, status, code);
    this.name = 'AuthError';
  }
}
