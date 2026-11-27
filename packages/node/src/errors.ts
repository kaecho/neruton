import type { TransportInfo } from './tls-stealth.js';

export class NerutonError extends Error {
  readonly code: string;

  constructor(message: string, code = 'NERUTON_ERROR', options?: ErrorOptions) {
    super(message, options);
    this.name = new.target.name;
    this.code = code;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export type PrefixErrorKind = 'empty' | 'too_long' | 'invalid_format' | 'reserved';

export class PrefixError extends NerutonError {
  readonly kind: PrefixErrorKind;
  readonly value: string;

  constructor(kind: PrefixErrorKind, value: string, message: string) {
    super(message, 'PREFIX_INVALID');
    this.kind = kind;
    this.value = value;
  }
}

export class AuthenticationError extends NerutonError {
  readonly statusCode: number;
  readonly serverMessage: string | undefined;
  readonly hadToken: boolean;
  readonly transport: TransportInfo | undefined;

  constructor(
    message: string,
    opts: { statusCode?: number; serverMessage?: string; hadToken: boolean; transport?: TransportInfo },
  ) {
    super(message, 'AUTH_FAILED');
    this.statusCode = opts.statusCode ?? 401;
    this.serverMessage = opts.serverMessage;
    this.hadToken = opts.hadToken;
    this.transport = opts.transport;
  }
}

export class RegistrationError extends NerutonError {
  readonly retryable: boolean;
  readonly serverMessage: string;

  constructor(message: string, opts: { retryable: boolean; serverMessage: string }) {
    super(message, 'REGISTRATION_REJECTED');
    this.retryable = opts.retryable;
    this.serverMessage = opts.serverMessage;
  }
}

export class YamuxError extends NerutonError {
  readonly goAwayCode: number | undefined;

  constructor(message: string, opts?: { code?: string; goAwayCode?: number; cause?: unknown }) {
    super(message, opts?.code ?? 'YAMUX_ERROR', opts?.cause !== undefined ? { cause: opts.cause } : undefined);
    this.goAwayCode = opts?.goAwayCode;
  }
}

export class ConfigError extends NerutonError {
  constructor(message: string, options?: ErrorOptions) {
    super(message, 'CONFIG_ERROR', options);
  }
}

export class DohError extends NerutonError {
  readonly endpoints: readonly string[];

  constructor(
    message: string,
    opts?: { code?: string; endpoints?: readonly string[]; cause?: unknown },
  ) {
    super(
      message,
      opts?.code ?? 'DOH_FAILED',
      opts?.cause !== undefined ? { cause: opts.cause } : undefined,
    );
    this.endpoints = opts?.endpoints ?? [];
  }
}
