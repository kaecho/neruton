import { EventEmitter } from 'node:events';
import type http from 'node:http';
import type tls from 'node:tls';
import WebSocket, { type RawData } from 'ws';
import { VERSION } from './constants.js';
import { resolveConnectionSettings } from './config.js';
import {
  resolveHostWithDoh,
  stripBrackets,
  type DohOption,
  type ParsedDohConfig,
} from './doh.js';
import {
  AuthenticationError,
  ConfigError,
  DohError,
  NerutonError,
  RegistrationError,
} from './errors.js';
import {
  createTargetConfig,
  LocalForwarder,
  type ForwardedRequestEvent,
  type TargetConfig,
} from './forwarder.js';
import {
  buildTunnelWsUrl,
  format401Error,
  formatClientOs,
  isNonRetryableRejection,
  normalizeTargetUrl,
  validatePrefix,
  type RegisterRequest,
  type RegisterResponse,
} from './protocol.js';
import {
  assertSniModeSupported,
  connectTcpWithFailover,
  createStealthTlsSocket,
  formatTransportSummary,
  planStealthTls,
  type ClientHelloFragmentDuplex,
  type EchStatus,
  type SniMode,
  type TcpConnectResult,
  type TransportInfo,
} from './tls-stealth.js';
import {
  EchRejectedError,
  connectTls13EchWithRetry,
  type ConnectTls13EchResult,
} from './tls13-ech.js';
import { WsByteStream } from './ws-stream.js';
import { YamuxGoAwayCode, YamuxSession } from './yamux.js';

export interface ConnectOptions {
  /** Local target URL or port (e.g. 'http://127.0.0.1:3000', 'localhost:3000', '3000', or 3000). */
  url: string | number;
  /** Neruton gateway server URL (defaults to NERUTON_SERVER, config.toml, or https://neruton.moer.eu.org). */
  server?: string;
  /** Tunnel authentication token (defaults to NERUTON_TOKEN, NERUTON_AUTH_TOKEN, or config.toml). */
  token?: string;
  /** Custom subdomain prefix (server generates a UUID v4 if omitted). */
  subdomain?: string;
  /** Alias for `subdomain`. */
  prefix?: string;
  /** Disable TLS certificate verification for self-signed servers or local HTTPS targets. */
  noTlsVerify?: boolean;
  /** Host header mode sent to local service: `'rewrite'` (default), `'preserve'`, or custom value. */
  hostHeader?: string;
  /** Explicit path to `config.toml` (default: `~/.config/neruton/config.toml`). */
  configPath?: string;
  /** DNS-over-HTTPS mode (`'auto'`, `'strict'`, `'off'`, `boolean`) or custom RFC 8484 endpoint URL(s). Default: `'auto'`. */
  doh?: DohOption;
  /** SNI hiding mode: `'auto'` (default), `'ech'`, `'fragment'`, `'none'`, or `'plain'`. */
  sniMode?: SniMode;
  /** Custom TLS SNI hostname (server certificate is still strictly verified against the real host). */
  sni?: string;
  /** Optional base64-encoded ECHConfigList overriding DoH HTTPS records for TLS 1.3 ECH. */
  echConfig?: string;
  /** Optional custom CA certificate(s) for verifying TLS gateway and custom DoH servers. */
  ca?: string | Buffer | Array<string | Buffer>;
  /** Optional per-endpoint DoH timeout in ms (default: `3000`). */
  dohTimeoutMs?: number;
  /** Reconnect automatically after transient disconnects once connected (default: `true`). */
  reconnect?: boolean;
  /** Retry initial connection on transient network failures (default: `false`; `true` in CLI). */
  retryInitialConnect?: boolean;
  /** Initial reconnect backoff delay in ms (default: `1000`). */
  reconnectInitialDelayMs?: number;
  /** Maximum reconnect backoff delay in ms (default: `30000`). */
  reconnectMaxDelayMs?: number;
  /** Registration handshake timeout in ms (default: `10000`). */
  handshakeTimeoutMs?: number;
  /** Optional WebSocket keepalive ping interval in ms (`0` disables client pings, default: `30000`). */
  keepaliveIntervalMs?: number;
  /** Optional `AbortSignal` to cancel connection or close the running tunnel. */
  signal?: AbortSignal;
  /** Optional callback invoked on reconnect attempts (including during initial connect retries). */
  onReconnecting?: (event: TunnelReconnectingEvent) => void;
  /** Optional callback invoked for non-fatal warnings (such as DoH or ECH auto-mode fallbacks/retries). */
  onWarning?: (message: string) => void;
  /** Optional callback invoked as soon as the underlying TLS / ECH transport is established. */
  onTransport?: (info: TransportInfo) => void;
}

export type TunnelOptions = ConnectOptions;

export type ForwardOptions = Omit<ConnectOptions, 'url'>;

export interface TunnelConnectedEvent {
  publicUrl: string;
  previewUrl: string;
  pathUrl: string;
  dashboardUrl: string;
  prefix: string;
  tunnelId: string;
  ownerUsername: string | null;
  tokenName: string | null;
  reconnected: boolean;
  transport?: TransportInfo;
}

export interface TunnelReconnectingEvent {
  attempt: number;
  delayMs: number;
  reason: string;
}

export interface TunnelDisconnectedEvent {
  reason: string;
  willReconnect: boolean;
}

export type TunnelRequestEvent = ForwardedRequestEvent;

export interface TunnelEventMap {
  connected: [event: TunnelConnectedEvent];
  reconnecting: [event: TunnelReconnectingEvent];
  disconnected: [event: TunnelDisconnectedEvent];
  error: [error: Error];
  request: [event: TunnelRequestEvent];
  warning: [message: string];
  transport: [info: TransportInfo];
}

const FATAL_ECH_ERROR_CODES = new Set([
  'ECH_UNSUPPORTED',
  'ECH_REQUIRED',
  'ECH_INVALID_CONFIG',
  'ECH_REJECTED',
]);

interface ActiveSession {
  ws: WebSocket;
  wsStream: WsByteStream;
  yamux: YamuxSession;
  regResp: RegisterResponse;
  transportInfo: TransportInfo;
  connectedAt: number;
  keepaliveTimer?: NodeJS.Timeout;
  closedPromise: Promise<string>;
}

function rawDataToBuffer(data: RawData): Buffer {
  if (Buffer.isBuffer(data)) return data;
  if (Array.isArray(data)) return Buffer.concat(data);
  return Buffer.from(data);
}

function sleep(ms: number, signal?: AbortSignal): Promise<boolean> {
  return new Promise<boolean>((resolve) => {
    if (signal?.aborted) {
      resolve(false);
      return;
    }
    const onAbort = (): void => {
      clearTimeout(timer);
      resolve(false);
    };
    const timer = setTimeout(() => {
      signal?.removeEventListener('abort', onAbort);
      resolve(true);
    }, ms);
    timer.unref?.();
    signal?.addEventListener('abort', onAbort, { once: true });
  });
}

function readHttpResponseBody(res: http.IncomingMessage): Promise<Buffer> {
  return new Promise<Buffer>((resolve) => {
    const chunks: Buffer[] = [];
    res.on('data', (chunk: Buffer | string) => {
      chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
    });
    res.on('end', () => resolve(Buffer.concat(chunks)));
    res.on('error', () => resolve(Buffer.concat(chunks)));
  });
}

export class Tunnel extends EventEmitter {
  private readonly wsUrl: URL;
  private readonly targetConfig: TargetConfig;
  private readonly token: string | undefined;
  private readonly noTlsVerify: boolean;
  private readonly dohConfig: ParsedDohConfig;
  private readonly sniMode: SniMode;
  private readonly sni: string | undefined;
  private readonly echConfig: string | undefined;
  private readonly ca: string | Buffer | Array<string | Buffer> | undefined;
  private readonly dohTimeoutMs: number | undefined;
  private readonly reconnectEnabled: boolean;
  private readonly retryInitialConnect: boolean;
  private readonly reconnectInitialDelayMs: number;
  private readonly reconnectMaxDelayMs: number;
  private readonly handshakeTimeoutMs: number;
  private readonly keepaliveIntervalMs: number;
  private readonly forwarder: LocalForwarder;
  private readonly externalSignal: AbortSignal | undefined;
  private readonly closeController = new AbortController();

  private stickyPrefix: string | null;
  private everConnected = false;
  private _connected = false;
  private _closed = false;
  private activeSession: ActiveSession | null = null;
  private lastRegResp: RegisterResponse | null = null;
  private lastTransportInfo: TransportInfo | null = null;
  private loopPromise: Promise<void> | null = null;
  private closePromise: Promise<void> | null = null;
  private fatalError: Error | null = null;
  private readonly waitResolvers: Array<{ resolve: () => void; reject: (err: Error) => void }> = [];
  private externalAbortListener?: () => void;

  private constructor(params: {
    wsUrl: URL;
    targetConfig: TargetConfig;
    token: string | undefined;
    initialPrefix: string | null;
    noTlsVerify: boolean;
    dohConfig: ParsedDohConfig;
    sniMode: SniMode;
    sni: string | undefined;
    echConfig: string | undefined;
    ca: string | Buffer | Array<string | Buffer> | undefined;
    dohTimeoutMs: number | undefined;
    reconnect: boolean;
    retryInitialConnect: boolean;
    reconnectInitialDelayMs: number;
    reconnectMaxDelayMs: number;
    handshakeTimeoutMs: number;
    keepaliveIntervalMs: number;
    signal?: AbortSignal;
  }) {
    super();
    this.wsUrl = params.wsUrl;
    this.targetConfig = params.targetConfig;
    this.token = params.token;
    this.stickyPrefix = params.initialPrefix;
    this.noTlsVerify = params.noTlsVerify;
    this.dohConfig = params.dohConfig;
    this.sniMode = params.sniMode;
    this.sni = params.sni;
    this.echConfig = params.echConfig;
    this.ca = params.ca;
    this.dohTimeoutMs = params.dohTimeoutMs;
    this.reconnectEnabled = params.reconnect;
    this.retryInitialConnect = params.retryInitialConnect;
    this.reconnectInitialDelayMs = params.reconnectInitialDelayMs;
    this.reconnectMaxDelayMs = params.reconnectMaxDelayMs;
    this.handshakeTimeoutMs = params.handshakeTimeoutMs;
    this.keepaliveIntervalMs = params.keepaliveIntervalMs;
    this.externalSignal = params.signal;

    this.forwarder = new LocalForwarder(this.targetConfig, (event) => {
      this.emit('request', event);
    });

    if (this.externalSignal) {
      if (this.externalSignal.aborted) {
        this.closeController.abort();
      } else {
        this.externalAbortListener = () => {
          void this.close();
        };
        this.externalSignal.addEventListener('abort', this.externalAbortListener, { once: true });
      }
    }
  }

  /** @internal */
  static async _createAndStart(options: ConnectOptions): Promise<Tunnel> {
    if (options.signal?.aborted) {
      throw new NerutonError('tunnel connection aborted', 'ABORTED');
    }

    const targetUrl = normalizeTargetUrl(options.url);
    const settings = resolveConnectionSettings({
      server: options.server,
      token: options.token,
      doh: options.doh,
      sniMode: options.sniMode,
      sni: options.sni,
      echConfig: options.echConfig,
      configPath: options.configPath,
    });
    assertSniModeSupported(settings.sniMode);
    const wsUrl = buildTunnelWsUrl(settings.server);

    const rawSubdomain = options.subdomain ?? options.prefix;
    let initialPrefix: string | null = null;
    if (rawSubdomain !== undefined && rawSubdomain.trim().length > 0) {
      initialPrefix = validatePrefix(rawSubdomain);
    }

    const targetConfig = createTargetConfig(targetUrl, {
      hostHeader: options.hostHeader,
      noTlsVerify: options.noTlsVerify,
    });

    const tunnel = new Tunnel({
      wsUrl,
      targetConfig,
      token: settings.token,
      initialPrefix,
      noTlsVerify: Boolean(options.noTlsVerify),
      dohConfig: settings.doh,
      sniMode: settings.sniMode,
      sni: settings.sni,
      echConfig: settings.echConfig,
      ca: options.ca,
      dohTimeoutMs: options.dohTimeoutMs,
      reconnect: options.reconnect ?? true,
      retryInitialConnect: options.retryInitialConnect ?? false,
      reconnectInitialDelayMs: options.reconnectInitialDelayMs ?? 1000,
      reconnectMaxDelayMs: options.reconnectMaxDelayMs ?? 30_000,
      handshakeTimeoutMs: options.handshakeTimeoutMs ?? 10_000,
      keepaliveIntervalMs: options.keepaliveIntervalMs ?? 30_000,
      signal: options.signal,
    });

    if (options.onReconnecting) {
      tunnel.on('reconnecting', options.onReconnecting);
    }
    if (options.onWarning) {
      tunnel.on('warning', options.onWarning);
    }
    if (options.onTransport) {
      tunnel.on('transport', options.onTransport);
    }

    await tunnel.startInitialConnection();
    return tunnel;
  }

  // Typed EventEmitter overloads
  override on<K extends keyof TunnelEventMap>(
    event: K,
    listener: (...args: TunnelEventMap[K]) => void,
  ): this {
    return super.on(event, listener as (...args: unknown[]) => void);
  }

  override once<K extends keyof TunnelEventMap>(
    event: K,
    listener: (...args: TunnelEventMap[K]) => void,
  ): this {
    return super.once(event, listener as (...args: unknown[]) => void);
  }

  override off<K extends keyof TunnelEventMap>(
    event: K,
    listener: (...args: TunnelEventMap[K]) => void,
  ): this {
    return super.off(event, listener as (...args: unknown[]) => void);
  }

  override addListener<K extends keyof TunnelEventMap>(
    event: K,
    listener: (...args: TunnelEventMap[K]) => void,
  ): this {
    return super.addListener(event, listener as (...args: unknown[]) => void);
  }

  override removeListener<K extends keyof TunnelEventMap>(
    event: K,
    listener: (...args: TunnelEventMap[K]) => void,
  ): this {
    return super.removeListener(event, listener as (...args: unknown[]) => void);
  }

  get publicUrl(): string {
    return this.lastRegResp?.public_url ?? '';
  }

  get previewUrl(): string {
    return this.lastRegResp?.preview_url ?? '';
  }

  get pathUrl(): string {
    return this.lastRegResp?.path_url ?? '';
  }

  get dashboardUrl(): string {
    return this.lastRegResp?.dashboard_url ?? '';
  }

  get prefix(): string {
    return this.lastRegResp?.prefix ?? this.stickyPrefix ?? '';
  }

  get tunnelId(): string {
    return this.lastRegResp?.tunnel_id ?? '';
  }

  get targetUrl(): string {
    return this.targetConfig.url.toString();
  }

  get ownerUsername(): string | null {
    return this.lastRegResp?.owner_username ?? null;
  }

  get tokenName(): string | null {
    return this.lastRegResp?.token_name ?? null;
  }

  get connected(): boolean {
    return this._connected;
  }

  get closed(): boolean {
    return this._closed;
  }

  get transportInfo(): TransportInfo | null {
    return this.lastTransportInfo;
  }

  /**
   * Wait until the tunnel closes cleanly, or rejects if terminated by a fatal error.
   */
  wait(): Promise<void> {
    if (this._closed) {
      return this.fatalError ? Promise.reject(this.fatalError) : Promise.resolve();
    }
    return new Promise<void>((resolve, reject) => {
      this.waitResolvers.push({ resolve, reject });
    });
  }

  /**
   * Gracefully close the tunnel, sending Yamux `GoAway(Normal)` and stopping reconnects.
   */
  close(): Promise<void> {
    if (this.closePromise) {
      return this.closePromise;
    }
    this.closePromise = this.closeInternal();
    return this.closePromise;
  }

  private async teardownSession(session: ActiveSession): Promise<void> {
    if (session.keepaliveTimer) {
      clearInterval(session.keepaliveTimer);
      session.keepaliveTimer = undefined;
    }
    await Promise.race([
      session.yamux.close(YamuxGoAwayCode.Normal),
      sleep(2000),
    ]);
    if (
      session.ws.readyState === WebSocket.OPEN ||
      session.ws.readyState === WebSocket.CONNECTING
    ) {
      session.ws.on('error', () => {});
      try {
        if (session.ws.readyState === WebSocket.OPEN) {
          session.ws.close(1000);
        } else {
          session.ws.terminate();
        }
      } catch {
        session.ws.terminate();
      }
    }
  }

  private async closeInternal(): Promise<void> {
    this._closed = true;
    this._connected = false;
    this.closeController.abort();

    if (this.externalSignal && this.externalAbortListener) {
      this.externalSignal.removeEventListener('abort', this.externalAbortListener);
      this.externalAbortListener = undefined;
    }

    const session = this.activeSession;
    this.activeSession = null;
    if (session) {
      await this.teardownSession(session);
    }

    if (this.loopPromise) {
      await this.loopPromise;
    }
    this.settleWaiters();
  }

  declare [Symbol.asyncDispose]: () => Promise<void>;

  private settleWaiters(err?: Error): void {
    if (err && !this.fatalError) {
      this.fatalError = err;
    }
    const waiters = this.waitResolvers.splice(0, this.waitResolvers.length);
    for (const w of waiters) {
      if (this.fatalError) {
        w.reject(this.fatalError);
      } else {
        w.resolve();
      }
    }
  }

  private emitErrorSafe(err: Error): void {
    if (this.listenerCount('error') > 0) {
      this.emit('error', err);
    }
  }

  private async startInitialConnection(): Promise<void> {
    let backoff = this.reconnectInitialDelayMs;
    let attempt = 0;

    while (true) {
      if (this._closed || this.closeController.signal.aborted) {
        throw new NerutonError('tunnel connection aborted', 'ABORTED');
      }

      try {
        const session = await this.openSingleSession();
        if (this._closed || this.closeController.signal.aborted) {
          await this.teardownSession(session);
          this._closed = true;
          const abortErr = new NerutonError('tunnel connection aborted', 'ABORTED');
          this.settleWaiters(abortErr);
          throw abortErr;
        }
        this.activateSession(session, false);
        this.loopPromise = this.runReconnectLoop(session);
        return;
      } catch (err) {
        const error = err instanceof Error ? err : new Error(String(err));
        const isFatal =
          error instanceof AuthenticationError ||
          error instanceof ConfigError ||
          (error instanceof NerutonError && FATAL_ECH_ERROR_CODES.has(error.code)) ||
          (error instanceof RegistrationError && !error.retryable);

        if (isFatal || !this.retryInitialConnect) {
          this._closed = true;
          this.settleWaiters(error);
          throw error;
        }

        attempt += 1;
        this.emit('reconnecting', {
          attempt,
          delayMs: backoff,
          reason: error.message,
        });

        const continued = await sleep(backoff, this.closeController.signal);
        if (!continued) {
          this._closed = true;
          const abortErr = new NerutonError('tunnel connection aborted during reconnect backoff', 'ABORTED');
          this.settleWaiters(abortErr);
          throw abortErr;
        }
        backoff = Math.min(backoff * 2, this.reconnectMaxDelayMs);
      }
    }
  }

  private activateSession(session: ActiveSession, reconnected: boolean): void {
    this.activeSession = session;
    this.lastRegResp = session.regResp;
    this.lastTransportInfo = session.transportInfo;
    this.stickyPrefix = session.regResp.prefix;
    this.everConnected = true;
    this._connected = true;

    this.emit('connected', {
      publicUrl: session.regResp.public_url,
      previewUrl: session.regResp.preview_url,
      pathUrl: session.regResp.path_url,
      dashboardUrl: session.regResp.dashboard_url,
      prefix: session.regResp.prefix,
      tunnelId: session.regResp.tunnel_id,
      ownerUsername: session.regResp.owner_username ?? null,
      tokenName: session.regResp.token_name ?? null,
      reconnected,
      transport: session.transportInfo,
    });
  }

  private async runReconnectLoop(initialSession: ActiveSession): Promise<void> {
    let currentSession: ActiveSession | null = initialSession;
    let backoff = this.reconnectInitialDelayMs;
    let attempt = 0;

    try {
      while (!this._closed && !this.closeController.signal.aborted) {
        if (currentSession) {
          const reason = await currentSession.closedPromise;
          if (currentSession.keepaliveTimer) {
            clearInterval(currentSession.keepaliveTimer);
            currentSession.keepaliveTimer = undefined;
          }
          const durationMs = Date.now() - currentSession.connectedAt;
          if (this.activeSession === currentSession) {
            this.activeSession = null;
          }
          this._connected = false;
          currentSession = null;

          if (this._closed || this.closeController.signal.aborted) {
            this.emit('disconnected', { reason: 'closed by client', willReconnect: false });
            break;
          }

          if (durationMs >= 10_000) {
            backoff = this.reconnectInitialDelayMs;
            attempt = 0;
          }

          if (!this.reconnectEnabled) {
            this.emit('disconnected', { reason, willReconnect: false });
            this._closed = true;
            break;
          }

          this.emit('disconnected', { reason, willReconnect: true });
          attempt += 1;
          this.emit('reconnecting', { attempt, delayMs: backoff, reason });

          const continued = await sleep(backoff, this.closeController.signal);
          if (!continued || this._closed) {
            break;
          }
          backoff = Math.min(backoff * 2, this.reconnectMaxDelayMs);
        }

        try {
          const nextSession = await this.openSingleSession();
          if (this._closed || this.closeController.signal.aborted) {
            await this.teardownSession(nextSession);
            break;
          }
          this.activateSession(nextSession, true);
          currentSession = nextSession;
        } catch (err) {
          const error = err instanceof Error ? err : new Error(String(err));
          const isFatal =
            error instanceof AuthenticationError ||
            error instanceof ConfigError ||
            (error instanceof NerutonError && FATAL_ECH_ERROR_CODES.has(error.code)) ||
            (error instanceof RegistrationError && !error.retryable);

          if (isFatal) {
            this._closed = true;
            this._connected = false;
            this.emit('disconnected', { reason: error.message, willReconnect: false });
            this.emitErrorSafe(error);
            this.settleWaiters(error);
            return;
          }

          if (this._closed || this.closeController.signal.aborted) {
            break;
          }

          attempt += 1;
          this.emit('reconnecting', {
            attempt,
            delayMs: backoff,
            reason: error.message,
          });
          const continued = await sleep(backoff, this.closeController.signal);
          if (!continued || this._closed) {
            break;
          }
          backoff = Math.min(backoff * 2, this.reconnectMaxDelayMs);
        }
      }
    } finally {
      if (currentSession) {
        const leftover = currentSession;
        currentSession = null;
        if (this.activeSession === leftover) {
          this.activeSession = null;
        }
        await this.teardownSession(leftover);
      }
      this._connected = false;
      this._closed = true;
      if (this.externalSignal && this.externalAbortListener) {
        this.externalSignal.removeEventListener('abort', this.externalAbortListener);
        this.externalAbortListener = undefined;
      }
      this.settleWaiters();
    }
  }

  private async openSingleSession(): Promise<ActiveSession> {
    if (this._closed || this.closeController.signal.aborted) {
      throw new NerutonError('tunnel closed', 'ABORTED');
    }

    const realHost = stripBrackets(this.wsUrl.hostname);
    if (this.wsUrl.protocol !== 'wss:' && this.sniMode === 'ech') {
      throw new NerutonError(
        `ECH mode (sniMode 'ech') requires a wss:// (HTTPS) server URL, got '${this.wsUrl.toString()}'`,
        'ECH_REQUIRED',
      );
    }

    const dohRes = await resolveHostWithDoh(realHost, {
      doh: this.dohConfig,
      timeoutMs: this.dohTimeoutMs,
      signal: this.closeController.signal,
      ca: this.ca,
      onWarn: (msg) => {
        this.emit('warning', msg);
      },
    });

    if (this._closed || this.closeController.signal.aborted) {
      throw new NerutonError('tunnel connection aborted', 'ABORTED');
    }

    if (dohRes.source === 'doh' && dohRes.addresses.length === 0) {
      throw new DohError(`DoH resolved no IP addresses for '${realHost}'`, {
        code: 'DOH_NO_ADDRESSES',
        endpoints: dohRes.endpoint ? [dohRes.endpoint] : this.dohConfig.endpoints,
      });
    }

    let plan = planStealthTls({
      wsUrl: this.wsUrl,
      sniMode: this.sniMode,
      sni: this.sni,
      echConfig: this.echConfig,
      dohEchConfigs: dohRes.echConfigs,
    });

    const targets =
      dohRes.addresses.length > 0
        ? dohRes.addresses.map((host) => ({ host, port: plan.port }))
        : [{ host: plan.realHost, port: plan.port }];

    let echConn: ConnectTls13EchResult | undefined;
    let echFallback = false;

    if (plan.useEch) {
      try {
        echConn = await connectTls13EchWithRetry({
          realHost: plan.realHost,
          echConfigList: plan.echConfigLists,
          connectTcp: (remainingMs) =>
            connectTcpWithFailover(targets, {
              timeoutMs: remainingMs,
              signal: this.closeController.signal,
            }),
          noTlsVerify: this.noTlsVerify,
          ca: this.ca,
          alpn: ['http/1.1'],
          timeoutMs: this.handshakeTimeoutMs,
          signal: this.closeController.signal,
          onWarn: (msg) => {
            this.emit('warning', msg);
          },
        });
      } catch (err) {
        if (this._closed || this.closeController.signal.aborted) {
          throw new NerutonError('tunnel connection aborted', 'ABORTED');
        }
        const canFallback =
          plan.echAllowFallback &&
          (err instanceof EchRejectedError ||
            (err instanceof NerutonError && err.code === 'ECH_INVALID_CONFIG'));
        if (canFallback) {
          const reason = err instanceof Error ? err.message : String(err);
          this.emit(
            'warning',
            `ECH unavailable (${reason}); falling back to ClientHello TCP fragmentation.`,
          );
          echFallback = true;
          plan = {
            ...plan,
            effectiveSniMode: 'fragment',
            servername: plan.realHost,
            fragmentClientHello: true,
            useEch: false,
            echAllowFallback: false,
            outerSni: undefined,
          };
        } else {
          throw err;
        }
      }

      if (echConn && (this._closed || this.closeController.signal.aborted)) {
        echConn.duplex.destroy();
        throw new NerutonError('tunnel connection aborted', 'ABORTED');
      }
    }

    const useCustomTransport =
      !echConn &&
      (dohRes.source === 'doh' ||
        plan.fragmentClientHello ||
        plan.effectiveSniMode === 'none' ||
        Boolean(plan.customSni) ||
        this.ca !== undefined);

    let tcpConn: TcpConnectResult | undefined;
    if (useCustomTransport) {
      tcpConn = await connectTcpWithFailover(targets, {
        timeoutMs: this.handshakeTimeoutMs,
        signal: this.closeController.signal,
      });
      if (this._closed || this.closeController.signal.aborted) {
        if (!tcpConn.socket.destroyed) {
          tcpConn.socket.destroy();
        }
        throw new NerutonError('tunnel connection aborted', 'ABORTED');
      }
    }

    const prebuiltEchTransportInfo: TransportInfo | undefined = echConn
      ? (() => {
          const base: Omit<TransportInfo, 'summary'> = {
            dohMode: this.dohConfig.mode,
            dohSource: dohRes.source,
            dohEndpoint: dohRes.endpoint,
            resolvedIp: echConn.address,
            resolvedAddresses: [...dohRes.addresses],
            echConfigsAvailable: Math.max(dohRes.echConfigs.length, plan.echConfigLists.length),
            echStatus: 'accepted' as EchStatus,
            outerSni: echConn.outerSni,
            echRetried: echConn.echRetried,
            sniMode: this.sniMode,
            effectiveSniMode: 'ech',
            sni: undefined,
            fragmented: false,
            fragmentCount: 0,
            tlsProtocol: echConn.duplex.getProtocol(),
            tlsAuthorized: echConn.duplex.authorized,
          };
          return {
            ...base,
            summary: formatTransportSummary(base),
          };
        })()
      : undefined;

    if (prebuiltEchTransportInfo) {
      this.lastTransportInfo = prebuiltEchTransportInfo;
      this.emit('transport', prebuiltEchTransportInfo);
    }

    return new Promise<ActiveSession>((resolve, reject) => {
      if (this._closed || this.closeController.signal.aborted) {
        if (echConn && !echConn.duplex.destroyed) {
          echConn.duplex.destroy();
        }
        if (tcpConn && !tcpConn.socket.destroyed) {
          tcpConn.socket.destroy();
        }
        reject(new NerutonError('tunnel closed', 'ABORTED'));
        return;
      }

      const headers: Record<string, string> = {};
      if (this.token) {
        headers.Authorization = `Bearer ${this.token}`;
      }

      let activeTlsSocket: tls.TLSSocket | undefined;
      let activeDuplex: ClientHelloFragmentDuplex | undefined;
      let socketAdopted = false;

      const wsOptions: WebSocket.ClientOptions = {
        headers,
        rejectUnauthorized: !this.noTlsVerify,
        handshakeTimeout: this.handshakeTimeoutMs,
      };

      if (echConn) {
        const echDuplex = echConn.duplex;
        wsOptions.createConnection = (() => {
          socketAdopted = true;
          return echDuplex;
        }) as unknown as WebSocket.ClientOptions['createConnection'];
      } else if (tcpConn) {
        const preconnectedSocket = tcpConn.socket;
        wsOptions.createConnection = (() => {
          socketAdopted = true;
          if (plan.protocol === 'wss:') {
            const wrapped = createStealthTlsSocket(preconnectedSocket, plan, {
              noTlsVerify: this.noTlsVerify,
              ca: this.ca,
            });
            activeTlsSocket = wrapped.socket;
            activeDuplex = wrapped.duplex;
            return wrapped.socket;
          }
          return preconnectedSocket;
        }) as unknown as WebSocket.ClientOptions['createConnection'];
      }

      let ws: WebSocket;
      try {
        ws = new WebSocket(this.wsUrl.toString(), wsOptions);
      } catch (err) {
        if (echConn && !socketAdopted && !echConn.duplex.destroyed) {
          echConn.duplex.destroy();
        }
        if (tcpConn && !socketAdopted && !tcpConn.socket.destroyed) {
          tcpConn.socket.destroy();
        }
        reject(err instanceof Error ? err : new Error(String(err)));
        return;
      }

      const buildTransportInfo = (): TransportInfo => {
        if (prebuiltEchTransportInfo) {
          return prebuiltEchTransportInfo;
        }
        const echStatus: EchStatus = echFallback ? 'fallback' : 'none';
        const base: Omit<TransportInfo, 'summary'> = {
          dohMode: this.dohConfig.mode,
          dohSource: dohRes.source,
          dohEndpoint: dohRes.endpoint,
          resolvedIp: tcpConn?.address,
          resolvedAddresses: [...dohRes.addresses],
          echConfigsAvailable: dohRes.echConfigs.length,
          echStatus,
          sniMode: this.sniMode,
          effectiveSniMode: plan.effectiveSniMode,
          sni: plan.customSni,
          fragmented: activeDuplex?.didFragment ?? false,
          fragmentCount: activeDuplex?.fragmentCount ?? 0,
          tlsProtocol: activeTlsSocket?.getProtocol() ?? undefined,
          tlsAuthorized: activeTlsSocket ? activeTlsSocket.authorized : undefined,
        };
        return {
          ...base,
          summary: formatTransportSummary(base),
        };
      };

      let settled = false;
      let handshakeDone = false;
      const earlyBinaryChunks: Buffer[] = [];
      let handshakeTimer: NodeJS.Timeout | undefined;

      const cleanupHandshake = (): void => {
        if (handshakeTimer) {
          clearTimeout(handshakeTimer);
          handshakeTimer = undefined;
        }
        ws.off('open', onOpen);
        ws.off('unexpected-response', onUnexpectedResponse);
        ws.off('error', onError);
        ws.off('close', onClose);
        this.closeController.signal.removeEventListener('abort', onAbort);
      };

      const fail = (err: Error): void => {
        if (settled) return;
        settled = true;
        cleanupHandshake();
        ws.off('message', onHandshakeMessage);
        // Attach a no-op error handler before terminating a CONNECTING socket so ws's
        // "WebSocket was closed before the connection was established" error never crashes Node.
        ws.on('error', () => {});
        if (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING) {
          try {
            ws.terminate();
          } catch {
            // Ignore.
          }
        }
        if (echConn && !socketAdopted && !echConn.duplex.destroyed) {
          echConn.duplex.destroy();
        }
        if (tcpConn && !socketAdopted && !tcpConn.socket.destroyed) {
          tcpConn.socket.destroy();
        }
        reject(err);
      };

      const onAbort = (): void => {
        fail(new NerutonError('tunnel connection aborted', 'ABORTED'));
      };
      this.closeController.signal.addEventListener('abort', onAbort, { once: true });

      const onUnexpectedResponse = (_req: http.ClientRequest, res: http.IncomingMessage): void => {
        void readHttpResponseBody(res).then((body) => {
          const status = res.statusCode ?? 0;
          if (status === 401) {
            const { message, serverMessage } = format401Error(body, Boolean(this.token));
            const transport = buildTransportInfo();
            this.lastTransportInfo = transport;
            fail(
              new AuthenticationError(message, {
                statusCode: 401,
                serverMessage,
                hadToken: Boolean(this.token),
                transport,
              }),
            );
            return;
          }
          const detail = body.toString('utf8').trim();
          fail(
            new NerutonError(
              `connect failed: unexpected HTTP ${status}${detail ? ` (${detail})` : ''}`,
              'WS_UPGRADE_FAILED',
            ),
          );
        });
      };

      const onError = (err: Error): void => {
        fail(new NerutonError(`connect failed: ${err.message}`, 'WS_CONNECT_FAILED', { cause: err }));
      };

      const onClose = (code: number, reasonBuf: Buffer): void => {
        const reasonText = reasonBuf.toString('utf8');
        fail(
          new NerutonError(
            `server closed connection before registration (code ${code}${reasonText ? `: ${reasonText}` : ''})`,
            'WS_CLOSED_EARLY',
          ),
        );
      };

      const onHandshakeMessage = (data: RawData, isBinary: boolean): void => {
        if (handshakeDone) {
          if (isBinary) {
            const buf = rawDataToBuffer(data);
            if (buf.length > 0) {
              earlyBinaryChunks.push(buf);
            }
          }
          return;
        }

        if (isBinary) {
          // Ignore non-text frames while waiting for RegisterResponse (matches tunnel.rs:206).
          return;
        }

        const text = rawDataToBuffer(data).toString('utf8');
        let regResp: RegisterResponse;
        try {
          regResp = JSON.parse(text) as RegisterResponse;
        } catch (err) {
          fail(
            new NerutonError(
              `invalid server response JSON: ${err instanceof Error ? err.message : String(err)}`,
              'INVALID_HANDSHAKE_JSON',
            ),
          );
          return;
        }

        if (typeof regResp.ok !== 'boolean') {
          fail(new NerutonError('invalid server registration response payload', 'INVALID_HANDSHAKE_JSON'));
          return;
        }

        if (!regResp.ok) {
          const serverMsg = regResp.error?.trim() || 'registration rejected by server';
          const retryable = this.everConnected && !isNonRetryableRejection(serverMsg);
          fail(
            new RegistrationError(`Registration rejected: ${serverMsg}`, {
              retryable,
              serverMessage: serverMsg,
            }),
          );
          return;
        }

        if (this._closed || this.closeController.signal.aborted) {
          fail(new NerutonError('tunnel connection aborted', 'ABORTED'));
          return;
        }

        // Registration succeeded! Synchronously switch to binary Yamux mode without losing any frames.
        handshakeDone = true;
        settled = true;
        cleanupHandshake();
        ws.off('message', onHandshakeMessage);

        const wsStream = new WsByteStream(ws, earlyBinaryChunks);
        const yamux = new YamuxSession(wsStream, { mode: 'server' });

        yamux.on('stream', (stream) => {
          this.forwarder.handleStream(stream);
        });

        let sessionClosedReason = 'tunnel stream closed by server';
        const closedPromise = new Promise<string>((resolveClosed) => {
          let resolved = false;
          const finish = (reason: string): void => {
            if (resolved) return;
            resolved = true;
            resolveClosed(reason);
          };

          yamux.on('goAway', (code) => {
            sessionClosedReason = `server sent GoAway (code ${code})`;
          });
          yamux.on('error', (err) => {
            sessionClosedReason = `yamux error: ${err.message}`;
            finish(sessionClosedReason);
          });
          yamux.on('close', () => {
            finish(sessionClosedReason);
          });
          ws.once('close', (code, reasonBuf) => {
            const textReason = reasonBuf.toString('utf8');
            sessionClosedReason = textReason
              ? `websocket closed (${code}: ${textReason})`
              : `websocket closed (${code})`;
            if (!yamux.isClosed) {
              yamux.destroy();
            }
            finish(sessionClosedReason);
          });
        });

        let keepaliveTimer: NodeJS.Timeout | undefined;
        if (this.keepaliveIntervalMs > 0) {
          let awaitingPong = false;
          const markAlive = (): void => {
            awaitingPong = false;
          };
          ws.on('pong', markAlive);
          ws.on('ping', markAlive);
          ws.on('message', markAlive);
          keepaliveTimer = setInterval(() => {
            if (ws.readyState !== WebSocket.OPEN) {
              return;
            }
            if (awaitingPong) {
              ws.terminate();
              return;
            }
            awaitingPong = true;
            try {
              ws.ping();
            } catch {
              ws.terminate();
            }
          }, this.keepaliveIntervalMs);
          keepaliveTimer.unref?.();
          ws.once('close', () => {
            if (keepaliveTimer) {
              clearInterval(keepaliveTimer);
              keepaliveTimer = undefined;
            }
            ws.off('pong', markAlive);
            ws.off('ping', markAlive);
            ws.off('message', markAlive);
          });
        }

        resolve({
          ws,
          wsStream,
          yamux,
          regResp,
          transportInfo: buildTransportInfo(),
          connectedAt: Date.now(),
          keepaliveTimer,
          closedPromise,
        });
      };

      const onOpen = (): void => {
        handshakeTimer = setTimeout(() => {
          fail(new NerutonError('registration timed out', 'HANDSHAKE_TIMEOUT'));
        }, this.handshakeTimeoutMs);
        handshakeTimer.unref?.();

        const regReq: RegisterRequest = {
          prefix: this.stickyPrefix,
          target_url: this.targetConfig.url.toString(),
          client_version: VERSION,
          client_os: formatClientOs(),
        };
        ws.send(JSON.stringify(regReq), (err) => {
          if (err) {
            fail(
              new NerutonError(`failed sending registration: ${err.message}`, 'HANDSHAKE_SEND_FAILED', {
                cause: err,
              }),
            );
          }
        });
      };

      ws.on('message', onHandshakeMessage);
      ws.once('open', onOpen);
      ws.once('unexpected-response', onUnexpectedResponse);
      ws.once('error', onError);
      ws.once('close', onClose);
    });
  }
}

const asyncDisposeSymbol: symbol =
  typeof Symbol.asyncDispose === 'symbol'
    ? Symbol.asyncDispose
    : Symbol.for('Symbol.asyncDispose');

Object.defineProperty(Tunnel.prototype, asyncDisposeSymbol, {
  value: Tunnel.prototype.close,
  configurable: true,
  writable: true,
});

/**
 * Connect to a Neruton gateway server and start forwarding traffic to a local HTTP/WebSocket service.
 */
export async function connect(options: ConnectOptions): Promise<Tunnel> {
  return Tunnel._createAndStart(options);
}

/**
 * Shorthand for `connect({ url: target, ...options })` (e.g. `forward(3000)`).
 */
export async function forward(
  target: number | string,
  options: ForwardOptions = {},
): Promise<Tunnel> {
  return Tunnel._createAndStart({ ...options, url: target });
}

/**
 * Alias for `forward(target, options)` mirroring `neruton http <port>`.
 */
export async function httpTunnel(
  target: number | string,
  options: ForwardOptions = {},
): Promise<Tunnel> {
  return Tunnel._createAndStart({ ...options, url: target });
}
