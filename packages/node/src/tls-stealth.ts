import net from 'node:net';
import { Duplex } from 'node:stream';
import tls from 'node:tls';
import {
  isIpLiteral,
  shouldSkipDoh,
  stripBrackets,
  type DohMode,
  type DohResolution,
} from './doh.js';
import { ConfigError, NerutonError } from './errors.js';
import { decodeEchConfigBase64, selectEchConfig } from './hpke.js';

export type SniMode = 'auto' | 'ech' | 'fragment' | 'none' | 'plain';

export type EchStatus = 'accepted' | 'fallback' | 'none';

export const VALID_SNI_MODES = ['auto', 'ech', 'fragment', 'none', 'plain'] as const;

export interface StealthTlsPlan {
  protocol: 'ws:' | 'wss:';
  realHost: string;
  port: number;
  requestedSniMode: SniMode;
  effectiveSniMode: 'ech' | 'fragment' | 'none' | 'plain' | 'n/a';
  servername: string;
  fragmentClientHello: boolean;
  useEch: boolean;
  echAllowFallback: boolean;
  echConfigLists: Buffer[];
  outerSni?: string;
  verifyHostname: string;
  customSni?: string;
}

export interface TransportInfo {
  dohMode: DohMode;
  dohSource: DohResolution['source'];
  dohEndpoint?: string;
  resolvedIp?: string;
  resolvedAddresses: string[];
  echConfigsAvailable: number;
  echStatus: EchStatus;
  outerSni?: string;
  echRetried?: boolean;
  sniMode: SniMode;
  effectiveSniMode: 'ech' | 'fragment' | 'none' | 'plain' | 'n/a';
  sni?: string;
  fragmented: boolean;
  fragmentCount: number;
  tlsProtocol?: string;
  tlsAuthorized?: boolean;
  summary: string;
}

export interface ClientHelloFragmentOptions {
  /** Split offset right after the 5-byte TLS record header (default: 5). */
  firstChunkSize?: number;
  /** Inter-fragment flush delay in ms so segments do not coalesce in TCP send buffers (default: 2). */
  interFragmentDelayMs?: number;
}

export interface TcpTarget {
  host: string;
  port: number;
}

export interface TcpConnectResult {
  socket: net.Socket;
  address: string;
}

/**
 * Parse and validate an SNI mode string (defaults to `'auto'`).
 */
export function parseSniMode(value?: string): SniMode {
  if (value === undefined) {
    return 'auto';
  }
  const normalized = value.trim().toLowerCase();
  if (!normalized) {
    return 'auto';
  }
  if (
    normalized === 'auto' ||
    normalized === 'ech' ||
    normalized === 'fragment' ||
    normalized === 'none' ||
    normalized === 'plain'
  ) {
    return normalized;
  }
  throw new ConfigError(
    `invalid sniMode '${value}': expected one of ${VALID_SNI_MODES.join(', ')}`,
  );
}

/**
 * Validate that an SNI mode is supported by this runtime.
 * All modes (`auto`, `ech`, `fragment`, `none`, `plain`) are natively supported in pure Node.js.
 */
export function assertSniModeSupported(sniMode: SniMode): void {
  if (!(VALID_SNI_MODES as readonly string[]).includes(sniMode)) {
    throw new ConfigError(
      `invalid sniMode '${sniMode}': expected one of ${VALID_SNI_MODES.join(', ')}`,
    );
  }
}

/**
 * Determine the effective TLS / SNI stealth plan for a WebSocket URL and options.
 */
export function planStealthTls(opts: {
  wsUrl: URL;
  sniMode?: SniMode;
  sni?: string;
  echConfig?: string;
  dohEchConfigs?: readonly Buffer[];
}): StealthTlsPlan {
  const requestedSniMode = opts.sniMode ?? 'auto';
  assertSniModeSupported(requestedSniMode);

  const protocol = opts.wsUrl.protocol === 'wss:' ? 'wss:' : 'ws:';
  const realHost = stripBrackets(opts.wsUrl.hostname);
  const defaultPort = protocol === 'wss:' ? 443 : 80;
  const port = opts.wsUrl.port ? Number(opts.wsUrl.port) : defaultPort;
  const customSni = opts.sni && opts.sni.trim().length > 0 ? opts.sni.trim() : undefined;
  const explicitEchStr =
    opts.echConfig && opts.echConfig.trim().length > 0 ? opts.echConfig.trim() : undefined;

  if (protocol === 'ws:') {
    if (requestedSniMode === 'ech') {
      throw new NerutonError(
        `ECH mode (sniMode 'ech') requires a wss:// (HTTPS) server URL, got '${opts.wsUrl.toString()}'`,
        'ECH_REQUIRED',
      );
    }
    return {
      protocol,
      realHost,
      port,
      requestedSniMode,
      effectiveSniMode: 'n/a',
      servername: '',
      fragmentClientHello: false,
      useEch: false,
      echAllowFallback: false,
      echConfigLists: [],
      verifyHostname: realHost,
      customSni,
    };
  }

  const defaultSni = isIpLiteral(realHost) ? '' : realHost;
  const isLocalOrIp = shouldSkipDoh(realHost);

  if (requestedSniMode === 'none') {
    return {
      protocol,
      realHost,
      port,
      requestedSniMode,
      effectiveSniMode: 'none',
      servername: '',
      fragmentClientHello: false,
      useEch: false,
      echAllowFallback: false,
      echConfigLists: [],
      verifyHostname: realHost,
    };
  }

  if (requestedSniMode === 'plain') {
    return {
      protocol,
      realHost,
      port,
      requestedSniMode,
      effectiveSniMode: 'plain',
      servername: customSni ?? defaultSni,
      fragmentClientHello: false,
      useEch: false,
      echAllowFallback: false,
      echConfigLists: [],
      verifyHostname: realHost,
      customSni,
    };
  }

  if (requestedSniMode === 'fragment') {
    return {
      protocol,
      realHost,
      port,
      requestedSniMode,
      effectiveSniMode: 'fragment',
      servername: customSni ?? defaultSni,
      fragmentClientHello: true,
      useEch: false,
      echAllowFallback: false,
      echConfigLists: [],
      verifyHostname: realHost,
      customSni,
    };
  }

  const explicitEchBuf = explicitEchStr ? decodeEchConfigBase64(explicitEchStr) : undefined;
  const availableEchLists: Buffer[] = explicitEchBuf
    ? [explicitEchBuf]
    : [...(opts.dohEchConfigs ?? [])];

  if (requestedSniMode === 'ech') {
    if (availableEchLists.length === 0) {
      throw new NerutonError(
        `ECH mode (sniMode 'ech') requires an ECHConfigList, but none was provided via --ech-config or DoH HTTPS record for '${realHost}'`,
        'ECH_REQUIRED',
      );
    }
    const selected = selectEchConfig(availableEchLists);
    if (!selected) {
      throw new NerutonError(
        `ECH mode (sniMode 'ech') found no compatible ECHConfig for '${realHost}'`,
        'ECH_INVALID_CONFIG',
      );
    }
    return {
      protocol,
      realHost,
      port,
      requestedSniMode,
      effectiveSniMode: 'ech',
      servername: selected.config.publicName,
      fragmentClientHello: false,
      useEch: true,
      echAllowFallback: false,
      echConfigLists: availableEchLists,
      outerSni: selected.config.publicName,
      verifyHostname: realHost,
    };
  }

  // requestedSniMode === 'auto'
  if (customSni) {
    return {
      protocol,
      realHost,
      port,
      requestedSniMode,
      effectiveSniMode: 'fragment',
      servername: customSni,
      fragmentClientHello: true,
      useEch: false,
      echAllowFallback: false,
      echConfigLists: [],
      verifyHostname: realHost,
      customSni,
    };
  }

  if (isLocalOrIp && !explicitEchBuf) {
    return {
      protocol,
      realHost,
      port,
      requestedSniMode,
      effectiveSniMode: 'plain',
      servername: defaultSni,
      fragmentClientHello: false,
      useEch: false,
      echAllowFallback: false,
      echConfigLists: [],
      verifyHostname: realHost,
    };
  }

  if (availableEchLists.length > 0) {
    const selected = selectEchConfig(availableEchLists);
    if (selected) {
      return {
        protocol,
        realHost,
        port,
        requestedSniMode,
        effectiveSniMode: 'ech',
        servername: selected.config.publicName,
        fragmentClientHello: false,
        useEch: true,
        echAllowFallback: !explicitEchBuf,
        echConfigLists: availableEchLists,
        outerSni: selected.config.publicName,
        verifyHostname: realHost,
      };
    }
    if (explicitEchBuf) {
      throw new NerutonError(
        `provided echConfig contains no compatible ECHConfig for '${realHost}'`,
        'ECH_INVALID_CONFIG',
      );
    }
  }

  return {
    protocol,
    realHost,
    port,
    requestedSniMode,
    effectiveSniMode: 'fragment',
    servername: defaultSni,
    fragmentClientHello: true,
    useEch: false,
    echAllowFallback: false,
    echConfigLists: [],
    verifyHostname: realHost,
  };
}

/**
 * Check whether a buffer begins with a TLS Handshake record (`0x16 0x03 ...`).
 */
export function isTlsClientHelloRecord(buf: Buffer): boolean {
  return buf.length > 5 && buf[0] === 0x16 && buf[1] === 0x03;
}

/**
 * Locate the byte span `[start, end)` of the SNI hostname inside a TLS ClientHello record, if present.
 */
function findSniHostSpan(record: Buffer): { start: number; end: number } | null {
  if (record.length < 48) return null;
  if (record[0] !== 0x16 || record[1] !== 0x03) return null;
  const recLen = record.readUInt16BE(3);
  const recEnd = Math.min(record.length, 5 + recLen);

  // Handshake header: type=0x01 (ClientHello), 3-byte length
  if (record[5] !== 0x01) return null;
  let pos = 5 + 4; // skip handshake header
  pos += 2; // legacy_version
  pos += 32; // random
  if (pos >= recEnd) return null;

  const sessionIdLen = record[pos];
  pos += 1 + sessionIdLen;
  if (pos + 2 > recEnd) return null;

  const cipherSuitesLen = record.readUInt16BE(pos);
  pos += 2 + cipherSuitesLen;
  if (pos + 1 > recEnd) return null;

  const compressionLen = record[pos];
  pos += 1 + compressionLen;
  if (pos + 2 > recEnd) return null;

  const extensionsLen = record.readUInt16BE(pos);
  pos += 2;
  const extensionsEnd = Math.min(recEnd, pos + extensionsLen);

  while (pos + 4 <= extensionsEnd) {
    const extType = record.readUInt16BE(pos);
    const extLen = record.readUInt16BE(pos + 2);
    pos += 4;
    if (pos + extLen > extensionsEnd) break;

    if (extType === 0x0000 && extLen >= 5) {
      // server_name list: list_len (2) + name_type (1, 0=host_name) + name_len (2) + name
      const listLen = record.readUInt16BE(pos);
      let sPos = pos + 2;
      const listEnd = Math.min(pos + extLen, sPos + listLen);
      while (sPos + 3 <= listEnd) {
        const nameType = record[sPos];
        const nameLen = record.readUInt16BE(sPos + 1);
        sPos += 3;
        if (sPos + nameLen > listEnd) break;
        if (nameType === 0x00 && nameLen > 0) {
          return { start: sPos, end: sPos + nameLen };
        }
        sPos += nameLen;
      }
    }
    pos += extLen;
  }

  return null;
}

/**
 * Compute byte cut points to split a TLS ClientHello record across multiple TCP segments,
 * separating the 5-byte TLS record header and slicing directly across the SNI hostname if present.
 */
export function findClientHelloSplitPoints(
  record: Buffer,
  opts: ClientHelloFragmentOptions = {},
): number[] {
  const len = record.length;
  if (len <= 6) {
    return len > 1 ? [Math.floor(len / 2)] : [];
  }

  const firstCut = Math.max(1, Math.min(opts.firstChunkSize ?? 5, len - 1));
  const cuts = new Set<number>([firstCut]);

  const sniSpan = findSniHostSpan(record);
  if (sniSpan && sniSpan.end - sniSpan.start >= 2) {
    const sniMid = Math.floor((sniSpan.start + sniSpan.end) / 2);
    if (sniMid > firstCut && sniMid < len) {
      cuts.add(sniMid);
    }
    // Also break between header and SNI so the ClientHello preamble isn't bundled with SNI prefix
    if (sniSpan.start > firstCut + 32) {
      cuts.add(firstCut + 32);
    }
  } else {
    // Fallback splits when no SNI extension is present
    if (len > firstCut + 35) {
      cuts.add(firstCut + 35);
    }
    const mid = Math.floor((firstCut + len) / 2);
    if (mid > firstCut && mid < len) {
      cuts.add(mid);
    }
  }

  return Array.from(cuts)
    .filter((c) => c > 0 && c < len)
    .sort((a, b) => a - b);
}

/**
 * JS `stream.Duplex` wrapping a `net.Socket` for `tls.connect({ socket: duplex })`.
 *
 * Node's `tls.TLSSocket` bypasses monkey-patched `net.Socket.write` via native `_handle`,
 * so passing a JS `Duplex` forces the TLS layer through JS `_write`, letting us split the
 * initial TLS ClientHello record (`0x16 0x03 ...`) across multiple flushed TCP segments
 * before switching to transparent pass-through with proper backpressure & teardown.
 */
export class ClientHelloFragmentDuplex extends Duplex {
  readonly raw: net.Socket;
  private readonly fragmentOptions: ClientHelloFragmentOptions;
  private handledFirstWrite = false;
  private _didFragment = false;
  private _fragmentCount = 0;
  private pendingTimer: NodeJS.Timeout | undefined;
  private drainCleanup: (() => void) | undefined;

  private readonly onRawData: (chunk: Buffer) => void;
  private readonly onRawEnd: () => void;
  private readonly onRawError: (err: Error) => void;
  private readonly onRawClose: () => void;

  constructor(raw: net.Socket, opts: ClientHelloFragmentOptions = {}) {
    super({ allowHalfOpen: true });
    this.raw = raw;
    this.fragmentOptions = opts;

    try {
      this.raw.setNoDelay(true);
    } catch {
      // Ignore if underlying socket does not support TCP_NODELAY.
    }

    this.onRawData = (chunk: Buffer): void => {
      if (this.destroyed) return;
      if (!this.push(chunk)) {
        this.raw.pause();
      }
    };

    this.onRawEnd = (): void => {
      if (!this.destroyed) {
        this.push(null);
      }
    };

    this.onRawError = (err: Error): void => {
      if (!this.destroyed) {
        this.destroy(err);
      }
    };

    this.onRawClose = (): void => {
      if (!this.destroyed) {
        this.destroy();
      }
    };

    this.raw.on('data', this.onRawData);
    this.raw.on('end', this.onRawEnd);
    this.raw.on('error', this.onRawError);
    this.raw.on('close', this.onRawClose);
  }

  get didFragment(): boolean {
    return this._didFragment;
  }

  get fragmentCount(): number {
    return this._fragmentCount;
  }

  get remoteAddress(): string | undefined {
    return this.raw.remoteAddress;
  }

  get remotePort(): number | undefined {
    return this.raw.remotePort;
  }

  get remoteFamily(): string | undefined {
    return this.raw.remoteFamily;
  }

  get localAddress(): string | undefined {
    return this.raw.localAddress;
  }

  get localPort(): number | undefined {
    return this.raw.localPort;
  }

  setNoDelay(noDelay = true): this {
    this.raw.setNoDelay(noDelay);
    return this;
  }

  setKeepAlive(enable = false, initialDelay = 0): this {
    this.raw.setKeepAlive(enable, initialDelay);
    return this;
  }

  setTimeout(timeout: number, callback?: () => void): this {
    this.raw.setTimeout(timeout, callback);
    return this;
  }

  ref(): this {
    this.raw.ref();
    return this;
  }

  unref(): this {
    this.raw.unref();
    return this;
  }

  override _read(_size: number): void {
    if (!this.raw.destroyed) {
      this.raw.resume();
    }
  }

  override _write(
    chunk: Buffer | Uint8Array | string,
    encoding: BufferEncoding,
    callback: (error?: Error | null) => void,
  ): void {
    if (this.destroyed || this.raw.destroyed) {
      callback(new Error('underlying socket destroyed'));
      return;
    }

    if (!this.handledFirstWrite) {
      this.handledFirstWrite = true;
      const buf = Buffer.isBuffer(chunk)
        ? chunk
        : typeof chunk === 'string'
          ? Buffer.from(chunk, encoding)
          : Buffer.from(chunk);

      if (isTlsClientHelloRecord(buf)) {
        const cuts = findClientHelloSplitPoints(buf, this.fragmentOptions);
        if (cuts.length > 0) {
          const segments: Buffer[] = [];
          let prev = 0;
          for (const cut of cuts) {
            segments.push(buf.subarray(prev, cut));
            prev = cut;
          }
          segments.push(buf.subarray(prev));
          this._didFragment = true;
          this._fragmentCount = segments.length;
          this.writeFragmentsSequentially(segments, 0, callback);
          return;
        }
      }
    }

    // Transparent pass-through with proper backpressure.
    const ok = this.raw.write(chunk, encoding);
    if (ok) {
      callback();
      return;
    }

    const onDrain = (): void => {
      cleanup();
      callback();
    };
    const onError = (err: Error): void => {
      cleanup();
      callback(err);
    };
    const onClose = (): void => {
      cleanup();
      callback(new Error('underlying socket closed before drain'));
    };
    const cleanup = (): void => {
      this.raw.off('drain', onDrain);
      this.raw.off('error', onError);
      this.raw.off('close', onClose);
      if (this.drainCleanup === cleanup) {
        this.drainCleanup = undefined;
      }
    };
    this.drainCleanup = cleanup;
    this.raw.once('drain', onDrain);
    this.raw.once('error', onError);
    this.raw.once('close', onClose);
  }

  private writeFragmentsSequentially(
    segments: Buffer[],
    index: number,
    callback: (error?: Error | null) => void,
  ): void {
    if (this.destroyed || this.raw.destroyed) {
      callback(new Error('underlying socket destroyed during ClientHello fragmentation'));
      return;
    }

    const seg = segments[index];
    const delayMs = this.fragmentOptions.interFragmentDelayMs ?? 2;

    this.raw.write(seg, (err) => {
      if (err) {
        callback(err);
        return;
      }
      if (index + 1 >= segments.length) {
        callback();
        return;
      }
      if (this.destroyed || this.raw.destroyed) {
        callback(new Error('underlying socket destroyed during ClientHello fragmentation'));
        return;
      }
      if (delayMs <= 0) {
        setImmediate(() => {
          this.writeFragmentsSequentially(segments, index + 1, callback);
        });
      } else {
        this.pendingTimer = setTimeout(() => {
          this.pendingTimer = undefined;
          this.writeFragmentsSequentially(segments, index + 1, callback);
        }, delayMs);
        this.pendingTimer.unref?.();
      }
    });
  }

  override _final(callback: (error?: Error | null) => void): void {
    if (this.raw.destroyed || this.raw.writableEnded) {
      callback();
      return;
    }
    this.raw.end(() => callback());
  }

  override _destroy(err: Error | null, callback: (error?: Error | null) => void): void {
    if (this.pendingTimer) {
      clearTimeout(this.pendingTimer);
      this.pendingTimer = undefined;
    }
    if (this.drainCleanup) {
      this.drainCleanup();
    }
    // Keep a no-op error listener on `raw` before detaching `onRawError` so destroying
    // or tearing down `raw` can never trigger an uncaught `'error'` event on Node.
    this.raw.on('error', () => {});
    this.raw.off('data', this.onRawData);
    this.raw.off('end', this.onRawEnd);
    this.raw.off('error', this.onRawError);
    this.raw.off('close', this.onRawClose);

    if (!this.raw.destroyed) {
      // Do not forward `err` to `raw.destroy(err)`; `callback(err)` already surfaces it on `this`.
      this.raw.destroy();
    }
    callback(err);
  }
}

function connectSingleTcpTarget(
  target: TcpTarget,
  opts: { timeoutMs: number; signal?: AbortSignal },
): Promise<TcpConnectResult> {
  return new Promise<TcpConnectResult>((resolve, reject) => {
    if (opts.signal?.aborted) {
      reject(new NerutonError('tunnel connection aborted', 'ABORTED'));
      return;
    }

    const socket = net.createConnection({
      host: target.host,
      port: target.port,
    });

    let settled = false;
    let timer: NodeJS.Timeout | undefined;

    const cleanup = (): void => {
      if (timer) {
        clearTimeout(timer);
        timer = undefined;
      }
      socket.off('connect', onConnect);
      socket.off('error', onError);
      opts.signal?.removeEventListener('abort', onAbort);
    };

    const fail = (err: Error): void => {
      if (settled) return;
      settled = true;
      cleanup();
      socket.on('error', () => {});
      if (!socket.destroyed) {
        socket.destroy();
      }
      reject(err);
    };

    const onConnect = (): void => {
      if (settled) return;
      settled = true;
      cleanup();
      try {
        socket.setNoDelay(true);
      } catch {
        // Ignore.
      }
      resolve({
        socket,
        address: socket.remoteAddress ?? target.host,
      });
    };

    const onError = (err: Error): void => {
      fail(err);
    };

    const onAbort = (): void => {
      fail(new NerutonError('tunnel connection aborted', 'ABORTED'));
    };

    opts.signal?.addEventListener('abort', onAbort, { once: true });

    timer = setTimeout(() => {
      fail(new NerutonError(`TCP connect to ${target.host}:${target.port} timed out`, 'TCP_TIMEOUT'));
    }, opts.timeoutMs);
    timer.unref?.();

    socket.once('connect', onConnect);
    socket.once('error', onError);
  });
}

/**
 * Connect TCP sequentially across candidate targets (multi-IP failover), enabling `TCP_NODELAY`.
 */
export async function connectTcpWithFailover(
  targets: TcpTarget[],
  opts: { timeoutMs?: number; signal?: AbortSignal } = {},
): Promise<TcpConnectResult> {
  if (targets.length === 0) {
    throw new NerutonError('no TCP target addresses available', 'TCP_CONNECT_FAILED');
  }

  const totalBudgetMs = opts.timeoutMs ?? 10_000;
  const deadline = Date.now() + totalBudgetMs;
  const errors: string[] = [];

  for (let i = 0; i < targets.length; i += 1) {
    if (opts.signal?.aborted) {
      throw new NerutonError('tunnel connection aborted', 'ABORTED');
    }
    const remaining = deadline - Date.now();
    if (remaining <= 0) {
      errors.push(`${targets[i].host}:${targets[i].port} (deadline exceeded)`);
      break;
    }
    const perTargetTimeout =
      targets.length === 1
        ? remaining
        : Math.max(1000, Math.min(remaining, Math.ceil(totalBudgetMs / Math.min(targets.length, 3))));
    try {
      return await connectSingleTcpTarget(targets[i], {
        timeoutMs: perTargetTimeout,
        signal: opts.signal,
      });
    } catch (err) {
      if (opts.signal?.aborted) {
        throw new NerutonError('tunnel connection aborted', 'ABORTED');
      }
      const msg = err instanceof Error ? err.message : String(err);
      errors.push(`${targets[i].host}:${targets[i].port} (${msg})`);
    }
  }

  throw new NerutonError(`TCP connect failed: ${errors.join('; ')}`, 'TCP_CONNECT_FAILED');
}

/**
 * Wrap an already-connected `net.Socket` in `tls.connect` according to `plan`,
 * applying ClientHello TCP fragmentation and/or omitted/custom SNI with strict
 * certificate identity verification against `plan.verifyHostname`.
 */
export function createStealthTlsSocket(
  rawSocket: net.Socket,
  plan: StealthTlsPlan,
  opts: {
    noTlsVerify?: boolean;
    ca?: string | Buffer | Array<string | Buffer>;
    fragmentOptions?: ClientHelloFragmentOptions;
  } = {},
): { socket: tls.TLSSocket; duplex?: ClientHelloFragmentDuplex } {
  try {
    rawSocket.setNoDelay(true);
  } catch {
    // Ignore.
  }

  let duplex: ClientHelloFragmentDuplex | undefined;
  let transportStream: Duplex = rawSocket;
  if (plan.fragmentClientHello) {
    duplex = new ClientHelloFragmentDuplex(rawSocket, opts.fragmentOptions);
    transportStream = duplex;
  }

  const verifyHost = plan.verifyHostname;
  const tlsOpts: tls.ConnectionOptions = {
    socket: transportStream,
    servername: plan.servername,
    rejectUnauthorized: !opts.noTlsVerify,
    checkServerIdentity: (_servername, cert) => tls.checkServerIdentity(verifyHost, cert),
    ...(opts.ca !== undefined ? { ca: opts.ca } : {}),
  };

  const tlsSocket = tls.connect(tlsOpts);
  return { socket: tlsSocket, duplex };
}

/**
 * Format a concise human-readable summary of the active transport stealth configuration.
 */
export function formatTransportSummary(info: Omit<TransportInfo, 'summary'>): string {
  const parts: string[] = [];

  let epLabel: string | undefined;
  if (info.dohSource === 'doh') {
    epLabel = info.dohEndpoint ?? 'DoH';
    if (info.dohEndpoint) {
      try {
        epLabel = stripBrackets(new URL(info.dohEndpoint).hostname);
      } catch {
        epLabel = info.dohEndpoint;
      }
    }
  }

  if (info.effectiveSniMode === 'ech') {
    const echLabel = `ECH (outer: ${info.outerSni ?? 'unknown'}${info.echRetried ? ', retried' : ''})`;
    if (info.dohSource === 'doh') {
      parts.push(`DoH + ${echLabel}`);
      if (epLabel) {
        parts.push(info.resolvedIp ? `${epLabel} -> ${info.resolvedIp}` : epLabel);
      }
    } else {
      if (info.dohSource === 'skipped') {
        parts.push('system DNS (local/IP)');
      } else if (info.dohSource === 'fallback') {
        parts.push('system DNS (DoH fallback)');
      } else {
        parts.push('system DNS (DoH off)');
      }
      parts.push(echLabel);
    }

    if (info.tlsProtocol) {
      parts.push(info.tlsProtocol);
    }
    return parts.join(' · ');
  }

  if (info.dohSource === 'doh') {
    parts.push(info.resolvedIp ? `DoH (${epLabel} -> ${info.resolvedIp})` : `DoH (${epLabel})`);
  } else if (info.dohSource === 'skipped') {
    parts.push('system DNS (local/IP)');
  } else if (info.dohSource === 'fallback') {
    parts.push('system DNS (DoH fallback)');
  } else {
    parts.push('system DNS (DoH off)');
  }

  if (info.effectiveSniMode === 'n/a') {
    parts.push('plain ws');
  } else if (info.effectiveSniMode === 'fragment') {
    const segLabel = info.fragmentCount > 1 ? ` (${info.fragmentCount} segments)` : '';
    const fbLabel = info.echStatus === 'fallback' ? ' [ECH fallback]' : '';
    if (info.sni) {
      parts.push(`custom SNI (${info.sni}) + ClientHello fragmentation${segLabel}${fbLabel}`);
    } else {
      parts.push(`ClientHello fragmentation${segLabel}${fbLabel}`);
    }
  } else if (info.effectiveSniMode === 'none') {
    parts.push('omitted SNI');
  } else if (info.sni) {
    parts.push(`custom SNI (${info.sni})`);
  } else {
    parts.push('plain TLS');
  }

  if (info.tlsProtocol) {
    parts.push(info.tlsProtocol);
  }

  return parts.join(' · ');
}
