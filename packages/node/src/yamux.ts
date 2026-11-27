import { EventEmitter } from 'node:events';
import { Duplex } from 'node:stream';
import { YamuxError } from './errors.js';

export const YAMUX_VERSION = 0;
export const YAMUX_HEADER_SIZE = 12;
export const YAMUX_DEFAULT_WINDOW = 256 * 1024; // 256 KiB per Yamux spec
export const YAMUX_DEFAULT_SPLIT_SEND_SIZE = 16 * 1024; // 16 KiB matching yamux 0.13
export const YAMUX_MAX_FRAME_BODY_LEN = 1024 * 1024; // 1 MiB matching yamux 0.13
export const YAMUX_DEFAULT_MAX_STREAMS = 2048; // matches crates/neruton-proto/src/yamux_session.rs
export const YAMUX_CONNECTION_ID = 0;

const MAX_U32 = 0xffffffff;
const EMPTY_BUFFER = Buffer.alloc(0);
const EAGER_ACK_THRESHOLD = 64; // well below yamux 0.13 MAX_ACK_BACKLOG (256)

export enum YamuxFrameType {
  Data = 0,
  WindowUpdate = 1,
  Ping = 2,
  GoAway = 3,
}

export const YamuxFlag = {
  NONE: 0x0000,
  SYN: 0x0001,
  ACK: 0x0002,
  FIN: 0x0004,
  RST: 0x0008,
} as const;

export enum YamuxGoAwayCode {
  Normal = 0,
  ProtocolError = 1,
  InternalError = 2,
}

export type YamuxMode = 'client' | 'server';
export type YamuxStreamState = 'open' | 'send-closed' | 'recv-closed' | 'closed';

export interface YamuxHeader {
  version: number;
  type: YamuxFrameType;
  flags: number;
  streamId: number;
  length: number;
}

export interface YamuxFrame {
  header: YamuxHeader;
  body: Buffer;
}

export interface YamuxSessionOptions {
  mode: YamuxMode;
  maxStreams?: number;
  initialWindow?: number;
  splitSendSize?: number;
  maxFrameBodyLen?: number;
  readAfterClose?: boolean;
}

/**
 * Encode a 12-byte Yamux v0 frame header in big-endian byte order.
 */
export function encodeYamuxHeader(header: Omit<YamuxHeader, 'version'> & { version?: number }): Buffer {
  const buf = Buffer.allocUnsafe(YAMUX_HEADER_SIZE);
  buf.writeUInt8(header.version ?? YAMUX_VERSION, 0);
  buf.writeUInt8(header.type, 1);
  buf.writeUInt16BE(header.flags & 0xffff, 2);
  buf.writeUInt32BE(header.streamId >>> 0, 4);
  buf.writeUInt32BE(header.length >>> 0, 8);
  return buf;
}

/**
 * Decode a 12-byte Yamux v0 frame header from `buf` starting at `offset`.
 */
export function decodeYamuxHeader(buf: Buffer, offset = 0): YamuxHeader {
  if (buf.length - offset < YAMUX_HEADER_SIZE) {
    throw new YamuxError(
      `incomplete Yamux header: need ${YAMUX_HEADER_SIZE} bytes, got ${buf.length - offset}`,
      { code: 'YAMUX_INCOMPLETE_HEADER' },
    );
  }
  const version = buf.readUInt8(offset);
  if (version !== YAMUX_VERSION) {
    throw new YamuxError(`unknown Yamux version: ${version}`, { code: 'YAMUX_INVALID_VERSION' });
  }
  const typeByte = buf.readUInt8(offset + 1);
  if (
    typeByte !== YamuxFrameType.Data &&
    typeByte !== YamuxFrameType.WindowUpdate &&
    typeByte !== YamuxFrameType.Ping &&
    typeByte !== YamuxFrameType.GoAway
  ) {
    throw new YamuxError(`unknown Yamux frame type: ${typeByte}`, { code: 'YAMUX_INVALID_TYPE' });
  }
  const flags = buf.readUInt16BE(offset + 2);
  const streamId = buf.readUInt32BE(offset + 4);
  const length = buf.readUInt32BE(offset + 8);

  return {
    version,
    type: typeByte as YamuxFrameType,
    flags,
    streamId,
    length,
  };
}

/**
 * Encode a complete Yamux frame (12-byte header + optional Data payload).
 */
export function encodeYamuxFrame(
  type: YamuxFrameType,
  flags: number,
  streamId: number,
  lengthOrBody: number | Buffer,
): Buffer {
  if (type === YamuxFrameType.Data) {
    const body = Buffer.isBuffer(lengthOrBody) ? lengthOrBody : EMPTY_BUFFER;
    const header = encodeYamuxHeader({
      type,
      flags,
      streamId,
      length: body.length,
    });
    return body.length > 0 ? Buffer.concat([header, body]) : header;
  }

  const length = typeof lengthOrBody === 'number' ? lengthOrBody : 0;
  return encodeYamuxHeader({
    type,
    flags,
    streamId,
    length,
  });
}

/**
 * Streaming Yamux v0 frame decoder handling arbitrary chunk boundaries.
 */
export class YamuxFrameDecoder {
  private readonly maxFrameBodyLen: number;
  private chunks: Buffer[] = [];
  private headOffset = 0;
  private totalBytes = 0;
  private pendingHeader: YamuxHeader | null = null;

  constructor(maxFrameBodyLen = YAMUX_MAX_FRAME_BODY_LEN) {
    this.maxFrameBodyLen = maxFrameBodyLen;
  }

  push(chunk: Buffer): YamuxFrame[] {
    if (chunk.length > 0) {
      this.chunks.push(chunk);
      this.totalBytes += chunk.length;
    }

    const frames: YamuxFrame[] = [];

    while (true) {
      if (this.pendingHeader === null) {
        if (this.totalBytes < YAMUX_HEADER_SIZE) {
          break;
        }
        const headerBuf = this.consume(YAMUX_HEADER_SIZE);
        const header = decodeYamuxHeader(headerBuf, 0);

        if (header.type !== YamuxFrameType.Data) {
          frames.push({ header, body: EMPTY_BUFFER });
          continue;
        }

        if (header.length > this.maxFrameBodyLen) {
          throw new YamuxError(
            `Yamux frame body too large (${header.length} > ${this.maxFrameBodyLen})`,
            { code: 'YAMUX_FRAME_TOO_LARGE' },
          );
        }

        if (header.length === 0) {
          frames.push({ header, body: EMPTY_BUFFER });
          continue;
        }

        this.pendingHeader = header;
      }

      if (this.totalBytes < this.pendingHeader.length) {
        break;
      }

      const body = this.consume(this.pendingHeader.length);
      frames.push({ header: this.pendingHeader, body });
      this.pendingHeader = null;
    }

    return frames;
  }

  get bufferedBytes(): number {
    return this.totalBytes;
  }

  private consume(n: number): Buffer {
    if (n === 0) {
      return EMPTY_BUFFER;
    }
    const first = this.chunks[0];
    const firstAvail = first.length - this.headOffset;
    if (firstAvail >= n) {
      const out = first.subarray(this.headOffset, this.headOffset + n);
      this.headOffset += n;
      this.totalBytes -= n;
      if (this.headOffset === first.length) {
        this.chunks.shift();
        this.headOffset = 0;
      }
      return out;
    }

    const out = Buffer.allocUnsafe(n);
    let written = 0;
    while (written < n) {
      const cur = this.chunks[0];
      const avail = cur.length - this.headOffset;
      const take = Math.min(avail, n - written);
      cur.copy(out, written, this.headOffset, this.headOffset + take);
      written += take;
      this.headOffset += take;
      this.totalBytes -= take;
      if (this.headOffset === cur.length) {
        this.chunks.shift();
        this.headOffset = 0;
      }
    }
    return out;
  }
}

interface PendingWrite {
  buf: Buffer;
  offset: number;
  callback: (err?: Error | null) => void;
}

type PendingStreamFlag = 'none' | 'syn' | 'ack';

/**
 * A single multiplexed bidirectional Yamux stream exposed as a Node.js `stream.Duplex`.
 */
export class YamuxStream extends Duplex {
  readonly id: number;
  private readonly session: YamuxSession;
  private readonly maxReceiveWindow: number;
  private readonly splitSendSize: number;
  private readonly readAfterClose: boolean;

  private _streamState: YamuxStreamState = 'open';
  private pendingFlag: PendingStreamFlag;
  private _acknowledged = false;
  private _sendWindow: number;
  private _receiveWindow: number;

  private readonly recvQueue: Buffer[] = [];
  private recvQueueBytes = 0;
  private readingPaused = false;
  private remoteFin = false;
  private remoteReset = false;
  private readableEndedPushed = false;

  private pendingWrite: PendingWrite | null = null;
  private waitingForTransportDrain = false;
  private flushingWrite = false;

  constructor(
    session: YamuxSession,
    id: number,
    opts: {
      inbound: boolean;
      initialSendWindow: number;
      maxReceiveWindow: number;
      splitSendSize: number;
      readAfterClose: boolean;
    },
  ) {
    const hwm = Math.min(64 * 1024, Math.max(16 * 1024, Math.floor(opts.maxReceiveWindow / 4)));
    super({
      allowHalfOpen: true,
      autoDestroy: false,
      readableHighWaterMark: hwm,
      writableHighWaterMark: hwm,
    });
    this.session = session;
    this.id = id;
    this.maxReceiveWindow = opts.maxReceiveWindow;
    this.splitSendSize = opts.splitSendSize;
    this.readAfterClose = opts.readAfterClose;
    this._sendWindow = opts.initialSendWindow;
    this._receiveWindow = opts.maxReceiveWindow;
    this.pendingFlag = opts.inbound ? 'ack' : 'syn';
  }

  get streamState(): YamuxStreamState {
    return this._streamState;
  }

  get sendWindow(): number {
    return this._sendWindow;
  }

  get receiveWindow(): number {
    return this._receiveWindow;
  }

  get isAcknowledged(): boolean {
    return this._acknowledged;
  }

  get needsAck(): boolean {
    return this.pendingFlag === 'ack';
  }

  canRead(): boolean {
    return this._streamState !== 'recv-closed' && this._streamState !== 'closed';
  }

  canWrite(): boolean {
    return this._streamState !== 'send-closed' && this._streamState !== 'closed';
  }

  private transitionState(next: YamuxStreamState): YamuxStreamState {
    const prev = this._streamState;
    if (prev === 'closed') {
      return prev;
    }
    if (next === 'closed') {
      this._streamState = 'closed';
    } else if (prev === 'open') {
      this._streamState = next;
    } else if (prev === 'recv-closed' && next === 'send-closed') {
      this._streamState = 'closed';
    } else if (prev === 'send-closed' && next === 'recv-closed') {
      this._streamState = 'closed';
    }
    if (this._streamState === 'closed') {
      this.session._removeStream(this.id);
    }
    return prev;
  }

  private consumeFlag(): number {
    if (this.pendingFlag === 'syn') {
      this.pendingFlag = 'none';
      return YamuxFlag.SYN;
    }
    if (this.pendingFlag === 'ack') {
      this.pendingFlag = 'none';
      this._acknowledged = true;
      this.session._decrementUnackedInbound();
      return YamuxFlag.ACK;
    }
    return YamuxFlag.NONE;
  }

  /** @internal */
  _sendImmediateAck(): void {
    if (this.pendingFlag !== 'ack' || this._streamState === 'closed' || this.session.isClosed) {
      return;
    }
    const flags = this.consumeFlag();
    this.session._enqueueFrame(YamuxFrameType.WindowUpdate, flags, this.id, 0, true);
  }

  /** @internal */
  _markAcknowledged(): void {
    this._acknowledged = true;
  }

  /** @internal */
  _onRemoteData(body: Buffer, fin: boolean): boolean {
    if (body.length > this._receiveWindow) {
      return false; // protocol error: sender exceeded receive window
    }
    this._receiveWindow -= body.length;

    if (body.length > 0 && (this.canRead() || this.readAfterClose)) {
      this.recvQueue.push(body);
      this.recvQueueBytes += body.length;
    }

    if (fin) {
      this.remoteFin = true;
      this.transitionState('recv-closed');
    }

    this.drainRecvQueue();
    this.maybeSendWindowUpdate();
    return true;
  }

  /** @internal */
  _onRemoteWindowUpdate(credit: number, fin: boolean): boolean {
    if (this._sendWindow + credit > MAX_U32) {
      return false; // protocol error: send window overflow
    }
    this._sendWindow += credit;

    if (fin) {
      this.remoteFin = true;
      this.transitionState('recv-closed');
      this.drainRecvQueue();
    }

    this.flushPendingWrite();
    return true;
  }

  /** @internal */
  _onRemoteReset(): void {
    this.remoteReset = true;
    this.remoteFin = true;
    this.transitionState('closed');
    this.failPendingWrite(new YamuxError(`Yamux stream ${this.id} reset by peer`, { code: 'YAMUX_STREAM_RESET' }));

    if (!this.readAfterClose) {
      this.recvQueue.length = 0;
      this.recvQueueBytes = 0;
    }
    this.drainRecvQueue();
  }

  /** @internal */
  _onSessionClosed(err?: Error): void {
    this.remoteFin = true;
    this.transitionState('closed');
    this.failPendingWrite(
      err ?? new YamuxError('Yamux session closed', { code: 'YAMUX_SESSION_CLOSED' }),
    );
    if (!this.readAfterClose) {
      this.recvQueue.length = 0;
      this.recvQueueBytes = 0;
    }
    this.drainRecvQueue();
  }

  /** @internal */
  _onTransportDrain(): void {
    if (this.waitingForTransportDrain) {
      this.waitingForTransportDrain = false;
      this.flushPendingWrite();
    }
  }

  private drainRecvQueue(): void {
    while (!this.readingPaused && this.recvQueue.length > 0) {
      const chunk = this.recvQueue.shift()!;
      this.recvQueueBytes -= chunk.length;
      const ok = this.push(chunk);
      if (!ok) {
        this.readingPaused = true;
        break;
      }
    }

    if (this.recvQueue.length === 0 && this.remoteFin && !this.readableEndedPushed) {
      this.readableEndedPushed = true;
      this.push(null);
      if (this._streamState === 'closed' && !this.destroyed) {
        queueMicrotask(() => {
          if (!this.destroyed && this.readableLength === 0) {
            this.destroy();
          }
        });
      }
    }
  }

  private maybeSendWindowUpdate(): void {
    if (!this.canRead() || this.session.isClosed) {
      return;
    }
    const inFlight = this.recvQueueBytes + this.readableLength;
    const credit = this.maxReceiveWindow - this._receiveWindow - inFlight;
    if (credit >= Math.floor(this.maxReceiveWindow / 2)) {
      this._receiveWindow += credit;
      const flags = this.consumeFlag();
      this.session._enqueueFrame(YamuxFrameType.WindowUpdate, flags, this.id, credit, true);
    }
  }

  private failPendingWrite(err: Error): void {
    const pw = this.pendingWrite;
    if (pw) {
      this.pendingWrite = null;
      this.waitingForTransportDrain = false;
      pw.callback(err);
    }
  }

  private flushPendingWrite(): void {
    if (this.flushingWrite) {
      return;
    }
    this.flushingWrite = true;
    try {
      while (this.pendingWrite) {
        if (!this.canWrite() || this.session.isClosed) {
          this.failPendingWrite(
            new YamuxError(`Yamux stream ${this.id} is closed for writing`, {
              code: 'YAMUX_STREAM_CLOSED',
            }),
          );
          return;
        }

        if (this._sendWindow <= 0) {
          return;
        }

        const pw = this.pendingWrite;
        const remaining = pw.buf.length - pw.offset;
        if (remaining <= 0) {
          this.pendingWrite = null;
          pw.callback();
          return;
        }

        const chunkLen = Math.min(remaining, this._sendWindow, this.splitSendSize);
        const slice = pw.buf.subarray(pw.offset, pw.offset + chunkLen);
        this._sendWindow -= chunkLen;
        pw.offset += chunkLen;
        const isComplete = pw.offset >= pw.buf.length;
        if (isComplete) {
          this.pendingWrite = null;
        }

        const flags = this.consumeFlag();
        const canContinue = this.session._enqueueFrame(
          YamuxFrameType.Data,
          flags,
          this.id,
          slice,
          false,
        );

        if (isComplete) {
          if (!canContinue) {
            this.session._onceTransportDrain(() => pw.callback());
          } else {
            pw.callback();
          }
          return;
        }

        if (!canContinue) {
          this.waitingForTransportDrain = true;
          this.session._onceTransportDrain(() => this._onTransportDrain());
          return;
        }
      }
    } finally {
      this.flushingWrite = false;
    }
  }

  override _read(_size: number): void {
    this.readingPaused = false;
    this.drainRecvQueue();
    this.maybeSendWindowUpdate();
  }

  override _write(
    chunk: Buffer | string,
    encoding: BufferEncoding,
    callback: (error?: Error | null) => void,
  ): void {
    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, encoding);
    if (buf.length === 0) {
      callback();
      return;
    }
    if (!this.canWrite() || this.session.isClosed) {
      callback(
        new YamuxError(`Yamux stream ${this.id} is closed for writing`, {
          code: 'YAMUX_STREAM_CLOSED',
        }),
      );
      return;
    }
    this.pendingWrite = { buf, offset: 0, callback };
    this.flushPendingWrite();
  }

  override _final(callback: (error?: Error | null) => void): void {
    if (this.canWrite() && !this.session.isClosed) {
      const flags = YamuxFlag.FIN | this.consumeFlag();
      this.session._enqueueFrame(YamuxFrameType.Data, flags, this.id, EMPTY_BUFFER, false);
      this.transitionState('send-closed');
    }
    callback();
    if (this._streamState === 'closed' && this.readableEndedPushed && this.readableLength === 0 && !this.destroyed) {
      queueMicrotask(() => {
        if (!this.destroyed && this.readableLength === 0) {
          this.destroy();
        }
      });
    }
  }

  override _destroy(err: Error | null, callback: (error?: Error | null) => void): void {
    this.failPendingWrite(
      err ?? new YamuxError(`Yamux stream ${this.id} destroyed`, { code: 'YAMUX_STREAM_DESTROYED' }),
    );
    this.recvQueue.length = 0;
    this.recvQueueBytes = 0;

    if (this._streamState !== 'closed') {
      const prev = this._streamState;
      const canSendFrame = !this.remoteReset && !this.session.isClosed;
      if (canSendFrame && prev === 'recv-closed' && !err) {
        const flags = YamuxFlag.FIN | this.consumeFlag();
        this.transitionState('closed');
        this.session._enqueueFrame(YamuxFrameType.Data, flags, this.id, EMPTY_BUFFER, false);
      } else {
        this.transitionState('closed');
        if (canSendFrame && (prev === 'open' || err)) {
          this.session._enqueueFrame(
            YamuxFrameType.Data,
            YamuxFlag.RST,
            this.id,
            EMPTY_BUFFER,
            true,
          );
        }
      }
    }

    callback(err);
  }
}

interface PendingPing {
  sentAt: number;
  resolve: (rttMs: number) => void;
  reject: (err: Error) => void;
  timer?: NodeJS.Timeout;
}

export interface YamuxSessionEvents {
  stream: [stream: YamuxStream];
  goAway: [code: YamuxGoAwayCode];
  error: [err: Error];
  close: [];
}

/**
 * Pure TypeScript Yamux v0 multiplexer matching Rust `yamux 0.13` byte-for-byte.
 */
export class YamuxSession extends EventEmitter {
  readonly mode: YamuxMode;
  private readonly transport: Duplex;
  private readonly maxStreams: number;
  private readonly initialWindow: number;
  private readonly splitSendSize: number;
  private readonly readAfterClose: boolean;
  private readonly decoder: YamuxFrameDecoder;

  private readonly streams = new Map<number, YamuxStream>();
  private readonly pendingPings = new Map<number, PendingPing>();
  private readonly drainWaiters: Array<() => void> = [];

  private nextStreamId: number;
  private nextPingNonce = 1;
  private unackedInboundCount = 0;
  private _closed = false;
  private closeEmitted = false;
  private transportBackpressured = false;

  private readonly onDataBound: (chunk: Buffer | string) => void;
  private readonly onEndBound: () => void;
  private readonly onCloseBound: () => void;
  private readonly onErrorBound: (err: Error) => void;
  private readonly onDrainBound: () => void;

  constructor(transport: Duplex, options: YamuxSessionOptions) {
    super();
    this.transport = transport;
    this.mode = options.mode;
    this.maxStreams = options.maxStreams ?? YAMUX_DEFAULT_MAX_STREAMS;
    this.initialWindow = options.initialWindow ?? YAMUX_DEFAULT_WINDOW;
    this.splitSendSize = options.splitSendSize ?? YAMUX_DEFAULT_SPLIT_SEND_SIZE;
    this.readAfterClose = options.readAfterClose ?? true;
    this.decoder = new YamuxFrameDecoder(options.maxFrameBodyLen ?? YAMUX_MAX_FRAME_BODY_LEN);

    // Client opens odd stream IDs (1, 3, 5...); server opens even stream IDs (2, 4, 6...).
    this.nextStreamId = options.mode === 'client' ? 1 : 2;

    this.onDataBound = (chunk: Buffer | string) => {
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      this.handleTransportData(buf);
    };
    this.onEndBound = () => {
      this.shutdownInternal();
    };
    this.onCloseBound = () => {
      this.shutdownInternal();
    };
    this.onErrorBound = (err: Error) => {
      this.shutdownInternal(err);
    };
    this.onDrainBound = () => {
      this.transportBackpressured = false;
      const waiters = this.drainWaiters.splice(0, this.drainWaiters.length);
      for (const fn of waiters) {
        fn();
      }
    };

    this.transport.on('data', this.onDataBound);
    this.transport.on('end', this.onEndBound);
    this.transport.on('close', this.onCloseBound);
    this.transport.on('error', this.onErrorBound);
    this.transport.on('drain', this.onDrainBound);
  }

  get isClosed(): boolean {
    return this._closed;
  }

  get streamCount(): number {
    return this.streams.size;
  }

  /**
   * Open a new outbound Yamux stream (odd IDs in client mode, even IDs in server mode).
   */
  openStream(): YamuxStream {
    if (this._closed) {
      throw new YamuxError('Yamux session is closed', { code: 'YAMUX_SESSION_CLOSED' });
    }
    if (this.streams.size >= this.maxStreams) {
      throw new YamuxError(`maximum number of Yamux streams reached (${this.maxStreams})`, {
        code: 'YAMUX_TOO_MANY_STREAMS',
      });
    }
    if (this.nextStreamId > MAX_U32) {
      throw new YamuxError('exhausted Yamux stream IDs', { code: 'YAMUX_NO_MORE_IDS' });
    }

    const id = this.nextStreamId;
    this.nextStreamId += 2;

    const stream = new YamuxStream(this, id, {
      inbound: false,
      initialSendWindow: YAMUX_DEFAULT_WINDOW,
      maxReceiveWindow: this.initialWindow,
      splitSendSize: this.splitSendSize,
      readAfterClose: this.readAfterClose,
    });
    this.streams.set(id, stream);
    return stream;
  }

  /**
   * Send a Yamux Ping(SYN) frame and await the matching Ping(ACK), returning RTT in ms.
   */
  ping(nonce?: number, timeoutMs = 10_000): Promise<number> {
    if (this._closed) {
      return Promise.reject(
        new YamuxError('Yamux session is closed', { code: 'YAMUX_SESSION_CLOSED' }),
      );
    }
    const value = (nonce ?? this.nextPingNonce++) >>> 0;
    return new Promise<number>((resolve, reject) => {
      const entry: PendingPing = {
        sentAt: Date.now(),
        resolve,
        reject,
      };
      if (timeoutMs > 0) {
        entry.timer = setTimeout(() => {
          this.pendingPings.delete(value);
          reject(new YamuxError(`Yamux ping timed out after ${timeoutMs}ms`, { code: 'YAMUX_PING_TIMEOUT' }));
        }, timeoutMs);
        entry.timer.unref?.();
      }
      this.pendingPings.set(value, entry);
      this._enqueueFrame(YamuxFrameType.Ping, YamuxFlag.SYN, YAMUX_CONNECTION_ID, value, true);
    });
  }

  /**
   * Gracefully close the session by sending `GoAway(code)` and ending the underlying transport.
   */
  async close(code: YamuxGoAwayCode = YamuxGoAwayCode.Normal): Promise<void> {
    if (this._closed) {
      return;
    }
    try {
      const frame = encodeYamuxFrame(YamuxFrameType.GoAway, YamuxFlag.NONE, YAMUX_CONNECTION_ID, code);
      if (!this.transport.destroyed && this.transport.writable) {
        await new Promise<void>((resolve) => {
          this.transport.write(frame, () => {
            this.transport.end(() => resolve());
          });
        });
      }
    } catch {
      // Ignore transport write failures while closing.
    }
    this.shutdownInternal();
  }

  /**
   * Immediately terminate the Yamux session and underlying transport.
   */
  destroy(err?: Error): void {
    this.shutdownInternal(err);
    if (!this.transport.destroyed) {
      this.transport.destroy(err);
    }
  }

  /** @internal */
  _removeStream(id: number): void {
    const stream = this.streams.get(id);
    if (stream) {
      if (stream.needsAck) {
        this._decrementUnackedInbound();
      }
      this.streams.delete(id);
    }
  }

  /** @internal */
  _decrementUnackedInbound(): void {
    if (this.unackedInboundCount > 0) {
      this.unackedInboundCount -= 1;
    }
  }

  /** @internal */
  _onceTransportDrain(fn: () => void): void {
    if (!this.transportBackpressured || this._closed) {
      queueMicrotask(fn);
      return;
    }
    this.drainWaiters.push(fn);
  }

  /** @internal */
  _enqueueFrame(
    type: YamuxFrameType,
    flags: number,
    streamId: number,
    lengthOrBody: number | Buffer,
    _highPriority: boolean,
  ): boolean {
    if (this._closed || this.transport.destroyed || !this.transport.writable) {
      return false;
    }
    const raw = encodeYamuxFrame(type, flags, streamId, lengthOrBody);
    const ok = this.transport.write(raw);
    if (!ok) {
      this.transportBackpressured = true;
    }
    return ok;
  }

  private isValidRemoteStreamId(id: number): boolean {
    if (id === YAMUX_CONNECTION_ID) {
      return false;
    }
    // In server mode, remote is client (odd IDs). In client mode, remote is server (even IDs).
    return this.mode === 'server' ? id % 2 === 1 : id % 2 === 0;
  }

  private sendGoAwayAndTerminate(code: YamuxGoAwayCode, reason: string): void {
    if (!this._closed && !this.transport.destroyed && this.transport.writable) {
      const frame = encodeYamuxFrame(YamuxFrameType.GoAway, YamuxFlag.NONE, YAMUX_CONNECTION_ID, code);
      try {
        this.transport.write(frame);
        this.transport.end();
      } catch {
        // Ignore write error on termination.
      }
    }
    this.shutdownInternal(new YamuxError(reason, { code: 'YAMUX_PROTOCOL_ERROR', goAwayCode: code }));
  }

  private handleTransportData(buf: Buffer): void {
    if (this._closed) {
      return;
    }

    let frames: YamuxFrame[];
    try {
      frames = this.decoder.push(buf);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      this.sendGoAwayAndTerminate(YamuxGoAwayCode.ProtocolError, message);
      return;
    }

    for (const frame of frames) {
      if (this._closed) {
        return;
      }
      this.handleFrame(frame);
    }
  }

  private handleFrame(frame: YamuxFrame): void {
    const { type, flags, streamId, length } = frame.header;

    if (
      (flags & YamuxFlag.ACK) !== 0 &&
      (type === YamuxFrameType.Data || type === YamuxFrameType.WindowUpdate)
    ) {
      const existing = this.streams.get(streamId);
      if (existing) {
        existing._markAcknowledged();
      }
    }

    switch (type) {
      case YamuxFrameType.Data:
        this.handleDataFrame(streamId, flags, frame.body);
        break;
      case YamuxFrameType.WindowUpdate:
        this.handleWindowUpdateFrame(streamId, flags, length);
        break;
      case YamuxFrameType.Ping:
        this.handlePingFrame(streamId, flags, length);
        break;
      case YamuxFrameType.GoAway:
        this.emit('goAway', length as YamuxGoAwayCode);
        this.shutdownInternal();
        break;
    }
  }

  private handleDataFrame(streamId: number, flags: number, body: Buffer): void {
    if ((flags & YamuxFlag.RST) !== 0) {
      const stream = this.streams.get(streamId);
      if (stream) {
        stream._onRemoteReset();
      }
      return;
    }

    const isFin = (flags & YamuxFlag.FIN) !== 0;

    if ((flags & YamuxFlag.SYN) !== 0) {
      if (!this.isValidRemoteStreamId(streamId)) {
        this.sendGoAwayAndTerminate(
          YamuxGoAwayCode.ProtocolError,
          `invalid remote stream ID ${streamId} for mode ${this.mode}`,
        );
        return;
      }
      if (this.streams.has(streamId)) {
        this.sendGoAwayAndTerminate(
          YamuxGoAwayCode.ProtocolError,
          `stream ${streamId} already exists`,
        );
        return;
      }
      if (this.streams.size >= this.maxStreams) {
        this.sendGoAwayAndTerminate(
          YamuxGoAwayCode.InternalError,
          `maximum number of streams reached (${this.maxStreams})`,
        );
        return;
      }
      if (body.length > this.initialWindow) {
        this.sendGoAwayAndTerminate(
          YamuxGoAwayCode.ProtocolError,
          `initial Data|SYN body (${body.length}) exceeds initial window (${this.initialWindow})`,
        );
        return;
      }

      const stream = new YamuxStream(this, streamId, {
        inbound: true,
        initialSendWindow: YAMUX_DEFAULT_WINDOW,
        maxReceiveWindow: this.initialWindow,
        splitSendSize: this.splitSendSize,
        readAfterClose: this.readAfterClose,
      });
      this.streams.set(streamId, stream);
      this.unackedInboundCount += 1;

      if (!stream._onRemoteData(body, isFin)) {
        this.sendGoAwayAndTerminate(
          YamuxGoAwayCode.ProtocolError,
          `stream ${streamId} exceeded receive window`,
        );
        return;
      }

      if (this.unackedInboundCount >= EAGER_ACK_THRESHOLD && stream.needsAck) {
        stream._sendImmediateAck();
      }

      this.emit('stream', stream);
      return;
    }

    const stream = this.streams.get(streamId);
    if (!stream) {
      // Ignore frames for already-closed/dropped streams (matches yamux 0.13 issue #110).
      return;
    }
    if (!stream._onRemoteData(body, isFin)) {
      this.sendGoAwayAndTerminate(
        YamuxGoAwayCode.ProtocolError,
        `stream ${streamId} received data exceeding receive window`,
      );
    }
  }

  private handleWindowUpdateFrame(streamId: number, flags: number, credit: number): void {
    if ((flags & YamuxFlag.RST) !== 0) {
      const stream = this.streams.get(streamId);
      if (stream) {
        stream._onRemoteReset();
      }
      return;
    }

    const isFin = (flags & YamuxFlag.FIN) !== 0;

    if ((flags & YamuxFlag.SYN) !== 0) {
      if (!this.isValidRemoteStreamId(streamId)) {
        this.sendGoAwayAndTerminate(
          YamuxGoAwayCode.ProtocolError,
          `invalid remote stream ID ${streamId} for mode ${this.mode}`,
        );
        return;
      }
      if (this.streams.has(streamId)) {
        this.sendGoAwayAndTerminate(
          YamuxGoAwayCode.ProtocolError,
          `stream ${streamId} already exists`,
        );
        return;
      }
      if (this.streams.size >= this.maxStreams) {
        this.sendGoAwayAndTerminate(
          YamuxGoAwayCode.ProtocolError,
          `maximum number of streams reached (${this.maxStreams})`,
        );
        return;
      }

      const initialSendWindow = YAMUX_DEFAULT_WINDOW + credit;
      if (initialSendWindow > MAX_U32) {
        this.sendGoAwayAndTerminate(
          YamuxGoAwayCode.ProtocolError,
          `stream ${streamId} initial send window overflow`,
        );
        return;
      }

      const stream = new YamuxStream(this, streamId, {
        inbound: true,
        initialSendWindow,
        maxReceiveWindow: this.initialWindow,
        splitSendSize: this.splitSendSize,
        readAfterClose: this.readAfterClose,
      });
      this.streams.set(streamId, stream);
      this.unackedInboundCount += 1;

      if (isFin) {
        stream._onRemoteData(EMPTY_BUFFER, true);
      }
      if (this.unackedInboundCount >= EAGER_ACK_THRESHOLD && stream.needsAck) {
        stream._sendImmediateAck();
      }

      this.emit('stream', stream);
      return;
    }

    const stream = this.streams.get(streamId);
    if (!stream) {
      // Ignore window updates for already-closed/dropped streams (matches yamux 0.13).
      return;
    }
    if (!stream._onRemoteWindowUpdate(credit, isFin)) {
      this.sendGoAwayAndTerminate(
        YamuxGoAwayCode.ProtocolError,
        `stream ${streamId} send window overflow`,
      );
    }
  }

  private handlePingFrame(streamId: number, flags: number, nonce: number): void {
    if ((flags & YamuxFlag.ACK) !== 0) {
      const pending = this.pendingPings.get(nonce);
      if (pending) {
        this.pendingPings.delete(nonce);
        if (pending.timer) {
          clearTimeout(pending.timer);
        }
        pending.resolve(Math.max(0, Date.now() - pending.sentAt));
      }
      return;
    }

    if (streamId === YAMUX_CONNECTION_ID || this.streams.has(streamId)) {
      // Reply with Ping(ACK), stream_id=0, echoing the exact nonce (matches yamux 0.13).
      this._enqueueFrame(YamuxFrameType.Ping, YamuxFlag.ACK, YAMUX_CONNECTION_ID, nonce, true);
    }
  }

  private shutdownInternal(err?: Error): void {
    if (this._closed) {
      return;
    }
    this._closed = true;

    this.transport.off('data', this.onDataBound);
    this.transport.off('end', this.onEndBound);
    this.transport.off('close', this.onCloseBound);
    this.transport.off('error', this.onErrorBound);
    this.transport.off('drain', this.onDrainBound);

    const waiters = this.drainWaiters.splice(0, this.drainWaiters.length);
    for (const fn of waiters) {
      fn();
    }

    for (const [nonce, pending] of this.pendingPings.entries()) {
      this.pendingPings.delete(nonce);
      if (pending.timer) {
        clearTimeout(pending.timer);
      }
      pending.reject(
        err ?? new YamuxError('Yamux session closed', { code: 'YAMUX_SESSION_CLOSED' }),
      );
    }

    const activeStreams = Array.from(this.streams.values());
    this.streams.clear();
    this.unackedInboundCount = 0;
    for (const stream of activeStreams) {
      stream._onSessionClosed(err);
    }

    if (err && this.listenerCount('error') > 0) {
      this.emit('error', err);
    }
    if (!this.closeEmitted) {
      this.closeEmitted = true;
      this.emit('close');
    }
  }
}
