import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import { ConfigError, DohError } from './errors.js';

export const DEFAULT_DOH_ENDPOINTS = [
  'https://1.0.0.1/dns-query',
  'https://223.5.5.5/dns-query',
  'https://1.1.1.1/dns-query',
  'https://8.8.4.4/dns-query',
] as const;

export const DEFAULT_DOH_TIMEOUT_MS = 3000;

export const DNS_TYPE_A = 1;
export const DNS_TYPE_CNAME = 5;
export const DNS_TYPE_AAAA = 28;
export const DNS_TYPE_HTTPS = 65;
export const DNS_CLASS_IN = 1;

export const SVC_PARAM_ALPN = 1;
export const SVC_PARAM_IPV4HINT = 4;
export const SVC_PARAM_ECH = 5;
export const SVC_PARAM_IPV6HINT = 6;

const DNS_RCODE_NOERROR = 0;
const DNS_RCODE_NXDOMAIN = 3;

export type DohMode = 'auto' | 'strict' | 'off';

export type DohOption = boolean | string | string[];

export interface ParsedDohConfig {
  mode: DohMode;
  endpoints: string[];
  isCustom: boolean;
}

export interface HttpsSvcRecord {
  priority: number;
  targetName: string;
  alpn: string[];
  ipv4Hints: string[];
  ipv6Hints: string[];
  echConfigs: Buffer[];
  params: Map<number, Buffer>;
}

export interface DnsAnswer {
  name: string;
  type: number;
  rrClass: number;
  ttl: number;
  rdata: Buffer;
  address?: string;
  cname?: string;
  https?: HttpsSvcRecord;
}

export interface DnsMessage {
  id: number;
  flags: number;
  rcode: number;
  truncated: boolean;
  answers: DnsAnswer[];
}

export interface DohResolution {
  hostname: string;
  ipv4: string[];
  ipv6: string[];
  addresses: string[];
  httpsRecords: HttpsSvcRecord[];
  echConfigs: Buffer[];
  endpoint?: string;
  source: 'doh' | 'skipped' | 'fallback' | 'off';
  warning?: string;
}

export interface DohResolveOptions {
  doh?: DohOption | ParsedDohConfig;
  timeoutMs?: number;
  signal?: AbortSignal;
  ca?: string | Buffer | Array<string | Buffer>;
  rejectUnauthorized?: boolean;
  onWarn?: (message: string) => void;
}

export interface DohPostOptions {
  timeoutMs?: number;
  signal?: AbortSignal;
  ca?: string | Buffer | Array<string | Buffer>;
  rejectUnauthorized?: boolean;
}

/**
 * Strip surrounding IPv6 brackets (`[::1]` -> `::1`) and trim whitespace.
 */
export function stripBrackets(host: string): string {
  const trimmed = host.trim();
  if (trimmed.startsWith('[') && trimmed.endsWith(']')) {
    return trimmed.slice(1, -1);
  }
  return trimmed;
}

/**
 * Return true if `host` is an IPv4 or IPv6 literal (with or without brackets).
 */
export function isIpLiteral(host: string): boolean {
  return net.isIP(stripBrackets(host)) !== 0;
}

/**
 * Auto-skip DoH for IPv4/IPv6 literals, `localhost`, `*.localhost`, and `*.local`.
 */
export function shouldSkipDoh(hostname: string): boolean {
  const clean = stripBrackets(hostname).toLowerCase().replace(/\.+$/, '');
  if (!clean) {
    return true;
  }
  if (net.isIP(clean) !== 0) {
    return true;
  }
  if (clean === 'localhost' || clean.endsWith('.localhost') || clean.endsWith('.local')) {
    return true;
  }
  return false;
}

function isParsedDohConfig(val: unknown): val is ParsedDohConfig {
  return (
    typeof val === 'object' &&
    val !== null &&
    !Array.isArray(val) &&
    'mode' in val &&
    'endpoints' in val &&
    Array.isArray((val as ParsedDohConfig).endpoints)
  );
}

function isLoopbackHost(host: string): boolean {
  const clean = stripBrackets(host).toLowerCase().replace(/\.+$/, '');
  return clean === 'localhost' || clean === '127.0.0.1' || clean === '::1';
}

function validateDohUrl(raw: string): string {
  const trimmed = raw.trim();
  if (!trimmed) {
    throw new ConfigError('DoH endpoint URL must not be empty');
  }
  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch (err) {
    throw new ConfigError(`invalid DoH endpoint URL '${trimmed}'`, { cause: err });
  }
  if (!parsed.hostname) {
    throw new ConfigError(`invalid DoH endpoint URL '${trimmed}': missing host`);
  }
  if (parsed.protocol === 'http:') {
    if (!isLoopbackHost(parsed.hostname)) {
      throw new ConfigError(
        `invalid DoH endpoint URL '${trimmed}': cleartext http:// is only allowed for loopback hosts (127.0.0.1, ::1, localhost)`,
      );
    }
  } else if (parsed.protocol !== 'https:') {
    throw new ConfigError(`invalid DoH endpoint URL '${trimmed}': expected https:// URL`);
  }
  return parsed.toString();
}

/**
 * Parse a DoH option (`boolean | string | string[]`) into a normalized `ParsedDohConfig`.
 */
export function parseDohOption(value?: DohOption | ParsedDohConfig): ParsedDohConfig {
  if (isParsedDohConfig(value)) {
    return {
      mode: value.mode,
      endpoints: [...value.endpoints],
      isCustom: value.isCustom,
    };
  }

  if (value === undefined || value === true) {
    return { mode: 'auto', endpoints: [...DEFAULT_DOH_ENDPOINTS], isCustom: false };
  }

  if (value === false) {
    return { mode: 'off', endpoints: [], isCustom: false };
  }

  if (Array.isArray(value)) {
    const cleaned = value.map((s) => s.trim()).filter((s) => s.length > 0);
    if (cleaned.length === 0) {
      throw new ConfigError('doh endpoint list must not be empty');
    }
    if (cleaned.length === 1 && !cleaned[0].includes('://')) {
      return parseDohOption(cleaned[0]);
    }
    const endpoints = cleaned.map(validateDohUrl);
    // Explicit custom DoH URLs fail closed rather than silently leaking plaintext system DNS.
    return { mode: 'strict', endpoints, isCustom: true };
  }

  const trimmed = value.trim();
  if (!trimmed) {
    return { mode: 'auto', endpoints: [...DEFAULT_DOH_ENDPOINTS], isCustom: false };
  }

  const lower = trimmed.toLowerCase();
  if (lower === 'auto' || lower === 'true' || lower === '1' || lower === 'on') {
    return { mode: 'auto', endpoints: [...DEFAULT_DOH_ENDPOINTS], isCustom: false };
  }
  if (lower === 'strict') {
    return { mode: 'strict', endpoints: [...DEFAULT_DOH_ENDPOINTS], isCustom: false };
  }
  if (lower === 'off' || lower === 'false' || lower === '0' || lower === 'none' || lower === 'disabled') {
    return { mode: 'off', endpoints: [], isCustom: false };
  }

  // Otherwise treat as comma-separated DoH endpoint URL(s).
  if (trimmed.includes('://')) {
    const parts = trimmed
      .split(',')
      .map((p) => p.trim())
      .filter((p) => p.length > 0);
    if (parts.length === 0) {
      throw new ConfigError(`invalid DoH value '${value}'`);
    }
    const endpoints = parts.map(validateDohUrl);
    // Explicit custom DoH URLs fail closed rather than silently leaking plaintext system DNS.
    return { mode: 'strict', endpoints, isCustom: true };
  }

  throw new ConfigError(
    `invalid DoH option '${value}': expected 'auto', 'strict', 'off', or comma-separated https:// URL(s)`,
  );
}

/**
 * Format a `DohOption` or `ParsedDohConfig` as a string suitable for `config.toml` or CLI display.
 */
export function formatDohValue(value: DohOption | ParsedDohConfig): string {
  const parsed = parseDohOption(value);
  if (parsed.isCustom) {
    return parsed.endpoints.join(',');
  }
  return parsed.mode;
}

/**
 * Encode an RFC 1035 DNS query message for `hostname` and record type `qtype`.
 * Defaults to ID = 0 per RFC 8484 Section 4.1.
 */
export function encodeDnsQuery(hostname: string, qtype: number, id = 0): Buffer {
  const clean = stripBrackets(hostname).replace(/\.+$/, '');
  const labels = clean.length === 0 ? [] : clean.split('.');

  const nameParts: Buffer[] = [];
  let wireLen = 1; // trailing root 0x00
  for (const label of labels) {
    const labelBytes = Buffer.from(label, 'ascii');
    if (labelBytes.length === 0 || labelBytes.length > 63) {
      throw new DohError(`invalid DNS label '${label}' in hostname '${hostname}'`, {
        code: 'DOH_INVALID_NAME',
      });
    }
    wireLen += 1 + labelBytes.length;
    if (wireLen > 255) {
      throw new DohError(`DNS hostname '${hostname}' exceeds 255 octets`, {
        code: 'DOH_INVALID_NAME',
      });
    }
    nameParts.push(Buffer.from([labelBytes.length]), labelBytes);
  }
  nameParts.push(Buffer.from([0x00]));

  const header = Buffer.alloc(12);
  header.writeUInt16BE(id & 0xffff, 0);
  header.writeUInt16BE(0x0100, 2); // Standard query with RD=1
  header.writeUInt16BE(1, 4); // QDCOUNT = 1
  header.writeUInt16BE(0, 6); // ANCOUNT
  header.writeUInt16BE(0, 8); // NSCOUNT
  header.writeUInt16BE(0, 10); // ARCOUNT

  const trailer = Buffer.alloc(4);
  trailer.writeUInt16BE(qtype & 0xffff, 0);
  trailer.writeUInt16BE(DNS_CLASS_IN, 2);

  return Buffer.concat([header, ...nameParts, trailer]);
}

/**
 * Format 16 raw bytes as a canonical RFC 5952 IPv6 string.
 */
export function formatIpv6(bytes: Uint8Array): string {
  if (bytes.length !== 16) {
    throw new DohError(`invalid IPv6 byte length: ${bytes.length}`, { code: 'DOH_MALFORMED_RESPONSE' });
  }
  const groups: number[] = [];
  for (let i = 0; i < 16; i += 2) {
    groups.push((bytes[i] << 8) | bytes[i + 1]);
  }

  // Find longest run of consecutive zero groups (length >= 2)
  let bestStart = -1;
  let bestLen = 0;
  let curStart = -1;
  let curLen = 0;
  for (let i = 0; i < 8; i += 1) {
    if (groups[i] === 0) {
      if (curStart === -1) {
        curStart = i;
        curLen = 1;
      } else {
        curLen += 1;
      }
      if (curLen > bestLen) {
        bestStart = curStart;
        bestLen = curLen;
      }
    } else {
      curStart = -1;
      curLen = 0;
    }
  }

  if (bestLen < 2) {
    return groups.map((g) => g.toString(16)).join(':');
  }

  const head = groups.slice(0, bestStart).map((g) => g.toString(16)).join(':');
  const tail = groups.slice(bestStart + bestLen).map((g) => g.toString(16)).join(':');
  return `${head}::${tail}`;
}

/**
 * Decode an RFC 1035 domain name starting at `offset`, supporting compression pointers
 * with cycle detection and strict bounds checking.
 */
export function decodeDnsName(
  buf: Buffer,
  offset: number,
  options?: { allowCompression?: boolean; endOffset?: number },
): { name: string; nextOffset: number } {
  const allowCompression = options?.allowCompression ?? true;
  const limit = options?.endOffset ?? buf.length;
  const labels: string[] = [];
  const visitedOffsets = new Set<number>();

  let pos = offset;
  let nextOffset = -1;
  let jumps = 0;

  while (true) {
    if (pos < 0 || pos >= limit) {
      throw new DohError('truncated DNS name in response', { code: 'DOH_MALFORMED_RESPONSE' });
    }
    if (visitedOffsets.has(pos)) {
      throw new DohError('DNS compression pointer loop detected', { code: 'DOH_MALFORMED_RESPONSE' });
    }
    visitedOffsets.add(pos);

    const len = buf[pos];
    if (len === 0) {
      if (nextOffset === -1) {
        nextOffset = pos + 1;
      }
      break;
    }

    const highBits = len & 0xc0;
    if (highBits === 0xc0) {
      if (!allowCompression) {
        throw new DohError('unexpected DNS compression pointer in uncompressed name', {
          code: 'DOH_MALFORMED_RESPONSE',
        });
      }
      if (pos + 1 >= limit) {
        throw new DohError('truncated DNS compression pointer', { code: 'DOH_MALFORMED_RESPONSE' });
      }
      const pointer = ((len & 0x3f) << 8) | buf[pos + 1];
      if (pointer >= buf.length) {
        throw new DohError('out-of-bounds DNS compression pointer', { code: 'DOH_MALFORMED_RESPONSE' });
      }
      if (nextOffset === -1) {
        nextOffset = pos + 2;
      }
      pos = pointer;
      jumps += 1;
      if (jumps > 64) {
        throw new DohError('too many DNS compression pointer jumps', { code: 'DOH_MALFORMED_RESPONSE' });
      }
      continue;
    }

    if (highBits !== 0) {
      throw new DohError(`unsupported DNS label type 0x${highBits.toString(16)}`, {
        code: 'DOH_MALFORMED_RESPONSE',
      });
    }

    pos += 1;
    if (pos + len > limit) {
      throw new DohError('truncated DNS label', { code: 'DOH_MALFORMED_RESPONSE' });
    }
    labels.push(buf.subarray(pos, pos + len).toString('ascii'));
    pos += len;
  }

  return {
    name: labels.join('.'),
    nextOffset: nextOffset === -1 ? pos + 1 : nextOffset,
  };
}

/**
 * Parse RFC 9460 `HTTPS` (Type 65) RDATA, extracting SvcParams including `alpn` (1),
 * `ipv4hint` (4), `ech` (5, raw ECHConfigList bytes), and `ipv6hint` (6).
 */
export function parseHttpsRdata(rdata: Buffer): HttpsSvcRecord {
  if (rdata.length < 3) {
    throw new DohError('truncated HTTPS RR RDATA', { code: 'DOH_MALFORMED_RESPONSE' });
  }
  const priority = rdata.readUInt16BE(0);
  // RFC 9460 Section 2.2: TargetName MUST NOT be compressed.
  const { name: targetName, nextOffset } = decodeDnsName(rdata, 2, {
    allowCompression: false,
    endOffset: rdata.length,
  });

  const alpn: string[] = [];
  const ipv4Hints: string[] = [];
  const ipv6Hints: string[] = [];
  const echConfigs: Buffer[] = [];
  const params = new Map<number, Buffer>();

  if (priority > 0) {
    let pos = nextOffset;
    while (pos < rdata.length) {
      if (pos + 4 > rdata.length) {
        throw new DohError('truncated HTTPS SvcParam header', { code: 'DOH_MALFORMED_RESPONSE' });
      }
      const key = rdata.readUInt16BE(pos);
      const valLen = rdata.readUInt16BE(pos + 2);
      pos += 4;
      if (pos + valLen > rdata.length) {
        throw new DohError(`truncated HTTPS SvcParam value for key ${key}`, {
          code: 'DOH_MALFORMED_RESPONSE',
        });
      }
      const val = Buffer.from(rdata.subarray(pos, pos + valLen));
      pos += valLen;
      params.set(key, val);

      if (key === SVC_PARAM_ALPN) {
        let aPos = 0;
        while (aPos < val.length) {
          const protoLen = val[aPos];
          aPos += 1;
          if (protoLen === 0 || aPos + protoLen > val.length) {
            break;
          }
          alpn.push(val.subarray(aPos, aPos + protoLen).toString('ascii'));
          aPos += protoLen;
        }
      } else if (key === SVC_PARAM_IPV4HINT) {
        if (val.length > 0 && val.length % 4 === 0) {
          for (let i = 0; i < val.length; i += 4) {
            ipv4Hints.push(`${val[i]}.${val[i + 1]}.${val[i + 2]}.${val[i + 3]}`);
          }
        }
      } else if (key === SVC_PARAM_ECH) {
        if (val.length > 0) {
          echConfigs.push(val);
        }
      } else if (key === SVC_PARAM_IPV6HINT) {
        if (val.length > 0 && val.length % 16 === 0) {
          for (let i = 0; i < val.length; i += 16) {
            ipv6Hints.push(formatIpv6(val.subarray(i, i + 16)));
          }
        }
      }
    }
  }

  return {
    priority,
    targetName,
    alpn,
    ipv4Hints,
    ipv6Hints,
    echConfigs,
    params,
  };
}

/**
 * Decode an RFC 1035 DNS wire response message.
 */
export function decodeDnsResponse(buf: Buffer): DnsMessage {
  if (buf.length < 12) {
    throw new DohError(`DNS response too short (${buf.length} bytes)`, {
      code: 'DOH_MALFORMED_RESPONSE',
    });
  }

  const id = buf.readUInt16BE(0);
  const flags = buf.readUInt16BE(2);
  if ((flags & 0x8000) === 0) {
    throw new DohError('DNS message is not a response (QR bit is 0)', {
      code: 'DOH_MALFORMED_RESPONSE',
    });
  }
  const qdcount = buf.readUInt16BE(4);
  const ancount = buf.readUInt16BE(6);
  const rcode = flags & 0x0f;
  const truncated = (flags & 0x0200) !== 0;

  let offset = 12;

  for (let i = 0; i < qdcount; i += 1) {
    const qName = decodeDnsName(buf, offset);
    offset = qName.nextOffset;
    if (offset + 4 > buf.length) {
      throw new DohError('truncated DNS question section', { code: 'DOH_MALFORMED_RESPONSE' });
    }
    offset += 4; // QTYPE + QCLASS
  }

  const answers: DnsAnswer[] = [];
  for (let i = 0; i < ancount; i += 1) {
    const aName = decodeDnsName(buf, offset);
    offset = aName.nextOffset;
    if (offset + 10 > buf.length) {
      throw new DohError('truncated DNS answer header', { code: 'DOH_MALFORMED_RESPONSE' });
    }
    const type = buf.readUInt16BE(offset);
    const rrClass = buf.readUInt16BE(offset + 2);
    const ttl = buf.readUInt32BE(offset + 4);
    const rdlength = buf.readUInt16BE(offset + 8);
    offset += 10;

    if (offset + rdlength > buf.length) {
      throw new DohError('truncated DNS answer RDATA', { code: 'DOH_MALFORMED_RESPONSE' });
    }
    const rdataStart = offset;
    const rdata = Buffer.from(buf.subarray(rdataStart, rdataStart + rdlength));
    offset += rdlength;

    const answer: DnsAnswer = {
      name: aName.name,
      type,
      rrClass,
      ttl,
      rdata,
    };

    if (rrClass === DNS_CLASS_IN) {
      if (type === DNS_TYPE_A && rdlength === 4) {
        answer.address = `${rdata[0]}.${rdata[1]}.${rdata[2]}.${rdata[3]}`;
      } else if (type === DNS_TYPE_AAAA && rdlength === 16) {
        answer.address = formatIpv6(rdata);
      } else if (type === DNS_TYPE_CNAME) {
        try {
          answer.cname = decodeDnsName(buf, rdataStart).name;
        } catch {
          // Ignore malformed CNAME target; A/AAAA records may still follow.
        }
      } else if (type === DNS_TYPE_HTTPS) {
        answer.https = parseHttpsRdata(rdata);
      }
    }

    answers.push(answer);
  }

  return {
    id,
    flags,
    rcode,
    truncated,
    answers,
  };
}

/**
 * Send a single RFC 8484 binary POST (`application/dns-message`) request to a DoH endpoint.
 */
export function postDohMessage(
  endpoint: string,
  wireQuery: Buffer,
  opts: DohPostOptions = {},
): Promise<Buffer> {
  const timeoutMs = opts.timeoutMs ?? DEFAULT_DOH_TIMEOUT_MS;
  const validatedEndpoint = validateDohUrl(endpoint);
  const parsed = new URL(validatedEndpoint);
  const rawHost = stripBrackets(parsed.hostname);
  const isHttps = parsed.protocol === 'https:';
  const port = parsed.port ? Number(parsed.port) : isHttps ? 443 : 80;

  return new Promise<Buffer>((resolve, reject) => {
    if (opts.signal?.aborted) {
      reject(new DohError(`DoH request to ${endpoint} aborted`, { code: 'ABORTED', endpoints: [endpoint] }));
      return;
    }

    let settled = false;
    let timer: NodeJS.Timeout | undefined;
    let req: http.ClientRequest | undefined;

    const cleanup = (): void => {
      if (timer) {
        clearTimeout(timer);
        timer = undefined;
      }
      if (opts.signal) {
        opts.signal.removeEventListener('abort', onAbort);
      }
    };

    const fail = (err: Error): void => {
      if (settled) return;
      settled = true;
      cleanup();
      if (req && !req.destroyed) {
        req.destroy();
      }
      reject(err);
    };

    const succeed = (body: Buffer): void => {
      if (settled) return;
      settled = true;
      cleanup();
      resolve(body);
    };

    const onAbort = (): void => {
      fail(new DohError(`DoH request to ${endpoint} aborted`, { code: 'ABORTED', endpoints: [endpoint] }));
    };

    opts.signal?.addEventListener('abort', onAbort, { once: true });

    timer = setTimeout(() => {
      fail(
        new DohError(`DoH request to ${endpoint} timed out after ${timeoutMs}ms`, {
          code: 'DOH_TIMEOUT',
          endpoints: [endpoint],
        }),
      );
    }, timeoutMs);
    timer.unref?.();

    const pathWithQuery = `${parsed.pathname || '/dns-query'}${parsed.search}`;
    const commonHeaders = {
      'Content-Type': 'application/dns-message',
      Accept: 'application/dns-message',
      'Content-Length': String(wireQuery.length),
    };

    const onResponse = (res: http.IncomingMessage): void => {
      const status = res.statusCode ?? 0;
      const chunks: Buffer[] = [];
      let totalBytes = 0;

      res.on('data', (chunk: Buffer | string) => {
        const b = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        totalBytes += b.length;
        if (totalBytes > 65536) {
          res.destroy();
          fail(
            new DohError(`DoH response from ${endpoint} exceeded 64 KiB`, {
              code: 'DOH_MALFORMED_RESPONSE',
              endpoints: [endpoint],
            }),
          );
          return;
        }
        chunks.push(b);
      });

      res.on('end', () => {
        if (status !== 200) {
          fail(
            new DohError(`DoH endpoint ${endpoint} returned HTTP ${status}`, {
              code: 'DOH_HTTP_ERROR',
              endpoints: [endpoint],
            }),
          );
          return;
        }
        succeed(Buffer.concat(chunks));
      });

      res.on('error', (err) => {
        fail(
          new DohError(`DoH response error from ${endpoint}: ${err.message}`, {
            code: 'DOH_FAILED',
            endpoints: [endpoint],
            cause: err,
          }),
        );
      });
    };

    if (isHttps) {
      const httpsOpts: https.RequestOptions = {
        host: rawHost,
        port,
        path: pathWithQuery,
        method: 'POST',
        headers: commonHeaders,
        agent: false,
        // Never put IP literals in TLS SNI (RFC 6066); Node still validates IP SAN against `host`.
        servername: isIpLiteral(rawHost) ? undefined : rawHost,
        rejectUnauthorized: opts.rejectUnauthorized ?? true,
        ...(opts.ca !== undefined ? { ca: opts.ca } : {}),
      };
      req = https.request(httpsOpts, onResponse);
    } else {
      const httpOpts: http.RequestOptions = {
        host: rawHost,
        port,
        path: pathWithQuery,
        method: 'POST',
        headers: commonHeaders,
        agent: false,
      };
      req = http.request(httpOpts, onResponse);
    }

    req.on('error', (err) => {
      fail(
        new DohError(`DoH request to ${endpoint} failed: ${err.message}`, {
          code: 'DOH_FAILED',
          endpoints: [endpoint],
          cause: err,
        }),
      );
    });

    req.end(wireQuery);
  });
}

function dedupeStrings(items: string[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const item of items) {
    if (!seen.has(item)) {
      seen.add(item);
      out.push(item);
    }
  }
  return out;
}

async function querySingleRecordType(
  endpoint: string,
  hostname: string,
  qtype: number,
  opts: DohPostOptions,
): Promise<DnsMessage> {
  const query = encodeDnsQuery(hostname, qtype, 0);
  const rawResp = await postDohMessage(endpoint, query, opts);
  const decoded = decodeDnsResponse(rawResp);
  if (decoded.rcode !== DNS_RCODE_NOERROR && decoded.rcode !== DNS_RCODE_NXDOMAIN) {
    throw new DohError(`DoH endpoint ${endpoint} returned DNS RCODE ${decoded.rcode} for qtype ${qtype}`, {
      code: 'DOH_DNS_ERROR',
      endpoints: [endpoint],
    });
  }
  return decoded;
}

/**
 * Query `A`, `AAAA`, and `HTTPS` (Type 65) records in parallel against a single DoH endpoint.
 */
export async function queryDohEndpoint(
  endpoint: string,
  hostname: string,
  opts: DohPostOptions = {},
): Promise<DohResolution> {
  const [aRes, aaaaRes, httpsRes] = await Promise.allSettled([
    querySingleRecordType(endpoint, hostname, DNS_TYPE_A, opts),
    querySingleRecordType(endpoint, hostname, DNS_TYPE_AAAA, opts),
    querySingleRecordType(endpoint, hostname, DNS_TYPE_HTTPS, opts),
  ]);

  if (aRes.status === 'rejected' && aaaaRes.status === 'rejected') {
    const reason = aRes.reason instanceof Error ? aRes.reason : new Error(String(aRes.reason));
    throw new DohError(`DoH endpoint ${endpoint} failed: ${reason.message}`, {
      code: 'DOH_FAILED',
      endpoints: [endpoint],
      cause: reason,
    });
  }

  const ipv4: string[] = [];
  const ipv6: string[] = [];
  const httpsRecords: HttpsSvcRecord[] = [];
  const echConfigs: Buffer[] = [];
  const ipv4Hints: string[] = [];
  const ipv6Hints: string[] = [];

  if (aRes.status === 'fulfilled') {
    for (const ans of aRes.value.answers) {
      if (ans.type === DNS_TYPE_A && ans.address) {
        ipv4.push(ans.address);
      }
    }
  }

  if (aaaaRes.status === 'fulfilled') {
    for (const ans of aaaaRes.value.answers) {
      if (ans.type === DNS_TYPE_AAAA && ans.address) {
        ipv6.push(ans.address);
      }
    }
  }

  if (httpsRes.status === 'fulfilled') {
    for (const ans of httpsRes.value.answers) {
      if (ans.type === DNS_TYPE_HTTPS && ans.https) {
        httpsRecords.push(ans.https);
      }
    }
    // Sort RFC 9460 HTTPS records by ascending SvcPriority before collecting ECH/hints.
    httpsRecords.sort((a, b) => a.priority - b.priority);
    for (const rec of httpsRecords) {
      for (const ech of rec.echConfigs) {
        echConfigs.push(ech);
      }
      ipv4Hints.push(...rec.ipv4Hints);
      ipv6Hints.push(...rec.ipv6Hints);
    }
  }

  const finalIpv4 = dedupeStrings(ipv4.length > 0 ? ipv4 : ipv4Hints);
  const finalIpv6 = dedupeStrings(ipv6.length > 0 ? ipv6 : ipv6Hints);
  const addresses = dedupeStrings([...finalIpv4, ...finalIpv6]);

  if (addresses.length === 0) {
    throw new DohError(`DoH endpoint ${endpoint} returned no IP addresses for '${hostname}'`, {
      code: 'DOH_NO_ADDRESSES',
      endpoints: [endpoint],
    });
  }

  return {
    hostname,
    ipv4: finalIpv4,
    ipv6: finalIpv6,
    addresses,
    httpsRecords,
    echConfigs,
    endpoint,
    source: 'doh',
  };
}

/**
 * Race a batch of DoH endpoints concurrently, aborting losing in-flight requests as soon as one succeeds.
 */
async function raceEndpointBatch(
  endpoints: string[],
  hostname: string,
  opts: DohPostOptions,
): Promise<DohResolution> {
  if (endpoints.length === 1) {
    return queryDohEndpoint(endpoints[0], hostname, opts);
  }

  const controllers = endpoints.map(() => new AbortController());
  const parentAbortListeners: Array<() => void> = [];

  if (opts.signal) {
    if (opts.signal.aborted) {
      throw new DohError('DoH resolution aborted', { code: 'ABORTED', endpoints });
    }
    for (const ctrl of controllers) {
      const fn = (): void => ctrl.abort();
      opts.signal.addEventListener('abort', fn, { once: true });
      parentAbortListeners.push(fn);
    }
  }

  const cleanupParentListeners = (): void => {
    if (opts.signal) {
      for (const fn of parentAbortListeners) {
        opts.signal.removeEventListener('abort', fn);
      }
    }
  };

  try {
    return await new Promise<DohResolution>((resolve, reject) => {
      let settled = false;
      let failures = 0;
      const errors: Error[] = [];

      endpoints.forEach((ep, idx) => {
        const ctrl = controllers[idx];
        queryDohEndpoint(ep, hostname, {
          ...opts,
          signal: ctrl.signal,
        }).then(
          (result) => {
            if (settled) return;
            settled = true;
            // Immediately cancel all other in-flight DoH requests in this race wave.
            controllers.forEach((other, otherIdx) => {
              if (otherIdx !== idx && !other.signal.aborted) {
                other.abort();
              }
            });
            resolve(result);
          },
          (err) => {
            errors[idx] = err instanceof Error ? err : new Error(String(err));
            failures += 1;
            if (!settled && failures === endpoints.length) {
              settled = true;
              const summary = endpoints
                .map((e, i) => `${e} (${errors[i]?.message ?? 'failed'})`)
                .join('; ');
              reject(new DohError(`all DoH endpoints in batch failed: ${summary}`, { endpoints }));
            }
          },
        );
      });
    });
  } finally {
    cleanupParentListeners();
  }
}

/**
 * Resolve `hostname` via RFC 8484 DoH according to `opts.doh` (`auto` | `strict` | `off` | custom URLs).
 * Races the first two endpoints and falls back across remaining endpoints in waves of 2.
 */
export async function resolveHostWithDoh(
  hostname: string,
  opts: DohResolveOptions = {},
): Promise<DohResolution> {
  const cleanHost = stripBrackets(hostname);
  const config = parseDohOption(opts.doh);

  if (config.mode === 'off') {
    return {
      hostname: cleanHost,
      ipv4: [],
      ipv6: [],
      addresses: [],
      httpsRecords: [],
      echConfigs: [],
      source: 'off',
    };
  }

  if (shouldSkipDoh(cleanHost)) {
    return {
      hostname: cleanHost,
      ipv4: [],
      ipv6: [],
      addresses: [],
      httpsRecords: [],
      echConfigs: [],
      source: 'skipped',
    };
  }

  const postOpts: DohPostOptions = {
    timeoutMs: opts.timeoutMs ?? DEFAULT_DOH_TIMEOUT_MS,
    signal: opts.signal,
    ca: opts.ca,
    rejectUnauthorized: opts.rejectUnauthorized,
  };

  const waveErrors: string[] = [];
  for (let i = 0; i < config.endpoints.length; i += 2) {
    if (opts.signal?.aborted) {
      throw new DohError('DoH resolution aborted', { code: 'ABORTED', endpoints: config.endpoints });
    }
    const wave = config.endpoints.slice(i, i + 2);
    try {
      return await raceEndpointBatch(wave, cleanHost, postOpts);
    } catch (err) {
      if (opts.signal?.aborted) {
        throw new DohError('DoH resolution aborted', { code: 'ABORTED', endpoints: config.endpoints });
      }
      waveErrors.push(err instanceof Error ? err.message : String(err));
    }
  }

  const detail = waveErrors.join(' | ');
  if (config.mode === 'strict') {
    throw new DohError(
      `DoH resolution failed in strict mode for '${cleanHost}': ${detail}`,
      { code: 'DOH_FAILED', endpoints: config.endpoints },
    );
  }

  const warning = `DoH resolution failed for '${cleanHost}' (${detail}); falling back to system DNS`;
  opts.onWarn?.(warning);
  return {
    hostname: cleanHost,
    ipv4: [],
    ipv6: [],
    addresses: [],
    httpsRecords: [],
    echConfigs: [],
    source: 'fallback',
    warning,
  };
}
