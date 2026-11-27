import { VERSION } from './constants.js';
import type { TunnelConnectedEvent, TunnelRequestEvent } from './tunnel.js';

function useColor(): boolean {
  return process.env.NO_COLOR === undefined;
}

function c(code: string, text: string): string {
  if (!useColor()) {
    return text;
  }
  return `\x1b[${code}m${text}\x1b[0m`;
}

function formatTime(now = new Date()): string {
  const hh = String(now.getHours()).padStart(2, '0');
  const mm = String(now.getMinutes()).padStart(2, '0');
  const ss = String(now.getSeconds()).padStart(2, '0');
  return `${hh}:${mm}:${ss}`;
}

export function formatBanner(info: TunnelConnectedEvent, targetUrl: string): string {
  let authLabel: string;
  if (info.ownerUsername && info.tokenName) {
    authLabel = `${info.ownerUsername} (${info.tokenName})`;
  } else if (info.ownerUsername) {
    authLabel = info.ownerUsername;
  } else if (info.tokenName) {
    authLabel = info.tokenName;
  } else {
    authLabel = 'anonymous (open mode)';
  }

  const rows: Array<[string, string, string]> = [
    ['Wildcard URL', info.publicUrl, '1;36'],
    ['Web Preview', info.previewUrl, '1;32'],
    ['Path URL', info.pathUrl, '36'],
    ['Dashboard', info.dashboardUrl, '34'],
    ['Forwarding', targetUrl, '33'],
    ['Prefix', info.prefix, '1;35'],
    ['Auth', authLabel, '37'],
  ];

  if (info.transport?.summary) {
    rows.push(['Transport', info.transport.summary, '32']);
  }

  const labelWidth = Math.max(12, ...rows.map(([l]) => l.length));
  const valWidth = Math.max(24, ...rows.map(([, v]) => v.length));
  const title = ` Neruton Tunnel v${VERSION} · Online `;
  const innerWidth = Math.max(labelWidth + 3 + valWidth, title.length) + 2;

  const topFill = Math.max(0, innerWidth - title.length);
  const leftFill = Math.min(2, topFill);
  const rightFill = Math.max(0, topFill - leftFill);

  const lines: string[] = [''];
  lines.push(
    `${c('36', `╭${'─'.repeat(leftFill)}`)}${c('1;32', title)}${c('36', '─'.repeat(rightFill))}${c('36', '╮')}`,
  );

  for (const [label, value, color] of rows) {
    const padLabel = ' '.repeat(Math.max(0, labelWidth - label.length));
    const contentLen = labelWidth + 3 + value.length;
    const padRight = ' '.repeat(Math.max(0, innerWidth - contentLen - 2));
    lines.push(
      `${c('36', '│')} ${c('2', label)}${padLabel} ${c('2', '→')} ${c(color, value)}${padRight} ${c('36', '│')}`,
    );
  }

  lines.push(c('36', `╰${'─'.repeat(innerWidth)}╯`));
  lines.push(c('2', 'Press Ctrl+C to close the tunnel.\n'));
  return lines.join('\n');
}

export function printBanner(
  info: TunnelConnectedEvent,
  targetUrl: string,
  out: NodeJS.WritableStream = process.stdout,
): void {
  out.write(`${formatBanner(info, targetUrl)}\n`);
}

export function logRequest(
  event: TunnelRequestEvent,
  out: NodeJS.WritableStream = process.stdout,
): void {
  const now = formatTime();
  let statusColor: string;
  if (event.status === 101) {
    statusColor = '1;35';
  } else if (event.status >= 200 && event.status <= 299) {
    statusColor = '1;32';
  } else if (event.status >= 300 && event.status <= 399) {
    statusColor = '1;36';
  } else if (event.status >= 400 && event.status <= 499) {
    statusColor = '1;33';
  } else {
    statusColor = '1;31';
  }
  const statusText = String(event.status).padStart(3, ' ');
  const methodText = event.method.padEnd(7, ' ');
  out.write(
    `${c('2', now)}  ${c(statusColor, statusText)}  ${c('1', methodText)}  ${event.path}  ${c('2', `(${event.durationMs}ms)`)}\n`,
  );
}

export function logInfo(msg: string, out: NodeJS.WritableStream = process.stdout): void {
  out.write(`${c('2', formatTime())}  ${c('1;36', 'INFO')}  ${msg}\n`);
}

export function logWarn(msg: string, err: NodeJS.WritableStream = process.stderr): void {
  err.write(`${c('2', formatTime())}  ${c('1;33', 'WARN')}  ${msg}\n`);
}

export function logError(msg: string, err: NodeJS.WritableStream = process.stderr): void {
  err.write(`${c('2', formatTime())}  ${c('1;31', 'ERR ')}  ${msg}\n`);
}
