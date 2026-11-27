export const VERSION = '0.4.0';
export const DEFAULT_BASE_DOMAIN = 'moer.eu.org';
export const DEFAULT_PANEL_HOST = 'neruton.moer.eu.org';
export const DEFAULT_SERVER_URL = 'https://neruton.moer.eu.org';
export const DEFAULT_PUBLIC_SCHEME = 'https';
export const TUNNEL_WS_PATH = '/_neruton/tunnel';

export const RESERVED_PREFIXES = [
  'neruton',
  'www',
  'api',
  'admin',
  '_neruton',
] as const;

export const HOP_BY_HOP_HEADERS = new Set<string>([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
  'proxy-connection',
]);
