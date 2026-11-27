import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { DEFAULT_SERVER_URL } from './constants.js';
import {
  formatDohValue,
  parseDohOption,
  type DohOption,
  type ParsedDohConfig,
} from './doh.js';
import { ConfigError } from './errors.js';
import { parseSniMode, type SniMode } from './tls-stealth.js';

export interface CliConfig {
  server?: string;
  token?: string;
  doh?: string;
  sniMode?: string;
  sni?: string;
  echConfig?: string;
}

export interface ResolveSettingsInput {
  server?: string;
  token?: string;
  doh?: DohOption;
  sniMode?: SniMode | string;
  sni?: string;
  echConfig?: string;
  configPath?: string;
  env?: NodeJS.ProcessEnv;
}

export interface ResolvedConnectionSettings {
  server: string;
  token?: string;
  doh: ParsedDohConfig;
  dohRaw: string;
  sniMode: SniMode;
  sni?: string;
  echConfig?: string;
}

/**
 * Resolve the config file path (defaults to `~/.config/neruton/config.toml` on Unix/macOS,
 * or `%APPDATA%/neruton/config.toml` on Windows, matching the Rust CLI).
 */
export function configPath(explicit?: string): string {
  if (explicit && explicit.trim().length > 0) {
    return path.resolve(explicit);
  }
  if (process.platform !== 'win32') {
    const home = os.homedir();
    if (home) {
      return path.join(home, '.config', 'neruton', 'config.toml');
    }
  }
  const appData =
    process.env.APPDATA ||
    (os.homedir() ? path.join(os.homedir(), 'AppData', 'Roaming') : '.');
  return path.join(appData, 'neruton', 'config.toml');
}

function unescapeTomlBasicString(raw: string, lineNo: number): string {
  let out = '';
  for (let i = 0; i < raw.length; i += 1) {
    const ch = raw[i];
    if (ch !== '\\') {
      out += ch;
      continue;
    }
    i += 1;
    if (i >= raw.length) {
      throw new ConfigError(`unterminated escape sequence at line ${lineNo}`);
    }
    const esc = raw[i];
    switch (esc) {
      case 'b':
        out += '\b';
        break;
      case 't':
        out += '\t';
        break;
      case 'n':
        out += '\n';
        break;
      case 'f':
        out += '\f';
        break;
      case 'r':
        out += '\r';
        break;
      case '"':
        out += '"';
        break;
      case '\\':
        out += '\\';
        break;
      case 'u': {
        const hex = raw.slice(i + 1, i + 5);
        if (!/^[0-9a-fA-F]{4}$/.test(hex)) {
          throw new ConfigError(`invalid \\u escape at line ${lineNo}`);
        }
        out += String.fromCodePoint(parseInt(hex, 16));
        i += 4;
        break;
      }
      case 'U': {
        const hex = raw.slice(i + 1, i + 9);
        if (!/^[0-9a-fA-F]{8}$/.test(hex)) {
          throw new ConfigError(`invalid \\U escape at line ${lineNo}`);
        }
        out += String.fromCodePoint(parseInt(hex, 16));
        i += 8;
        break;
      }
      default:
        throw new ConfigError(`invalid escape '\\${esc}' at line ${lineNo}`);
    }
  }
  return out;
}

function parseTomlStringValue(rawValue: string, lineNo: number): string {
  const s = rawValue.trim();
  if (s.startsWith('"')) {
    let end = -1;
    for (let i = 1; i < s.length; i += 1) {
      if (s[i] === '\\') {
        i += 1;
        continue;
      }
      if (s[i] === '"') {
        end = i;
        break;
      }
    }
    if (end === -1) {
      throw new ConfigError(`unterminated quoted string at line ${lineNo}`);
    }
    const trailing = s.slice(end + 1).trim();
    if (trailing.length > 0 && !trailing.startsWith('#')) {
      throw new ConfigError(`unexpected trailing characters at line ${lineNo}`);
    }
    return unescapeTomlBasicString(s.slice(1, end), lineNo);
  }
  if (s.startsWith("'")) {
    const end = s.indexOf("'", 1);
    if (end === -1) {
      throw new ConfigError(`unterminated literal string at line ${lineNo}`);
    }
    const trailing = s.slice(end + 1).trim();
    if (trailing.length > 0 && !trailing.startsWith('#')) {
      throw new ConfigError(`unexpected trailing characters at line ${lineNo}`);
    }
    return s.slice(1, end);
  }
  throw new ConfigError(`expected string value at line ${lineNo}`);
}

/**
 * Parse Neruton `config.toml` content into a `CliConfig` object.
 */
export function parseConfigToml(content: string): CliConfig {
  const cfg: CliConfig = {};
  const lines = content.replace(/^\uFEFF/, '').split(/\r?\n/);
  let inTopLevel = true;

  for (let idx = 0; idx < lines.length; idx += 1) {
    const lineNo = idx + 1;
    const trimmed = lines[idx].trim();
    if (!trimmed || trimmed.startsWith('#')) {
      continue;
    }
    if (trimmed.startsWith('[')) {
      // Entering a TOML table section; top-level keys only live before sections.
      inTopLevel = false;
      continue;
    }
    if (!inTopLevel) {
      continue;
    }

    const eqIdx = trimmed.indexOf('=');
    if (eqIdx === -1) {
      throw new ConfigError(`invalid TOML syntax at line ${lineNo}`);
    }

    let key = trimmed.slice(0, eqIdx).trim();
    if (
      (key.startsWith('"') && key.endsWith('"')) ||
      (key.startsWith("'") && key.endsWith("'"))
    ) {
      key = key.slice(1, -1);
    }
    const rawVal = trimmed.slice(eqIdx + 1).trim();

    if (key === 'server') {
      cfg.server = parseTomlStringValue(rawVal, lineNo);
    } else if (key === 'token') {
      cfg.token = parseTomlStringValue(rawVal, lineNo);
    } else if (key === 'doh') {
      cfg.doh = parseTomlStringValue(rawVal, lineNo);
    } else if (key === 'sni_mode') {
      cfg.sniMode = parseTomlStringValue(rawVal, lineNo);
    } else if (key === 'sni') {
      cfg.sni = parseTomlStringValue(rawVal, lineNo);
    } else if (key === 'ech_config') {
      cfg.echConfig = parseTomlStringValue(rawVal, lineNo);
    }
  }

  return cfg;
}

function escapeTomlBasicString(value: string): string {
  let out = '';
  for (const ch of value) {
    switch (ch) {
      case '\\':
        out += '\\\\';
        break;
      case '"':
        out += '\\"';
        break;
      case '\b':
        out += '\\b';
        break;
      case '\f':
        out += '\\f';
        break;
      case '\n':
        out += '\\n';
        break;
      case '\r':
        out += '\\r';
        break;
      case '\t':
        out += '\\t';
        break;
      default: {
        const cp = ch.codePointAt(0)!;
        if (cp < 0x20 || cp === 0x7f) {
          out += `\\u${cp.toString(16).padStart(4, '0')}`;
        } else {
          out += ch;
        }
      }
    }
  }
  return `"${out}"`;
}

/**
 * Serialize a `CliConfig` to TOML matching Rust `toml::to_string_pretty`.
 */
export function serializeConfigToml(cfg: CliConfig): string {
  const lines: string[] = [];
  if (cfg.server !== undefined) {
    lines.push(`server = ${escapeTomlBasicString(cfg.server)}`);
  }
  if (cfg.token !== undefined) {
    lines.push(`token = ${escapeTomlBasicString(cfg.token)}`);
  }
  if (cfg.doh !== undefined) {
    lines.push(`doh = ${escapeTomlBasicString(cfg.doh)}`);
  }
  if (cfg.sniMode !== undefined) {
    lines.push(`sni_mode = ${escapeTomlBasicString(cfg.sniMode)}`);
  }
  if (cfg.sni !== undefined) {
    lines.push(`sni = ${escapeTomlBasicString(cfg.sni)}`);
  }
  if (cfg.echConfig !== undefined) {
    lines.push(`ech_config = ${escapeTomlBasicString(cfg.echConfig)}`);
  }
  return lines.length > 0 ? `${lines.join('\n')}\n` : '';
}

/**
 * Load `~/.config/neruton/config.toml` (or an explicit path). Returns `{}` if the file does not exist.
 */
export function loadConfig(explicitPath?: string): CliConfig {
  const filePath = configPath(explicitPath);
  if (!fs.existsSync(filePath)) {
    return {};
  }
  let content: string;
  try {
    content = fs.readFileSync(filePath, 'utf8');
  } catch (err) {
    throw new ConfigError(`failed to read config file ${filePath}`, { cause: err });
  }
  try {
    return parseConfigToml(content);
  } catch (err) {
    if (err instanceof ConfigError) {
      throw new ConfigError(`failed to parse TOML config ${filePath}: ${err.message}`, {
        cause: err,
      });
    }
    throw new ConfigError(`failed to parse TOML config ${filePath}`, { cause: err });
  }
}

/**
 * Save configuration to `~/.config/neruton/config.toml` (or an explicit path)
 * with `0600` permissions on POSIX platforms.
 */
export function saveConfig(cfg: CliConfig, explicitPath?: string): string {
  const filePath = configPath(explicitPath);
  const parentDir = path.dirname(filePath);
  try {
    fs.mkdirSync(parentDir, { recursive: true });
  } catch (err) {
    throw new ConfigError(`failed to create config directory ${parentDir}`, { cause: err });
  }

  const normalized: CliConfig = {};
  if (cfg.server !== undefined && cfg.server.trim().length > 0) {
    normalized.server = cfg.server;
  }
  if (cfg.token !== undefined && cfg.token.trim().length > 0) {
    normalized.token = cfg.token;
  }
  if (cfg.doh !== undefined && cfg.doh.trim().length > 0) {
    normalized.doh = cfg.doh.trim();
  }
  if (cfg.sniMode !== undefined && cfg.sniMode.trim().length > 0) {
    normalized.sniMode = cfg.sniMode.trim();
  }
  if (cfg.sni !== undefined && cfg.sni.trim().length > 0) {
    normalized.sni = cfg.sni.trim();
  }
  if (cfg.echConfig !== undefined && cfg.echConfig.trim().length > 0) {
    normalized.echConfig = cfg.echConfig.trim();
  }

  const content = serializeConfigToml(normalized);
  try {
    fs.writeFileSync(filePath, content, { encoding: 'utf8', mode: 0o600 });
  } catch (err) {
    throw new ConfigError(`failed to write config file ${filePath}`, { cause: err });
  }

  if (process.platform !== 'win32') {
    try {
      fs.chmodSync(filePath, 0o600);
    } catch {
      // Best-effort permission hardening (matching Rust CLI).
    }
  }

  return filePath;
}

function nonEmpty(value: string | undefined): string | undefined {
  if (value === undefined) return undefined;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

/**
 * Resolve effective server, auth token, DoH, and SNI stealth settings with exact cross-client precedence:
 * - explicit option/CLI flag > env var > config.toml > defaults (`doh: 'auto'`, `sniMode: 'auto'`)
 */
export function resolveConnectionSettings(
  input: ResolveSettingsInput = {},
): ResolvedConnectionSettings {
  const env = input.env ?? process.env;
  const fileCfg = loadConfig(input.configPath);

  const server =
    nonEmpty(input.server) ??
    nonEmpty(env.NERUTON_SERVER) ??
    nonEmpty(fileCfg.server) ??
    DEFAULT_SERVER_URL;

  const token =
    nonEmpty(input.token) ??
    nonEmpty(env.NERUTON_TOKEN) ??
    nonEmpty(env.NERUTON_AUTH_TOKEN) ??
    nonEmpty(fileCfg.token);

  let effectiveDohInput: DohOption | undefined;
  if (input.doh !== undefined) {
    if (typeof input.doh === 'string') {
      effectiveDohInput = nonEmpty(input.doh);
    } else {
      effectiveDohInput = input.doh;
    }
  }
  if (effectiveDohInput === undefined) {
    effectiveDohInput = nonEmpty(env.NERUTON_DOH) ?? nonEmpty(fileCfg.doh) ?? 'auto';
  }
  const doh = parseDohOption(effectiveDohInput);
  const dohRaw = formatDohValue(doh);

  const sniModeRaw =
    nonEmpty(input.sniMode) ??
    nonEmpty(env.NERUTON_SNI_MODE) ??
    nonEmpty(fileCfg.sniMode) ??
    'auto';
  const sniMode = parseSniMode(sniModeRaw);

  const sni =
    nonEmpty(input.sni) ??
    nonEmpty(env.NERUTON_SNI) ??
    nonEmpty(fileCfg.sni);

  const echConfig =
    nonEmpty(input.echConfig) ??
    nonEmpty(env.NERUTON_ECH_CONFIG) ??
    nonEmpty(fileCfg.echConfig);

  return {
    server,
    token,
    doh,
    dohRaw,
    sniMode,
    sni,
    echConfig,
  };
}
