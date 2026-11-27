import { VERSION } from './constants.js';
import {
  configPath,
  loadConfig,
  resolveConnectionSettings,
  saveConfig,
} from './config.js';
import { formatDohValue, parseDohOption } from './doh.js';
import {
  buildTunnelWsUrl,
  formatClientOs,
  normalizeTargetUrl,
} from './protocol.js';
import { parseSniMode } from './tls-stealth.js';
import { connect } from './tunnel.js';
import { logError, logInfo, logRequest, logWarn, printBanner } from './ui.js';

export interface CliIo {
  stdout?: NodeJS.WritableStream;
  stderr?: NodeJS.WritableStream;
  env?: NodeJS.ProcessEnv;
}

const HELP_ROOT = `neruton ${VERSION}
Self-hosted intranet penetration & wildcard tunnel client inspired by cloudflared

Usage:
  neruton <command> [options]

Commands:
  tunnel    Start an HTTP/WebSocket tunnel forwarding to a local service
  http      Shorthand for \`neruton tunnel --url <PORT_OR_URL>\` (e.g. \`neruton http 3000\`)
  config    Manage persistent CLI configuration (~/.config/neruton/config.toml)
  version   Print version and runtime metadata

Options:
  -h, --help      Show help
  -V, --version   Show version
`;

const HELP_TUNNEL = `Start an HTTP/WebSocket tunnel forwarding to a local service

Usage:
  neruton tunnel --url <URL_OR_PORT> [options]

Options:
  -u, --url <URL>           Local target URL or port (e.g. http://localhost:3000 or 3000)
      --server <URL>        Neruton gateway server URL (env: NERUTON_SERVER)
  -s, --subdomain <PREFIX>  Custom subdomain prefix (alias: --prefix)
      --token <TOKEN>       Bearer auth token (env: NERUTON_TOKEN)
      --no-tls-verify       Disable TLS certificate verification
      --host-header <MODE>  Host header sent to local service ('rewrite', 'preserve', or custom)
      --doh <MODE_OR_URLS>  DoH mode ('auto', 'strict', 'off') or comma-separated RFC 8484 URLs (env: NERUTON_DOH)
      --no-doh              Disable DNS-over-HTTPS and use system DNS
      --sni-mode <MODE>     SNI hiding mode: auto, ech, fragment, none, plain (env: NERUTON_SNI_MODE)
      --sni <HOST>          Custom TLS SNI hostname (cert still verified against real host; env: NERUTON_SNI)
      --ech-config <B64>    Base64 ECHConfigList for TLS 1.3 ECH (env: NERUTON_ECH_CONFIG)
      --config <PATH>       Path to config.toml (default: ~/.config/neruton/config.toml)
  -h, --help                Show help
`;

const HELP_HTTP = `Shorthand for \`neruton tunnel --url <PORT_OR_URL>\`

Usage:
  neruton http <PORT_OR_URL> [options]

Options:
      --server <URL>        Neruton gateway server URL (env: NERUTON_SERVER)
  -s, --subdomain <PREFIX>  Custom subdomain prefix (alias: --prefix)
      --token <TOKEN>       Bearer auth token (env: NERUTON_TOKEN)
      --no-tls-verify       Disable TLS certificate verification
      --host-header <MODE>  Host header sent to local service ('rewrite', 'preserve', or custom)
      --doh <MODE_OR_URLS>  DoH mode ('auto', 'strict', 'off') or comma-separated RFC 8484 URLs (env: NERUTON_DOH)
      --no-doh              Disable DNS-over-HTTPS and use system DNS
      --sni-mode <MODE>     SNI hiding mode: auto, ech, fragment, none, plain (env: NERUTON_SNI_MODE)
      --sni <HOST>          Custom TLS SNI hostname (cert still verified against real host; env: NERUTON_SNI)
      --ech-config <B64>    Base64 ECHConfigList for TLS 1.3 ECH (env: NERUTON_ECH_CONFIG)
      --config <PATH>       Path to config.toml (default: ~/.config/neruton/config.toml)
  -h, --help                Show help
`;

const HELP_CONFIG = `Manage persistent CLI configuration (~/.config/neruton/config.toml)

Usage:
  neruton config <subcommand> [options]

Subcommands:
  set     Save default settings (server, token, doh, sni-mode, sni, ech-config) to config.toml
  show    Show the current resolved configuration
  path    Print the resolved path to config.toml

Options:
      --server <URL>        Server URL (for \`config set\`)
      --token <TOKEN>       Auth token (for \`config set\`)
      --doh <MODE_OR_URLS>  Default DoH mode or URL(s) (for \`config set\`)
      --no-doh              Save \`doh = "off"\` (for \`config set\`)
      --sni-mode <MODE>     Default SNI mode: auto, ech, fragment, none, plain (for \`config set\`)
      --sni <HOST>          Default custom SNI hostname (for \`config set\`)
      --ech-config <B64>    Default base64 ECHConfigList (for \`config set\`)
      --config <PATH>       Path to config file
  -h, --help                Show help
`;

interface ParsedFlags {
  flags: Record<string, string | boolean>;
  positionals: string[];
}

const VALUE_FLAGS = new Set([
  '--url',
  '-u',
  '--server',
  '--subdomain',
  '-s',
  '--prefix',
  '--token',
  '--host-header',
  '--doh',
  '--sni-mode',
  '--sni',
  '--ech-config',
  '--config',
]);

const BOOL_FLAGS = new Set([
  '--no-tls-verify',
  '--no-doh',
  '--help',
  '-h',
  '--version',
  '-V',
]);

function parseFlagArgs(args: string[]): ParsedFlags {
  const flags: Record<string, string | boolean> = {};
  const positionals: string[] = [];

  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i];
    if (arg === '--') {
      positionals.push(...args.slice(i + 1));
      break;
    }

    if (arg.startsWith('--') && arg.includes('=')) {
      const eq = arg.indexOf('=');
      const name = arg.slice(0, eq);
      const value = arg.slice(eq + 1);
      if (!VALUE_FLAGS.has(name)) {
        throw new Error(`unknown option '${name}'`);
      }
      flags[name] = value;
      continue;
    }

    if (BOOL_FLAGS.has(arg)) {
      flags[arg] = true;
      continue;
    }

    if (VALUE_FLAGS.has(arg)) {
      if (i + 1 >= args.length) {
        throw new Error(`option '${arg}' requires a value`);
      }
      flags[arg] = args[i + 1];
      i += 1;
      continue;
    }

    if (arg.startsWith('-')) {
      throw new Error(`unknown option '${arg}'`);
    }

    positionals.push(arg);
  }

  return { flags, positionals };
}

function getStringFlag(flags: Record<string, string | boolean>, ...names: string[]): string | undefined {
  for (const name of names) {
    const v = flags[name];
    if (typeof v === 'string') {
      return v;
    }
  }
  return undefined;
}

async function runTunnelCommand(
  target: string,
  flags: Record<string, string | boolean>,
  io: Required<CliIo>,
): Promise<number> {
  const explicitServer = getStringFlag(flags, '--server');
  const explicitToken = getStringFlag(flags, '--token');
  const subdomain = getStringFlag(flags, '--subdomain', '-s', '--prefix');
  const hostHeader = getStringFlag(flags, '--host-header');
  const cfgPath = getStringFlag(flags, '--config');
  const noTlsVerify = Boolean(flags['--no-tls-verify']);
  const explicitDohFlag = getStringFlag(flags, '--doh');
  const noDoh = Boolean(flags['--no-doh']);
  if (noDoh && explicitDohFlag !== undefined) {
    throw new Error('cannot combine --doh and --no-doh');
  }
  const explicitDoh = noDoh ? 'off' : explicitDohFlag;
  const explicitSniMode = getStringFlag(flags, '--sni-mode');
  const explicitSni = getStringFlag(flags, '--sni');
  const explicitEchConfig = getStringFlag(flags, '--ech-config');

  const settings = resolveConnectionSettings({
    server: explicitServer,
    token: explicitToken,
    doh: explicitDoh,
    sniMode: explicitSniMode,
    sni: explicitSni,
    echConfig: explicitEchConfig,
    configPath: cfgPath,
    env: io.env,
  });

  const normalizedTarget = normalizeTargetUrl(target);
  const wsUrl = buildTunnelWsUrl(settings.server);
  logInfo(
    `Connecting to ${wsUrl.toString()} (target: ${normalizedTarget.toString()}, doh: ${settings.dohRaw}, sni-mode: ${settings.sniMode}${settings.sni ? `, sni: ${settings.sni}` : ''})...`,
    io.stdout,
  );

  const abortController = new AbortController();
  let closing = false;
  const onSignal = (): void => {
    if (closing) {
      process.exit(130);
    }
    closing = true;
    abortController.abort();
  };

  process.on('SIGINT', onSignal);
  process.on('SIGTERM', onSignal);

  try {
    const tunnel = await connect({
      url: target,
      server: settings.server,
      token: settings.token,
      subdomain,
      noTlsVerify,
      hostHeader,
      doh: settings.dohRaw,
      sniMode: settings.sniMode,
      sni: settings.sni,
      echConfig: settings.echConfig,
      configPath: cfgPath,
      reconnect: true,
      retryInitialConnect: true,
      signal: abortController.signal,
      onReconnecting: ({ delayMs, reason }) => {
        logWarn(
          `Disconnected (${reason}). Reconnecting in ${Math.round(delayMs / 1000)}s...`,
          io.stderr,
        );
      },
      onWarning: (msg) => {
        logWarn(msg, io.stderr);
      },
    });

    printBanner(
      {
        publicUrl: tunnel.publicUrl,
        previewUrl: tunnel.previewUrl,
        pathUrl: tunnel.pathUrl,
        dashboardUrl: tunnel.dashboardUrl,
        prefix: tunnel.prefix,
        tunnelId: tunnel.tunnelId,
        ownerUsername: tunnel.ownerUsername,
        tokenName: tunnel.tokenName,
        reconnected: false,
        transport: tunnel.transportInfo ?? undefined,
      },
      tunnel.targetUrl,
      io.stdout,
    );

    tunnel.on('connected', (info) => {
      if (info.reconnected) {
        printBanner(info, tunnel.targetUrl, io.stdout);
      }
    });

    tunnel.on('request', (event) => {
      logRequest(event, io.stdout);
    });

    tunnel.on('error', () => {
      // Fatal error is also surfaced via tunnel.wait().
    });

    await tunnel.wait();
    logInfo('Tunnel shut down cleanly.', io.stdout);
    return 0;
  } catch (err) {
    if (abortController.signal.aborted) {
      logInfo('Tunnel shut down cleanly.', io.stdout);
      return 0;
    }
    const msg = err instanceof Error ? err.message : String(err);
    logError(msg, io.stderr);
    return 1;
  } finally {
    process.off('SIGINT', onSignal);
    process.off('SIGTERM', onSignal);
  }
}

export async function runCli(argv: string[] = process.argv.slice(2), ioOpts: CliIo = {}): Promise<number> {
  const io: Required<CliIo> = {
    stdout: ioOpts.stdout ?? process.stdout,
    stderr: ioOpts.stderr ?? process.stderr,
    env: ioOpts.env ?? process.env,
  };

  if (argv.length === 0 || argv[0] === '-h' || argv[0] === '--help') {
    io.stdout.write(HELP_ROOT);
    return 0;
  }

  if (argv[0] === '-V' || argv[0] === '--version' || argv[0] === 'version') {
    io.stdout.write(`neruton ${VERSION} (${formatClientOs()})\n`);
    return 0;
  }

  const command = argv[0];
  const rest = argv.slice(1);

  try {
    if (command === 'tunnel') {
      const { flags } = parseFlagArgs(rest);
      if (flags['--help'] || flags['-h']) {
        io.stdout.write(HELP_TUNNEL);
        return 0;
      }
      const url = getStringFlag(flags, '--url', '-u');
      if (!url) {
        logError('missing required option: --url <URL_OR_PORT>', io.stderr);
        return 1;
      }
      return await runTunnelCommand(url, flags, io);
    }

    if (command === 'http') {
      const { flags, positionals } = parseFlagArgs(rest);
      if (flags['--help'] || flags['-h']) {
        io.stdout.write(HELP_HTTP);
        return 0;
      }
      if (positionals.length === 0) {
        logError('missing required argument: <PORT_OR_URL>', io.stderr);
        return 1;
      }
      return await runTunnelCommand(positionals[0], flags, io);
    }

    if (command === 'config') {
      if (rest.length === 0 || rest[0] === '-h' || rest[0] === '--help') {
        io.stdout.write(HELP_CONFIG);
        return 0;
      }
      const sub = rest[0];
      const { flags } = parseFlagArgs(rest.slice(1));
      if (flags['--help'] || flags['-h']) {
        io.stdout.write(HELP_CONFIG);
        return 0;
      }
      const cfgPath = getStringFlag(flags, '--config');

      if (sub === 'path') {
        io.stdout.write(`${configPath(cfgPath)}\n`);
        return 0;
      }

      if (sub === 'set') {
        const server = getStringFlag(flags, '--server');
        const token = getStringFlag(flags, '--token');
        const dohFlag = getStringFlag(flags, '--doh');
        const noDoh = Boolean(flags['--no-doh']);
        if (noDoh && dohFlag !== undefined) {
          logError('cannot combine --doh and --no-doh', io.stderr);
          return 1;
        }
        const doh = noDoh ? 'off' : dohFlag;
        const sniMode = getStringFlag(flags, '--sni-mode');
        const sni = getStringFlag(flags, '--sni');
        const echConfig = getStringFlag(flags, '--ech-config');

        if (
          server === undefined &&
          token === undefined &&
          doh === undefined &&
          sniMode === undefined &&
          sni === undefined &&
          echConfig === undefined
        ) {
          logError(
            'provide at least one of --server, --token, --doh, --no-doh, --sni-mode, --sni, or --ech-config',
            io.stderr,
          );
          return 1;
        }
        const cfg = loadConfig(cfgPath);
        if (server !== undefined) {
          cfg.server = server.trim().length === 0 ? undefined : server;
        }
        if (token !== undefined) {
          cfg.token = token.trim().length === 0 ? undefined : token;
        }
        if (doh !== undefined) {
          if (doh.trim().length === 0) {
            cfg.doh = undefined;
          } else {
            cfg.doh = formatDohValue(parseDohOption(doh));
          }
        }
        if (sniMode !== undefined) {
          cfg.sniMode = sniMode.trim().length === 0 ? undefined : parseSniMode(sniMode);
        }
        if (sni !== undefined) {
          cfg.sni = sni.trim().length === 0 ? undefined : sni.trim();
        }
        if (echConfig !== undefined) {
          cfg.echConfig = echConfig.trim().length === 0 ? undefined : echConfig.trim();
        }
        const saved = saveConfig(cfg, cfgPath);
        io.stdout.write(`Saved configuration to ${saved}\n`);
        return 0;
      }

      if (sub === 'show') {
        const resolvedPath = configPath(cfgPath);
        const cfg = loadConfig(cfgPath);
        const resolved = resolveConnectionSettings({
          configPath: cfgPath,
          env: io.env,
        });
        const tokenStatus = cfg.token && cfg.token.length > 0 ? '<configured>' : '<not set>';
        const echStatus = cfg.echConfig && cfg.echConfig.length > 0 ? '<configured>' : '<not set>';
        const effectiveEchStatus =
          resolved.echConfig && resolved.echConfig.length > 0 ? '<configured>' : '<not set>';

        io.stdout.write(`Config file:      ${resolvedPath}\n`);
        io.stdout.write(`Effective server: ${resolved.server}\n`);
        io.stdout.write(`Saved server:     ${cfg.server ?? '<default>'}\n`);
        io.stdout.write(`Saved token:      ${tokenStatus}\n`);
        io.stdout.write(`Effective DoH:    ${resolved.dohRaw}\n`);
        io.stdout.write(`Saved DoH:        ${cfg.doh ?? '<default: auto>'}\n`);
        io.stdout.write(`Effective SNI:    mode=${resolved.sniMode}${resolved.sni ? `, host=${resolved.sni}` : ''}\n`);
        io.stdout.write(`Saved SNI mode:   ${cfg.sniMode ?? '<default: auto>'}\n`);
        io.stdout.write(`Saved SNI host:   ${cfg.sni ?? '<not set>'}\n`);
        io.stdout.write(`Effective ECH:    ${effectiveEchStatus}\n`);
        io.stdout.write(`Saved ECH config: ${echStatus}\n`);
        return 0;
      }

      logError(`unknown config subcommand '${sub}' (expected: set, show, path)`, io.stderr);
      return 1;
    }

    logError(`unknown command '${command}'. Run \`neruton --help\` for usage.`, io.stderr);
    return 1;
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    logError(msg, io.stderr);
    return 1;
  }
}
