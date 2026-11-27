"""CLI entrypoint (`neruton` and `python -m neruton`) mirroring Rust `neruton-cli`."""

from __future__ import annotations

import argparse
import asyncio
import os
import signal
import sys
from pathlib import Path
from typing import Optional, Sequence

from . import ui
from ._version import DEFAULT_SERVER_URL, __version__
from .client import Tunnel
from .config import (
    config_path,
    load_config,
    resolve_server_and_token,
    resolve_stealth_options,
    save_config,
)
from .doh import parse_doh_option
from .errors import NerutonError
from .forwarder import RequestEvent
from .protocol import RegisterResponse, detect_client_os
from .tls_stealth import VALID_SNI_MODES, normalize_sni_mode


def _add_common_tunnel_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--server",
        default=None,
        help="Neruton gateway server URL (env: NERUTON_SERVER, default: https://neruton.moer.eu.org)",
    )
    parser.add_argument(
        "-s",
        "--subdomain",
        "--prefix",
        dest="subdomain",
        default=None,
        help="Custom subdomain prefix (auto-generates a UUID v4 if omitted)",
    )
    parser.add_argument(
        "--token",
        default=None,
        help="Optional Bearer auth token for protected servers (env: NERUTON_TOKEN)",
    )
    parser.add_argument(
        "--no-tls-verify",
        action="store_true",
        default=False,
        help="Disable TLS certificate verification for self-signed servers or local HTTPS targets",
    )
    parser.add_argument(
        "--host-header",
        default=None,
        help="Control the Host header sent to the local service (`preserve`, `rewrite`, or custom value)",
    )
    parser.add_argument(
        "--doh",
        default=None,
        metavar="MODE_OR_URLS",
        help="DNS-over-HTTPS mode (`auto`, `strict`, `off`) or comma-separated DoH URL(s) (env: NERUTON_DOH, default: auto)",
    )
    parser.add_argument(
        "--no-doh",
        action="store_true",
        default=False,
        help="Disable DNS-over-HTTPS and use system DNS (equivalent to --doh off)",
    )
    parser.add_argument(
        "--sni-mode",
        choices=VALID_SNI_MODES,
        default=None,
        help="TLS SNI hiding mode: auto, ech, fragment, none, plain (env: NERUTON_SNI_MODE, default: auto)",
    )
    parser.add_argument(
        "--sni",
        default=None,
        metavar="HOST",
        help="Custom TLS SNI hostname (certificate still verified against real server host; env: NERUTON_SNI)",
    )
    parser.add_argument(
        "--ech-config",
        default=None,
        metavar="BASE64",
        help="Base64-encoded RFC 9849 ECHConfigList for TLS 1.3 ECH (env: NERUTON_ECH_CONFIG)",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=None,
        help="Path to config file (default: ~/.config/neruton/config.toml)",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="neruton",
        description="Self-hosted intranet penetration & wildcard tunnel client inspired by cloudflared",
    )
    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"neruton {__version__}",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # `neruton tunnel --url <url>`
    p_tunnel = subparsers.add_parser(
        "tunnel",
        help="Start an HTTP/WebSocket tunnel forwarding to a local service",
    )
    p_tunnel.add_argument(
        "-u",
        "--url",
        required=True,
        help="Local target URL or port to expose (e.g. http://localhost:3000 or 3000)",
    )
    _add_common_tunnel_flags(p_tunnel)

    # `neruton http <target>`
    p_http = subparsers.add_parser(
        "http",
        help="Shorthand for `neruton tunnel --url <PORT_OR_URL>` (e.g. `neruton http 3000`)",
    )
    p_http.add_argument(
        "target",
        help="Local port or URL (e.g. `3000`, `localhost:8080`, or `http://127.0.0.1:3000`)",
    )
    _add_common_tunnel_flags(p_http)

    # `neruton config <set|show|path>`
    p_config = subparsers.add_parser(
        "config",
        help="Manage persistent CLI configuration (~/.config/neruton/config.toml)",
    )
    cfg_sub = p_config.add_subparsers(dest="config_action", required=True)

    p_cfg_set = cfg_sub.add_parser(
        "set",
        help="Save default server, auth token, or DoH/SNI stealth settings to config.toml",
    )
    p_cfg_set.add_argument("--server", default=None, help="Default server URL (empty to unset)")
    p_cfg_set.add_argument("--token", default=None, help="Default auth token (empty to unset)")
    p_cfg_set.add_argument(
        "--doh",
        default=None,
        metavar="MODE_OR_URLS",
        help="Default DoH mode (`auto`, `strict`, `off`) or comma-separated URLs (empty to unset)",
    )
    p_cfg_set.add_argument(
        "--no-doh",
        action="store_true",
        default=False,
        help="Save `off` as the default DoH mode (equivalent to --doh off)",
    )
    p_cfg_set.add_argument(
        "--sni-mode",
        default=None,
        help="Default SNI mode (`auto`, `ech`, `fragment`, `none`, `plain`; empty to unset)",
    )
    p_cfg_set.add_argument("--sni", default=None, metavar="HOST", help="Default custom SNI host (empty to unset)")
    p_cfg_set.add_argument(
        "--ech-config",
        default=None,
        metavar="BASE64",
        help="Default base64 ECHConfigList (empty to unset)",
    )
    p_cfg_set.add_argument("--config", type=Path, default=None, help="Path to config file")

    p_cfg_show = cfg_sub.add_parser(
        "show",
        help="Show the current resolved configuration",
    )
    p_cfg_show.add_argument("--config", type=Path, default=None, help="Path to config file")

    p_cfg_path = cfg_sub.add_parser(
        "path",
        help="Print the resolved path to config.toml",
    )
    p_cfg_path.add_argument("--config", type=Path, default=None, help="Path to config file")

    # `neruton version`
    subparsers.add_parser("version", help="Print version and build metadata")

    return parser


async def _run_tunnel_cli(args: argparse.Namespace, target_url: str) -> int:
    if args.no_doh and args.doh is not None:
        raise NerutonError("cannot specify both --doh and --no-doh")
    doh_arg: Optional[str] = "off" if args.no_doh else args.doh

    server, token = resolve_server_and_token(
        server=args.server,
        token=args.token,
        config_file=args.config,
    )

    def _on_connect(reg: RegisterResponse) -> None:
        ui.print_banner(reg, tunnel.target_url, transport_info=tunnel.transport_info)

    def _on_reconnect(_attempt: int, backoff: float, reason: str) -> None:
        ui.log_warn(f"Disconnected ({reason}). Reconnecting in {int(backoff)}s...")

    def _on_request(ev: RequestEvent) -> None:
        ui.log_request(ev.method, ev.path, ev.status, ev.duration_ms)

    tunnel = Tunnel(
        target_url=target_url,
        server=server,
        token=token,
        subdomain=args.subdomain,
        no_tls_verify=args.no_tls_verify,
        host_header=args.host_header,
        doh=doh_arg,
        sni_mode=args.sni_mode,
        sni=args.sni,
        ech_config=args.ech_config,
        config_file=args.config,
        reconnect=True,
        retry_initial=True,
        on_connect=_on_connect,
        on_reconnect=_on_reconnect,
        on_request=_on_request,
        on_warn=ui.log_warn,
    )

    ui.log_info(
        f"Connecting to {tunnel.ws_url} (target: {tunnel.target_url}, "
        f"doh: {tunnel.doh_config.to_config_string()}, sni-mode: {tunnel.sni_mode})..."
    )

    loop = asyncio.get_running_loop()
    stop_triggered = False

    def _request_stop() -> None:
        nonlocal stop_triggered
        if not stop_triggered:
            stop_triggered = True
            loop.create_task(tunnel.close())

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _request_stop)
        except (NotImplementedError, RuntimeError):
            pass

    try:
        await tunnel.start()
        if not tunnel.closed:
            await tunnel.wait()
        if stop_triggered:
            ui.log_info("Tunnel shut down cleanly.")
        return 0
    except KeyboardInterrupt:
        await tunnel.close()
        ui.log_info("Tunnel shut down cleanly.")
        return 0
    finally:
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.remove_signal_handler(sig)
            except (NotImplementedError, RuntimeError):
                pass
        if not tunnel.closed:
            await tunnel.close()


def _cmd_config(args: argparse.Namespace) -> int:
    action = args.config_action
    if action == "set":
        if args.no_doh and args.doh is not None:
            raise NerutonError("cannot specify both --doh and --no-doh")
        if not args.no_doh and all(
            v is None
            for v in (
                args.server,
                args.token,
                args.doh,
                args.sni_mode,
                args.sni,
                args.ech_config,
            )
        ):
            raise NerutonError(
                "provide at least one of --server, --token, --doh, --no-doh, --sni-mode, --sni, or --ech-config"
            )
        cfg = load_config(args.config)
        if args.server is not None:
            cfg.server = args.server.strip() if args.server.strip() else None
        if args.token is not None:
            cfg.token = args.token.strip() if args.token.strip() else None
        if args.no_doh:
            cfg.doh = "off"
        elif args.doh is not None:
            if args.doh.strip():
                parsed_doh = parse_doh_option(args.doh)
                cfg.doh = parsed_doh.to_config_string()
            else:
                cfg.doh = None
        if args.sni_mode is not None:
            if args.sni_mode.strip():
                cfg.sni_mode = normalize_sni_mode(args.sni_mode)
            else:
                cfg.sni_mode = None
        if args.sni is not None:
            cfg.sni = args.sni.strip() if args.sni.strip() else None
        if args.ech_config is not None:
            cfg.ech_config = args.ech_config.strip() if args.ech_config.strip() else None

        saved = save_config(cfg, args.config)
        print(f"Saved configuration to {saved}")
        return 0

    if action == "show":
        path = config_path(args.config)
        cfg = load_config(args.config)
        env_server = os.environ.get("NERUTON_SERVER", "").strip()
        effective_server = env_server or cfg.server or DEFAULT_SERVER_URL
        token_status = "<configured>" if cfg.token else "<not set>"
        stealth = resolve_stealth_options(config_file=args.config)
        ech_status = "<configured>" if stealth.ech_config else "<not set>"

        print(f"Config file:        {path}")
        print(f"Effective server:   {effective_server}")
        print(f"Saved server:       {cfg.server or '<default>'}")
        print(f"Saved token:        {token_status}")
        print(f"Effective DoH:      {stealth.doh.to_config_string()}")
        print(f"Saved DoH:          {cfg.doh or '<default: auto>'}")
        print(f"Effective SNI mode: {stealth.sni_mode}")
        print(f"Saved SNI mode:     {cfg.sni_mode or '<default: auto>'}")
        print(f"Effective SNI:      {stealth.sni or '<auto>'}")
        print(f"Saved ECH config:   {ech_status}")
        return 0

    if action == "path":
        print(config_path(args.config))
        return 0

    raise NerutonError(f"unknown config action: {action}")


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Entry point for the `neruton` CLI script."""
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    try:
        if args.command == "version":
            print(f"neruton {__version__} ({detect_client_os()})")
            return 0
        if args.command == "config":
            return _cmd_config(args)
        if args.command == "tunnel":
            return asyncio.run(_run_tunnel_cli(args, args.url))
        if args.command == "http":
            return asyncio.run(_run_tunnel_cli(args, args.target))
        parser.error(f"unknown command: {args.command}")
        return 2
    except KeyboardInterrupt:
        ui.log_info("Tunnel shut down cleanly.")
        return 0
    except Exception as exc:
        ui.log_error(str(exc))
        return 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
