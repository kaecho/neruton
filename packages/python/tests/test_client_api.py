"""Unit tests for Async/Sync Tunnel Client APIs, reconnect/401 behavior, and CLI."""

from __future__ import annotations

import asyncio
import contextlib
import io
import json
import subprocess
import sys
import tempfile
import threading
import unittest
from http import HTTPStatus
from pathlib import Path
from typing import Any, List, Optional, Tuple

import websockets
from websockets.asyncio.server import ServerConnection, serve
from websockets.datastructures import Headers
from websockets.http11 import Response as WsHttpResponse

import neruton
from neruton.cli import build_parser, main as cli_main
from neruton.errors import AuthError, RegistrationError
from neruton.protocol import RegisterRequest, RegisterResponse, generate_uuid_prefix
from neruton.yamux import Mode, WsByteTransport, YamuxSession


class _MockNerutonServer:
    """In-process mock Neruton gateway implementing /_neruton/tunnel + Yamux Mode.CLIENT."""

    def __init__(self, *, required_token: Optional[str] = "ntk_secret") -> None:
        self.required_token = required_token
        self.connect_attempts = 0
        self.registered_prefixes: List[Optional[str]] = []
        self.active_sessions: List[YamuxSession] = []
        self.reject_error: Optional[str] = None
        self.reject_once_on_attempt: Optional[int] = None
        self.reject_once_error: Optional[str] = None
        self.handshake_delay: float = 0.0
        self.drop_after_first = False
        self.revoke_after_first = False
        self._server: Any = None
        self.port = 0

    async def start(self) -> None:
        self._server = await serve(
            self._handle_ws,
            "127.0.0.1",
            0,
            process_request=self._process_request,
            compression=None,
        )
        self.port = self._server.sockets[0].getsockname()[1]

    async def stop(self) -> None:
        for s in list(self.active_sessions):
            await s.close()
        self.active_sessions.clear()
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()

    def _process_request(
        self, connection: ServerConnection, request: Any
    ) -> Optional[WsHttpResponse]:
        self.connect_attempts += 1
        if request.path.split("?", 1)[0] != "/_neruton/tunnel":
            return WsHttpResponse(
                HTTPStatus.NOT_FOUND.value, "Not Found", Headers(), b"not found"
            )
        if self.required_token is not None:
            auth = request.headers.get("Authorization", "")
            expected = f"Bearer {self.required_token}"
            if auth != expected:
                body = json.dumps({"error": "Invalid or revoked tunnel token."}).encode()
                return WsHttpResponse(
                    HTTPStatus.UNAUTHORIZED.value,
                    "Unauthorized",
                    Headers({"Content-Type": "application/json"}),
                    body,
                )
        return None

    async def _handle_ws(self, ws: ServerConnection) -> None:
        if self.handshake_delay > 0:
            await asyncio.sleep(self.handshake_delay)
        raw_req = await ws.recv()
        assert isinstance(raw_req, str)
        reg = RegisterRequest.from_json(raw_req)
        self.registered_prefixes.append(reg.prefix)

        attempt_num = len(self.registered_prefixes)
        if self.reject_once_on_attempt == attempt_num and self.reject_once_error is not None:
            resp = RegisterResponse(ok=False, error=self.reject_once_error)
            await ws.send(resp.to_json())
            await ws.close()
            return

        if self.reject_error is not None:
            resp = RegisterResponse(ok=False, error=self.reject_error)
            await ws.send(resp.to_json())
            await ws.close()
            return

        prefix = reg.prefix or generate_uuid_prefix()
        resp = RegisterResponse(
            ok=True,
            tunnel_id="tun-mock-1",
            prefix=prefix,
            public_url=f"http://{prefix}.moer.eu.org",
            path_url=f"http://127.0.0.1:{self.port}/t/{prefix}/",
            preview_url=f"http://127.0.0.1:{self.port}/preview/{prefix}",
            dashboard_url=f"http://127.0.0.1:{self.port}/",
            owner_username="tester",
            token_name="Mock Token",
        )
        await ws.send(resp.to_json())

        session = YamuxSession(WsByteTransport(ws), Mode.CLIENT).start()
        self.active_sessions.append(session)

        if self.drop_after_first and len(self.registered_prefixes) == 1:
            await asyncio.sleep(0.05)
            if self.revoke_after_first:
                self.required_token = "ntk_rotated_secret"
            await session.close()
            return

        await session.wait_closed()

    async def proxy_get(self, path: str, host: str = "demo.moer.eu.org") -> bytes:
        session = self.active_sessions[-1]
        stream = await session.open_stream()
        await stream.write(
            f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode()
        )
        await stream.write_eof()
        return await stream.read_all()


async def _start_local_echo_http() -> Tuple[asyncio.AbstractServer, int]:
    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            raw = await reader.readuntil(b"\r\n\r\n")
            first_line = raw.split(b"\r\n", 1)[0].decode()
            body = f"local-ok:{first_line}".encode()
            writer.write(
                f"HTTP/1.1 200 OK\r\nContent-Length: {len(body)}\r\n\r\n".encode() + body
            )
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    srv = await asyncio.start_server(handler, "127.0.0.1", 0)
    return srv, srv.sockets[0].getsockname()[1]


class TestClientAPIs(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.local_srv, self.local_port = await _start_local_echo_http()
        self.mock_gw = _MockNerutonServer(required_token="ntk_valid")
        await self.mock_gw.start()
        self.server_url = f"http://127.0.0.1:{self.mock_gw.port}"

    async def asyncTearDown(self) -> None:
        await self.mock_gw.stop()
        self.local_srv.close()
        await self.local_srv.wait_closed()

    async def test_async_connect_forward_http_apis(self) -> None:
        # 1. async with neruton.connect(url=...)
        async with neruton.connect(
            url=f"http://127.0.0.1:{self.local_port}",
            server=self.server_url,
            token="ntk_valid",
            subdomain="demo-app",
        ) as tunnel:
            self.assertEqual(tunnel.prefix, "demo-app")
            self.assertEqual(tunnel.public_url, "http://demo-app.moer.eu.org")
            self.assertIn("/preview/demo-app", tunnel.preview_url)
            self.assertIn("/t/demo-app/", tunnel.path_url)
            self.assertTrue(tunnel.connected)

            resp = await self.mock_gw.proxy_get("/hello")
            self.assertIn(b"local-ok:GET /hello HTTP/1.1", resp)

        self.assertTrue(tunnel.closed)

        # 2. await neruton.forward(port) + manual close()
        tunnel2 = await neruton.forward(
            self.local_port,
            server=self.server_url,
            token="ntk_valid",
        )
        try:
            self.assertEqual(len(tunnel2.prefix), 36)  # auto UUID v4
            resp2 = await self.mock_gw.proxy_get("/fwd")
            self.assertIn(b"local-ok:GET /fwd HTTP/1.1", resp2)
        finally:
            await tunnel2.close()

        # 3. async with neruton.http(port)
        async with neruton.http(
            self.local_port,
            server=self.server_url,
            token="ntk_valid",
            subdomain="quick-http",
        ) as tunnel3:
            self.assertEqual(tunnel3.prefix, "quick-http")

    async def test_401_auth_error_fails_fast_without_retrying(self) -> None:
        with self.assertRaises(AuthError) as cm:
            async with neruton.connect(
                url=f"http://127.0.0.1:{self.local_port}",
                server=self.server_url,
                token="ntk_wrong",
                retry_initial=True,  # even with retry_initial=True, 401 MUST fail fast!
            ):
                pass
        self.assertEqual(cm.exception.status_code, 401)
        self.assertIn("Invalid or revoked tunnel token", str(cm.exception))
        self.assertEqual(self.mock_gw.connect_attempts, 1)

    async def test_registration_rejection_fails_fast(self) -> None:
        self.mock_gw.reject_error = "prefix 'demo' is not permitted by this token"
        with self.assertRaises(RegistrationError) as cm:
            async with neruton.connect(
                url=f"http://127.0.0.1:{self.local_port}",
                server=self.server_url,
                token="ntk_valid",
                subdomain="demo",
                retry_initial=True,
            ):
                pass
        self.assertIn("not permitted", str(cm.exception))
        self.assertEqual(self.mock_gw.connect_attempts, 1)

    async def test_transient_reconnect_preserves_sticky_uuid_prefix(self) -> None:
        self.mock_gw.drop_after_first = True
        reconnected = asyncio.Event()
        connect_count = 0

        def on_connect(_reg: RegisterResponse) -> None:
            nonlocal connect_count
            connect_count += 1
            if connect_count >= 2:
                reconnected.set()

        async with neruton.connect(
            url=f"http://127.0.0.1:{self.local_port}",
            server=self.server_url,
            token="ntk_valid",
            initial_backoff=0.05,
            max_backoff=0.2,
            on_connect=on_connect,
        ) as tunnel:
            first_prefix = tunnel.prefix
            self.assertEqual(len(first_prefix), 36)
            await asyncio.wait_for(reconnected.wait(), timeout=3.0)
            self.assertEqual(tunnel.prefix, first_prefix)
            # First request sent prefix=None, reconnect sent sticky prefix!
            self.assertEqual(self.mock_gw.registered_prefixes[0], None)
            self.assertEqual(self.mock_gw.registered_prefixes[1], first_prefix)

            resp = await self.mock_gw.proxy_get("/after-reconnect")
            self.assertIn(b"local-ok:GET /after-reconnect HTTP/1.1", resp)

    async def test_revoked_token_on_reconnect_exits_with_auth_error(self) -> None:
        self.mock_gw.drop_after_first = True
        self.mock_gw.revoke_after_first = True

        tunnel = await neruton.connect(
            url=f"http://127.0.0.1:{self.local_port}",
            server=self.server_url,
            token="ntk_valid",
            initial_backoff=0.05,
            max_backoff=0.1,
        )
        try:
            with self.assertRaises(AuthError):
                await asyncio.wait_for(tunnel.wait(), timeout=3.0)
        finally:
            await tunnel.close()

    async def test_sync_open_api_and_clean_thread_shutdown(self) -> None:
        def sync_threads() -> List[threading.Thread]:
            return [t for t in threading.enumerate() if t.name == "neruton-sync-tunnel"]

        self.assertEqual(sync_threads(), [])
        sync_tunnel = await asyncio.to_thread(
            lambda: neruton.open(
                self.local_port,
                server=self.server_url,
                token="ntk_valid",
                subdomain="sync-app",
            )
        )
        try:
            self.assertEqual(len(sync_threads()), 1)
            self.assertEqual(sync_tunnel.prefix, "sync-app")
            self.assertEqual(sync_tunnel.public_url, "http://sync-app.moer.eu.org")
            self.assertTrue(sync_tunnel.connected)

            resp = await self.mock_gw.proxy_get("/sync-req")
            self.assertIn(b"local-ok:GET /sync-req HTTP/1.1", resp)
        finally:
            await asyncio.to_thread(sync_tunnel.close)

        self.assertTrue(sync_tunnel.closed)
        self.assertEqual(sync_threads(), [])

        # Also verify `neruton.open(...)` cleans up its thread on 401 without leaking
        with self.assertRaises(AuthError):
            await asyncio.to_thread(
                lambda: neruton.open(
                    self.local_port,
                    server=self.server_url,
                    token="ntk_bad",
                )
            )
        self.assertEqual(sync_threads(), [])

    async def test_close_during_start_and_reconnect_cancels_cleanly(self) -> None:
        # 1. close() while start() is in flight (slow handshake) cancels promptly without leaking
        self.mock_gw.handshake_delay = 5.0
        t1 = neruton.Tunnel(
            target_url=f"http://127.0.0.1:{self.local_port}",
            server=self.server_url,
            token="ntk_valid",
            subdomain="race-start",
        )
        start_task = asyncio.create_task(t1.start())
        await asyncio.sleep(0.05)
        t0 = asyncio.get_running_loop().time()
        await t1.close()
        await asyncio.wait_for(start_task, timeout=1.0)
        elapsed = asyncio.get_running_loop().time() - t0
        self.assertLess(elapsed, 1.0)
        self.assertTrue(t1.closed)
        self.assertFalse(t1.connected)
        self.assertEqual(self.mock_gw.active_sessions, [])

        # 2. close() immediately after asyncio.sleep(0) during fast handshake leaves no live session
        self.mock_gw.handshake_delay = 0.0
        t2 = neruton.Tunnel(
            target_url=f"http://127.0.0.1:{self.local_port}",
            server=self.server_url,
            token="ntk_valid",
            subdomain="race-fast",
        )
        start_task2 = asyncio.create_task(t2.start())
        await asyncio.sleep(0)
        await t2.close()
        await asyncio.wait_for(start_task2, timeout=1.0)
        self.assertTrue(t2.closed)
        self.assertFalse(t2.connected)
        await asyncio.sleep(0.05)
        self.assertTrue(all(s.is_closed for s in self.mock_gw.active_sessions))

        # 3. close() during an in-flight reconnect cancels promptly and leaves no live session
        self.mock_gw.drop_after_first = True
        reconnecting = asyncio.Event()

        def on_reconnect(_attempt: int, _backoff: float, _reason: str) -> None:
            self.mock_gw.handshake_delay = 5.0
            reconnecting.set()

        t3 = await neruton.connect(
            url=f"http://127.0.0.1:{self.local_port}",
            server=self.server_url,
            token="ntk_valid",
            subdomain="race-reconn",
            initial_backoff=0.05,
            max_backoff=0.2,
            on_reconnect=on_reconnect,
        )
        await asyncio.wait_for(reconnecting.wait(), timeout=2.0)
        await asyncio.sleep(0.08)  # now inside slow reconnect handshake
        t0 = asyncio.get_running_loop().time()
        await t3.close()
        self.assertLess(asyncio.get_running_loop().time() - t0, 1.0)
        self.assertTrue(t3.closed)
        self.assertFalse(t3.connected)
        await asyncio.sleep(0.05)
        self.assertTrue(all(s.is_closed for s in self.mock_gw.active_sessions))

    async def test_reconnect_preserves_real_error_reason_across_attempts(self) -> None:
        self.mock_gw.drop_after_first = True
        self.mock_gw.reject_once_on_attempt = 2
        self.mock_gw.reject_once_error = "prefix 'sticky-app' is already in use"
        reasons: List[Tuple[int, float, str]] = []
        recovered = asyncio.Event()
        connects = 0

        def on_connect(_reg: RegisterResponse) -> None:
            nonlocal connects
            connects += 1
            if connects >= 2:
                recovered.set()

        def on_reconnect(attempt: int, backoff: float, reason: str) -> None:
            reasons.append((attempt, backoff, reason))

        async with neruton.connect(
            url=f"http://127.0.0.1:{self.local_port}",
            server=self.server_url,
            token="ntk_valid",
            subdomain="sticky-app",
            initial_backoff=0.05,
            max_backoff=0.2,
            on_connect=on_connect,
            on_reconnect=on_reconnect,
        ):
            await asyncio.wait_for(recovered.wait(), timeout=3.0)

        self.assertGreaterEqual(len(reasons), 2)
        self.assertEqual(reasons[0][0], 1)
        self.assertIn("closed", reasons[0][2])
        self.assertEqual(reasons[1][0], 2)
        self.assertIn("already in use", reasons[1][2])
        self.assertNotEqual(reasons[1][2], "connection failed")


class TestCLI(unittest.TestCase):
    def test_arg_parser_mirrors_rust_cli(self) -> None:
        parser = build_parser()
        args = parser.parse_args(
            [
                "tunnel",
                "--url",
                "http://localhost:3000",
                "--server",
                "https://neruton.moer.eu.org",
                "-s",
                "my-app",
                "--token",
                "tok123",
                "--no-tls-verify",
                "--host-header",
                "preserve",
            ]
        )
        self.assertEqual(args.command, "tunnel")
        self.assertEqual(args.url, "http://localhost:3000")
        self.assertEqual(args.server, "https://neruton.moer.eu.org")
        self.assertEqual(args.subdomain, "my-app")
        self.assertEqual(args.token, "tok123")
        self.assertTrue(args.no_tls_verify)
        self.assertEqual(args.host_header, "preserve")

        http_args = parser.parse_args(["http", "3000", "--prefix", "quick-demo"])
        self.assertEqual(http_args.command, "http")
        self.assertEqual(http_args.target, "3000")
        self.assertEqual(http_args.subdomain, "quick-demo")

    def test_config_set_show_path_and_version_commands(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cfg_path = Path(tmp) / "config.toml"

            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = cli_main(
                    [
                        "config",
                        "set",
                        "--server",
                        "https://demo.example",
                        "--token",
                        "ntk_cli_test",
                        "--config",
                        str(cfg_path),
                    ]
                )
            self.assertEqual(rc, 0)
            self.assertIn(str(cfg_path), buf.getvalue())

            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = cli_main(["config", "show", "--config", str(cfg_path)])
            self.assertEqual(rc, 0)
            out = buf.getvalue()
            self.assertIn("https://demo.example", out)
            self.assertIn("<configured>", out)
            self.assertNotIn("ntk_cli_test", out)  # never print raw token

            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = cli_main(["config", "path", "--config", str(cfg_path)])
            self.assertEqual(rc, 0)
            self.assertEqual(buf.getvalue().strip(), str(cfg_path))

            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = cli_main(["version"])
            self.assertEqual(rc, 0)
            self.assertIn(f"neruton {neruton.__version__}", buf.getvalue())

    def test_python_m_neruton_version(self) -> None:
        pkg_src = str(Path(__file__).resolve().parents[1] / "src")
        proc = subprocess.run(
            [sys.executable, "-m", "neruton", "version"],
            capture_output=True,
            text=True,
            env={"PYTHONPATH": pkg_src},
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn(f"neruton {neruton.__version__}", proc.stdout)


if __name__ == "__main__":
    unittest.main()
