"""Real end-to-end integration tests against the compiled Rust `target/debug/neruton-server`."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import http.client
import json
import os
import socket
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from typing import Optional, Tuple

import websockets
from websockets.asyncio.client import connect as ws_connect

import neruton
from neruton.errors import AuthError

REPO_ROOT = Path(__file__).resolve().parents[3]
SERVER_BIN = REPO_ROOT / "target" / "debug" / "neruton-server"
_WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _http_request(
    port: int,
    method: str,
    path: str,
    *,
    headers: Optional[dict[str, str]] = None,
    body: Optional[bytes] = None,
    timeout: float = 10.0,
) -> Tuple[int, dict[str, str], bytes]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        conn.request(method, path, body=body, headers=headers or {})
        resp = conn.getresponse()
        data = resp.read()
        resp_headers = {k.lower(): v for k, v in resp.getheaders()}
        return resp.status, resp_headers, data
    finally:
        conn.close()


async def _start_local_app() -> Tuple[asyncio.AbstractServer, int]:
    """Local HTTP/1.1 + real RFC 6455 WebSocket echo backend."""

    async def handle_ws_frames(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        while True:
            hdr = await reader.readexactly(2)
            opcode = hdr[0] & 0x0F
            masked = (hdr[1] & 0x80) != 0
            length = hdr[1] & 0x7F
            if length == 126:
                length = int.from_bytes(await reader.readexactly(2), "big")
            elif length == 127:
                length = int.from_bytes(await reader.readexactly(8), "big")
            mask_key = await reader.readexactly(4) if masked else b""
            payload = bytearray(await reader.readexactly(length))
            if masked:
                for i in range(length):
                    payload[i] ^= mask_key[i % 4]

            if opcode == 0x8:  # Close
                writer.write(b"\x88\x00")
                await writer.drain()
                break
            if opcode == 0x1:  # Text
                reply = b"echo:" + bytes(payload)
                if len(reply) < 126:
                    frame = bytes([0x81, len(reply)]) + reply
                else:
                    frame = bytes([0x81, 126]) + len(reply).to_bytes(2, "big") + reply
                writer.write(frame)
                await writer.drain()

    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            raw_head = await reader.readuntil(b"\r\n\r\n")
            lines = raw_head[:-4].decode("latin-1").split("\r\n")
            method, target, _ = lines[0].split(" ", 2)
            path, _, query = target.partition("?")
            headers = {}
            for line in lines[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip().lower()] = v.strip()

            body = b""
            if "transfer-encoding" in headers and "chunked" in headers["transfer-encoding"].lower():
                parts = []
                while True:
                    sz_line = await reader.readuntil(b"\r\n")
                    sz = int(sz_line[:-2].split(b";", 1)[0].strip(), 16)
                    if sz == 0:
                        await reader.readuntil(b"\r\n")
                        break
                    parts.append(await reader.readexactly(sz))
                    await reader.readexactly(2)
                body = b"".join(parts)
            elif "content-length" in headers:
                cl = int(headers["content-length"])
                if cl > 0:
                    body = await reader.readexactly(cl)

            if path == "/hello":
                xfh = headers.get("x-forwarded-host", "")
                host = headers.get("host", "")
                out = f"hello|q={query}|xfh={xfh}|host={host}".encode()
                writer.write(
                    f"HTTP/1.1 200 OK\r\nX-Backend: ok\r\nContent-Length: {len(out)}\r\n\r\n".encode()
                    + out
                )
                await writer.drain()
            elif path == "/echo":
                writer.write(
                    f"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n"
                    f"Content-Length: {len(body)}\r\n\r\n".encode()
                    + body
                )
                await writer.drain()
            elif path == "/stream":
                writer.write(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
                for c in (b"chunk-1|", b"chunk-2|", b"chunk-3"):
                    writer.write(f"{len(c):x}\r\n".encode() + c + b"\r\n")
                    await writer.drain()
                    await asyncio.sleep(0.01)
                writer.write(b"0\r\n\r\n")
                await writer.drain()
            elif path == "/page":
                html = b"<!doctype html><html><head><title>PyDemo</title></head><body>Hi</body></html>"
                writer.write(
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: text/html; charset=utf-8\r\n"
                    b"X-Frame-Options: DENY\r\n"
                    + f"Content-Length: {len(html)}\r\n\r\n".encode()
                    + html
                )
                await writer.drain()
            elif path == "/ws":
                ws_key = headers["sec-websocket-key"]
                accept = base64.b64encode(
                    hashlib.sha1((ws_key + _WS_GUID).encode("ascii")).digest()
                ).decode("ascii")
                writer.write(
                    (
                        "HTTP/1.1 101 Switching Protocols\r\n"
                        "Upgrade: websocket\r\n"
                        "Connection: Upgrade\r\n"
                        f"Sec-WebSocket-Accept: {accept}\r\n\r\n"
                    ).encode("ascii")
                )
                await writer.drain()
                await handle_ws_frames(reader, writer)
            else:
                writer.write(b"HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n\r\nnot found")
                await writer.drain()
        except Exception:
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    srv = await asyncio.start_server(handler, "127.0.0.1", 0)
    return srv, srv.sockets[0].getsockname()[1]


@unittest.skipUnless(SERVER_BIN.exists(), f"Rust server binary not built at {SERVER_BIN}")
class TestE2EAgainstRustServer(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self._tmp_dir = tempfile.TemporaryDirectory(prefix="neruton-py-e2e-")
        self.server_port = _free_port()
        self.server_url = f"http://127.0.0.1:{self.server_port}"

        env = os.environ.copy()
        env["RUST_LOG"] = "warn"
        self._proc = subprocess.Popen(
            [
                str(SERVER_BIN),
                "--bind",
                f"127.0.0.1:{self.server_port}",
                "--base-domain",
                "moer.eu.org",
                "--panel-host",
                "neruton.moer.eu.org",
                "--public-scheme",
                "http",
                "--data-dir",
                self._tmp_dir.name,
                "--require-auth",
                "true",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )

        # Wait for /_neruton/health
        deadline = time.monotonic() + 10.0
        ready = False
        while time.monotonic() < deadline:
            if self._proc.poll() is not None:
                err = self._proc.stderr.read().decode() if self._proc.stderr else ""
                raise RuntimeError(f"neruton-server exited early: {err}")
            try:
                status, _, _ = _http_request(self.server_port, "GET", "/_neruton/health", timeout=1.0)
                if status == 200:
                    ready = True
                    break
            except OSError:
                await asyncio.sleep(0.05)
        if not ready:
            raise RuntimeError("timed out waiting for neruton-server /_neruton/health")

        # Run first-run admin setup to obtain a real ntk_... tunnel token & session cookie
        setup_body = json.dumps(
            {"username": "admin", "password": "AdminPassword123!"}
        ).encode()
        status, resp_headers, raw = _http_request(
            self.server_port,
            "POST",
            "/_neruton/api/auth/setup",
            headers={"Content-Type": "application/json"},
            body=setup_body,
        )
        self.assertEqual(status, 201, raw.decode(errors="replace"))
        setup = json.loads(raw.decode())
        self.token: str = setup["initial_token"]["secret"]
        self.assertTrue(self.token.startswith("ntk_"))
        self.session_cookie = resp_headers.get("set-cookie", "").split(";", 1)[0]

        self.local_srv, self.local_port = await _start_local_app()

    async def asyncTearDown(self) -> None:
        self.local_srv.close()
        await self.local_srv.wait_closed()
        if self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5.0)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                self._proc.wait(timeout=5.0)
        if self._proc.stdout:
            self._proc.stdout.close()
        if self._proc.stderr:
            self._proc.stderr.close()
        self._tmp_dir.cleanup()

    async def test_e2e_auth_http_large_body_streaming_path_proxy_ws_and_sync_api(self) -> None:
        # 1. Missing token & bad token -> 401 fail-fast AuthError
        with self.assertRaises(AuthError) as cm_missing:
            async with neruton.connect(
                url=f"http://127.0.0.1:{self.local_port}",
                server=self.server_url,
                token=None,
                subdomain="unauth-test",
                config_file=Path(self._tmp_dir.name) / "nonexistent.toml",
            ):
                pass
        self.assertEqual(cm_missing.exception.status_code, 401)

        with self.assertRaises(AuthError) as cm_bad:
            async with neruton.connect(
                url=f"http://127.0.0.1:{self.local_port}",
                server=self.server_url,
                token="ntk_invalid_secret_value",
                subdomain="unauth-test",
            ):
                pass
        self.assertEqual(cm_bad.exception.status_code, 401)

        # 2. Custom subdomain over real Rust neruton-server (yamux 0.13!)
        async with neruton.connect(
            url=f"http://127.0.0.1:{self.local_port}",
            server=self.server_url,
            token=self.token,
            subdomain="Py-E2E",
        ) as tunnel:
            self.assertEqual(tunnel.prefix, "py-e2e")
            self.assertEqual(tunnel.public_url, "http://py-e2e.moer.eu.org")
            self.assertEqual(tunnel.preview_url, "http://neruton.moer.eu.org/preview/py-e2e")
            self.assertEqual(tunnel.path_url, "http://neruton.moer.eu.org/t/py-e2e/")
            self.assertEqual(tunnel.owner_username, "admin")
            self.assertEqual(tunnel.token_name, "Default CLI Token")

            # 2a. Wildcard subdomain HTTP GET + Host rewrite + X-Forwarded-Host
            st, hdrs, body = await asyncio.to_thread(
                _http_request,
                self.server_port,
                "GET",
                "/hello?foo=bar",
                headers={"Host": "py-e2e.moer.eu.org"},
            )
            self.assertEqual(st, 200)
            self.assertEqual(hdrs.get("x-backend"), "ok")
            self.assertEqual(
                body.decode(),
                f"hello|q=foo=bar|xfh=py-e2e.moer.eu.org|host=127.0.0.1:{self.local_port}",
            )

            # 2b. Large 600 KiB POST body (verifies Yamux 0.13 <-> Python flow control!)
            large_payload = bytes((i * 7 + 13) % 256 for i in range(600 * 1024))
            st, _, body = await asyncio.to_thread(
                _http_request,
                self.server_port,
                "POST",
                "/echo",
                headers={
                    "Host": "py-e2e.moer.eu.org",
                    "Content-Type": "application/octet-stream",
                },
                body=large_payload,
            )
            self.assertEqual(st, 200)
            self.assertEqual(body, large_payload)

            # 2c. Chunked streaming response
            st, _, body = await asyncio.to_thread(
                _http_request,
                self.server_port,
                "GET",
                "/stream",
                headers={"Host": "py-e2e.moer.eu.org"},
            )
            self.assertEqual(st, 200)
            self.assertEqual(body, b"chunk-1|chunk-2|chunk-3")

            # 2d. 10 concurrent requests multiplexed over the single WSS + Yamux tunnel
            async def one_req(idx: int) -> None:
                s, _, b = await asyncio.to_thread(
                    _http_request,
                    self.server_port,
                    "GET",
                    f"/hello?n={idx}",
                    headers={"Host": "py-e2e.moer.eu.org"},
                )
                self.assertEqual(s, 200)
                self.assertIn(f"q=n={idx}", b.decode())

            await asyncio.gather(*(one_req(i) for i in range(10)))

            # 2e. Path proxy /t/py-e2e/page (HTML <base> injection + X-Frame-Options strip)
            st, hdrs, body = await asyncio.to_thread(
                _http_request,
                self.server_port,
                "GET",
                "/t/py-e2e/page",
            )
            self.assertEqual(st, 200)
            self.assertNotIn("x-frame-options", hdrs)
            self.assertIn(
                '<head><base href="/t/py-e2e/"><title>PyDemo</title></head>',
                body.decode(),
            )

            # 2f. Real WebSocket upgrade over wildcard subdomain AND path proxy
            async with ws_connect(
                "ws://py-e2e.moer.eu.org/ws",
                host="127.0.0.1",
                port=self.server_port,
                compression=None,
            ) as ws_sub:
                await ws_sub.send("hello-sub")
                self.assertEqual(await ws_sub.recv(), "echo:hello-sub")

            async with ws_connect(
                f"ws://127.0.0.1:{self.server_port}/t/py-e2e/ws",
                compression=None,
            ) as ws_path:
                await ws_path.send("hello-path")
                self.assertEqual(await ws_path.recv(), "echo:hello-path")

            # 2g. Let server initial 200ms WS ping probe complete and check API stats
            await asyncio.sleep(0.35)
            st, _, raw_info = await asyncio.to_thread(
                _http_request,
                self.server_port,
                "GET",
                "/_neruton/api/tunnels/py-e2e",
                headers={"Cookie": self.session_cookie},
            )
            self.assertEqual(st, 200)
            info = json.loads(raw_info.decode())
            self.assertEqual(info["prefix"], "py-e2e")
            self.assertGreaterEqual(info["requests_total"], 14)
            self.assertGreater(info["bytes_in"], 600 * 1024)
            self.assertGreater(info["bytes_out"], 600 * 1024)

        # After closing tunnel, wildcard returns 502 offline page
        await asyncio.sleep(0.1)
        st, _, _ = await asyncio.to_thread(
            _http_request,
            self.server_port,
            "GET",
            "/hello",
            headers={"Host": "py-e2e.moer.eu.org"},
        )
        self.assertEqual(st, 502)

        # 3. Auto-UUID prefix via neruton.forward(port)
        async with neruton.forward(
            self.local_port,
            server=self.server_url,
            token=self.token,
        ) as uuid_tunnel:
            self.assertEqual(len(uuid_tunnel.prefix), 36)
            st, _, body = await asyncio.to_thread(
                _http_request,
                self.server_port,
                "GET",
                "/hello?uuid=1",
                headers={"Host": f"{uuid_tunnel.prefix}.moer.eu.org"},
            )
            self.assertEqual(st, 200)
            self.assertIn("q=uuid=1", body.decode())

        # 4. Sync API `with neruton.open(...)` against real Rust neruton-server
        def run_sync_check() -> None:
            with neruton.open(
                self.local_port,
                server=self.server_url,
                token=self.token,
                subdomain="py-sync",
            ) as sync_t:
                self.assertEqual(sync_t.prefix, "py-sync")
                st_s, _, body_s = _http_request(
                    self.server_port,
                    "GET",
                    "/hello?sync=ok",
                    headers={"Host": "py-sync.moer.eu.org"},
                )
                self.assertEqual(st_s, 200)
                self.assertIn("q=sync=ok", body_s.decode())

        await asyncio.to_thread(run_sync_check)

        # 5. Unreachable local target -> 502 Bad Gateway while tunnel stays connected
        dead_port = _free_port()
        async with neruton.connect(
            url=f"http://127.0.0.1:{dead_port}",
            server=self.server_url,
            token=self.token,
            subdomain="py-dead",
        ):
            st, _, body = await asyncio.to_thread(
                _http_request,
                self.server_port,
                "GET",
                "/anything",
                headers={"Host": "py-dead.moer.eu.org"},
            )
            self.assertEqual(st, 502)
            self.assertIn(b"neruton: failed to connect to local service", body)

        # 6. Regression: close() during in-flight start() must leave ZERO zombie tunnels on server
        race_tunnel = neruton.Tunnel(
            target_url=f"http://127.0.0.1:{self.local_port}",
            server=self.server_url,
            token=self.token,
            subdomain="race-check",
        )
        start_task = asyncio.create_task(race_tunnel.start())
        await asyncio.sleep(0)
        await race_tunnel.close()
        await start_task
        self.assertTrue(race_tunnel.closed)
        self.assertFalse(race_tunnel.connected)
        await asyncio.sleep(0.1)
        st, _, raw_tunnels = await asyncio.to_thread(
            _http_request,
            self.server_port,
            "GET",
            "/_neruton/api/tunnels",
            headers={"Cookie": self.session_cookie},
        )
        self.assertEqual(st, 200)
        tunnels_data = json.loads(raw_tunnels.decode())
        active_prefixes = [t["prefix"] for t in tunnels_data["tunnels"]]
        self.assertNotIn("race-check", active_prefixes)


if __name__ == "__main__":
    unittest.main()
