"""Unit tests for the local HTTP/1.1 & WebSocket stream forwarder (`neruton.forwarder`)."""

from __future__ import annotations

import asyncio
import unittest
from typing import List, Tuple

from neruton.forwarder import (
    HostHeaderKind,
    HostHeaderMode,
    RequestEvent,
    TargetConfig,
    handle_yamux_stream,
)
from neruton.yamux import Mode, YamuxSession, create_memory_transport_pair


async def _start_mock_backend() -> Tuple[asyncio.AbstractServer, int]:
    """Start a lightweight raw asyncio HTTP/1.1 + 101 Upgrade test server."""

    async def handle_client(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            raw_head = await reader.readuntil(b"\r\n\r\n")
            lines = raw_head[:-4].decode("latin-1").split("\r\n")
            method, path, _ = lines[0].split(" ", 2)
            headers = {}
            for line in lines[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip().lower()] = v.strip()

            if path == "/early-413":
                # Respond immediately WITHOUT reading the request body (like nginx/gunicorn 413)
                writer.write(
                    b"HTTP/1.1 413 Payload Too Large\r\n"
                    b"Content-Length: 3\r\n"
                    b"Connection: close\r\n\r\n413"
                )
                await writer.drain()
                return
            if path == "/chunked-with-cl":
                writer.write(
                    b"HTTP/1.1 200 OK\r\n"
                    b"Transfer-Encoding: chunked\r\n"
                    b"Content-Length: 999\r\n\r\n"
                    b"2\r\nok\r\n0\r\n\r\n"
                )
                await writer.drain()
                return
            if path == "/bad-neg-chunk":
                writer.write(
                    b"HTTP/1.1 200 OK\r\n"
                    b"Transfer-Encoding: chunked\r\n\r\n"
                    b"-1\r\n"
                )
                await writer.drain()
                return

            # Read request body if present
            body = b""
            if "transfer-encoding" in headers and "chunked" in headers["transfer-encoding"].lower():
                chunks = []
                while True:
                    size_line = await reader.readuntil(b"\r\n")
                    sz = int(size_line[:-2].split(b";", 1)[0].strip(), 16)
                    if sz == 0:
                        await reader.readuntil(b"\r\n")
                        break
                    chunks.append(await reader.readexactly(sz))
                    await reader.readexactly(2)
                body = b"".join(chunks)
            elif "content-length" in headers:
                cl = int(headers["content-length"])
                if cl > 0:
                    body = await reader.readexactly(cl)

            if path.startswith("/inspect"):
                host = headers.get("host", "")
                ka = headers.get("keep-alive", "stripped")
                payload = f"method={method}|path={path}|host={host}|ka={ka}".encode()
                writer.write(
                    f"HTTP/1.1 200 OK\r\nContent-Length: {len(payload)}\r\n"
                    f"Keep-Alive: timeout=5\r\nX-Custom: yes\r\n\r\n".encode()
                    + payload
                )
                await writer.drain()
            elif path == "/echo":
                writer.write(
                    f"HTTP/1.1 200 OK\r\nContent-Length: {len(body)}\r\n\r\n".encode()
                    + body
                )
                await writer.drain()
            elif path == "/chunked":
                writer.write(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
                for part in (b"part-1|", b"part-2|", b"part-3"):
                    writer.write(f"{len(part):x}\r\n".encode() + part + b"\r\n")
                    await writer.drain()
                    await asyncio.sleep(0.01)
                writer.write(b"0\r\n\r\n")
                await writer.drain()
            elif path == "/http10-eof":
                writer.write(b"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\neof-body-data")
                await writer.drain()
            elif path == "/empty-204":
                writer.write(b"HTTP/1.1 204 No Content\r\nX-Empty: 1\r\n\r\n")
                await writer.drain()
            elif path == "/head-check":
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 9999\r\n\r\n")
                await writer.drain()
            elif path == "/ws":
                # 101 Switching Protocols + immediately send a pipelined greeting byte
                writer.write(
                    b"HTTP/1.1 101 Switching Protocols\r\n"
                    b"Upgrade: websocket\r\n"
                    b"Connection: Upgrade\r\n"
                    b"Sec-WebSocket-Accept: fake-accept\r\n"
                    b"\r\n"
                    b"WELCOME:"
                )
                await writer.drain()
                while True:
                    chunk = await reader.read(4096)
                    if not chunk:
                        break
                    writer.write(b"UP:" + chunk)
                    await writer.drain()
                    if b"QUIT" in chunk:
                        break
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

    server = await asyncio.start_server(handle_client, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    return server, port


async def _send_raw_http_over_yamux(
    client_session: YamuxSession, raw_request: bytes
) -> bytes:
    stream = await client_session.open_stream()
    await stream.write(raw_request)
    await stream.write_eof()
    return await stream.read_all()


class TestForwarder(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.backend, self.backend_port = await _start_mock_backend()

    async def asyncTearDown(self) -> None:
        self.backend.close()
        await self.backend.wait_closed()

    async def _run_with_target(
        self, target: TargetConfig
    ) -> Tuple[YamuxSession, YamuxSession, asyncio.Task[None], List[RequestEvent]]:
        ta, tb = create_memory_transport_pair()
        client = YamuxSession(ta, Mode.CLIENT).start()
        server = YamuxSession(tb, Mode.SERVER).start()
        events: List[RequestEvent] = []

        async def accept_loop() -> None:
            tasks = []
            while True:
                s = await server.accept()
                if s is None:
                    break
                tasks.append(
                    asyncio.create_task(
                        handle_yamux_stream(s, target, on_request=events.append)
                    )
                )
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)

        loop_task = asyncio.create_task(accept_loop())
        return client, server, loop_task, events

    def test_host_header_mode_parsing(self) -> None:
        self.assertEqual(HostHeaderMode.from_option(None).kind, HostHeaderKind.REWRITE_TO_TARGET)
        self.assertEqual(
            HostHeaderMode.from_option("rewrite").kind, HostHeaderKind.REWRITE_TO_TARGET
        )
        self.assertEqual(
            HostHeaderMode.from_option("PRESERVE").kind, HostHeaderKind.PRESERVE
        )
        custom = HostHeaderMode.from_option("internal.svc:9000")
        self.assertEqual(custom.kind, HostHeaderKind.CUSTOM)
        self.assertEqual(custom.custom_value, "internal.svc:9000")

    async def test_http_get_post_chunked_head_204_http10_and_host_rewrite(self) -> None:
        target = TargetConfig.from_url(f"http://127.0.0.1:{self.backend_port}/")
        client, server, loop_task, events = await self._run_with_target(target)
        try:
            # 1. GET with Host rewritten & hop-by-hop Keep-Alive stripped
            raw = await _send_raw_http_over_yamux(
                client,
                b"GET /inspect?a=1 HTTP/1.1\r\n"
                b"Host: demo.moer.eu.org\r\n"
                b"Keep-Alive: timeout=99\r\n"
                b"Connection: close\r\n\r\n",
            )
            head, body = raw.split(b"\r\n\r\n", 1)
            self.assertIn(b"HTTP/1.1 200 OK", head)
            self.assertIn(b"X-Custom: yes", head)
            self.assertNotIn(b"Keep-Alive:", head)
            self.assertEqual(
                body.decode(),
                f"method=GET|path=/inspect?a=1|host=127.0.0.1:{self.backend_port}|ka=stripped",
            )

            # 2. POST with large >300 KiB body (exercises Yamux flow control!)
            large = b"X" * (320 * 1024)
            raw_post = await _send_raw_http_over_yamux(
                client,
                f"POST /echo HTTP/1.1\r\nHost: demo.moer.eu.org\r\nContent-Length: {len(large)}\r\nConnection: close\r\n\r\n".encode()
                + large,
            )
            _, post_body = raw_post.split(b"\r\n\r\n", 1)
            self.assertEqual(post_body, large)

            # 3. POST with chunked request body
            raw_chunked_req = await _send_raw_http_over_yamux(
                client,
                b"POST /echo HTTP/1.1\r\n"
                b"Host: demo.moer.eu.org\r\n"
                b"Transfer-Encoding: chunked\r\n"
                b"Connection: close\r\n\r\n"
                b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n",
            )
            _, cr_body = raw_chunked_req.split(b"\r\n\r\n", 1)
            self.assertEqual(cr_body, b"hello world")

            # 4. Chunked streaming response
            raw_stream = await _send_raw_http_over_yamux(
                client,
                b"GET /chunked HTTP/1.1\r\nHost: demo.moer.eu.org\r\nConnection: close\r\n\r\n",
            )
            s_head, s_body = raw_stream.split(b"\r\n\r\n", 1)
            self.assertIn(b"Transfer-Encoding: chunked", s_head)
            self.assertIn(b"part-1|", s_body)
            self.assertIn(b"part-2|", s_body)
            self.assertIn(b"part-3", s_body)
            self.assertTrue(s_body.endswith(b"0\r\n\r\n"))

            # 5. HTTP/1.0 close-delimited response -> chunked HTTP/1.1
            raw_10 = await _send_raw_http_over_yamux(
                client,
                b"GET /http10-eof HTTP/1.1\r\nHost: demo.moer.eu.org\r\nConnection: close\r\n\r\n",
            )
            h10, b10 = raw_10.split(b"\r\n\r\n", 1)
            self.assertIn(b"Transfer-Encoding: chunked", h10)
            self.assertIn(b"eof-body-data", b10)

            # 6. HEAD and 204 No Content (must not hang waiting for body!)
            raw_head = await asyncio.wait_for(
                _send_raw_http_over_yamux(
                    client,
                    b"HEAD /head-check HTTP/1.1\r\nHost: demo.moer.eu.org\r\nConnection: close\r\n\r\n",
                ),
                timeout=2.0,
            )
            self.assertIn(b"Content-Length: 9999", raw_head)
            self.assertTrue(raw_head.endswith(b"\r\n\r\n"))

            raw_204 = await asyncio.wait_for(
                _send_raw_http_over_yamux(
                    client,
                    b"GET /empty-204 HTTP/1.1\r\nHost: demo.moer.eu.org\r\nConnection: close\r\n\r\n",
                ),
                timeout=2.0,
            )
            self.assertIn(b"HTTP/1.1 204 No Content", raw_204)

            self.assertGreaterEqual(len(events), 7)
        finally:
            await client.close()
            await server.close()
            await loop_task

    async def test_host_preserve_custom_and_base_path(self) -> None:
        target_preserve = TargetConfig.from_url(
            f"http://127.0.0.1:{self.backend_port}/inspect",
            host_header="preserve",
        )
        client, server, loop_task, _ = await self._run_with_target(target_preserve)
        try:
            raw = await _send_raw_http_over_yamux(
                client,
                b"GET /sub HTTP/1.1\r\nHost: custom-in.moer.eu.org\r\nConnection: close\r\n\r\n",
            )
            _, body = raw.split(b"\r\n\r\n", 1)
            self.assertEqual(
                body.decode(),
                "method=GET|path=/inspect/sub|host=custom-in.moer.eu.org|ka=stripped",
            )
        finally:
            await client.close()
            await server.close()
            await loop_task

        target_custom = TargetConfig.from_url(
            f"http://127.0.0.1:{self.backend_port}/",
            host_header="override.internal",
        )
        client2, server2, loop_task2, _ = await self._run_with_target(target_custom)
        try:
            raw = await _send_raw_http_over_yamux(
                client2,
                b"GET /inspect HTTP/1.1\r\nHost: demo.moer.eu.org\r\nConnection: close\r\n\r\n",
            )
            _, body = raw.split(b"\r\n\r\n", 1)
            self.assertIn("host=override.internal", body.decode())
        finally:
            await client2.close()
            await server2.close()
            await loop_task2

    async def test_websocket_101_upgrade_bidirectional_and_pipelined_bytes(self) -> None:
        target = TargetConfig.from_url(f"http://127.0.0.1:{self.backend_port}/")
        client, server, loop_task, events = await self._run_with_target(target)
        try:
            s = await client.open_stream()
            await s.write(
                b"GET /ws HTTP/1.1\r\n"
                b"Host: demo.moer.eu.org\r\n"
                b"Connection: Upgrade\r\n"
                b"Upgrade: websocket\r\n"
                b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                b"Sec-WebSocket-Version: 13\r\n\r\n"
            )

            # Read 101 headers + pipelined WELCOME: bytes
            buf = bytearray()
            while b"WELCOME:" not in buf:
                chunk = await asyncio.wait_for(s.read(4096), timeout=2.0)
                self.assertTrue(chunk)
                buf.extend(chunk)
            head, rest = bytes(buf).split(b"\r\n\r\n", 1)
            self.assertIn(b"HTTP/1.1 101 Switching Protocols", head)
            self.assertIn(b"Upgrade: websocket", head)
            self.assertIn(b"Sec-WebSocket-Accept: fake-accept", head)
            self.assertEqual(rest, b"WELCOME:")

            # Bidirectional raw tunnel after 101
            await s.write(b"ping-1")
            self.assertEqual(await asyncio.wait_for(s.read(4096), timeout=2.0), b"UP:ping-1")
            await s.write(b"QUIT")
            self.assertEqual(await asyncio.wait_for(s.read(4096), timeout=2.0), b"UP:QUIT")
            await s.write_eof()

            self.assertTrue(any(ev.method == "WS" and ev.status == 101 for ev in events))
        finally:
            await client.close()
            await server.close()
            await loop_task

    async def test_unreachable_local_service_returns_502(self) -> None:
        # Pick an ephemeral port and immediately close it so connection is refused
        tmp_srv = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)
        dead_port = tmp_srv.sockets[0].getsockname()[1]
        tmp_srv.close()
        await tmp_srv.wait_closed()

        target = TargetConfig.from_url(f"http://127.0.0.1:{dead_port}/")
        client, server, loop_task, events = await self._run_with_target(target)
        try:
            raw = await _send_raw_http_over_yamux(
                client,
                b"GET /hello HTTP/1.1\r\nHost: demo.moer.eu.org\r\nConnection: close\r\n\r\n",
            )
            head, body = raw.split(b"\r\n\r\n", 1)
            self.assertIn(b"HTTP/1.1 502 Bad Gateway", head)
            self.assertIn(b"text/plain; charset=utf-8", head)
            self.assertIn(b"neruton: failed to connect to local service", body)
            self.assertEqual(events[-1].status, 502)
        finally:
            await client.close()
            await server.close()
            await loop_task

    async def test_early_413_response_closes_stream_without_smuggling_unread_body(self) -> None:
        target = TargetConfig.from_url(f"http://127.0.0.1:{self.backend_port}/")
        client, server, loop_task, events = await self._run_with_target(target)
        try:
            # Keep-alive POST whose unread body looks like a second HTTP request!
            smuggled = b"GET /inspect HTTP/1.1\r\nHost: evil\r\n\r\n"
            # Pad to make sure body cannot finish before backend responds 413
            big_body = smuggled + (b"A" * (512 * 1024))
            s = await client.open_stream()
            await s.write(
                f"POST /early-413 HTTP/1.1\r\n"
                f"Host: demo.moer.eu.org\r\n"
                f"Content-Length: {len(big_body)}\r\n"
                f"\r\n".encode()
                + smuggled
            )
            # Do NOT send the remaining 512 KiB so body_task stays incomplete while 413 arrives
            raw = await asyncio.wait_for(s.read_all(), timeout=3.0)
            self.assertEqual(raw.count(b"HTTP/1.1 "), 1)
            self.assertIn(b"HTTP/1.1 413 Payload Too Large", raw)
            self.assertTrue(raw.endswith(b"\r\n\r\n413"))
            self.assertEqual([ev.path for ev in events], ["/early-413"])
            await s.write_eof()
        finally:
            await client.close()
            await server.close()
            await loop_task

    async def test_chunked_response_strips_content_length_and_rejects_negative_chunk_size(
        self,
    ) -> None:
        target = TargetConfig.from_url(f"http://127.0.0.1:{self.backend_port}/")
        client, server, loop_task, _ = await self._run_with_target(target)
        try:
            raw = await _send_raw_http_over_yamux(
                client,
                b"GET /chunked-with-cl HTTP/1.1\r\nHost: demo.moer.eu.org\r\nConnection: close\r\n\r\n",
            )
            head, body = raw.split(b"\r\n\r\n", 1)
            self.assertIn(b"Transfer-Encoding: chunked", head)
            self.assertNotIn(b"Content-Length:", head)
            self.assertEqual(body, b"2\r\nok\r\n0\r\n\r\n")

            # Negative chunk size in response body resets the stream cleanly without crashing
            raw_bad = await _send_raw_http_over_yamux(
                client,
                b"GET /bad-neg-chunk HTTP/1.1\r\nHost: demo.moer.eu.org\r\nConnection: close\r\n\r\n",
            )
            self.assertNotIn(b"0\r\n\r\n", raw_bad)

            # Negative chunk size in request body is also rejected safely (400 Bad Request, no hang)
            raw_bad_req = await asyncio.wait_for(
                _send_raw_http_over_yamux(
                    client,
                    b"POST /echo HTTP/1.1\r\n"
                    b"Host: demo.moer.eu.org\r\n"
                    b"Transfer-Encoding: chunked\r\n"
                    b"Connection: close\r\n\r\n"
                    b"-1\r\n",
                ),
                timeout=3.0,
            )
            self.assertIn(b"HTTP/1.1 400 Bad Request", raw_bad_req)
        finally:
            await client.close()
            await server.close()
            await loop_task


if __name__ == "__main__":
    unittest.main()
