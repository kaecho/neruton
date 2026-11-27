"""Unit tests for the pure-Python Yamux v0 multiplexer (`neruton.yamux`)."""

from __future__ import annotations

import asyncio
import struct
import unittest
from typing import List

from neruton.errors import YamuxClosedError, YamuxProtocolError, YamuxStreamResetError
from neruton.yamux import (
    DEFAULT_CREDIT,
    HEADER_SIZE,
    FrameFlags,
    FrameHeader,
    FrameType,
    GoAwayCode,
    Mode,
    StreamState,
    WsByteTransport,
    YamuxSession,
    create_memory_transport_pair,
)


class TestYamuxHeader(unittest.TestCase):
    def test_header_wire_bytes_match_rust_yamux_0_13(self) -> None:
        # Data | SYN on stream 1, len 5
        hdr = FrameHeader(FrameType.DATA, FrameFlags.SYN, stream_id=1, length=5)
        raw = hdr.encode()
        self.assertEqual(len(raw), HEADER_SIZE)
        self.assertEqual(raw, bytes.fromhex("000000010000000100000005"))
        self.assertEqual(FrameHeader.decode(raw), hdr)

        # WindowUpdate | ACK on stream 3, credit 131072 (0x00020000)
        wu = FrameHeader(FrameType.WINDOW_UPDATE, FrameFlags.ACK, stream_id=3, length=131072)
        raw_wu = wu.encode()
        self.assertEqual(raw_wu, bytes.fromhex("000100020000000300020000"))
        self.assertEqual(FrameHeader.decode(raw_wu), wu)

        # Ping | SYN on stream 0, nonce 0x12345678
        ping = FrameHeader(FrameType.PING, FrameFlags.SYN, stream_id=0, length=0x12345678)
        raw_ping = ping.encode()
        self.assertEqual(raw_ping, bytes.fromhex("000200010000000012345678"))
        self.assertEqual(FrameHeader.decode(raw_ping), ping)

        # GoAway normal termination (code 0) & protocol error (code 1)
        ga0 = FrameHeader(FrameType.GO_AWAY, FrameFlags.NONE, stream_id=0, length=0)
        self.assertEqual(ga0.encode(), bytes.fromhex("000300000000000000000000"))
        ga1 = FrameHeader(FrameType.GO_AWAY, FrameFlags.NONE, stream_id=0, length=1)
        self.assertEqual(ga1.encode(), bytes.fromhex("000300000000000000000001"))

        # Combined flags FIN | ACK = 6, RST = 8
        fin_ack = FrameHeader(
            FrameType.DATA, FrameFlags.FIN | FrameFlags.ACK, stream_id=7, length=0
        )
        self.assertEqual(fin_ack.encode(), bytes.fromhex("000000060000000700000000"))

    def test_header_decode_rejects_invalid_version_type_and_length(self) -> None:
        with self.assertRaises(YamuxProtocolError):
            FrameHeader.decode(b"\x01" + b"\x00" * 11)
        with self.assertRaises(YamuxProtocolError):
            FrameHeader.decode(b"\x00\x09" + b"\x00" * 10)
        with self.assertRaises(YamuxProtocolError):
            FrameHeader.decode(b"\x00" * 11)


class _RecordingTransport:
    """Wraps a transport and records all raw outgoing bytes for wire-level assertions."""

    def __init__(self, inner: object) -> None:
        self._inner = inner
        self.written = bytearray()

    async def read(self, n: int) -> bytes:
        return await self._inner.read(n)  # type: ignore[attr-defined]

    async def write(self, data: bytes) -> None:
        self.written.extend(data)
        await self._inner.write(data)  # type: ignore[attr-defined]

    async def close(self) -> None:
        await self._inner.close()  # type: ignore[attr-defined]


def _parse_wire_frames(buf: bytes) -> List[tuple[FrameHeader, bytes]]:
    frames: List[tuple[FrameHeader, bytes]] = []
    offset = 0
    while offset < len(buf):
        hdr = FrameHeader.decode(buf[offset : offset + HEADER_SIZE])
        offset += HEADER_SIZE
        body = b""
        if hdr.frame_type == FrameType.DATA and hdr.length > 0:
            body = buf[offset : offset + hdr.length]
            offset += hdr.length
        frames.append((hdr, body))
    return frames


class TestYamuxSession(unittest.IsolatedAsyncioTestCase):
    async def test_stream_id_parity_and_roundtrip(self) -> None:
        ta, tb = create_memory_transport_pair()
        client = YamuxSession(ta, Mode.CLIENT).start()
        server = YamuxSession(tb, Mode.SERVER).start()

        async def echo_server() -> None:
            while True:
                s = await server.accept()
                if s is None:
                    break
                data = await s.read_all()
                await s.write(b"echo:" + data)
                await s.write_eof()

        srv_task = asyncio.create_task(echo_server())
        try:
            s1 = await client.open_stream()
            s2 = await client.open_stream()
            self.assertEqual(s1.stream_id, 1)
            self.assertEqual(s2.stream_id, 3)

            # Server-opened stream should have even ID (2)
            s_srv = await server.open_stream()
            self.assertEqual(s_srv.stream_id, 2)
            s_cli_in = await client.accept()
            self.assertIsNotNone(s_cli_in)
            assert s_cli_in is not None
            self.assertEqual(s_cli_in.stream_id, 2)
            await s_srv.write(b"from-server")
            await s_srv.write_eof()
            self.assertEqual(await s_cli_in.read_all(), b"from-server")
            await s_cli_in.write_eof()

            await s1.write(b"hello-1")
            await s1.write_eof()
            await s2.write(b"hello-2")
            await s2.write_eof()

            self.assertEqual(await s1.read_all(), b"echo:hello-1")
            self.assertEqual(await s2.read_all(), b"echo:hello-2")
        finally:
            await client.close()
            await server.close()
            await srv_task

    async def test_lazy_data_syn_and_mandatory_ack_on_first_reply(self) -> None:
        ta, tb = create_memory_transport_pair()
        rec_server_tx = _RecordingTransport(tb)
        server = YamuxSession(rec_server_tx, Mode.SERVER).start()

        try:
            # Simulate yamux 0.13 Mode::Client lazy open with Data|SYN + payload
            payload = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"
            syn_hdr = FrameHeader(
                FrameType.DATA, FrameFlags.SYN, stream_id=1, length=len(payload)
            )
            await ta.write(syn_hdr.encode() + payload)

            stream = await asyncio.wait_for(server.accept(), timeout=2.0)
            self.assertIsNotNone(stream)
            assert stream is not None
            self.assertEqual(stream.stream_id, 1)
            self.assertEqual(stream.recv_window, DEFAULT_CREDIT - len(payload))
            self.assertEqual(await stream.readexactly(len(payload)), payload)

            # First reply frame MUST carry ACK; second frame MUST NOT carry ACK
            await stream.write(b"HTTP/1.1 200 OK\r\n\r\n")
            await stream.write(b"body")
            await stream.write_eof()
            await server.flush()

            # Read wire bytes sent by server
            frames = _parse_wire_frames(bytes(rec_server_tx.written))
            self.assertGreaterEqual(len(frames), 3)
            self.assertEqual(frames[0][0].frame_type, FrameType.DATA)
            self.assertTrue(FrameFlags.ACK in frames[0][0].flags)
            self.assertEqual(frames[0][1], b"HTTP/1.1 200 OK\r\n\r\n")

            self.assertEqual(frames[1][0].frame_type, FrameType.DATA)
            self.assertFalse(FrameFlags.ACK in frames[1][0].flags)
            self.assertEqual(frames[1][1], b"body")

            self.assertEqual(frames[2][0].frame_type, FrameType.DATA)
            self.assertTrue(FrameFlags.FIN in frames[2][0].flags)
            self.assertFalse(FrameFlags.ACK in frames[2][0].flags)
        finally:
            await server.close()
            await ta.close()

    async def test_flow_control_large_transfer_exceeds_256k_window(self) -> None:
        ta, tb = create_memory_transport_pair()
        rec_server_tx = _RecordingTransport(tb)
        client = YamuxSession(ta, Mode.CLIENT).start()
        server = YamuxSession(rec_server_tx, Mode.SERVER).start()

        # 1 MiB payload = 4x initial 256 KiB window -> requires multiple WindowUpdates!
        big_payload = bytes(i % 251 for i in range(1024 * 1024))

        async def server_worker() -> None:
            s = await server.accept()
            assert s is not None
            received = await s.read_all()
            self.assertEqual(len(received), len(big_payload))
            self.assertEqual(received, big_payload)
            await s.write(received)
            await s.write_eof()

        srv_task = asyncio.create_task(server_worker())
        try:
            cs = await client.open_stream()

            async def writer() -> None:
                await cs.write(big_payload)
                await cs.write_eof()

            async def reader() -> bytes:
                return await cs.read_all()

            _, echoed = await asyncio.wait_for(
                asyncio.gather(writer(), reader()),
                timeout=10.0,
            )
            self.assertEqual(echoed, big_payload)
            await srv_task

            frames = _parse_wire_frames(bytes(rec_server_tx.written))
            wu_frames = [h for h, _ in frames if h.frame_type == FrameType.WINDOW_UPDATE]
            self.assertGreaterEqual(len(wu_frames), 4)
            # First frame emitted for stream 1 (likely a WindowUpdate) carried ACK
            stream1_frames = [h for h, _ in frames if h.stream_id == 1]
            self.assertTrue(FrameFlags.ACK in stream1_frames[0].flags)
        finally:
            await client.close()
            await server.close()

    async def test_concurrent_multiplexed_streams(self) -> None:
        ta, tb = create_memory_transport_pair()
        client = YamuxSession(ta, Mode.CLIENT).start()
        server = YamuxSession(tb, Mode.SERVER).start()

        async def handle_one(s: object) -> None:
            data = await s.read_all()  # type: ignore[attr-defined]
            await s.write(data[::-1])  # type: ignore[attr-defined]
            await s.write_eof()  # type: ignore[attr-defined]

        async def accept_loop() -> None:
            tasks = []
            while True:
                s = await server.accept()
                if s is None:
                    break
                tasks.append(asyncio.create_task(handle_one(s)))
            if tasks:
                await asyncio.gather(*tasks)

        srv_task = asyncio.create_task(accept_loop())
        try:
            async def run_one(idx: int) -> None:
                s = await client.open_stream()
                msg = f"stream-{idx}-".encode() * (200 + idx * 50)
                await s.write(msg)
                await s.write_eof()
                got = await s.read_all()
                self.assertEqual(got, msg[::-1])

            await asyncio.wait_for(
                asyncio.gather(*(run_one(i) for i in range(20))),
                timeout=10.0,
            )
        finally:
            await client.close()
            await server.close()
            await srv_task

    async def test_ping_ack_and_rst_isolation_and_go_away(self) -> None:
        ta, tb = create_memory_transport_pair()
        client = YamuxSession(ta, Mode.CLIENT).start()
        server = YamuxSession(tb, Mode.SERVER).start()

        try:
            # 1. Ping/Pong RTT
            rtt = await client.ping(timeout=2.0)
            self.assertGreaterEqual(rtt, 0.0)
            rtt2 = await server.ping(timeout=2.0)
            self.assertGreaterEqual(rtt2, 0.0)

            # 2. Reset one stream without breaking another stream
            s_bad = await client.open_stream()
            s_good = await client.open_stream()
            srv_bad = await server.accept()
            srv_good = await server.accept()
            assert srv_bad is not None and srv_good is not None

            await srv_bad.reset()
            await asyncio.sleep(0.05)
            self.assertEqual(s_bad.state, StreamState.CLOSED)
            with self.assertRaises((YamuxStreamResetError, YamuxClosedError)):
                await s_bad.write(b"should-fail")

            await s_good.write(b"still-alive")
            await s_good.write_eof()
            self.assertEqual(await srv_good.read_all(), b"still-alive")
            await srv_good.write(b"ok")
            await srv_good.write_eof()
            self.assertEqual(await s_good.read_all(), b"ok")

            # 3. GoAway closes remote session cleanly
            await client.close(GoAwayCode.NORMAL)
            await asyncio.wait_for(server.wait_closed(), timeout=2.0)
            self.assertEqual(server.remote_go_away, GoAwayCode.NORMAL)
            self.assertIsNone(await server.accept())
        finally:
            await client.close()
            await server.close()

    async def test_invalid_stream_id_parity_triggers_protocol_error_go_away(self) -> None:
        ta, tb = create_memory_transport_pair()
        server = YamuxSession(tb, Mode.SERVER).start()
        try:
            # Mode.SERVER expects ODD inbound IDs; send EVEN ID 2 -> protocol error!
            bad_syn = FrameHeader(FrameType.DATA, FrameFlags.SYN, stream_id=2, length=0)
            await ta.write(bad_syn.encode())
            raw_reply = await asyncio.wait_for(ta.read(HEADER_SIZE), timeout=2.0)
            reply = FrameHeader.decode(raw_reply)
            self.assertEqual(reply.frame_type, FrameType.GO_AWAY)
            self.assertEqual(reply.length, int(GoAwayCode.PROTOCOL_ERROR))
            await asyncio.wait_for(server.wait_closed(), timeout=2.0)
            self.assertIsInstance(server.error, YamuxProtocolError)
        finally:
            await server.close()
            await ta.close()

    async def test_window_update_syn_adds_extra_credit(self) -> None:
        ta, tb = create_memory_transport_pair()
        server = YamuxSession(tb, Mode.SERVER).start()
        try:
            wu_syn = FrameHeader(
                FrameType.WINDOW_UPDATE, FrameFlags.SYN, stream_id=1, length=65536
            )
            await ta.write(wu_syn.encode())
            s = await asyncio.wait_for(server.accept(), timeout=2.0)
            assert s is not None
            self.assertEqual(s.send_window, DEFAULT_CREDIT + 65536)
        finally:
            await server.close()
            await ta.close()

    async def test_ws_byte_transport_chunking_and_text_ignore(self) -> None:
        class _FakeWs:
            def __init__(self) -> None:
                self.incoming: List[object] = [
                    "unexpected-text-frame",
                    b"",
                    b"hello ",
                    b"world!",
                ]
                self.sent: List[bytes] = []
                self.closed = False

            async def recv(self) -> object:
                if self.incoming:
                    return self.incoming.pop(0)
                raise EOFError("closed")

            async def send(self, data: bytes) -> None:
                self.sent.append(data)

            async def close(self) -> None:
                self.closed = True

        fake = _FakeWs()
        transport = WsByteTransport(fake, max_binary_frame=4)

        self.assertEqual(await transport.read(3), b"hel")
        self.assertEqual(await transport.read(10), b"lo ")
        self.assertEqual(await transport.read(10), b"world!")
        self.assertEqual(await transport.read(10), b"")

        await transport.write(b"0123456789")
        self.assertEqual(fake.sent, [b"0123", b"4567", b"89"])
        await transport.close()
        self.assertTrue(fake.closed)


if __name__ == "__main__":
    unittest.main()
