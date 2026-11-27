"""Pure-Python Yamux v0 stream multiplexer matching Rust `yamux 0.13` byte-for-byte.

Wire specification: https://github.com/hashicorp/yamux/blob/master/spec.md
Interop notes for Neruton (`crates/neruton-proto/src/yamux_session.rs` & `yamux 0.13.10`):
- 12-byte big-endian header: version (u8=0), type (u8), flags (u16), stream_id (u32), length (u32).
- `neruton-server` runs `Mode.CLIENT` (opens odd stream IDs 1, 3, 5, ...).
- Tunnel clients run `Mode.SERVER` (accepts odd stream IDs, opens even stream IDs 2, 4, ...).
- Initial stream window is 256 KiB (262,144 bytes); split send size is 16 KiB (16,384 bytes).
- Inbound streams MUST set `ACK` on their first outbound frame (Data, WindowUpdate, or FIN)
  so the remote never exhausts `MAX_ACK_BACKLOG` (256).
- `yamux 0.13` sends Yamux `Ping(SYN)` frames for RTT estimation; we reply immediately with
  `Ping(ACK)` carrying the exact same nonce.
"""

from __future__ import annotations

import asyncio
import collections
import random
import struct
from dataclasses import dataclass
from enum import Enum, IntEnum, IntFlag
from typing import Any, Deque, Dict, Optional, Protocol, Tuple, Union

from .errors import (
    YamuxClosedError,
    YamuxProtocolError,
    YamuxStreamResetError,
)

YAMUX_VERSION = 0
HEADER_SIZE = 12
DEFAULT_CREDIT = 256 * 1024  # 256 KiB per Yamux spec
DEFAULT_SPLIT_SEND_SIZE = 16 * 1024  # 16 KiB matching yamux 0.13
MAX_FRAME_BODY_LEN = 1024 * 1024  # 1 MiB matching yamux 0.13
DEFAULT_MAX_NUM_STREAMS = 2048  # matching crates/neruton-proto/src/yamux_session.rs
MAX_WS_BINARY_FRAME = 64 * 1024  # 64 KiB matching crates/neruton-proto/src/ws_stream.rs

_HEADER_STRUCT = struct.Struct("!BBHII")
_U32_MAX = 0xFFFFFFFF


class FrameType(IntEnum):
    DATA = 0
    WINDOW_UPDATE = 1
    PING = 2
    GO_AWAY = 3


class FrameFlags(IntFlag):
    NONE = 0
    SYN = 1
    ACK = 2
    FIN = 4
    RST = 8


class GoAwayCode(IntEnum):
    NORMAL = 0
    PROTOCOL_ERROR = 1
    INTERNAL_ERROR = 2


class Mode(Enum):
    CLIENT = "client"
    SERVER = "server"


class StreamState(Enum):
    OPEN = "open"
    SEND_CLOSED = "send_closed"
    RECV_CLOSED = "recv_closed"
    CLOSED = "closed"

    def can_read(self) -> bool:
        return self not in (StreamState.RECV_CLOSED, StreamState.CLOSED)

    def can_write(self) -> bool:
        return self not in (StreamState.SEND_CLOSED, StreamState.CLOSED)


@dataclass(frozen=True)
class FrameHeader:
    """12-byte big-endian Yamux v0 frame header."""

    frame_type: FrameType
    flags: FrameFlags
    stream_id: int
    length: int
    version: int = YAMUX_VERSION

    def encode(self) -> bytes:
        return _HEADER_STRUCT.pack(
            self.version,
            int(self.frame_type),
            int(self.flags),
            self.stream_id,
            self.length,
        )

    @classmethod
    def decode(cls, data: Union[bytes, bytearray, memoryview]) -> FrameHeader:
        if len(data) != HEADER_SIZE:
            raise YamuxProtocolError(
                f"invalid Yamux header length: expected {HEADER_SIZE}, got {len(data)}"
            )
        version, raw_type, raw_flags, stream_id, length = _HEADER_STRUCT.unpack(data)
        if version != YAMUX_VERSION:
            raise YamuxProtocolError(f"unsupported Yamux version: {version}")
        try:
            frame_type = FrameType(raw_type)
        except ValueError as exc:
            raise YamuxProtocolError(f"unknown Yamux frame type: {raw_type}") from exc
        return cls(
            version=version,
            frame_type=frame_type,
            flags=FrameFlags(raw_flags),
            stream_id=stream_id,
            length=length,
        )


class ByteTransport(Protocol):
    """Minimal async bidirectional byte-stream interface for YamuxSession."""

    async def read(self, n: int) -> bytes:
        """Read up to `n` bytes. Return `b''` on clean EOF."""
        ...

    async def write(self, data: bytes) -> None:
        """Write all `data` bytes to the underlying transport."""
        ...

    async def close(self) -> None:
        """Close the underlying transport."""
        ...


class WsByteTransport:
    """Adapts a `websockets` connection onto `ByteTransport` over WebSocket binary frames.

    Mirrors `crates/neruton-proto/src/ws_stream.rs`:
    - Concatenates incoming WS binary frames into a continuous byte stream.
    - Ignores unexpected WS text frames once in binary Yamux mode.
    - Treats WS close as clean EOF (`b''`).
    - Splits outgoing writes into chunks <= 64 KiB WS binary frames.
    """

    def __init__(self, ws: Any, *, max_binary_frame: int = MAX_WS_BINARY_FRAME) -> None:
        self._ws = ws
        self._max_binary_frame = max_binary_frame
        self._buf = bytearray()
        self._eof = False
        self._write_lock = asyncio.Lock()

    async def read(self, n: int) -> bytes:
        if n <= 0:
            return b""
        if self._buf:
            out = bytes(self._buf[:n])
            del self._buf[:n]
            return out
        if self._eof:
            return b""

        while True:
            try:
                msg = await self._ws.recv()
            except Exception as exc:
                # websockets raises ConnectionClosed (OK or Error) on close/disconnect.
                self._eof = True
                if _is_ws_clean_close(exc):
                    return b""
                raise YamuxClosedError(f"websocket read error: {exc}") from exc

            if isinstance(msg, (bytes, bytearray, memoryview)):
                if len(msg) == 0:
                    continue
                if len(msg) <= n:
                    return bytes(msg)
                out = bytes(msg[:n])
                self._buf.extend(msg[n:])
                return out
            # Ignore unexpected text frames once in binary Yamux mode.

    async def write(self, data: bytes) -> None:
        if not data:
            return
        async with self._write_lock:
            view = memoryview(data)
            offset = 0
            total = len(view)
            while offset < total:
                end = min(offset + self._max_binary_frame, total)
                try:
                    await self._ws.send(bytes(view[offset:end]))
                except Exception as exc:
                    raise YamuxClosedError(f"websocket write error: {exc}") from exc
                offset = end

    async def close(self) -> None:
        self._eof = True
        try:
            await self._ws.close()
        except Exception:
            pass


def _is_ws_clean_close(exc: BaseException) -> bool:
    name = type(exc).__name__
    return name in ("ConnectionClosedOK", "ConnectionClosed", "EOFError")


class MemoryByteTransport:
    """In-memory full-duplex byte transport for deterministic testing."""

    def __init__(
        self,
        rx_buf: bytearray,
        rx_event: asyncio.Event,
        tx_buf: bytearray,
        tx_event: asyncio.Event,
        closed_flags: Dict[str, bool],
        side: str,
    ) -> None:
        self._rx_buf = rx_buf
        self._rx_event = rx_event
        self._tx_buf = tx_buf
        self._tx_event = tx_event
        self._closed = closed_flags
        self._side = side
        self._peer = "b" if side == "a" else "a"

    async def read(self, n: int) -> bytes:
        if n <= 0:
            return b""
        while not self._rx_buf:
            if self._closed[self._peer] or self._closed[self._side]:
                return b""
            self._rx_event.clear()
            if self._rx_buf or self._closed[self._peer] or self._closed[self._side]:
                break
            await self._rx_event.wait()
        if not self._rx_buf:
            return b""
        out = bytes(self._rx_buf[:n])
        del self._rx_buf[:n]
        return out

    async def write(self, data: bytes) -> None:
        if self._closed[self._side] or self._closed[self._peer]:
            raise YamuxClosedError("memory pipe closed")
        if data:
            self._tx_buf.extend(data)
            self._tx_event.set()
        await asyncio.sleep(0)

    async def close(self) -> None:
        self._closed[self._side] = True
        self._tx_event.set()
        self._rx_event.set()


def create_memory_transport_pair() -> Tuple[MemoryByteTransport, MemoryByteTransport]:
    """Create a pair of connected in-memory `ByteTransport` endpoints."""
    buf_a_to_b = bytearray()
    buf_b_to_a = bytearray()
    ev_a_to_b = asyncio.Event()
    ev_b_to_a = asyncio.Event()
    closed = {"a": False, "b": False}
    a = MemoryByteTransport(buf_b_to_a, ev_b_to_a, buf_a_to_b, ev_a_to_b, closed, "a")
    b = MemoryByteTransport(buf_a_to_b, ev_a_to_b, buf_b_to_a, ev_b_to_a, closed, "b")
    return a, b


class YamuxStream:
    """A single bidirectional flow-controlled stream multiplexed over a `YamuxSession`."""

    def __init__(
        self,
        session: YamuxSession,
        stream_id: int,
        *,
        send_window: int = DEFAULT_CREDIT,
        recv_window: int = DEFAULT_CREDIT,
        outbound_flag: FrameFlags = FrameFlags.NONE,
    ) -> None:
        self._session = session
        self.stream_id = stream_id
        self.send_window = send_window
        self.recv_window = recv_window
        self.max_recv_window = recv_window
        self._outbound_flag = outbound_flag
        self.state = StreamState.OPEN
        self._reset = False

        self._recv_buf = bytearray()
        self._recv_event = asyncio.Event()
        self._send_window_event = asyncio.Event()
        if self.send_window > 0:
            self._send_window_event.set()

    @property
    def is_closed(self) -> bool:
        return self.state == StreamState.CLOSED

    @property
    def is_write_closed(self) -> bool:
        return not self.state.can_write()

    @property
    def is_read_closed(self) -> bool:
        return not self.state.can_read()

    def _take_outbound_flag(self) -> FrameFlags:
        flag = self._outbound_flag
        self._outbound_flag = FrameFlags.NONE
        return flag

    def _transition_state(self, target: StreamState) -> StreamState:
        prev = self.state
        if prev == StreamState.CLOSED:
            return prev
        if target == StreamState.CLOSED:
            self.state = StreamState.CLOSED
        elif prev == StreamState.OPEN:
            self.state = target
        elif prev == StreamState.RECV_CLOSED and target == StreamState.SEND_CLOSED:
            self.state = StreamState.CLOSED
        elif prev == StreamState.SEND_CLOSED and target == StreamState.RECV_CLOSED:
            self.state = StreamState.CLOSED
        return prev

    def _on_data_received(self, payload: bytes, *, fin: bool) -> None:
        if payload:
            self._recv_buf.extend(payload)
        if fin:
            self._transition_state(StreamState.RECV_CLOSED)
        self._recv_event.set()
        if self.state == StreamState.CLOSED:
            self._session._remove_stream(self.stream_id)

    def _on_window_update(self, credit: int, *, fin: bool) -> None:
        self.send_window += credit
        if self.send_window > 0:
            self._send_window_event.set()
        if fin:
            self._transition_state(StreamState.RECV_CLOSED)
            self._recv_event.set()
        if self.state == StreamState.CLOSED:
            self._session._remove_stream(self.stream_id)

    def _on_remote_reset(self) -> None:
        self._reset = True
        self._transition_state(StreamState.CLOSED)
        self._recv_event.set()
        self._send_window_event.set()
        self._session._remove_stream(self.stream_id)

    def _on_session_closed(self) -> None:
        self._transition_state(StreamState.CLOSED)
        self._recv_event.set()
        self._send_window_event.set()

    def _maybe_send_window_update(self) -> None:
        if not self.state.can_read() or self._session.is_closed:
            return
        bytes_received = self.max_recv_window - self.recv_window
        delta = max(0, bytes_received - len(self._recv_buf))
        if delta < self.max_recv_window // 2:
            return
        self.recv_window += delta
        flags = self._take_outbound_flag()
        hdr = FrameHeader(
            frame_type=FrameType.WINDOW_UPDATE,
            flags=flags,
            stream_id=self.stream_id,
            length=delta,
        )
        self._session._enqueue_stream_frame(hdr, b"")

    async def read(self, n: int = 65536) -> bytes:
        """Read up to `n` bytes from the stream. Returns `b''` on EOF."""
        if n <= 0:
            return b""

        if not self._session._read_after_close and self._session.is_closed:
            return b""

        self._maybe_send_window_update()

        while not self._recv_buf:
            if not self.state.can_read() or self._session.is_closed:
                return b""
            self._recv_event.clear()
            if self._recv_buf or not self.state.can_read() or self._session.is_closed:
                break
            await self._recv_event.wait()

        if not self._recv_buf:
            return b""

        out = bytes(self._recv_buf[:n])
        del self._recv_buf[:n]
        self._maybe_send_window_update()
        return out

    async def readexactly(self, n: int) -> bytes:
        """Read exactly `n` bytes or raise `EOFError` if stream ends prematurely."""
        if n <= 0:
            return b""
        buf = bytearray()
        while len(buf) < n:
            chunk = await self.read(n - len(buf))
            if not chunk:
                raise EOFError(f"stream {self.stream_id} EOF after {len(buf)}/{n} bytes")
            buf.extend(chunk)
        return bytes(buf)

    async def read_all(self) -> bytes:
        """Read until EOF and return all bytes."""
        chunks = []
        while True:
            chunk = await self.read(65536)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)

    async def write(self, data: Union[bytes, bytearray, memoryview]) -> int:
        """Write all `data` respecting Yamux flow-control send window and split size."""
        if not data:
            return 0
        view = memoryview(data)
        total = len(view)
        offset = 0
        split_size = self._session._split_send_size

        while offset < total:
            if self._reset:
                raise YamuxStreamResetError(f"stream {self.stream_id} reset")
            if not self.state.can_write() or self._session.is_closed:
                raise YamuxClosedError(f"stream {self.stream_id} write closed")

            if self.send_window == 0:
                self._send_window_event.clear()
                if self.send_window == 0:
                    await self._send_window_event.wait()
                continue

            await self._session._wait_write_capacity()
            if self._reset:
                raise YamuxStreamResetError(f"stream {self.stream_id} reset")
            if not self.state.can_write() or self._session.is_closed:
                raise YamuxClosedError(f"stream {self.stream_id} write closed")
            if self.send_window == 0:
                continue

            chunk_len = min(total - offset, self.send_window, split_size)
            self.send_window -= chunk_len
            if self.send_window == 0:
                self._send_window_event.clear()

            flags = self._take_outbound_flag()
            payload = bytes(view[offset : offset + chunk_len])
            hdr = FrameHeader(
                frame_type=FrameType.DATA,
                flags=flags,
                stream_id=self.stream_id,
                length=chunk_len,
            )
            self._session._enqueue_stream_frame(hdr, payload)
            offset += chunk_len

        return total

    async def drain(self) -> None:
        """Wait until queued frames have been flushed to the underlying transport."""
        await self._session.flush()

    async def write_eof(self) -> None:
        """Half-close the local write direction by sending a FIN frame (idempotent)."""
        if not self.state.can_write():
            return
        self._transition_state(StreamState.SEND_CLOSED)
        self._send_window_event.set()
        if not self._session.is_closed:
            flags = FrameFlags.FIN | self._take_outbound_flag()
            hdr = FrameHeader(
                frame_type=FrameType.DATA,
                flags=flags,
                stream_id=self.stream_id,
                length=0,
            )
            self._session._enqueue_stream_frame(hdr, b"")
        if self.state == StreamState.CLOSED:
            self._session._remove_stream(self.stream_id)

    async def reset(self) -> None:
        """Immediately abort the stream by sending RST (idempotent)."""
        if self.state == StreamState.CLOSED:
            return
        self._reset = True
        self._transition_state(StreamState.CLOSED)
        self._recv_event.set()
        self._send_window_event.set()
        self._session._remove_stream(self.stream_id)
        if not self._session.is_closed:
            hdr = FrameHeader(
                frame_type=FrameType.DATA,
                flags=FrameFlags.RST,
                stream_id=self.stream_id,
                length=0,
            )
            self._session._enqueue_stream_frame(hdr, b"")

    async def close(self) -> None:
        """Gracefully close our write side (sending FIN)."""
        await self.write_eof()

    async def __aenter__(self) -> YamuxStream:
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        if exc is not None:
            await self.reset()
        else:
            await self.close()


class YamuxSession:
    """Async Yamux v0 multiplexer supporting both `Mode.SERVER` and `Mode.CLIENT`."""

    def __init__(
        self,
        transport: ByteTransport,
        mode: Mode,
        *,
        max_num_streams: int = DEFAULT_MAX_NUM_STREAMS,
        initial_window: int = DEFAULT_CREDIT,
        split_send_size: int = DEFAULT_SPLIT_SEND_SIZE,
        read_after_close: bool = True,
        write_queue_limit: int = 512,
    ) -> None:
        self._transport = transport
        self.mode = mode
        self._max_num_streams = max_num_streams
        self._initial_window = initial_window
        self._split_send_size = split_send_size
        self._read_after_close = read_after_close
        self._write_queue_limit = write_queue_limit

        self._next_stream_id = 1 if mode == Mode.CLIENT else 2
        self._streams: Dict[int, YamuxStream] = {}
        self._inbound_queue: asyncio.Queue[Optional[YamuxStream]] = asyncio.Queue()
        self._pending_pings: Dict[int, Tuple[float, asyncio.Future[float]]] = {}

        # Separate high-priority session control frames (Ping/GoAway, stream_id=0)
        # from strictly FIFO per-stream frames so stream SYN/ACK/Data/FIN never reorder.
        self._ctrl_deque: Deque[Tuple[FrameHeader, bytes]] = collections.deque()
        self._stream_deque: Deque[Tuple[FrameHeader, bytes]] = collections.deque()
        self._write_event = asyncio.Event()
        self._write_space_event = asyncio.Event()
        self._write_space_event.set()
        self._flush_event = asyncio.Event()
        self._flush_event.set()

        self._closed = False
        self._closing = False
        self._remote_go_away: Optional[GoAwayCode] = None
        self._error: Optional[BaseException] = None
        self._closed_event = asyncio.Event()

        self._reader_task: Optional[asyncio.Task[None]] = None
        self._writer_task: Optional[asyncio.Task[None]] = None

    @property
    def is_closed(self) -> bool:
        return self._closed

    @property
    def remote_go_away(self) -> Optional[GoAwayCode]:
        return self._remote_go_away

    @property
    def error(self) -> Optional[BaseException]:
        return self._error

    @property
    def active_stream_count(self) -> int:
        return len(self._streams)

    def start(self) -> YamuxSession:
        """Start the background reader and writer tasks."""
        if self._reader_task is None and not self._closed:
            self._reader_task = asyncio.create_task(
                self._reader_loop(), name=f"yamux-reader-{self.mode.value}"
            )
            self._writer_task = asyncio.create_task(
                self._writer_loop(), name=f"yamux-writer-{self.mode.value}"
            )
        return self

    def _is_valid_remote_stream_id(self, stream_id: int) -> bool:
        if stream_id == 0:
            return False
        if self.mode == Mode.SERVER:
            return (stream_id % 2) == 1
        return (stream_id % 2) == 0

    def _remove_stream(self, stream_id: int) -> None:
        self._streams.pop(stream_id, None)

    def _enqueue_ctrl_frame(self, header: FrameHeader, payload: bytes = b"") -> None:
        self._ctrl_deque.append((header, payload))
        self._flush_event.clear()
        self._write_event.set()

    def _enqueue_stream_frame(self, header: FrameHeader, payload: bytes) -> None:
        self._stream_deque.append((header, payload))
        if len(self._stream_deque) >= self._write_queue_limit:
            self._write_space_event.clear()
        self._flush_event.clear()
        self._write_event.set()

    async def _wait_write_capacity(self) -> None:
        if not self._write_space_event.is_set() and not self._closed:
            await self._write_space_event.wait()

    async def flush(self) -> None:
        """Wait until all currently queued frames have been written to the transport."""
        if self._closed:
            return
        await self._flush_event.wait()

    async def open_stream(self) -> YamuxStream:
        """Open a new outbound stream (odd IDs in CLIENT mode, even IDs in SERVER mode)."""
        if self._closed or self._closing:
            raise YamuxClosedError("yamux session is closed")
        if len(self._streams) >= self._max_num_streams:
            raise YamuxProtocolError("maximum number of Yamux streams reached")
        if self._next_stream_id > _U32_MAX:
            raise YamuxProtocolError("Yamux stream ID space exhausted")

        stream_id = self._next_stream_id
        self._next_stream_id += 2

        stream = YamuxStream(
            self,
            stream_id,
            send_window=DEFAULT_CREDIT,
            recv_window=self._initial_window,
            outbound_flag=FrameFlags.NONE,
        )
        self._streams[stream_id] = stream

        extra_credit = max(0, self._initial_window - DEFAULT_CREDIT)
        hdr = FrameHeader(
            frame_type=FrameType.WINDOW_UPDATE,
            flags=FrameFlags.SYN,
            stream_id=stream_id,
            length=extra_credit,
        )
        self._enqueue_stream_frame(hdr, b"")
        return stream

    async def accept(self) -> Optional[YamuxStream]:
        """Accept the next inbound stream opened by the peer, or `None` when closed."""
        if self._closed and self._inbound_queue.empty():
            return None
        return await self._inbound_queue.get()

    async def ping(self, *, timeout: float = 10.0) -> float:
        """Send a Yamux Ping(SYN) frame and await the matching Ping(ACK), returning RTT seconds."""
        if self._closed or self._closing:
            raise YamuxClosedError("yamux session is closed")
        loop = asyncio.get_running_loop()
        nonce = random.getrandbits(32)
        while nonce in self._pending_pings:
            nonce = random.getrandbits(32)
        fut: asyncio.Future[float] = loop.create_future()
        self._pending_pings[nonce] = (loop.time(), fut)

        hdr = FrameHeader(
            frame_type=FrameType.PING,
            flags=FrameFlags.SYN,
            stream_id=0,
            length=nonce,
        )
        self._enqueue_ctrl_frame(hdr)
        try:
            return await asyncio.wait_for(fut, timeout=timeout)
        finally:
            self._pending_pings.pop(nonce, None)

    async def wait_closed(self) -> None:
        """Wait until the Yamux session terminates."""
        await self._closed_event.wait()

    async def close(self, code: GoAwayCode = GoAwayCode.NORMAL) -> None:
        """Gracefully close the session by sending `GoAway` and shutting down transport."""
        if self._closed:
            return
        if not self._closing:
            self._closing = True
            hdr = FrameHeader(
                frame_type=FrameType.GO_AWAY,
                flags=FrameFlags.NONE,
                stream_id=0,
                length=int(code),
            )
            self._enqueue_ctrl_frame(hdr)
            try:
                await asyncio.wait_for(self._flush_event.wait(), timeout=1.0)
            except (asyncio.TimeoutError, Exception):
                pass

        await self._finalize(error=None)

    async def _terminate_with_go_away(self, code: GoAwayCode, error: BaseException) -> None:
        if not self._closing and not self._closed:
            self._closing = True
            hdr = FrameHeader(
                frame_type=FrameType.GO_AWAY,
                flags=FrameFlags.NONE,
                stream_id=0,
                length=int(code),
            )
            self._enqueue_ctrl_frame(hdr)
            try:
                await asyncio.wait_for(self._flush_event.wait(), timeout=0.5)
            except (asyncio.TimeoutError, Exception):
                pass
        await self._finalize(error=error)

    async def _finalize(self, *, error: Optional[BaseException]) -> None:
        if self._closed:
            return
        self._closed = True
        self._closing = True
        if error is not None and self._error is None:
            self._error = error

        self._write_event.set()
        self._write_space_event.set()
        self._flush_event.set()

        for stream in list(self._streams.values()):
            stream._on_session_closed()
        self._streams.clear()

        for _, fut in list(self._pending_pings.values()):
            if not fut.done():
                fut.set_exception(error or YamuxClosedError("yamux session closed"))
        self._pending_pings.clear()

        try:
            await self._transport.close()
        except Exception:
            pass

        current = asyncio.current_task()
        for task in (self._reader_task, self._writer_task):
            if task is not None and task is not current and not task.done():
                task.cancel()
        for task in (self._reader_task, self._writer_task):
            if task is not None and task is not current:
                try:
                    await task
                except (asyncio.CancelledError, Exception):
                    pass

        self._inbound_queue.put_nowait(None)
        self._closed_event.set()

    async def _read_exact(self, n: int) -> Optional[bytes]:
        buf = bytearray()
        while len(buf) < n:
            chunk = await self._transport.read(n - len(buf))
            if not chunk:
                if len(buf) == 0:
                    return None
                raise YamuxClosedError(
                    f"unexpected EOF in Yamux transport ({len(buf)}/{n} bytes)"
                )
            buf.extend(chunk)
        return bytes(buf)

    async def _reader_loop(self) -> None:
        try:
            while not self._closed:
                raw_hdr = await self._read_exact(HEADER_SIZE)
                if raw_hdr is None:
                    break
                header = FrameHeader.decode(raw_hdr)

                if header.frame_type == FrameType.DATA:
                    if header.length > MAX_FRAME_BODY_LEN:
                        raise YamuxProtocolError(
                            f"Yamux data frame body too large: {header.length}"
                        )
                    payload = b""
                    if header.length > 0:
                        raw_body = await self._read_exact(header.length)
                        if raw_body is None:
                            raise YamuxClosedError("unexpected EOF reading Yamux DATA payload")
                        payload = raw_body
                    self._handle_data_frame(header, payload)

                elif header.frame_type == FrameType.WINDOW_UPDATE:
                    self._handle_window_update_frame(header)

                elif header.frame_type == FrameType.PING:
                    self._handle_ping_frame(header)

                elif header.frame_type == FrameType.GO_AWAY:
                    try:
                        self._remote_go_away = GoAwayCode(header.length)
                    except ValueError:
                        self._remote_go_away = GoAwayCode.PROTOCOL_ERROR
                    break

        except asyncio.CancelledError:
            return
        except YamuxProtocolError as exc:
            await self._terminate_with_go_away(GoAwayCode.PROTOCOL_ERROR, exc)
            return
        except Exception as exc:
            await self._finalize(error=exc)
            return

        await self._finalize(error=None)

    def _handle_data_frame(self, header: FrameHeader, payload: bytes) -> None:
        sid = header.stream_id
        flags = header.flags

        if FrameFlags.RST in flags:
            stream = self._streams.get(sid)
            if stream is not None:
                stream._on_remote_reset()
            return

        is_fin = FrameFlags.FIN in flags

        if FrameFlags.SYN in flags:
            if not self._is_valid_remote_stream_id(sid):
                raise YamuxProtocolError(f"invalid inbound stream id {sid}")
            if sid in self._streams:
                raise YamuxProtocolError(f"duplicate stream id {sid}")
            if len(self._streams) >= self._max_num_streams:
                raise YamuxProtocolError("maximum number of streams reached")
            if len(payload) > DEFAULT_CREDIT:
                raise YamuxProtocolError(
                    f"initial SYN body ({len(payload)}) exceeds default credit ({DEFAULT_CREDIT})"
                )

            stream = YamuxStream(
                self,
                sid,
                send_window=DEFAULT_CREDIT,
                recv_window=DEFAULT_CREDIT,
                outbound_flag=FrameFlags.ACK,
            )
            stream.recv_window -= len(payload)
            stream._on_data_received(payload, fin=is_fin)
            if stream.state != StreamState.CLOSED:
                self._streams[sid] = stream
            self._inbound_queue.put_nowait(stream)
            return

        stream = self._streams.get(sid)
        if stream is None:
            # Ignore frames for already dropped/closed streams (matches yamux 0.13 issue #110).
            return

        if len(payload) > stream.recv_window:
            raise YamuxProtocolError(
                f"stream {sid} frame body ({len(payload)}) exceeds receive window ({stream.recv_window})"
            )
        stream.recv_window -= len(payload)
        stream._on_data_received(payload, fin=is_fin)

    def _handle_window_update_frame(self, header: FrameHeader) -> None:
        sid = header.stream_id
        flags = header.flags

        if FrameFlags.RST in flags:
            stream = self._streams.get(sid)
            if stream is not None:
                stream._on_remote_reset()
            return

        is_fin = FrameFlags.FIN in flags

        if FrameFlags.SYN in flags:
            if not self._is_valid_remote_stream_id(sid):
                raise YamuxProtocolError(f"invalid inbound stream id {sid}")
            if sid in self._streams:
                raise YamuxProtocolError(f"duplicate stream id {sid}")
            if len(self._streams) >= self._max_num_streams:
                raise YamuxProtocolError("maximum number of streams reached")

            initial_send_window = DEFAULT_CREDIT + header.length
            if initial_send_window > _U32_MAX:
                raise YamuxProtocolError(f"stream {sid} initial send window overflow")

            stream = YamuxStream(
                self,
                sid,
                send_window=initial_send_window,
                recv_window=DEFAULT_CREDIT,
                outbound_flag=FrameFlags.ACK,
            )
            if is_fin:
                stream._transition_state(StreamState.RECV_CLOSED)
            if stream.state != StreamState.CLOSED:
                self._streams[sid] = stream
            self._inbound_queue.put_nowait(stream)
            return

        stream = self._streams.get(sid)
        if stream is None:
            return

        if stream.send_window + header.length > _U32_MAX:
            raise YamuxProtocolError(f"stream {sid} send window overflow")
        stream._on_window_update(header.length, fin=is_fin)

    def _handle_ping_frame(self, header: FrameHeader) -> None:
        if FrameFlags.ACK in header.flags:
            entry = self._pending_pings.pop(header.length, None)
            if entry is not None:
                sent_at, fut = entry
                if not fut.done():
                    rtt = max(0.0, asyncio.get_running_loop().time() - sent_at)
                    fut.set_result(rtt)
            return

        # Reply to Ping(SYN) (or any non-ACK ping) with Ping(ACK) and matching nonce.
        if header.stream_id == 0 or header.stream_id in self._streams:
            pong = FrameHeader(
                frame_type=FrameType.PING,
                flags=FrameFlags.ACK,
                stream_id=0,
                length=header.length,
            )
            self._enqueue_ctrl_frame(pong)

    async def _writer_loop(self) -> None:
        try:
            while True:
                while self._ctrl_deque or self._stream_deque:
                    if self._ctrl_deque:
                        hdr, payload = self._ctrl_deque.popleft()
                    else:
                        hdr, payload = self._stream_deque.popleft()
                        if len(self._stream_deque) < self._write_queue_limit:
                            self._write_space_event.set()

                    raw = hdr.encode() + payload if payload else hdr.encode()
                    await self._transport.write(raw)

                self._flush_event.set()
                if self._closed or self._closing:
                    break

                self._write_event.clear()
                if not self._ctrl_deque and not self._stream_deque and not self._closed:
                    await self._write_event.wait()
        except asyncio.CancelledError:
            return
        except Exception as exc:
            await self._finalize(error=exc)
