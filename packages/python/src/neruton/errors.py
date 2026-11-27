"""Exception hierarchy for the Neruton Python SDK."""

from __future__ import annotations

from typing import Any, Optional


class NerutonError(Exception):
    """Base exception for all Neruton errors."""


class PrefixError(NerutonError, ValueError):
    """Raised when a subdomain prefix fails validation or is reserved."""

    def __init__(self, message: str, *, code: str = "invalid") -> None:
        super().__init__(message)
        self.code = code


class AuthError(NerutonError):
    """Raised on HTTP 401 Unauthorized authentication failures (non-retryable)."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int = 401,
        server_message: Optional[str] = None,
        transport_info: Optional[Any] = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.server_message = server_message
        self.transport_info = transport_info


class RegistrationError(NerutonError):
    """Raised when the Neruton server rejects tunnel registration."""

    def __init__(self, message: str, *, retryable: bool = False) -> None:
        super().__init__(message)
        self.retryable = retryable


class TunnelError(NerutonError):
    """Base exception for tunnel configuration, transport, or lifecycle errors."""


class TunnelConnectionError(TunnelError, ConnectionError):
    """Raised when establishing or maintaining the tunnel WebSocket connection fails."""


class DohError(TunnelConnectionError):
    """Raised when DNS-over-HTTPS resolution fails."""


class TunnelClosedError(TunnelError):
    """Raised when operating on an already closed tunnel or session."""


class YamuxError(NerutonError):
    """Base exception for Yamux multiplexing errors."""


class YamuxProtocolError(YamuxError):
    """Raised on Yamux framing or flow-control protocol violations."""


class YamuxClosedError(YamuxError):
    """Raised when reading/writing on a closed Yamux session or stream."""


class YamuxStreamResetError(YamuxClosedError, ConnectionResetError):
    """Raised when a Yamux stream is reset (RST) by either peer."""
