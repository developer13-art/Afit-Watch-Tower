"""RTSP connection-string parsing and validation (proposal sections 6.2 and 6.3).

Both registration methods converge on the same `ConnectionSpec`. Method A parses an address
the operator copied from VLC; Method B assembles one from validated individual fields,
including percent-encoding credentials so a password containing `@` or `:` does not corrupt
the URL.

`to_url()` is the only place the credential is re-embedded, and it is called by the
ingestion service on the server side. Nothing that leaves the backend uses it.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import quote, unquote, urlsplit

DEFAULT_RTSP_PORT = 554
ALLOWED_SCHEMES = {"rtsp"}

_HOST_RE = re.compile(r"^[A-Za-z0-9_.\-]+$|^\[[0-9A-Fa-f:.]+\]$")


class RTSPSpecError(ValueError):
    """Raised with a field name so the wizard can highlight the offending input."""

    def __init__(self, field_name: str, message: str) -> None:
        super().__init__(message)
        self.field = field_name
        self.message = message


@dataclass(slots=True)
class ConnectionSpec:
    host: str
    port: int
    path: str
    username: str | None = None
    password: str | None = field(default=None, repr=False)
    transport: str = "tcp"

    @property
    def host_without_brackets(self) -> str:
        return self.host.removeprefix("[").removesuffix("]")

    @property
    def requires_network_review(self) -> bool:
        """True when the camera address is publicly routable.

        Section 16 requires camera streams to stay inside network isolation, so a public
        address is surfaced to the operator instead of being silently accepted.
        """
        try:
            address = ipaddress.ip_address(self.host_without_brackets)
        except ValueError:
            # A hostname may resolve to anything; the connection test decides.
            return False
        return not (
            address.is_private
            or address.is_loopback
            or address.is_link_local
        )

    def to_url(self) -> str:
        """A credential-bearing URL for the ingestion service. Never returned to a client."""
        authority = self.host
        if self.username is not None:
            authority = f"{quote(self.username, safe='')}:{quote(self.password or '', safe='')}@{self.host}"
        return f"rtsp://{authority}:{self.port}{self.path}"

    def redacted_url(self) -> str:
        authority = f"{self.username}:***@" if self.username else ""
        return f"rtsp://{authority}{self.host}:{self.port}{self.path}"

    def non_secret_dict(self) -> dict:
        """The shape safe to store in a response or audit row."""
        return {
            "host": self.host,
            "port": self.port,
            "stream_path": self.path,
            "username": self.username,
            "transport": self.transport,
            "has_password": bool(self.password),
        }


def parse_connection_string(raw: str) -> ConnectionSpec:
    """Method A: parse a pasted RTSP address into a validated spec."""
    value = (raw or "").strip()
    if not value:
        raise RTSPSpecError("rtsp_url", "An RTSP connection string is required.")

    try:
        parts = urlsplit(value)
    except ValueError as exc:
        raise RTSPSpecError("rtsp_url", f"This is not a parseable address: {exc}") from exc

    if parts.scheme.lower() not in ALLOWED_SCHEMES:
        raise RTSPSpecError(
            "rtsp_url",
            f"Protocol {parts.scheme!r} is not supported. Register verified RTSP "
            "addresses; other protocols need a separate feasibility check.",
        )

    username = unquote(parts.username) if parts.username else None
    password = unquote(parts.password) if parts.password else None
    host = (parts.hostname or "").lower()
    if not host:
        raise RTSPSpecError("rtsp_url", "No host address found in the connection string.")

    try:
        port = parts.port if parts.port is not None else DEFAULT_RTSP_PORT
    except ValueError as exc:
        raise RTSPSpecError("rtsp_url", f"Invalid port: {exc}") from exc

    # Many cameras select the stream with query parameters (`/cam/realmonitor?channel=1
    # &subtype=0`). Dropping them would make Method A dial a different stream from the one
    # the operator verified in VLC, and the two registration methods must converge.
    stream_path = parts.path or ""
    if parts.query:
        stream_path = f"{stream_path}?{parts.query}"

    return _build(host, port, stream_path, username, password)


def build_spec(
    *,
    host: str,
    port: int | str | None,
    stream_path: str,
    username: str | None,
    password: str | None,
    transport: str = "tcp",
) -> ConnectionSpec:
    """Method B: assemble the same validated spec from guided form fields."""
    normalised_host = (host or "").strip().lower().removeprefix("rtsp://").rstrip("/")
    normalised_path = (stream_path or "").strip()
    if normalised_path and not normalised_path.startswith("/"):
        normalised_path = "/" + normalised_path

    try:
        resolved_port = int(port) if port not in (None, "") else DEFAULT_RTSP_PORT
    except (TypeError, ValueError) as exc:
        raise RTSPSpecError("port", f"Port must be a whole number, got {port!r}.") from exc

    return _build(
        normalised_host,
        resolved_port,
        normalised_path,
        (username or "").strip() or None,
        password if password else None,
        transport,
    )


def _build(
    host: str,
    port: int,
    path: str,
    username: str | None,
    password: str | None,
    transport: str = "tcp",
) -> ConnectionSpec:
    if not host or not _HOST_RE.match(host):
        raise RTSPSpecError("host", f"{host!r} is not a valid camera address.")
    if not 1 <= port <= 65535:
        raise RTSPSpecError("port", f"Port {port} is outside the valid range.")
    if not path or path == "/":
        raise RTSPSpecError(
            "stream_path",
            "A stream path is required - the exact path confirmed in VLC, for example "
            "/cam/realmonitor?channel=1&subtype=0.",
        )
    if transport not in {"tcp", "udp"}:
        raise RTSPSpecError("transport", f"Unsupported transport {transport!r}.")
    if username is not None and not username:
        raise RTSPSpecError("username", "Username must not be empty when provided.")

    return ConnectionSpec(
        host=host,
        port=port,
        path=path,
        username=username,
        password=password,
        transport=transport,
    )
