"""Runtime configuration, loaded from the environment.

Section 16 of the proposal requires HTTPS, protected secrets and network isolation.
Nothing here reads camera credentials into the process environment: secrets travel
only through `watchtower.security.secrets` and stay encrypted at rest.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

_POSTGRES_SCHEMES = ("postgresql://", "postgresql+psycopg://")
# Session tokens are HMAC-signed with a key derived from this value. Anything short enough to
# guess is short enough to forge a dashboard session from, so the documented 48-byte
# `secrets.token_urlsafe(48)` is treated as the floor rather than a suggestion.
_MIN_JWT_SECRET_LENGTH = 32


class ConfigError(RuntimeError):
    pass


def _split(value: str, default: str = "") -> list[str]:
    raw = value or default
    return [part.strip() for part in raw.split(",") if part.strip()]


_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost", "testserver"})


def _cloud_settings(get: callable, *, environment: str) -> dict:
    """Personnel-mobile forwarding configuration.

    Absent means "this deployment does not forward", which is a supported state: the
    monitoring product must not become unable to run because a cloud service is missing.
    Present-but-incomplete is refused, because a forwarder that cannot sign produces
    alerts the cloud will reject in silence.
    """
    url = (get("WATCHTOWER_CLOUD_API_URL") or "").strip() or None
    key_id = (get("WATCHTOWER_CLOUD_KEY_ID") or "").strip() or None
    secret = (get("WATCHTOWER_CLOUD_KEY_SECRET") or "").strip() or None

    if url is None:
        if key_id or secret:
            raise ConfigError(
                "WATCHTOWER_CLOUD_KEY_ID / WATCHTOWER_CLOUD_KEY_SECRET are set but "
                "WATCHTOWER_CLOUD_API_URL is not; there is nowhere to forward to."
            )
        return {}

    parsed = urlparse(url)
    if parsed.scheme.lower() != "https":
        # Loopback HTTP is allowed in development only, so the forwarder can be exercised
        # against a local cloud process. Anywhere else, alerts carrying incident detail
        # would cross the network in clear text.
        if not (parsed.scheme.lower() == "http" and parsed.hostname in _LOOPBACK_HOSTS):
            raise ConfigError(
                "WATCHTOWER_CLOUD_API_URL must be https:// (mobile proposal section 13); "
                f"got {parsed.scheme!r} for host {parsed.hostname!r}. Loopback http is "
                "permitted only in development."
            )
        if environment.lower() != "development":
            raise ConfigError(
                f"plain-http cloud URL to {parsed.hostname!r} is only permitted in the "
                "development environment."
            )
    if not key_id or not secret:
        raise ConfigError(
            "WATCHTOWER_CLOUD_API_URL is set, so the machine credential is mandatory: "
            "WATCHTOWER_CLOUD_KEY_ID and WATCHTOWER_CLOUD_KEY_SECRET must both be present. "
            "An unsigned ingest request is refused by the cloud service."
        )
    if len(secret) < 32:
        raise ConfigError(
            "WATCHTOWER_CLOUD_KEY_SECRET must be at least 32 characters; it HMAC-signs every "
            "forwarded alert, so a shorter value is guessable. Generate one with: "
            'python -c "import secrets; print(secrets.token_urlsafe(48))"'
        )

    return {
        "cloud_api_url": url,
        "cloud_key_id": key_id,
        "cloud_key_secret": secret,
        "outbox_backoff_seconds": tuple(
            int(v) for v in _split(get("WATCHTOWER_OUTBOX_BACKOFF"), "5,15,60,300,900,1800")
        ),
        "outbox_max_attempts": int(get("WATCHTOWER_OUTBOX_MAX_ATTEMPTS", "12")),
        "outbox_batch_size": int(get("WATCHTOWER_OUTBOX_BATCH_SIZE", "20")),
        "relay_evidence": (get("WATCHTOWER_RELAY_EVIDENCE", "1") or "1").strip() != "0",
        "spool_dir": Path(get("WATCHTOWER_SPOOL_DIR", "./var/spool")),
    }


@dataclass(slots=True)
class Settings:
    database_url: str
    secret_key_path: Path
    jwt_secret: str
    jwt_ttl_minutes: int = 480
    environment: str = "development"
    require_https: bool = True
    evidence_dir: Path = field(default_factory=lambda: Path("./var/evidence"))
    evidence_retention_days: int = 90
    health_retention_days: int = 30
    audit_retention_days: int = 365

    # Ingestion limits (section 7: initial deployment imposes configurable limits).
    max_concurrent_streams: int = 8
    max_concurrent_connection_tests: int = 2
    stream_retry_backoff_seconds: tuple[int, ...] = (2, 5, 15, 30, 60)
    max_stream_restarts: int = 10

    # Connection testing (section 6.5).
    probe_timeout_seconds: int = 12
    probe_frame_count: int = 12
    probe_sustain_seconds: float = 3.0

    # Health evaluation (section 10).
    degraded_after_seconds: float = 4.0
    offline_after_seconds: float = 15.0
    reconnecting_grace_seconds: float = 20.0

    # AI analysis (section 11).
    analysis_fps: float = 4.0
    detection_min_confidence: float = 0.55
    duplicate_event_window_seconds: int = 90

    # Live delivery (section 9).
    live_jpeg_quality: int = 78
    live_max_mbps_per_stream: int = 6

    # Section 15: notification channels are configured, never assumed.
    webhook_url: str | None = None

    # Personnel mobile integration (mobile proposal sections 4, 10 and 11). All optional:
    # a deployment with no cloud service simply never forwards, and the monitoring product
    # keeps working. When a cloud URL *is* set the machine credential is mandatory, because
    # a forwarder that cannot sign is a forwarder whose alerts the cloud will refuse.
    cloud_api_url: str | None = None
    cloud_key_id: str | None = None
    cloud_key_secret: str | None = None
    outbox_backoff_seconds: tuple[int, ...] = (5, 15, 60, 300, 900, 1800)
    outbox_max_attempts: int = 12
    outbox_batch_size: int = 20
    relay_evidence: bool = True
    spool_dir: Path = field(default_factory=lambda: Path("./var/spool"))

    @property
    def mobile_forwarding_enabled(self) -> bool:
        return bool(self.cloud_api_url and self.cloud_key_id and self.cloud_key_secret)

    @property
    def is_production(self) -> bool:
        return self.environment.lower() in {"production", "prod", "pilot"}


def load_settings(env: dict[str, str] | None = None) -> Settings:
    env = os.environ if env is None else env
    get = env.get

    database_url = get("WATCHTOWER_DATABASE_URL", "").strip()
    if not database_url:
        raise ConfigError(
            "WATCHTOWER_DATABASE_URL is required. Section 8.1 makes PostgreSQL the "
            "primary application database; there is no implicit local fallback."
        )
    if not database_url.startswith(_POSTGRES_SCHEMES):
        raise ConfigError(
            "WATCHTOWER_DATABASE_URL must be a PostgreSQL URL (section 8.1). "
            f"Got scheme {database_url.split('://', 1)[0]!r}."
        )

    jwt_secret = get("WATCHTOWER_JWT_SECRET", "").strip()
    if len(jwt_secret) < _MIN_JWT_SECRET_LENGTH:
        raise ConfigError(
            "WATCHTOWER_JWT_SECRET is required and must be at least "
            f"{_MIN_JWT_SECRET_LENGTH} characters (got {len(jwt_secret)}). Dashboard session "
            "tokens are HMAC-signed with a key derived from it, so a missing or guessable "
            "value lets anyone forge a signed-in session. Generate one with: "
            'python -c "import secrets; print(secrets.token_urlsafe(48))"'
        )

    environment = get("WATCHTOWER_ENVIRONMENT", "development")
    require_https = get("WATCHTOWER_REQUIRE_HTTPS", "1" if environment != "development" else "0") == "1"

    # The webhook endpoint is POSTed to with urllib. Validating the scheme once here means
    # the notification path can never be pointed at a local file or an arbitrary protocol.
    webhook_url = get("WATCHTOWER_WEBHOOK_URL") or None
    if webhook_url is not None and urlparse(webhook_url).scheme.lower() not in ("http", "https"):
        raise ConfigError(
            "WATCHTOWER_WEBHOOK_URL must be an http(s) endpoint; got "
            f"{urlparse(webhook_url).scheme!r}. Alerts must not be able to write to the "
            "local filesystem."
        )

    cloud = _cloud_settings(get, environment=environment)

    return Settings(
        database_url=database_url,
        secret_key_path=Path(get("WATCHTOWER_SECRET_KEY_PATH", "./var/watchtower.key")),
        jwt_secret=jwt_secret,
        jwt_ttl_minutes=int(get("WATCHTOWER_JWT_TTL_MINUTES", "480")),
        environment=environment,
        require_https=require_https,
        evidence_dir=Path(get("WATCHTOWER_EVIDENCE_DIR", "./var/evidence")),
        evidence_retention_days=int(get("WATCHTOWER_EVIDENCE_RETENTION_DAYS", "90")),
        health_retention_days=int(get("WATCHTOWER_HEALTH_RETENTION_DAYS", "30")),
        audit_retention_days=int(get("WATCHTOWER_AUDIT_RETENTION_DAYS", "365")),
        max_concurrent_streams=int(get("WATCHTOWER_MAX_CONCURRENT_STREAMS", "8")),
        max_concurrent_connection_tests=int(get("WATCHTOWER_MAX_CONNECTION_TESTS", "2")),
        stream_retry_backoff_seconds=tuple(
            int(v) for v in _split(get("WATCHTOWER_STREAM_BACKOFF"), "2,5,15,30,60")
        ),
        max_stream_restarts=int(get("WATCHTOWER_MAX_STREAM_RESTARTS", "10")),
        probe_timeout_seconds=int(get("WATCHTOWER_PROBE_TIMEOUT_SECONDS", "12")),
        probe_frame_count=int(get("WATCHTOWER_PROBE_FRAMES", "12")),
        probe_sustain_seconds=float(get("WATCHTOWER_PROBE_SUSTAIN_SECONDS", "3")),
        degraded_after_seconds=float(get("WATCHTOWER_DEGRADED_AFTER_SECONDS", "4")),
        offline_after_seconds=float(get("WATCHTOWER_OFFLINE_AFTER_SECONDS", "15")),
        reconnecting_grace_seconds=float(get("WATCHTOWER_RECONNECTING_GRACE_SECONDS", "20")),
        analysis_fps=float(get("WATCHTOWER_ANALYSIS_FPS", "4")),
        detection_min_confidence=float(get("WATCHTOWER_DETECTION_MIN_CONFIDENCE", "0.55")),
        duplicate_event_window_seconds=int(get("WATCHTOWER_DUPLICATE_EVENT_WINDOW", "90")),
        live_jpeg_quality=int(get("WATCHTOWER_LIVE_JPEG_QUALITY", "78")),
        live_max_mbps_per_stream=int(get("WATCHTOWER_LIVE_MAX_MBPS", "6")),
        webhook_url=webhook_url,
        **cloud,
    )
