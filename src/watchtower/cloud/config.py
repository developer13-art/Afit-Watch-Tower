"""Cloud-service configuration, loaded from the environment.

Nothing here is shared with the monitoring host's `WATCHTOWER_*` variables except the database
URL, on purpose: the two processes run with different secrets, and a deployment that reuses the
monitoring JWT secret in the cloud would let a phone token open the console.

Every value that a phone or the monitoring host can influence is validated at load time, so a
misconfiguration fails the process at startup instead of quietly weakening a guarantee later.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

_POSTGRES_SCHEMES = ("postgresql://", "postgresql+psycopg://")
_MIN_SECRET_LENGTH = 32
_KEY_ID_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")

DEFAULT_FORCED_ALERTS = ("critical", "incident.escalated")


class CloudConfigError(RuntimeError):
    pass


def _split(value: str | None, default: str = "") -> list[str]:
    raw = (value or default).strip()
    return [part.strip() for part in raw.split(",") if part.strip()]


@dataclass(slots=True)
class CloudSettings:
    database_url: str
    jwt_secret: str
    environment: str = "development"
    require_https: bool = True

    secret_key_path: Path = field(default_factory=lambda: Path("./var/cloud.key"))
    evidence_dir: Path = field(default_factory=lambda: Path("./var/cloud-evidence"))

    access_token_ttl_seconds: int = 900
    refresh_token_ttl_seconds: int = 2_592_000
    token_issuer: str = "watchtower-cloud"  # noqa: S105 - the JWT iss claim, not a credential

    # key_id -> secret. More than one entry is the documented rotation window: both verify
    # until the old host is switched over, then the old entry is deleted from configuration.
    service_keys: dict[str, str] = field(default_factory=dict)
    ingest_max_skew_seconds: int = 300

    public_base_url: str = "http://127.0.0.1:8080"
    allowed_origins: tuple[str, ...] = ()
    deep_link_scheme: str = "watchtower"

    # Push. Absent configuration is a supported state: alerts are recorded as failed
    # deliveries with a visible reason rather than pretending to have been sent.
    firebase_project_id: str | None = None
    firebase_service_account_file: Path | None = None
    push_batch_limit: int = 200

    escalate_after_seconds: int = 180
    forced_alerts: tuple[str, ...] = DEFAULT_FORCED_ALERTS

    max_evidence_bytes: int = 20 * 1024 * 1024
    evidence_token_ttl_seconds: int = 600
    # The shared `evidence_assets` rows carry `expires_at` set by the monitoring host; this is
    # the cloud-side default for a relayed copy whose row predates the retention policy.
    evidence_retention_days: int = 30

    login_attempts_per_5_minutes: int = 10
    login_attempts_per_ip_per_minute: int = 30
    refresh_attempts_per_5_minutes: int = 60
    action_attempts_per_minute: int = 60
    evidence_attempts_per_minute: int = 200

    supervision_poll_seconds: float = 5.0

    # Live updates. A server-sent-events channel the app holds open while it is in the
    # foreground; the stream re-reads the shared database on `stream_poll_seconds` rather than
    # trusting a second, in-memory copy of the truth, which is what lets a delivery that happened
    # in the worker process reach a connection served by the API process with no broker at all.
    stream_enabled: bool = True
    stream_poll_seconds: float = 2.0
    stream_heartbeat_seconds: float = 15.0
    stream_max_lifetime_seconds: int = 600
    stream_max_connections: int = 24

    @property
    def is_production(self) -> bool:
        return self.environment.lower() in {"production", "prod", "pilot"}

    @property
    def push_enabled(self) -> bool:
        return bool(self.firebase_project_id and self.firebase_service_account_file)

    @property
    def ingest_enabled(self) -> bool:
        return bool(self.service_keys)

    @property
    def deep_link_base(self) -> str:
        return f"{self.deep_link_scheme}://"


def _service_keys(get) -> dict[str, str]:
    """Machine credentials for the monitoring host.

    Either `CLOUD_SERVICE_KEYS_JSON` (a JSON object) or the single-key pair
    `CLOUD_INGEST_KEY_ID` / `CLOUD_INGEST_KEY_SECRET`. Both are accepted at once; a key id
    appearing in both must carry the same secret, or a rotation is being applied to two hosts
    under one name and the process should not start.
    """
    keys: dict[str, str] = {}
    raw = (get("CLOUD_SERVICE_KEYS_JSON") or "").strip()
    if raw:
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise CloudConfigError(f"CLOUD_SERVICE_KEYS_JSON is not valid JSON: {exc.msg}") from exc
        if not isinstance(parsed, dict):
            raise CloudConfigError("CLOUD_SERVICE_KEYS_JSON must be a JSON object of key_id: secret")
        for key_id, secret in parsed.items():
            keys[str(key_id)] = str(secret)

    single_id = (get("CLOUD_INGEST_KEY_ID") or "").strip()
    single_secret = (get("CLOUD_INGEST_KEY_SECRET") or "").strip()
    if single_id and single_secret:
        existing = keys.get(single_id)
        if existing is not None and existing != single_secret:
            raise CloudConfigError(
                f"key id {single_id!r} has two different secrets configured; rotation must "
                "rename the key, not overwrite it."
            )
        keys[single_id] = single_secret

    for key_id, secret in keys.items():
        if not _KEY_ID_RE.match(key_id):
            raise CloudConfigError(
                f"service key id {key_id!r} must be 1-64 characters of [A-Za-z0-9_.:-]"
            )
        if len(secret) < _MIN_SECRET_LENGTH:
            raise CloudConfigError(
                f"the secret for {key_id!r} is {len(secret)} characters; ingest signatures need "
                "at least 32. Generate one with: "
                'python -c "import secrets; print(secrets.token_urlsafe(48))"'
            )
    return keys


def _checked_url(name: str, value: str, *, allow_loopback_http: bool, environment: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme.lower() == "https":
        return value.rstrip("/")
    if parsed.scheme.lower() == "http" and allow_loopback_http:
        if parsed.hostname not in {"127.0.0.1", "::1", "localhost", "testserver"}:
            raise CloudConfigError(
                f"{name} uses plain http for {parsed.hostname!r}; only loopback is permitted "
                "in development."
            )
        if environment.lower() != "development":
            raise CloudConfigError(
                f"{name} may only use plain http against loopback in the development environment."
            )
        return value.rstrip("/")
    raise CloudConfigError(
        f"{name} must be an https:// URL (mobile proposal section 13); got {parsed.scheme!r}. "
        "A phone carrying security alerts must never talk to the cloud in clear text."
    )


def load_cloud_settings(env: dict[str, str] | None = None) -> CloudSettings:
    env = os.environ if env is None else env
    get = env.get

    database_url = (get("CLOUD_DATABASE_URL") or get("WATCHTOWER_DATABASE_URL") or "").strip()
    if not database_url:
        raise CloudConfigError(
            "CLOUD_DATABASE_URL is required. The cloud service reads the same PostgreSQL "
            "database as the monitoring host; there is no separate mobile schema and no local "
            "fallback."
        )
    if not database_url.startswith(_POSTGRES_SCHEMES):
        raise CloudConfigError(
            "CLOUD_DATABASE_URL must be a PostgreSQL URL. "
            f"Got scheme {database_url.split('://', 1)[0]!r}."
        )

    jwt_secret = (get("CLOUD_JWT_SECRET") or "").strip()
    if len(jwt_secret) < _MIN_SECRET_LENGTH:
        raise CloudConfigError(
            "CLOUD_JWT_SECRET is required and must be at least "
            f"{_MIN_SECRET_LENGTH} characters (got {len(jwt_secret)}). Personnel access tokens "
            "are signed with a key derived from it, so a guessable value lets anyone mint a "
            "session. Generate one with: "
            'python -c "import secrets; print(secrets.token_urlsafe(48))"'
        )

    environment = (get("CLOUD_ENVIRONMENT") or get("WATCHTOWER_ENVIRONMENT") or "development")
    development = environment.lower() == "development"

    public_base_url = _checked_url(
        "CLOUD_PUBLIC_BASE_URL",
        (get("CLOUD_PUBLIC_BASE_URL") or "http://127.0.0.1:8080").strip(),
        allow_loopback_http=development,
        environment=environment,
    )

    service_file = (get("CLOUD_FIREBASE_SERVICE_ACCOUNT_FILE") or "").strip()
    project_id = (get("CLOUD_FIREBASE_PROJECT_ID") or "").strip() or None
    if service_file and project_id is None:
        raise CloudConfigError(
            "CLOUD_FIREBASE_SERVICE_ACCOUNT_FILE is set but CLOUD_FIREBASE_PROJECT_ID is not; "
            "the FCM HTTP v1 endpoint is addressed by project id."
        )

    settings = CloudSettings(
        database_url=database_url,
        jwt_secret=jwt_secret,
        environment=environment,
        require_https=(get("CLOUD_REQUIRE_HTTPS", "0" if development else "1") == "1"),
        secret_key_path=Path(get("CLOUD_SECRET_KEY_PATH", "./var/cloud.key")),
        evidence_dir=Path(get("CLOUD_EVIDENCE_DIR", "./var/cloud-evidence")),
        access_token_ttl_seconds=int(get("CLOUD_ACCESS_TOKEN_TTL_SECONDS", "900")),
        refresh_token_ttl_seconds=int(get("CLOUD_REFRESH_TOKEN_TTL_SECONDS", "2592000")),
        service_keys=_service_keys(get),
        ingest_max_skew_seconds=int(get("CLOUD_INGEST_MAX_SKEW_SECONDS", "300")),
        public_base_url=public_base_url,
        allowed_origins=tuple(_split(get("CLOUD_ALLOWED_ORIGINS"))),
        firebase_project_id=project_id,
        firebase_service_account_file=Path(service_file) if service_file else None,
        escalate_after_seconds=int(get("CLOUD_ESCALATE_AFTER_SECONDS", "180")),
        forced_alerts=tuple(
            _split(get("CLOUD_FORCED_ALERTS"), ",".join(DEFAULT_FORCED_ALERTS))
        ),
        supervision_poll_seconds=float(get("CLOUD_POLL_SECONDS", "5")),
        stream_enabled=(get("CLOUD_STREAM_ENABLED", "1") == "1"),
        stream_poll_seconds=float(get("CLOUD_STREAM_POLL_SECONDS", "2")),
        stream_heartbeat_seconds=float(get("CLOUD_STREAM_HEARTBEAT_SECONDS", "15")),
        stream_max_lifetime_seconds=int(get("CLOUD_STREAM_MAX_LIFETIME_SECONDS", "600")),
        stream_max_connections=int(get("CLOUD_STREAM_MAX_CONNECTIONS", "24")),
    )
    if service_file and not settings.firebase_service_account_file.exists():
        raise CloudConfigError(
            f"CLOUD_FIREBASE_SERVICE_ACCOUNT_FILE points at {service_file!r}, which does not "
            "exist. Push stays configured-off only when the variables are absent entirely."
        )
    _check_stream(settings)
    return settings


def _check_stream(settings: CloudSettings) -> None:
    """A stream cadence that cannot work is refused at startup, not discovered by a phone.

    The lifetime floor matters more than it looks: each connection is one task that wakes every
    poll interval, and a connection that never ends is one that outlives the bearer identity it
    was authorised with. Closing below the access-token TTL is what keeps the answer to "may this
    person still see incident data?" a fresh one, re-asked by the reconnect, instead of a decision
    taken when the connection opened.
    """
    if settings.stream_poll_seconds <= 0:
        raise CloudConfigError("CLOUD_STREAM_POLL_SECONDS must be greater than 0.")
    if settings.stream_heartbeat_seconds <= 0:
        raise CloudConfigError("CLOUD_STREAM_HEARTBEAT_SECONDS must be greater than 0.")
    if settings.stream_max_lifetime_seconds < 60:
        raise CloudConfigError(
            "CLOUD_STREAM_MAX_LIFETIME_SECONDS must be at least 60; a shorter cap than one "
            "minute spends the connection budget on reconnects instead of on alerts."
        )
    if not 1 <= settings.stream_max_connections <= 1024:
        raise CloudConfigError(
            "CLOUD_STREAM_MAX_CONNECTIONS must be between 1 and 1024. Keep it comfortably below "
            "the database pool (`db.build_engine` opens 10 with 20 overflow): a stream borrows a "
            "connection for one read every poll interval, and a cap above the pool turns every "
            "alerting phone into a queue for the connection that serves logins."
        )
    if settings.stream_max_lifetime_seconds >= settings.access_token_ttl_seconds:
        raise CloudConfigError(
            f"CLOUD_STREAM_MAX_LIFETIME_SECONDS ({settings.stream_max_lifetime_seconds}) must be "
            f"shorter than CLOUD_ACCESS_TOKEN_TTL_SECONDS ({settings.access_token_ttl_seconds}): "
            "a stream that outlives its access token keeps sending alerts against permissions "
            "nobody has re-checked since the connection opened."
        )
