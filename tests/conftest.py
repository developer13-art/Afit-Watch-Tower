"""Shared pytest fixtures for the AFIT WATCH TOWER backend.

TEST HARNESS ONLY - read before changing anything here.

`watchtower.config.load_settings()` deliberately rejects any non-PostgreSQL database URL
(proposal section 8.1: PostgreSQL is the primary application database and there is no
implicit local fallback). That rule stays untouched in `src/`. Because `Settings` is a plain
dataclass, a test can build one directly with a `sqlite://` file URL; that is a harness
convenience which exercises the service and API layers without a database server, not a
supported production configuration. `watchtower.models` already carries dialect variants
(`JsonType` falls back to JSON on SQLite), so `Base.metadata.create_all()` works.

No camera hardware and no network service exist in the test environment, so every probe is
monkeypatched (see the `fake_probe` fixture) and the stream supervisor is replaced with an
in-process fake before the application lifespan starts.
"""

from __future__ import annotations

import contextlib
import datetime as dt
import time
import uuid
from pathlib import Path
from types import SimpleNamespace
from typing import TYPE_CHECKING

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from starlette.testclient import TestClient

from watchtower import models as wt_models
# Registers the personnel-mobile tables on the same `Base`; without it `create_all()` below
# silently builds a schema with no `notification_outbox`, and `test_mobile_schema.py` fails.
from watchtower.mobile import models as wt_mobile  # noqa: F401
from watchtower.api.deps import TOKEN_COOKIE
from watchtower.api.routers import cameras as cameras_router
from watchtower.api.routers import incidents as incidents_router
from watchtower.api.routers import live as live_router
from watchtower.config import Settings
from watchtower.db import build_engine, build_sessionmaker
from watchtower.ingest.supervisor import StreamCapacityError, TestCapacityError
from watchtower.ingest.worker import StreamStats
from watchtower.rtsp import probe as rtsp_probe_module
from watchtower.rtsp.parser import ConnectionSpec
from watchtower.security.passwords import hash_password
from watchtower.security.rbac import Principal, bootstrap_access_control, resolve_principal
from watchtower.security.secrets import KeyRing, SecretStore
from watchtower.services.notifications import NotificationService

if TYPE_CHECKING:
    # Annotation only: the cloud service modules stay un-imported at harness load because a test
    # that never touches the personnel API should not pay for its dependencies.
    from watchtower.cloud.config import CloudSettings

TEST_PASSWORD = "tower-test-password"  # 19 chars, above the 12 character minimum
CSRF_HEADER = {"X-Watchtower-Client": "dashboard"}
SECRET_KEY_PATH_ENV = "WATCHTOWER_SECRET_KEY_PATH"


# --------------------------------------------------------------------------- #
# Settings / schema
# --------------------------------------------------------------------------- #


def make_settings(tmp_path: Path, **overrides) -> Settings:
    """A SQLite-backed Settings object for the harness (see module docstring)."""
    values: dict = {
        "database_url": f"sqlite:///{(tmp_path / 'watchtower.db').as_posix()}",
        "secret_key_path": tmp_path / "keyring.json",
        "jwt_secret": "unit-test-master-secret-value",
        "jwt_ttl_minutes": 60,
        "environment": "development",
        "require_https": False,
        "evidence_dir": tmp_path / "evidence",
        # The outbox spool is a crash fallback that writes real files. Left at its default it
        # would point at the repository's own ./var/spool, so one test's spooled alert would
        # be replayed by the next test's forwarder.
        "spool_dir": tmp_path / "spool",
        "max_concurrent_streams": 8,
        "max_concurrent_connection_tests": 2,
        "probe_timeout_seconds": 1,
        "probe_frame_count": 2,
        "probe_sustain_seconds": 0.0,
        "degraded_after_seconds": 4.0,
        "offline_after_seconds": 15.0,
        "reconnecting_grace_seconds": 20.0,
    }
    values.update(overrides)
    return Settings(**values)


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return make_settings(tmp_path)


def ensure_schema(settings: Settings):
    """Create the tables on a throwaway engine (`create_all` is checkfirst=True)."""
    engine = build_engine(settings)
    try:
        wt_models.Base.metadata.create_all(engine)
    finally:
        engine.dispose()


@pytest.fixture
def engine(settings):
    eng = build_engine(settings)
    wt_models.Base.metadata.create_all(eng)
    yield eng
    eng.dispose()


@pytest.fixture
def session_factory(engine):
    return build_sessionmaker(engine)


@pytest.fixture
def db(session_factory) -> Session:
    """A real SQLAlchemy session; tests use real rows, not mocks, for persistence."""
    session = session_factory()
    try:
        yield session
        session.commit()
    finally:
        session.close()


@pytest.fixture
def secret_store(settings) -> SecretStore:
    ring = KeyRing(settings.secret_key_path, create_if_missing=True)
    return SecretStore(ring)


# --------------------------------------------------------------------------- #
# Row factory
# --------------------------------------------------------------------------- #


@pytest.fixture
def seeded(db: Session) -> Session:
    """Access-control catalogue (section 14) committed and ready to use.

    This is the production path - `bootstrap_access_control()` on an empty database, the
    same call the CLI makes. An earlier revision of this harness had to pre-insert the
    `permissions` rows because the function read `permission.id` before flushing; that
    defect is fixed in `src/watchtower/security/rbac.py` and `test_rbac_seeding.py` keeps a
    test on the empty-database path so it cannot come back.
    """
    bootstrap_access_control(db)
    db.commit()
    return db


class Factory:
    """Creates real database rows; nothing here is a mock."""

    def __init__(self, session: Session, secrets: SecretStore) -> None:
        self.session = session
        self.secrets = secrets
        self._counter = 0

    def _next(self) -> int:
        self._counter += 1
        return self._counter

    # -- access control -------------------------------------------------- #

    def group(self, *, code: str | None = None, name: str = "Gate line") -> wt_models.CameraGroup:
        code = code or f"GRP-{self._next():03d}"
        group = wt_models.CameraGroup(code=code, name=name)
        self.session.add(group)
        self.session.flush()
        return group

    def user(
        self,
        *,
        username: str | None = None,
        display_name: str | None = None,
        roles: tuple[str, ...] = ("security_supervisor",),
        camera_group_id: int | None = None,
        password: str = TEST_PASSWORD,
        is_active: bool = True,
        email: str | None = None,
    ) -> wt_models.User:
        username = username or f"user{self._next()}"
        user = wt_models.User(
            username=username,
            display_name=display_name or username.replace(".", " ").title(),
            email=email or f"{username}@example.test",
            password_hash=hash_password(password),
            is_active=is_active,
        )
        self.session.add(user)
        self.session.flush()
        for role_code in roles:
            role = self.session.scalar(select(wt_models.Role).where(wt_models.Role.code == role_code))
            assert role is not None, f"role {role_code!r} is not seeded"
            self.session.add(
                wt_models.UserRole(user_id=user.id, role_id=role.id, camera_group_id=camera_group_id)
            )
        self.session.flush()
        return user

    def principal(self, user: wt_models.User) -> Principal:
        return resolve_principal(self.session, user)

    def grant(
        self, user: wt_models.User, role_code: str, *, camera_group_id: int | None = None
    ) -> wt_models.UserRole:
        """An additional role grant - several grants are what section 14 unions together."""
        role = self.session.scalar(select(wt_models.Role).where(wt_models.Role.code == role_code))
        assert role is not None, f"role {role_code!r} is not seeded"
        assignment = wt_models.UserRole(
            user_id=user.id, role_id=role.id, camera_group_id=camera_group_id
        )
        self.session.add(assignment)
        self.session.flush()
        return assignment

    def policy(
        self,
        *,
        code: str | None = None,
        enabled: bool = True,
        detectors: tuple[str, ...] = ("loitering",),
        severity: str = wt_models.Severity.HIGH.value,
    ) -> wt_models.MonitoringPolicy:
        policy = wt_models.MonitoringPolicy(
            code=code or f"POL-{self._next():03d}",
            name=f"Policy {self._next()}",
            enabled=enabled,
            detector_codes=list(detectors),
            severity=severity,
        )
        self.session.add(policy)
        self.session.flush()
        return policy

    # -- cameras --------------------------------------------------------- #

    def camera(
        self,
        *,
        code: str | None = None,
        display_name: str | None = None,
        host: str = "10.20.0.5",
        port: int = 554,
        stream_path: str = "/cam/realmonitor",
        username: str | None = "admin",
        password: str | None = "sup3r-secret-pw",
        transport: str = "tcp",
        group_id: int | None = None,
        status: str = wt_models.CameraStatus.PENDING_SETUP.value,
        probe_result: str | None = None,
        desired_state: str = "stopped",
        is_registered: bool = False,
        last_frame_at: dt.datetime | None = None,
        policy_id: int | None = None,
        verified_in_vlc: bool = True,
    ) -> wt_models.Camera:
        code = code or f"CAM-{self._next():04d}"
        profile = wt_models.CameraConnectionProfile(
            host=host,
            port=port,
            stream_path=stream_path,
            username=username,
            transport=transport,
            verified_in_vlc=verified_in_vlc,
            last_probe_result=probe_result,
        )
        if password:
            profile.secret_reference = self.seal(password)
        self.session.add(profile)
        self.session.flush()
        camera = wt_models.Camera(
            id=uuid.uuid4(),
            code=code,
            display_name=display_name or f"Camera {code}",
            campus_location="Main gate",
            camera_group_id=group_id,
            connection_profile_id=profile.id,
            monitoring_policy_id=policy_id,
            status=status,
            desired_state=desired_state,
            is_registered=is_registered,
            last_successful_frame_at=last_frame_at,
        )
        self.session.add(camera)
        self.session.flush()
        return camera

    def seal(self, plaintext: str) -> str:
        sealed = self.secrets.seal(plaintext)
        self.session.add(
            wt_models.CameraSecret(
                reference=sealed.reference,
                ciphertext=sealed.ciphertext,
                key_id=sealed.key_id,
            )
        )
        self.session.flush()
        return sealed.reference

    # -- events / incidents --------------------------------------------- #

    def event(
        self,
        camera: wt_models.Camera,
        *,
        category: str = "loitering",
        confidence: float = 0.81,
        status: str = wt_models.EventStatus.NEW.value,
        occurred_at: dt.datetime | None = None,
    ) -> wt_models.DetectionEvent:
        event = wt_models.DetectionEvent(
            camera_id=camera.id,
            category=category,
            confidence=confidence,
            occurred_at=occurred_at or _utc(),
            status=status,
            event_metadata={"zone_id": "z1"},
        )
        self.session.add(event)
        self.session.flush()
        return event

    def incident(
        self,
        camera: wt_models.Camera | None = None,
        *,
        title: str = "Person loitering at the gate",
        category: str = "loitering",
        severity: str = wt_models.Severity.MEDIUM.value,
        status: str = wt_models.IncidentStatus.OPEN.value,
    ) -> wt_models.Incident:
        incident = wt_models.Incident(
            reference=f"INC-SEED-{self._next():04d}",
            title=title,
            category=category,
            severity=severity,
            status=status,
            camera_id=camera.id if camera else None,
            campus_location=camera.campus_location if camera else "Main gate",
            occurred_at=_utc(),
        )
        self.session.add(incident)
        self.session.flush()
        return incident


def _utc() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


@pytest.fixture
def factory(seeded: Session, secret_store: SecretStore) -> Factory:
    return Factory(seeded, secret_store)


# --------------------------------------------------------------------------- #
# Stream supervisor fake
# --------------------------------------------------------------------------- #


class FakeSupervisor:
    """In-process stand-in for `StreamSupervisor`.

    No test in this suite may spawn a real stream worker: there is no camera and no video.
    The registry, the stream ceiling and the connection-test ceiling are the behaviour the
    design promises, so those are what this fake implements.
    """

    def __init__(
        self,
        *,
        max_concurrent_streams: int = 1_000_000,
        max_concurrent_connection_tests: int = 1_000_000,
    ) -> None:
        self.max_streams = max_concurrent_streams
        self.max_tests = max_concurrent_connection_tests
        self.stats_by_camera: dict[str, StreamStats] = {}
        self.ensure_calls: list[str] = []
        self.stop_calls: list[tuple[str, str]] = []
        self.tests_in_flight = 0
        self.test_slot_high_water = 0
        self.frames: dict[str, tuple[float, bytes, float]] = {}
        self._viewers: dict[str, int] = {}

    # activation ---------------------------------------------------------- #

    def ensure(self, camera_id: str, spec: ConnectionSpec, *, restart: bool = False) -> str:
        if camera_id not in self.stats_by_camera:
            if len(self.stats_by_camera) >= self.max_streams:
                raise StreamCapacityError(
                    f"the configured ceiling of {self.max_streams} simultaneous streams "
                    "has been reached"
                )
            self.stats_by_camera[camera_id] = StreamStats(
                camera_id=camera_id,
                state="starting",
                pid=400000 + len(self.stats_by_camera),
                started_at=time.time(),
            )
        self.ensure_calls.append(camera_id)
        return camera_id

    def stop(self, camera_id: str, *, reason: str = "disabled") -> bool:
        self.stop_calls.append((camera_id, reason))
        return self.stats_by_camera.pop(camera_id, None) is not None

    def shutdown(self) -> None:  # pragma: no cover - lifespan teardown hook
        self.stats_by_camera.clear()

    # telemetry ----------------------------------------------------------- #

    def stats(self, camera_id: str) -> StreamStats | None:
        return self.stats_by_camera.get(camera_id)

    def snapshot_all(self) -> dict[str, StreamStats]:
        return dict(self.stats_by_camera)

    def latest_frame(self, camera_id: str):
        return self.frames.get(camera_id)

    def attach_viewer(self, camera_id: str) -> None:
        self._viewers[camera_id] = self._viewers.get(camera_id, 0) + 1

    def detach_viewer(self, camera_id: str) -> None:
        self._viewers[camera_id] = max(0, self._viewers.get(camera_id, 0) - 1)

    def viewers(self, camera_id: str) -> int:
        return self._viewers.get(camera_id, 0)

    def publish_frame(self, camera_id: str, payload: bytes = b"\xff\xd8jpeg", fps: float = 12.0):
        stamp = time.time()
        self.frames[camera_id] = (stamp, payload, fps)
        stats = self.stats_by_camera.setdefault(
            camera_id, StreamStats(camera_id=camera_id, state="online")
        )
        stats.last_frame_at = stamp
        stats.frames_received += 1
        stats.measured_fps = fps
        return stamp

    # connection-test budget ---------------------------------------------- #

    @contextlib.contextmanager
    def acquire_test_slot(self):
        if self.tests_in_flight >= self.max_tests:
            raise TestCapacityError("another connection test is already running on this host")
        self.tests_in_flight += 1
        self.test_slot_high_water = max(self.test_slot_high_water, self.tests_in_flight)
        try:
            yield SimpleNamespace(released=False)
        finally:
            self.tests_in_flight -= 1


@pytest.fixture
def supervisor() -> FakeSupervisor:
    return FakeSupervisor()


# --------------------------------------------------------------------------- #
# Application + HTTP clients
# --------------------------------------------------------------------------- #


@pytest.fixture
def make_app():
    """Build an app, run its lifespan once, and hand back dashboard clients.

    `create_app(..., start_supervision=False)` is what lets a test call
    `SupervisionLoop.cycle()` itself instead of racing a background thread.
    """
    launched: list[tuple[TestClient, object]] = []
    prepared_urls: set[str] = set()

    def _make(settings: Settings, *, supervisor_obj=..., base_url: str = "http://testserver"):
        if settings.database_url not in prepared_urls:
            prepared_urls.add(settings.database_url)
            ensure_schema(settings)
        app = _create_app(settings, start_supervision=False)
        if supervisor_obj is not ...:
            app.state.container.supervisor = supervisor_obj
        client = TestClient(app, base_url=base_url)
        client.__enter__()  # runs the lifespan: engine, container, supervision loop
        launched.append((client, app))
        return SimpleNamespace(app=app, client=client)

    yield _make
    for client, _app in reversed(launched):
        client.__exit__(None, None, None)


def _create_app(settings: Settings, *, start_supervision: bool, analysis=None):
    from watchtower.api.app import create_app

    return create_app(settings, analysis=analysis, start_supervision=start_supervision)


@pytest.fixture
def launched(make_app, settings, supervisor):
    return make_app(settings, supervisor_obj=supervisor)


@pytest.fixture
def app(launched):
    return launched.app


@pytest.fixture
def client(launched) -> TestClient:
    return launched.client


class Dashboard:
    """The dashboard's HTTP behaviour: CSRF header on every write, plus the session cookie.

    Section 16's CSRF defence needs `X-Watchtower-Client: dashboard` on any cookie-authenticated
    state-changing request; this helper makes that impossible to forget in a test.
    """

    def __init__(self, client: TestClient) -> None:
        self.client = client
        self.username: str | None = None

    @staticmethod
    def _headers(extra: dict | None) -> dict:
        headers = dict(CSRF_HEADER)
        headers.update(extra or {})
        return headers

    def login(self, username: str, password: str = TEST_PASSWORD):
        self.username = username
        return self.client.post(
            "/api/auth/login",
            json={"username": username, "password": password},
            headers=self._headers(None),
        )

    def get(self, url, **kwargs):
        return self.client.get(url, **kwargs)

    def post(self, url, **kwargs):
        kwargs["headers"] = self._headers(kwargs.get("headers"))
        return self.client.post(url, **kwargs)

    def patch(self, url, **kwargs):
        kwargs["headers"] = self._headers(kwargs.get("headers"))
        return self.client.patch(url, **kwargs)

    def put(self, url, **kwargs):
        kwargs["headers"] = self._headers(kwargs.get("headers"))
        return self.client.put(url, **kwargs)

    def delete(self, url, **kwargs):
        kwargs["headers"] = self._headers(kwargs.get("headers"))
        return self.client.delete(url, **kwargs)

    def as_(self, username: str, password: str = TEST_PASSWORD) -> Dashboard:
        """A second identity on the same application instance."""
        other = Dashboard(TestClient(self.client.app, base_url=str(self.client.base_url)))
        assert other.login(username, password).status_code == 200
        return other

    def token(self, username: str, password: str = TEST_PASSWORD) -> str:
        """A session token for the same account, for bearer-authenticated API clients.

        The login endpoint only ever sets the cookie; the value is the same signed token,
        so a bearer client can be built from the cookie jar.
        """
        login_client = TestClient(self.client.app, base_url=str(self.client.base_url))
        response = login_client.post(
            "/api/auth/login", json={"username": username, "password": password}
        )
        assert response.status_code == 200, response.text
        token = login_client.cookies.get(TOKEN_COOKIE)
        assert token, "login did not issue a session token"
        return token


@pytest.fixture
def dashboard(client) -> Dashboard:
    return Dashboard(client)


@pytest.fixture
def dashboard_for():
    """Log an existing user into a (possibly second) client of the same app."""

    def _make(client: TestClient, username: str, password: str = TEST_PASSWORD) -> Dashboard:
        actor = Dashboard(client)
        response = actor.login(username, password)
        assert response.status_code == 200, response.text
        return actor

    return _make


@pytest.fixture
def read_audit(db: Session):
    """Read the audit trail the application wrote, oldest row first.

    The request-handling session commits on its own; the harness session is inside a
    transaction of its own (sqlite file database, separate connections), so the read
    happens after a commit to guarantee the app's rows are visible.
    """

    def _read(*, actions: bool = False):
        db.commit()
        rows = db.scalars(select(wt_models.AuditLog).order_by(wt_models.AuditLog.id)).all()
        return [row.action for row in rows] if actions else rows

    return _read


@pytest.fixture
def count_rows(db: Session):
    def _count(model) -> int:
        db.commit()
        return db.scalar(select(func.count()).select_from(model)) or 0

    return _count


@pytest.fixture
def admin(factory: Factory, dashboard: Dashboard) -> SimpleNamespace:
    """A logged-in System Administrator - the default actor for camera workflow tests."""
    user = factory.user(username="admin", roles=("system_administrator",))
    factory.session.commit()
    assert dashboard.login(user.username).status_code == 200
    return SimpleNamespace(user=user, username=user.username, client=dashboard)


@pytest.fixture
def actor(client, factory: Factory, dashboard: Dashboard):
    """Create a user holding exactly the named roles and hand back their dashboard.

    Each identity gets its own cookie jar on the same application instance, so a test can
    ask "what does the auditor see?" and "what does the operator see?" in one breath.
    """

    def _make(
        *roles: str,
        username: str | None = None,
        group_id: int | None = None,
        password: str = TEST_PASSWORD,
    ) -> SimpleNamespace:
        name = username or ("actor." + "-".join(roles) if roles else "actor.anonymous")
        user = factory.user(username=name, roles=roles, camera_group_id=group_id, password=password)
        factory.session.commit()
        return SimpleNamespace(user=user, username=name, client=dashboard.as_(name))

    return _make


@pytest.fixture
def evidence_store(settings, db: Session):
    from watchtower.services.evidence import EvidenceStore

    return EvidenceStore(settings, db)


# --------------------------------------------------------------------------- #
# Probe fakes
# --------------------------------------------------------------------------- #


def outcome(
    result: rtsp_probe_module.ProbeResult,
    *,
    message: str | None = None,
    frames: int = 0,
    fps: float = 12.0,
    width: int = 1920,
    height: int = 1080,
    stage: str = "complete",
) -> rtsp_probe_module.ProbeOutcome:
    return rtsp_probe_module.ProbeOutcome(
        result=result,
        message=message or f"synthetic probe result {result.value}",
        frames_decoded=frames if frames else (30 if result is rtsp_probe_module.ProbeResult.CONNECTED else 0),
        measured_fps=fps,
        width=width,
        height=height,
        elapsed_seconds=0.1,
        stage=stage,
    )


@pytest.fixture
def fake_probe(monkeypatch):
    """Patch `run_probe` everywhere it is reached from an HTTP request.

    `services/cameras.py` looks the function up on the imported module
    (`rtsp_probe.run_probe`), so patching the module attribute is intercepted. A router that
    imported the symbol directly (`from ...rtsp.probe import run_probe`) binds its own name,
    so any module that still owns such an attribute is patched too.
    """

    calls: list[ConnectionSpec] = []

    def _install(result_or_outcome, message: str | None = None):
        def run_probe(spec, **kwargs):
            calls.append(spec)
            if isinstance(result_or_outcome, rtsp_probe_module.ProbeOutcome):
                return result_or_outcome
            return outcome(result_or_outcome, message=message)

        monkeypatch.setattr(rtsp_probe_module, "run_probe", run_probe)
        for module in (cameras_router, live_router, incidents_router):
            if hasattr(module, "run_probe"):
                monkeypatch.setattr(module, "run_probe", run_probe)
        return run_probe

    _install.calls = calls
    _install.outcome = outcome
    return _install


# --------------------------------------------------------------------------- #
# Service-level wiring
# --------------------------------------------------------------------------- #


@pytest.fixture
def camera_service(db: Session, settings, secret_store, supervisor):
    from watchtower.services.cameras import CameraService

    return CameraService(db, settings, secret_store, supervisor)


@pytest.fixture
def notification_service(db: Session, settings) -> NotificationService:
    return NotificationService(db, webhook_url=settings.webhook_url)


# --------------------------------------------------------------------------- #
# Cloud (personnel mobile) service
# --------------------------------------------------------------------------- #
#
# The same harness exception applies as at the top of this file: `load_cloud_settings()` refuses a
# non-PostgreSQL URL, and a test builds `CloudSettings` directly instead. Nothing in `src/` is
# relaxed for this.


INGEST_KEY_ID = "test-host-1"
INGEST_SECRET = "unit-test-ingest-secret-value-abcdef123456"  # 43 chars, above the 32 minimum
CLOUD_JWT_SECRET = "unit-test-cloud-jwt-secret-value-0123456789"
INSTALLATION_ID = "11111111-2222-4333-8444-555555555555"


def make_cloud_settings(tmp_path: Path, **overrides) -> CloudSettings:
    from watchtower.cloud.config import CloudSettings

    values: dict = {
        "database_url": f"sqlite:///{(tmp_path / 'watchtower.db').as_posix()}",
        # A different secret from the console's on purpose: a phone token must not open the
        # console. The harness mirrors the production rule.
        "jwt_secret": CLOUD_JWT_SECRET,
        "environment": "development",
        "require_https": False,
        "secret_key_path": tmp_path / "cloud-keyring.json",
        "evidence_dir": tmp_path / "cloud-evidence",
        "public_base_url": "http://testserver",
        "allowed_origins": ("http://localhost:5173",),
        "service_keys": {INGEST_KEY_ID: INGEST_SECRET},
        "access_token_ttl_seconds": 900,
        "escalate_after_seconds": 180,
        "supervision_poll_seconds": 5.0,
    }
    values.update(overrides)
    return CloudSettings(**values)


@pytest.fixture
def cloud_settings(tmp_path: Path):
    return make_cloud_settings(tmp_path)


@pytest.fixture
def make_cloud_app(engine):
    """Build the cloud app on the harness engine, so `db` and the service see the same rows.

    `session_factory` is injected rather than derived from `CLOUD_DATABASE_URL`: the app must not
    open a second pool against a throwaway file, and `start_worker` stays off so no test races a
    delivery thread. A test that wants a database the app cannot reach passes its own factory, and
    a test that wants to watch a push attempt passes its own `push_sender`.
    """
    from watchtower.cloud.app import create_app

    factory = build_sessionmaker(engine)
    launched: list[TestClient] = []

    def _make(cloud_settings, *, session_factory=None, push_sender=None, **overrides):
        if overrides:
            from dataclasses import replace

            cloud_settings = replace(cloud_settings, **overrides)
        app = create_app(
            cloud_settings,
            session_factory=session_factory or factory,
            start_worker=False,
            push_sender=push_sender,
        )
        client = TestClient(app, base_url="http://testserver")
        client.__enter__()
        launched.append(client)
        return client

    yield _make
    for client in reversed(launched):
        client.__exit__(None, None, None)


@pytest.fixture
def cloud_app(make_cloud_app, cloud_settings):
    return make_cloud_app(cloud_settings)


class Personnel:
    """A handset: bearer token on every call, plus the installation id header.

    Mirrors what the Android app actually sends, so a test that forgets the installation header is
    writing a request the app cannot make.
    """

    def __init__(self, client: TestClient, *, installation_id: str = INSTALLATION_ID) -> None:
        self.client = client
        self.installation_id = installation_id
        self.access_token: str | None = None
        self.refresh_token: str | None = None

    @property
    def headers(self) -> dict[str, str]:
        headers = {"x-installation-id": self.installation_id}
        if self.access_token:
            headers["authorization"] = f"Bearer {self.access_token}"
        return headers

    def login(
        self,
        username: str,
        password: str = TEST_PASSWORD,
        *,
        push_token: str | None = None,
        platform: str = "android",
        installation_id: str | None = None,
    ):
        body = {
            "username": username,
            "password": password,
            "device": {
                "installation_id": installation_id or self.installation_id,
                "platform": platform,
                "push_token": push_token,
                "model": "Test Handset",
            },
        }
        response = self.client.post("/api/v1/auth/login", json=body, headers=self.headers)
        if response.status_code == 200:
            payload = response.json()
            self.access_token = payload["access_token"]
            self.refresh_token = payload["refresh_token"]
        return response

    def get(self, url, **kwargs):
        return self.client.get(url, headers=self.headers, **kwargs)

    def post(self, url, **kwargs):
        return self.client.post(url, headers=self.headers, **kwargs)

    def put(self, url, **kwargs):
        return self.client.put(url, headers=self.headers, **kwargs)

    def patch(self, url, **kwargs):
        return self.client.patch(url, headers=self.headers, **kwargs)

    def delete(self, url, **kwargs):
        return self.client.delete(url, headers=self.headers, **kwargs)


@pytest.fixture
def personnel(cloud_app) -> Personnel:
    return Personnel(cloud_app)


@pytest.fixture
def signed_in(cloud_app, factory):
    """Create a committed account and hand back a signed-in handset for it.

    The commit is not ceremony: the harness session and the request session are separate SQLite
    connections, so an uncommitted user is invisible to the login the test is about to make.
    """

    def _make(
        *roles: str,
        username: str | None = None,
        group_id: int | None = None,
        password: str = TEST_PASSWORD,
        push_token: str | None = "fcm-test-token-value",
        installation_id: str | None = None,
        must_change_password: bool = False,
    ) -> SimpleNamespace:
        name = username or ("handset." + "-".join(roles or ("security_operator",)))
        user = factory.user(username=name, roles=roles or ("security_operator",),
                            camera_group_id=group_id, password=password)
        if must_change_password:
            user.must_change_password = True
        factory.session.commit()
        actor = Personnel(
            cloud_app, installation_id=installation_id or INSTALLATION_ID
        )
        response = actor.login(user.username, password, push_token=push_token)
        assert response.status_code == 200, response.text
        return SimpleNamespace(user=user, actor=actor, response=response, client=cloud_app)

    return _make


@pytest.fixture
def signed_ingest_headers():
    """Produce the four headers a monitoring host puts on a signed call.

    The default nonce is a counter in hex: `x-watchtower-nonce` has to be 16-64 hex characters,
    and a test that replays a request has to be able to ask for the same one twice.
    """
    from watchtower.mobile.signing import ServiceCredentials, build_headers

    credentials = ServiceCredentials(key_id=INGEST_KEY_ID, secret=INGEST_SECRET)
    counter = {"n": 0}

    def _make(path: str, body: bytes, *, method: str = "POST", nonce: str | None = None,
              timestamp: int | None = None, secret: str | None = None, key_id: str | None = None):
        counter["n"] += 1
        used = nonce or f"{counter['n']:016x}"
        creds = ServiceCredentials(
            key_id=key_id or credentials.key_id, secret=secret or credentials.secret
        )
        return build_headers(
            creds, method=method, path=path, body=body, nonce=used, timestamp=timestamp
        )

    return _make


__all__ = [
    "CSRF_HEADER",
    "INGEST_KEY_ID",
    "INGEST_SECRET",
    "INSTALLATION_ID",
    "TEST_PASSWORD",
    "Dashboard",
    "Factory",
    "FakeSupervisor",
    "Personnel",
    "ensure_schema",
    "make_cloud_settings",
    "make_settings",
    "outcome",
]
