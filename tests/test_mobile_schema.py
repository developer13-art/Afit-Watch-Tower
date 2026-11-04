"""The personnel-mobile schema layer: registration, creation and the constraints that matter.

`watchtower.mobile.models` attaches its tables to the same `Base` as the monitoring schema but
is imported from a different module, which is easy to forget. The first test is the guard that
fails when a new process (application, migration environment, dev server) omits the import.
"""

from __future__ import annotations

import datetime as dt
import uuid

import sqlalchemy as sa
import pytest
from sqlalchemy.exc import IntegrityError, StatementError
from sqlalchemy.orm import Session

from watchtower import models as wt_models
from watchtower.mobile import models as mobile

MOBILE_TABLES = (
    "notification_outbox",
    "mobile_devices",
    "refresh_tokens",
    "notification_attempts",
    "incident_acknowledgements",
    "personnel_preferences",
    "ingest_nonces",
    "ingest_records",
    "monitoring_heartbeats",
    "evidence_relay_states",
)


def test_mobile_tables_are_registered_on_the_shared_base():
    missing = [name for name in MOBILE_TABLES if name not in wt_models.Base.metadata.tables]
    assert not missing, f"{missing} are not part of Base.metadata"


def test_mobile_schema_adds_no_core_tables():
    """The mobile layer reuses incidents/cameras/notifications; it must not fork them."""
    core = {"incidents", "cameras", "evidence_assets", "notifications", "users", "camera_groups"}
    declared = {table.name for table in mobile.Base.metadata.sorted_tables}
    assert core <= declared
    # Every core table is declared exactly once; a second class would collide on the name.
    assert len([name for name in declared if name in core]) == len(core)
    assert not {name for name in declared if name.endswith("_mobile")}


def test_create_all_builds_every_mobile_table(engine):
    inspector = sa.inspect(engine)
    present = set(inspector.get_table_names())
    assert set(MOBILE_TABLES) <= present


def test_outbox_state_is_a_varchar_with_the_documented_vocabulary(engine):
    column = wt_models.Base.metadata.tables["notification_outbox"].c.state
    assert isinstance(column.type, mobile.EnumColumn)
    assert {member.value for member in mobile.OutboxState} == {
        "queued", "processing", "delivered", "failed", "dead",
    }


def test_rejects_an_unknown_outbox_state_at_the_database_boundary(db: Session):
    row = mobile.NotificationOutbox(
        idempotency_key="incident:1:created",
        kind="incident.created",
        severity=wt_models.Severity.HIGH.value,
        title="Gate",
        body="Person at the gate",
        payload={},
        evidence_keys=[],
        state="sent",
        next_retry_at=wt_models.utcnow(),
    )
    # A rejected flush poisons the session, so the violation happens inside a savepoint.
    # SQLAlchemy wraps the type decorator's ValueError in StatementError at the boundary.
    with db.begin_nested(), pytest.raises(StatementError, match="not a valid outbox_state"):
        db.add(row)
        db.flush()


def test_idempotency_key_is_unique(db: Session, factory):
    incident = factory.incident()

    def row() -> mobile.NotificationOutbox:
        return mobile.NotificationOutbox(
            idempotency_key=f"incident:{incident.id}:created",
            kind="incident.created",
            severity=wt_models.Severity.HIGH.value,
            title="Gate",
            body="Person at the gate",
            payload={},
            evidence_keys=[],
            state=mobile.OutboxState.QUEUED.value,
            incident_id=incident.id,
            next_retry_at=wt_models.utcnow(),
        )

    db.add(row())
    db.flush()
    with db.begin_nested(), pytest.raises(IntegrityError):
        db.add(row())
        db.flush()


def test_one_acknowledgement_per_incident_and_user(db: Session, factory):
    """The rule the proposal states as 'do not create duplicate records' is a constraint."""
    incident = factory.incident()
    user = factory.user()
    db.add(
        mobile.IncidentAcknowledgement(
            incident_id=incident.id, user_id=user.id, source="mobile"
        )
    )
    db.flush()
    with db.begin_nested(), pytest.raises(IntegrityError):
        db.add(
            mobile.IncidentAcknowledgement(
                incident_id=incident.id, user_id=user.id, source="dashboard"
            )
        )
        db.flush()


def test_two_users_can_acknowledge_the_same_incident(db: Session, factory):
    incident = factory.incident()
    for name in ("first", "second"):
        db.add(
            mobile.IncidentAcknowledgement(
                incident_id=incident.id, user_id=factory.user(username=name).id, source="mobile"
            )
        )
    db.flush()
    assert db.scalar(
        sa.select(sa.func.count()).select_from(mobile.IncidentAcknowledgement)
    ) == 2


def test_a_push_token_is_never_stored_in_the_clear(db: Session, factory, secret_store):
    """`mobile_devices` holds ciphertext plus a fingerprint, and nothing reversible."""
    from watchtower.security.secrets import fingerprint

    user = factory.user()
    token = "d-abcdef1234567890-fcm-registration-token"
    sealed = secret_store.seal(token)
    device = mobile.MobileDevice(
        user_id=user.id,
        installation_id="install-1",
        push_token_ciphertext=sealed.ciphertext,
        push_token_key_id=sealed.key_id,
        push_token_fingerprint=fingerprint(token),
        push_state=mobile.PushState.ACTIVE.value,
    )
    db.add(device)
    db.flush()

    raw = db.scalar(
        sa.select(mobile.MobileDevice.push_token_ciphertext).where(
            mobile.MobileDevice.id == device.id
        )
    )
    assert token.encode() not in raw
    assert device.push_token_fingerprint == fingerprint(token)
    assert secret_store._keys.fernet(sealed.key_id).decrypt(raw).decode() == token


def test_one_device_row_per_installation(db: Session, factory):
    user = factory.user()
    db.add(mobile.MobileDevice(user_id=user.id, installation_id="install-1"))
    db.flush()
    with db.begin_nested(), pytest.raises(IntegrityError):
        db.add(mobile.MobileDevice(user_id=user.id, installation_id="install-1"))
        db.flush()


def test_a_different_user_may_use_the_same_installation_id(db: Session, factory):
    """A shared test handset is two devices, not a conflict."""
    installation = "emulator-5554"
    for name in ("alpha", "beta"):
        db.add(
            mobile.MobileDevice(
                user_id=factory.user(username=name).id, installation_id=installation
            )
        )
    db.flush()


def test_refresh_token_hash_is_unique(db: Session, factory):
    user = factory.user()
    expires = dt.datetime.now(dt.UTC) + dt.timedelta(days=30)
    digest = "a" * 64
    db.add(
        mobile.RefreshToken(
            user_id=user.id, token_hash=digest, family=uuid.uuid4(), expires_at=expires
        )
    )
    db.flush()
    with db.begin_nested(), pytest.raises(IntegrityError):
        db.add(
            mobile.RefreshToken(
                user_id=user.id, token_hash=digest, family=uuid.uuid4(), expires_at=expires
            )
        )
        db.flush()


def test_replay_protection_is_a_persisted_unique_pair(db: Session):
    db.add(mobile.IngestNonce(key_id="mon-1", nonce="n" * 16))
    db.flush()
    with db.begin_nested(), pytest.raises(IntegrityError):
        db.add(mobile.IngestNonce(key_id="mon-1", nonce="n" * 16))
        db.flush()
    # A different key may reuse the same nonce string; the cache is per service credential.
    db.add(mobile.IngestNonce(key_id="mon-2", nonce="n" * 16))
    db.flush()


def test_one_relay_state_per_asset(db: Session, factory):
    camera = factory.camera()
    asset = wt_models.EvidenceAsset(
        incident_id=factory.incident(camera).id,
        camera_id=camera.id,
        kind="snapshot",
        filename="a.jpg",
        storage_key="evidence/a.jpg",
        content_type="image/jpeg",
        byte_size=10,
        sha256="b" * 64,
    )
    db.add(asset)
    db.flush()
    db.add(mobile.EvidenceRelayState(asset_id=asset.id))
    db.flush()
    with db.begin_nested(), pytest.raises(IntegrityError):
        db.add(mobile.EvidenceRelayState(asset_id=asset.id))
        db.flush()


def test_one_preference_row_per_user(db: Session, factory):
    user = factory.user()
    db.add(mobile.PersonnelPreference(user_id=user.id))
    db.flush()
    with db.begin_nested(), pytest.raises(IntegrityError):
        db.add(mobile.PersonnelPreference(user_id=user.id))
        db.flush()


def test_outbox_and_acknowledgement_rows_survive_a_rollback_without_side_effects(
    session_factory,
):
    """Nothing here may write an alert the incident it belongs to did not commit with."""
    from watchtower.mobile import outbox

    with session_factory() as session:
        intent = outbox.EnqueueIntent(
            kind="incident.created",
            severity=wt_models.Severity.HIGH.value,
            title="Gate",
            body="Person at the gate",
            idempotency_key="incident:999999:created",
            payload={},
        )
        outbox.enqueue(session, intent)
        session.rollback()

    with session_factory() as session:
        assert session.scalar(sa.select(mobile.NotificationOutbox)) is None


def test_the_migration_history_is_linear_and_the_cli_can_name_its_head():
    """`check-schema` fails a deployment whose database revision is not the scripts' head.

    That comparison is only meaningful if the history has exactly one head, so it is asserted
    here instead of being discovered on a server where the answer is "cannot tell".
    """
    from alembic.script import ScriptDirectory

    from watchtower.cli.main import _alembic_config, _scripts_head

    head, branches = _scripts_head()
    assert branches is None, f"the migration history branched: {branches}"
    assert head is not None

    script = ScriptDirectory.from_config(_alembic_config())
    assert script.get_heads() == [head]
    walked = [revision.revision for revision in script.walk_revisions()]
    assert len(walked) == len(set(walked)), "a revision id is used twice"
    assert walked == sorted(walked, reverse=True), "the chain is not in file order"
