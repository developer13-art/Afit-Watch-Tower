"""Turning an alert into rows, and rows into push attempts.

Two steps, deliberately separate:

  * `enqueue_alert()` writes `notifications` rows inside the caller's transaction, alongside the
    incident it is about. Nothing network-shaped happens here, so an ingest request never holds
    a database transaction open across a call to Google.
  * `dispatch_pushes()` is run by the cloud worker a moment later. It creates one
    `notification_attempts` row per device send, records exactly what FCM said, and moves the
    notification to `delivered` or `failed`.

The states mean what they say. `delivered` here means FCM accepted the message, which is not the
same claim as a human having seen it, and the vocabulary in the contract
(`queued -> submitted -> accepted_by_fcm -> opened -> acknowledged`) keeps those apart on the way
out as well.
"""

from __future__ import annotations

import datetime as dt
import logging
from dataclasses import dataclass, field

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..mobile.models import AttemptState, NotificationAttempt
from ..models import Notification, NotificationChannel, NotificationState, utcnow
from . import devices as device_store
from .deps import CloudContainer
from .targeting import AlertIntent, preferences_for, resolve_recipients

LOGGER = logging.getLogger("watchtower.cloud.delivery")

# How many times one notification is handed to Google before the worker stops trying. A retryable
# answer (429, 5xx, a socket that closed) is not a failure the recipient should be told about on
# the first pass, but it is not an infinite loop either: after this many attempts the row is
# marked failed and the attempt table holds the whole story.
MAX_SEND_ATTEMPTS = 3


@dataclass(slots=True)
class EnqueueReport:
    created: int = 0
    suppressed: int = 0
    duplicates: int = 0
    devices_targeted: int = 0
    notification_ids: list[int] = field(default_factory=list)
    reasons: dict[str, int] = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "notifications_created": self.created,
            "notifications_suppressed": self.suppressed,
            "duplicate_recipients": self.duplicates,
            "devices_targeted": self.devices_targeted,
            "suppression_reasons": dict(self.reasons),
        }


@dataclass(slots=True)
class DispatchReport:
    attempted: int = 0
    accepted: int = 0
    failed: int = 0
    retried: int = 0
    devices_invalidated: int = 0
    without_device: int = 0
    in_app_only: int = 0
    detail: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "devices_targeted": self.attempted,
            "accepted_by_fcm": self.accepted,
            "failed": self.failed,
            "scheduled_for_retry": self.retried,
            "devices_invalidated": self.devices_invalidated,
            "recipients_without_device": self.without_device,
            "recorded_in_app_only": self.in_app_only,
        }


def dedupe_key(intent: AlertIntent) -> str:
    subject = (
        f"incident:{intent.incident_id}"
        if intent.incident_id is not None
        else f"event:{intent.event_id}"
        if intent.event_id is not None
        else f"camera:{intent.camera_id}"
    )
    stage = f":{intent.stage}" if intent.stage else ""
    return f"{intent.kind}:{subject}{stage}"[:160]


def enqueue_alert(
    session: Session,
    settings,
    intent: AlertIntent,
    *,
    now: dt.datetime | None = None,
    exclude_user_ids: set[int] | None = None,
) -> EnqueueReport:
    """One `mobile_push` row per eligible recipient. Durable before anything is sent."""
    report = EnqueueReport()
    targets = resolve_recipients(
        session, settings, intent, now=now, exclude_user_ids=exclude_user_ids
    )
    key = dedupe_key(intent)

    for target in targets:
        if not target.deliver:
            if _existing(session, key, target.user.id) is not None:
                report.duplicates += 1
                continue
            session.add(
                Notification(
                    kind=intent.kind[:48],
                    title=intent.title[:200],
                    body=intent.body,
                    severity=intent.severity,
                    channel=NotificationChannel.MOBILE_PUSH.value,
                    state=NotificationState.SUPPRESSED.value,
                    dedupe_key=key,
                    camera_id=intent.camera_id,
                    incident_id=intent.incident_id,
                    event_id=intent.event_id,
                    recipient_id=target.user.id,
                    failure_reason=(target.reason or "suppressed")[:256],
                )
            )
            report.suppressed += 1
            report.reasons[target.reason or "suppressed"] = (
                report.reasons.get(target.reason or "suppressed", 0) + 1
            )
            continue

        # Two different questions, and conflating them is what hides alerts from a phone that has
        # no push channel. Is there a handset this person could read the alert on - that is what
        # decides whether the row is recorded. Can any handset be paged - only `targetable` answers
        # that, and dispatch consults it again when it sends.
        if not device_store.registered(session, [target.user.id]):
            # No handset has ever signed in as this person: there is no screen that could show the
            # alert and no token to page, so no row is invented for them.
            continue

        if _existing(session, key, target.user.id) is not None:
            report.duplicates += 1
            continue

        # A savepoint, not the caller's transaction: the unique
        # (dedupe_key, recipient_id, channel) constraint is the answer to a re-delivered ingest
        # call, and the rollback it forces must discard only this row - never the incident the
        # same transaction is creating.
        try:
            with session.begin_nested():
                row = Notification(
                    kind=intent.kind[:48],
                    title=intent.title[:200],
                    body=intent.body,
                    severity=intent.severity,
                    channel=NotificationChannel.MOBILE_PUSH.value,
                    state=NotificationState.PENDING.value,
                    dedupe_key=key,
                    camera_id=intent.camera_id,
                    incident_id=intent.incident_id,
                    event_id=intent.event_id,
                    recipient_id=target.user.id,
                )
                session.add(row)
            report.created += 1
            # Push-capable handsets only: `devices_targeted` is the number of sends this alert can
            # actually produce, not the number of phones the person owns.
            report.devices_targeted += len(device_store.targetable(session, [target.user.id]))
            if row.id is not None:
                report.notification_ids.append(int(row.id))
        except IntegrityError:
            report.duplicates += 1
            continue

    return report


def _existing(session: Session, key: str, user_id: int) -> Notification | None:
    return session.scalar(
        select(Notification).where(
            Notification.dedupe_key == key,
            Notification.recipient_id == user_id,
            Notification.channel == NotificationChannel.MOBILE_PUSH.value,
        )
    )


def sound_for(session: Session, settings, note: Notification) -> str:
    """How loudly this person asked to be alerted, unless the service says this may not be quiet.

    `silent` is a real preference and is honoured by leaving the sound off the Android
    notification block; `alarm` and `default` both mean "the channel's own sound", because a
    ringtone is a property of the handset channel the app created, not something this service can
    choose per message. A forced alert ignores the preference exactly the way
    `targeting.apply_preferences()` ignores it when deciding whether to send at all.
    """
    preference = preferences_for(session, note.recipient_id) if note.recipient_id else None
    sound = (preference.sound if preference else "default") or "default"
    forced = set(settings.forced_alerts)
    return "default" if note.severity in forced or note.kind in forced else sound


def pending_notifications(session: Session, *, limit: int = 50) -> list[Notification]:
    return list(
        session.scalars(
            select(Notification)
            .where(
                Notification.channel == NotificationChannel.MOBILE_PUSH.value,
                Notification.state == NotificationState.PENDING.value,
            )
            .order_by(Notification.created_at)
            .limit(limit)
        )
    )


def dispatch_pushes(
    session: Session,
    container: CloudContainer,
    *,
    notifications: list[Notification] | None = None,
    limit: int = 50,
) -> DispatchReport:
    """Send what has not been sent. Every outcome is written down, including the bad ones."""
    report = DispatchReport()
    if notifications is None:
        notifications = pending_notifications(session, limit=limit)
    if not notifications:
        return report

    settings = container.settings
    for note in notifications:
        recipients = device_store.targetable(
            session, [note.recipient_id] if note.recipient_id else []
        )
        if not recipients:
            if device_store.registered(session, [note.recipient_id] if note.recipient_id else []):
                # The handset can show the alert but cannot be woken for it - no FCM token, which is
                # every handset on a build with no Firebase project. The row is the delivery, and it
                # is recorded as suppressed rather than failed because nothing was attempted and
                # nothing broke. The officer's queue and badge still count it.
                note.state = NotificationState.SUPPRESSED.value
                note.failure_reason = "in_app_only"
                report.in_app_only += 1
                continue
            note.state = NotificationState.FAILED.value
            note.failure_reason = "no_active_device"
            report.without_device += 1
            continue

        # The preference belongs to the person, so it is read once per alert, not per handset.
        sound = sound_for(session, settings, note)

        for device in recipients:
            # The ordinal is part of the attempt's idempotency key. Without it the unique
            # (notification, device, key) index would reject the second row of a retry, which
            # is the one case a retry exists to record.
            ordinal = _attempt_count(session, note.id, device.id) + 1
            token = device_store.reveal_token(container, device)
            if not token:
                _record_attempt(
                    session,
                    note,
                    device,
                    ordinal=ordinal,
                    outcome_state=AttemptState.FAILED.value,
                    error_code="token_unavailable",
                    failure_reason="The stored push token could not be decrypted.",
                )
                device_store.mark_invalid(session, device, "token_unavailable")
                report.attempted += 1
                report.failed += 1
                report.devices_invalidated += 1
                if note.state != NotificationState.DELIVERED.value:
                    note.state = NotificationState.FAILED.value
                    note.failure_reason = "token_unavailable"
                continue

            data = push_data(session, note, settings, notification_id=note.id, device_id=device.id)
            outcome = container.push.send(
                token, title=note.title, body=note.body, data=data, sound=sound
            )
            report.attempted += 1
            if outcome.ok:
                report.accepted += 1
                note.state = NotificationState.DELIVERED.value
                note.delivered_at = utcnow()
                note.failure_reason = None
                _record_attempt(
                    session,
                    note,
                    device,
                    ordinal=ordinal,
                    outcome_state=AttemptState.ACCEPTED.value,
                    provider_message_id=outcome.provider_message_id,
                )
            else:
                # One device failing does not fail the alert for the recipient's other phones;
                # the notification only reports `failed` when nothing at all was accepted.
                _record_attempt(
                    session,
                    note,
                    device,
                    ordinal=ordinal,
                    outcome_state=AttemptState.FAILED.value,
                    error_code=outcome.error_code,
                    failure_reason=outcome.failure_reason,
                )
                if outcome.token_is_dead:
                    device_store.mark_invalid(session, device, outcome.error_code or "invalid")
                    report.devices_invalidated += 1
                if outcome.retryable and ordinal < MAX_SEND_ATTEMPTS:
                    # Google said "try later" or the network moved. The row stays queued and the
                    # next pass sends it; the attempt above is the record that this one happened.
                    report.retried += 1
                    report.detail.append(f"notification {note.id}: retry after attempt {ordinal}")
                    continue
                report.failed += 1
                if note.state != NotificationState.DELIVERED.value:
                    reason = outcome.failure_reason or outcome.error_code or "failed"
                    note.state = NotificationState.FAILED.value
                    note.failure_reason = reason[:256]
            device_store.touch(session, device)

    session.flush()
    return report


def push_data(
    session: Session, note: Notification, settings, *, notification_id: int, device_id: int
) -> dict[str, str]:
    """The push payload. Fields the contract lists, and nothing that helps a bystander.

    No incident summary, no evidence URL, no camera credential and no tactical detail: a push
    traverses Google's servers and is readable on a locked screen.
    """
    from ..models import Camera

    camera_name = None
    if note.camera_id is not None:
        camera = session.get(Camera, note.camera_id)
        camera_name = camera.display_name if camera else None
    data = {
        "notification_id": str(notification_id),
        "device_id": str(device_id),
        "kind": note.kind,
        "severity": note.severity,
        "title": note.title,
    }
    if note.incident_id is not None:
        data["incident_id"] = str(note.incident_id)
        data["deep_link"] = f"{settings.deep_link_base}incidents/{note.incident_id}"
    if camera_name:
        data["camera_name"] = camera_name
    return data


def _attempt_count(session: Session, notification_id: int, device_id: int) -> int:
    return int(
        session.scalar(
            select(func.count())
            .select_from(NotificationAttempt)
            .where(
                NotificationAttempt.notification_id == notification_id,
                NotificationAttempt.device_id == device_id,
            )
        )
        or 0
    )


def _record_attempt(
    session: Session,
    note: Notification,
    device,
    *,
    ordinal: int,
    outcome_state: str,
    provider_message_id: str | None = None,
    error_code: str | None = None,
    failure_reason: str | None = None,
) -> NotificationAttempt:
    now = utcnow()
    attempt = NotificationAttempt(
        notification_id=note.id,
        device_id=device.id,
        provider=device.push_provider,
        provider_message_id=provider_message_id,
        state=outcome_state,
        idempotency_key=f"push:{note.id}:{device.id}:{ordinal}:{note.dedupe_key}"[:160],
        requested_at=now,
        accepted_at=now if outcome_state == AttemptState.ACCEPTED.value else None,
        failed_at=now if outcome_state == AttemptState.FAILED.value else None,
        error_code=(error_code or "")[:64] or None,
        failure_reason=(failure_reason or "")[:256] or None,
    )
    session.add(attempt)
    session.flush()
    return attempt
