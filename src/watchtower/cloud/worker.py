"""The cloud worker: dispatch what was queued, and escalate what nobody picked up.

The API process writes rows and answers; this loop is the only thing that talks to FCM. The split
is the whole point of the two-phase design - a phone's `POST /acknowledge` must not wait on a
round trip to Google, and an ingest call must not hold a database transaction open across one.

One thread, two jobs per tick:

  * hand every `pending` mobile notification to the push sender (`cloud.delivery`);
  * look for critical incidents that are still open and still unacknowledged past the deadline,
    and queue a re-page to a wider role.

Both are idempotent, so a second worker process - or a restart in the middle of a batch - widens
the audience at most once per stage rather than multiplying it. The unique dedupe key on
`notifications` is the enforcement; this module only asks for the stage numbers that key needs.

Either job can run alone. A hosting platform that gives one process to the API and another to
background work may still want delivery and escalation apart, because they fail differently: a
push sender that keeps erroring is a Google/Firebase problem, while an escalation sweep that keeps
erroring is a role-model or query problem, and restarting only the one that is faulty keeps alerts
flowing. `jobs` selects which of the two a tick performs; the default is both, which is what the
served process and every existing caller use.
"""

from __future__ import annotations

import datetime as dt
import logging
import threading
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from ..mobile.models import IncidentAcknowledgement
from ..models import Incident, Notification, NotificationChannel, NotificationState, Severity
from ..models import utcnow
from ..security.secrets import redact
from .deps import CloudContainer
from .delivery import dispatch_pushes, enqueue_alert
from .targeting import AlertIntent
from .views import OPEN_STATUSES

LOGGER = logging.getLogger("watchtower.cloud.worker")

ESCALATION_KIND = "incident.escalated"

# Critical, unacknowledged, past the deadline: page the supervisors. Still unacknowledged after
# another interval: tell the administrators. Beyond that the alert has reached everybody the
# system knows how to reach, and a third re-page would be noise rather than escalation.
#
# Each stage says whether it demands an in-app action. `security_supervisor` holds
# `incident.acknowledge`, so a page to them can be answered by taking the incident.
# `system_administrator` does not: an alert marked "requires action" is filtered away from anyone
# who cannot act on it, so an actionable page to an administrator would page nobody and the
# escalation would silently do nothing. The second stage is therefore an accountability notice -
# "this incident has no owner" - which is what an administrator can actually resolve.
ESCALATION_STAGES: tuple[tuple[tuple[str, ...], bool], ...] = (
    (("security_supervisor",), True),
    (("system_administrator",), False),
)
MAX_ESCALATION_STAGES = len(ESCALATION_STAGES)

# The two jobs, addressable by name so a deployment can run them in separate processes. The names
# are the CLI's `--jobs` vocabulary; keeping them as constants means a typo in a start command is
# refused at startup instead of silently becoming a worker that does nothing.
DELIVERY = "delivery"
ESCALATION = "escalation"
JOB_NAMES: tuple[str, ...] = (DELIVERY, ESCALATION)
ALL_JOBS: frozenset[str] = frozenset(JOB_NAMES)

BACKOFF_AFTER_CONSECUTIVE_FAILURES = 3
MAX_IDLE_SECONDS = 30.0


def select_jobs(jobs: str | Iterable[str] | None) -> frozenset[str]:
    """Normalise a job selection, refusing anything that would make a worker do nothing.

    `None` means every job - the default every existing caller relies on. A bare name, a list of
    names and a comma-separated string all select the same set, because the value arrives from
    three different places (a Python caller, an argparse `choices` list, a platform environment
    variable) and none of them should need to know which form the loop prefers.
    """
    if jobs is None:
        return ALL_JOBS
    if isinstance(jobs, str):
        chosen = frozenset(part.strip() for part in jobs.split(",") if part.strip())
    else:
        chosen = frozenset(str(job).strip() for job in jobs if str(job).strip())
    unknown = sorted(chosen - ALL_JOBS)
    if unknown:
        raise ValueError(
            f"unknown worker job(s): {', '.join(unknown)}; choose from {', '.join(JOB_NAMES)}"
        )
    if not chosen:
        raise ValueError(f"a worker needs at least one job: {', '.join(JOB_NAMES)}")
    return chosen


def _as_utc(value: dt.datetime) -> dt.datetime:
    return value if value.tzinfo else value.replace(tzinfo=dt.UTC)


@dataclass(slots=True)
class TickReport:
    """What one pass of the worker did, in the words the operator needs."""

    dispatched: dict[str, Any] = field(default_factory=dict)
    escalated: list[int] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "dispatch": dict(self.dispatched),
            "escalated_incidents": list(self.escalated),
            "errors": list(self.errors),
        }


def eligible_for_escalation(
    session: Session, settings, *, now: dt.datetime | None = None, limit: int = 20
) -> list[tuple[Incident, int]]:
    """Open, unacknowledged critical incidents and the stage the next re-page should be.

    A stage of 0 means nothing has been escalated yet; 1 means the supervisors have already been
    paged once. A pair at or beyond `MAX_ESCALATION_STAGES` is not returned: the escalation has
    gone as wide as the role model allows, and repeating it would train people to ignore it.
    """
    moment = _as_utc(now or utcnow())
    deadline = moment - dt.timedelta(seconds=max(int(settings.escalate_after_seconds), 30))

    delivered = (NotificationState.PENDING.value, NotificationState.DELIVERED.value)
    incident_ids = session.execute(
        select(Notification.incident_id)
        .where(
            Notification.channel == NotificationChannel.MOBILE_PUSH.value,
            Notification.state.in_(delivered),
            Notification.severity == Severity.CRITICAL.value,
            Notification.incident_id.is_not(None),
            Notification.created_at <= deadline,
        )
        .group_by(Notification.incident_id)
        .limit(limit * 4)
    ).all()

    out: list[tuple[Incident, int]] = []
    for (incident_id,) in incident_ids:
        incident = session.get(Incident, incident_id)
        if incident is None or incident.status not in OPEN_STATUSES:
            continue
        acknowledged = session.scalar(
            select(func.count())
            .select_from(IncidentAcknowledgement)
            .where(IncidentAcknowledgement.incident_id == incident_id)
        )
        if int(acknowledged or 0) > 0:
            # Somebody has taken responsibility. The screen that shows "unacknowledged" now shows
            # their name, which is the outcome the escalation was meant to produce.
            continue
        # Rows are created per recipient, so the stage count comes from the distinct dedupe keys -
        # how many different re-pages exist - not from how many people each one reached.
        stages = {
            str(key).rsplit(":", 1)[-1]
            for (key,) in session.execute(
                select(Notification.dedupe_key)
                .where(
                    Notification.incident_id == incident_id,
                    Notification.kind == ESCALATION_KIND,
                    Notification.channel == NotificationChannel.MOBILE_PUSH.value,
                )
            ).all()
        }
        stage = 0
        while f"escalated-{stage + 1}" in stages and stage < MAX_ESCALATION_STAGES:
            stage += 1
        if stage >= MAX_ESCALATION_STAGES:
            continue
        out.append((incident, stage))
        if len(out) >= limit:
            break
    return out


def escalation_intent(incident: Incident, stage: int) -> AlertIntent:
    roles, demands_action = ESCALATION_STAGES[min(stage, MAX_ESCALATION_STAGES - 1)]
    ask = (
        "Acknowledge it and record who is responding."
        if demands_action
        else "This reports that nobody has responded, for the person who can assign one."
    )
    return AlertIntent(
        kind=ESCALATION_KIND,
        severity=Severity.CRITICAL.value,
        title=f"Unacknowledged: {incident.title}"[:200],
        body=(
            f"{incident.reference} is still open and nobody has acknowledged it "
            f"{max(int(stage), 0) + 1} interval(s) after the first alert. "
            f"{ask} It is a reminder about an existing incident, not a new finding."
        )[:2000],
        incident_id=incident.id,
        camera_id=incident.camera_id,
        event_id=incident.origin_event_id,
        requires_action=demands_action,
        role_override=roles,
        stage=f"escalated-{stage + 1}",
    )


def escalate_once(
    session: Session, settings, *, now: dt.datetime | None = None
) -> list[dict[str, Any]]:
    """Queue the re-pages that are due. Returns one entry per incident escalated."""
    results: list[dict[str, Any]] = []
    for incident, stage in eligible_for_escalation(session, settings, now=now):
        intent = escalation_intent(incident, stage)
        report = enqueue_alert(session, settings, intent)
        results.append(
            {
                "incident_id": incident.id,
                "reference": incident.reference,
                "stage": intent.stage,
                "roles": list(intent.role_override or ()),
                **report.as_dict(),
            }
        )
        LOGGER.info(
            "escalated incident %s to %s (stage %s): %s notification(s)",
            incident.reference,
            ",".join(intent.role_override or ()),
            intent.stage,
            report.created,
        )
    return results


def run_once(
    session: Session,
    container: CloudContainer,
    *,
    now: dt.datetime | None = None,
    jobs: str | Iterable[str] | None = None,
) -> TickReport:
    """The selected jobs, in one transaction each, on the session the caller already opened.

    Delivery runs first when both are selected: an escalation this tick only reaches a phone on
    the next one, which is the right ordering anyway - a re-page is queued, not sent, so a worker
    that dispatches before escalating never holds a fresh alert behind a stale batch.
    """
    chosen = select_jobs(jobs)
    report = TickReport()
    settings = container.settings
    if DELIVERY in chosen:
        try:
            dispatch = dispatch_pushes(session, container, limit=settings.push_batch_limit)
            report.dispatched = dispatch.as_dict()
            session.commit()
        except Exception as exc:  # noqa: BLE001 - one bad batch must not stop the other job
            session.rollback()
            report.errors.append(f"dispatch: {redact(str(exc))[:200]}")
            LOGGER.error("push dispatch failed: %s", redact(str(exc)))
    if ESCALATION in chosen:
        try:
            report.escalated = [
                str(item["reference"]) for item in escalate_once(session, settings, now=now)
            ]
            session.commit()
        except Exception as exc:  # noqa: BLE001 - an escalation fault still leaves delivery running
            session.rollback()
            report.errors.append(f"escalation: {redact(str(exc))[:200]}")
            LOGGER.error("escalation sweep failed: %s", redact(str(exc)))
    return report


class CloudWorker:
    """The loop. `start()` is for the served process; `run_once()` is for a test."""

    def __init__(
        self,
        settings,
        session_factory: sessionmaker[Session],
        container: CloudContainer,
        *,
        idle_seconds: float = 2.0,
        jobs: str | Iterable[str] | None = None,
    ) -> None:
        self._settings = settings
        self._session_factory = session_factory
        self._container = container
        self._idle_seconds = max(float(idle_seconds), 0.25)
        self.jobs = select_jobs(jobs)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.consecutive_failures = 0
        self.ticks = 0

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._loop, name="watchtower-cloud-worker", daemon=True
        )
        self._thread.start()
        LOGGER.info(
            "cloud worker started: jobs %s, push %s%s",
            ",".join(job for job in JOB_NAMES if job in self.jobs),
            "live" if self._container.push.configured else "not delivering",
            ""
            if ESCALATION not in self.jobs
            else f", escalation every {self._settings.escalate_after_seconds}s",
        )

    def stop(self, *, timeout: float = 5.0) -> None:
        self._stop.set()
        thread = self._thread
        self._thread = None
        if thread is not None and thread.is_alive():
            thread.join(timeout=timeout)

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def _loop(self) -> None:
        # One session per tick, not one for the life of the thread: a pooled connection held for
        # hours is how a Neon idle timeout becomes a crash at 3 a.m.
        while not self._stop.is_set():
            report = self._tick()
            self._stop.wait(self._next_sleep(report))

    def _tick(self) -> TickReport | None:
        session = self._session_factory()
        try:
            report = run_once(session, self._container, jobs=self.jobs)
            self.ticks += 1
            self.consecutive_failures = 0 if not report.errors else self.consecutive_failures + 1
            return report
        except Exception as exc:  # noqa: BLE001 - a dead database must not end the process
            session.rollback()
            self.consecutive_failures += 1
            LOGGER.error("worker tick failed: %s", redact(str(exc)))
            return None
        finally:
            session.close()

    def _next_sleep(self, report: TickReport | None) -> float:
        if self.consecutive_failures >= BACKOFF_AFTER_CONSECUTIVE_FAILURES:
            return min(
                self._idle_seconds * (2 ** min(self.consecutive_failures, 6)), MAX_IDLE_SECONDS
            )
        busy = report is not None and bool(
            report.dispatched.get("devices_targeted") or report.escalated
        )
        return self._idle_seconds if busy else min(self._idle_seconds * 2, MAX_IDLE_SECONDS)


def build_worker(
    container: CloudContainer, *, jobs: str | Iterable[str] | None = None
) -> CloudWorker | None:
    session_factory = container.session_factory
    if session_factory is None:
        LOGGER.warning("no session factory on the container; the worker stays stopped")
        return None
    return CloudWorker(container.settings, session_factory, container, jobs=jobs)
