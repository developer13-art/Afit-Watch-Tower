"""The operational report (proposal sections 18 and 21).

A report number is the kind of figure somebody is eventually asked to defend, so the three things
this suite pins down are: the window cuts at both ends, every chart is built from the same rows the
counters above it counted, and a chart that cannot show the whole window says so instead of quietly
thinning the sample.
"""

from __future__ import annotations

import datetime as dt

ENDPOINT = "/api/admin/reports/operations"


def report(admin, *, since=None, until=None) -> dict:
    params = {}
    if since is not None:
        params["since"] = since.isoformat()
    if until is not None:
        params["until"] = until.isoformat()
    response = admin.client.get(ENDPOINT, params=params)
    assert response.status_code == 200, response.text
    return response.json()


def stamp_at(days_ago: int, now: dt.datetime) -> dt.datetime:
    """Midday, `days_ago` days back. Midday keeps every case clear of the midnight boundary the day
    buckets are made of, so a failure below means a grouping bug and not a slow test run."""
    return (now - dt.timedelta(days=days_ago)).replace(hour=12, minute=0, second=0, microsecond=0)


def test_the_window_excludes_records_on_either_side_of_it(factory, admin) -> None:
    now = dt.datetime.now(dt.UTC)
    camera = factory.camera()
    factory.event(camera, occurred_at=stamp_at(2, now))
    factory.event(camera, occurred_at=stamp_at(40, now))
    inside = factory.incident(camera, severity="high")
    inside.created_at = stamp_at(2, now)
    outside = factory.incident(camera, severity="critical")
    outside.created_at = stamp_at(40, now)
    factory.session.commit()

    payload = report(admin, since=stamp_at(10, now), until=now)
    assert payload["candidate_events"] == 1
    assert payload["incidents_raised"] == 1
    assert [row["count"] for row in payload["incidents_by_severity"]] == [0, 1, 0, 0]
    assert payload["window_start"] == stamp_at(10, now).isoformat()


def test_the_severity_buckets_are_zero_filled_and_sum_to_the_incidents_counted(factory, admin) -> None:
    now = dt.datetime.now(dt.UTC)
    camera = factory.camera()
    for severity, days_ago in (("critical", 1), ("critical", 2), ("low", 3)):
        row = factory.incident(camera, severity=severity)
        row.created_at = stamp_at(days_ago, now)
    factory.session.commit()

    payload = report(admin, since=stamp_at(5, now), until=now)
    buckets = {row["severity"]: row["count"] for row in payload["incidents_by_severity"]}
    assert buckets == {"critical": 2, "high": 0, "medium": 0, "low": 1}
    assert sum(buckets.values()) == payload["incidents_raised"]


def test_the_trend_draws_a_bucket_for_every_day_including_the_quiet_ones(factory, admin) -> None:
    now = dt.datetime.now(dt.UTC)
    camera = factory.camera()
    factory.event(camera, occurred_at=stamp_at(3, now))
    factory.event(camera, occurred_at=stamp_at(3, now))
    factory.event(camera, occurred_at=stamp_at(1, now))
    incident = factory.incident(camera)
    incident.created_at = stamp_at(1, now)
    factory.session.commit()

    trend = report(admin, since=stamp_at(4, now), until=now)["daily_trend"]
    assert trend["truncated"] is False
    assert trend["excluded_days"] == 0
    assert len(trend["days"]) == 5
    days = {row["day"]: row for row in trend["days"]}
    quiet = (now.date() - dt.timedelta(days=2)).isoformat()
    assert days[quiet] == {"day": quiet, "detections": 0, "incidents": 0}
    assert sum(row["detections"] for row in trend["days"]) == 3
    assert sum(row["incidents"] for row in trend["days"]) == 1


def test_a_window_wider_than_the_chart_cap_keeps_the_newest_days_and_admits_what_it_dropped(
    factory, admin
) -> None:
    now = dt.datetime.now(dt.UTC)
    camera = factory.camera()
    factory.event(camera, occurred_at=stamp_at(180, now))
    factory.event(camera, occurred_at=stamp_at(5, now))
    factory.session.commit()

    payload = report(admin, since=stamp_at(180, now), until=now)
    trend = payload["daily_trend"]
    assert len(trend["days"]) == 90
    assert trend["truncated"] is True
    assert trend["excluded_days"] == 91
    # The counter still counts the whole window; only the chart is capped, which is why the screen
    # has to be able to say the two differ.
    assert payload["candidate_events"] == 2
    assert sum(row["detections"] for row in trend["days"]) == 1


def test_the_busiest_cameras_are_ranked_and_only_five_are_listed(factory, admin) -> None:
    now = dt.datetime.now(dt.UTC)
    cameras = [factory.camera(code=f"CAM-{letter}") for letter in "ABCDE"]
    for index, camera in enumerate(cameras):
        for _ in range(6 - index):
            factory.event(camera, occurred_at=stamp_at(1, now))
    quiet = factory.camera(code="CAM-Z")
    factory.event(quiet, occurred_at=stamp_at(1, now))
    busiest = factory.incident(cameras[0])
    busiest.created_at = stamp_at(1, now)
    # An incident with no camera belongs to no site: it is counted in the window, never ranked.
    unassigned = factory.incident(None)
    unassigned.created_at = stamp_at(1, now)
    factory.session.commit()

    rows = report(admin, since=stamp_at(3, now), until=now)["top_cameras"]
    assert [row["code"] for row in rows] == ["CAM-A", "CAM-B", "CAM-C", "CAM-D", "CAM-E"]
    assert rows[0]["detections"] == 6
    assert rows[0]["incidents"] == 1
    assert rows[0]["display_name"] and rows[0]["campus_location"]
    assert sum(row["incidents"] for row in rows) == 1


def test_a_window_that_ends_before_it_starts_is_refused(admin) -> None:
    now = dt.datetime.now(dt.UTC)
    response = admin.client.get(
        ENDPOINT, params={"since": now.isoformat(), "until": stamp_at(5, now).isoformat()}
    )
    assert response.status_code == 422, response.text
    assert response.json()["detail"]["code"] == "inverted_window"


def test_a_role_that_reports_nothing_cannot_read_the_report(actor) -> None:
    viewer = actor("technical_operator")
    response = viewer.client.get(ENDPOINT)
    assert response.status_code == 403, response.text
