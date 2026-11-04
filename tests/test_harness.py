"""Harness smoke check: the app boots, logs in, answers a camera query, and the dashboard's
hard-coded API paths still exist. A renamed route otherwise surfaces as a blank panel in the
browser and as nothing at all in the backend suite."""

from __future__ import annotations

import re
from pathlib import Path

from watchtower.models import CameraStatus

WEB_ROOT = Path(__file__).resolve().parents[1] / "src" / "watchtower" / "api" / "web"
# A backtick literal may carry a query string built from an interpolation, which contains quotes;
# a quoted literal may not contain its own delimiter. Both forms are collected.
API_LITERAL = re.compile(r"""`(/api/[^`]*)`|'(/api/[^'\n]*)'|\"(/api/[^\"\n]*)\"""")


def _segments(url: str) -> list[str]:
    """One part per path segment, with every `${...}` interpolation collapsed to `*`.

    A template literal can carry an interpolation the scan cannot see the end of, because it
    contains a quote; both the complete and the truncated form have to yield the same segment.
    """
    path = re.sub(r"\$\{.*?\}", "*", url)
    path = re.sub(r"\$\{.*", "*", path)
    path = re.sub(r"\*+", "*", path).split("?")[0]
    return [part for part in path.split("/") if part]


def _matches(segs: list[str], template: list[str]) -> bool:
    return len(segs) == len(template) and all(
        part == seg or seg == "*" for part, seg in zip(template, segs, strict=True)
    )


def _route_templates(app) -> dict[str, list[str]]:
    return {route: [p for p in route.split("/") if p] for route in app.openapi()["paths"]}


def dashboard_api_paths() -> set[str]:
    found: set[str] = set()
    for source in list(WEB_ROOT.rglob("*.js")) + list(WEB_ROOT.rglob("*.html")):
        for groups in API_LITERAL.findall(source.read_text(encoding="utf-8")):
            found.update(part for part in groups if part)
    return found


def test_app_boots_and_serves_camera_list(admin, factory, client):
    camera = factory.camera(status=CameraStatus.ONLINE.value)
    factory.session.commit()

    response = admin.client.get("/api/cameras")
    assert response.status_code == 200, response.text
    payload = response.json()
    assert [row["code"] for row in payload] == [camera.code]
    assert payload[0]["status"] == "online"


def test_login_is_issued_and_me_reports_permissions(admin, factory):
    me = admin.client.get("/api/auth/me")
    assert me.status_code == 200, me.text
    assert "camera.register" in me.json()["permissions"]
    assert me.json()["is_administrative"] is True


def test_healthz_and_readyz_are_up(client):
    assert client.get("/healthz").status_code == 200
    ready = client.get("/readyz")
    assert ready.status_code == 200, ready.text
    assert ready.json() == {"status": "ready"}


def test_every_dashboard_api_call_names_a_route_that_exists(app):
    templates = _route_templates(app)

    unreachable = sorted(
        url
        for url in dashboard_api_paths()
        if not any(_matches(_segments(url), segs) for segs in templates.values())
    )

    assert unreachable == []


def test_only_the_audit_purge_is_deliberately_absent_from_the_dashboard(app):
    """Erasing the trail must not become a button an operator can reach by accident."""
    called = [_segments(url) for url in dashboard_api_paths()]

    unused = sorted(
        route
        for route, segs in _route_templates(app).items()
        if route.startswith("/api")
        and not any(_matches(call, segs) for call in called)
    )

    assert unused == ["/api/admin/audit/purge"]
