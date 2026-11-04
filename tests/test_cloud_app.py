"""Cloud service wiring: the envelope, the request id, the transport rule, the operational routes.

These are the promises that hold for every other endpoint in this suite, so they are tested once,
here, against the real ASGI stack rather than assumed.
"""

from __future__ import annotations

import pytest


def _envelope(response):
    assert response.status_code in (401, 403, 404, 405, 409, 410, 413, 422, 429, 500, 503), response
    body = response.json()
    assert set(body) == {"error"}, f"unexpected top-level keys: {sorted(body)}"
    assert set(body["error"]) == {"code", "message", "request_id"}
    assert body["error"]["request_id"].startswith("req_")
    return body["error"]


class TestErrorEnvelope:
    def test_every_failure_leaves_through_one_shape(self, personnel):
        response = personnel.get("/api/v1/incidents/999999")
        assert response.status_code == 401, "an unauthenticated call is a 401, not a 404"
        error = _envelope(response)
        assert error["code"] == "authentication_required"

    def test_a_validation_failure_names_the_field_and_not_the_schema(self, signed_in):
        actor = signed_in("security_supervisor").actor
        response = actor.post("/api/v1/auth/password", json={"current_password": "x"})
        assert response.status_code == 422
        error = _envelope(response)
        assert error["code"] == "validation_failed"
        assert "new_password" in error["message"]
        # Pydantic's own detail would repeat the constraint and echo the input value; the contract
        # promises a field name and a sentence.
        assert "Field required" not in error["message"]

    def test_a_framework_refusal_uses_the_same_envelope(self, cloud_app):
        # An unmatched path is refused by Starlette, not by a router. `{"detail": "Not Found"}`
        # would mean the app has to parse two error shapes for one API.
        response = cloud_app.get("/api/v1/nothing-here")
        assert response.status_code == 404
        error = _envelope(response)
        assert error["code"] == "not_found"

    def test_a_wrong_method_is_the_same_shape(self, cloud_app):
        response = cloud_app.delete("/api/v1/auth/login")
        assert response.status_code == 405
        assert _envelope(response)["code"] == "method_not_allowed"


class TestRequestId:
    def test_a_generated_id_is_echoed_on_success_and_failure(self, cloud_app):
        for response in (cloud_app.get("/healthz"), cloud_app.get("/api/v1/auth/me")):
            assert response.headers["x-request-id"].startswith("req_")

    def test_an_inbound_id_is_honoured(self, cloud_app):
        response = cloud_app.get("/healthz", headers={"x-request-id": "support-ticket-417"})
        assert response.headers["x-request-id"] == "support-ticket-417"

    def test_a_dirty_inbound_id_is_replaced(self, cloud_app):
        # A value that would change meaning in a log line, or carry control text, is not echoed.
        # An HTTP header value is bytes, so this is everything a client can actually put there.
        for hostile in ("a" * 200, "line1\nline2", "a\r\nx-request-id: forged", " ", ""):
            response = cloud_app.get("/healthz", headers={"x-request-id": hostile})
            assert response.headers["x-request-id"].startswith("req_"), repr(hostile)

    def test_a_non_ascii_id_is_replaced(self):
        """Not sendable as a header, so the rule itself has to be tested at the pattern."""
        from watchtower.cloud.app import _REQUEST_ID_RE

        assert _REQUEST_ID_RE.match("ref-é") is None
        assert _REQUEST_ID_RE.match("req_0f3a9c1b22").group(0) == "req_0f3a9c1b22"


class TestTransport:
    def test_plain_http_is_refused_when_the_rule_is_on(self, make_cloud_app, cloud_settings):
        client = make_cloud_app(cloud_settings, require_https=True)
        # `TestClient` connects from the test peer, so the loopback exemption cannot mask the rule
        # unless the client claims to be elsewhere; the middleware reads the ASGI scheme.
        response = client.get("/api/v1/auth/me", headers={"host": "watchtower.example"})
        assert response.status_code == 401, "loopback is exempt; the scheme is already https here"

    def test_a_get_is_redirected_when_https_is_required(self, make_cloud_app, cloud_settings):
        client = make_cloud_app(
            cloud_settings, require_https=True, public_base_url="https://wt.example.test"
        )
        # `base_url` decides the ASGI scheme; a non-loopback peer is what a real proxy presents.
        other = type(client)(client.app, base_url="http://10.1.1.8:8080")
        with other:
            response = other.get(
                "/api/v1/incidents",
                headers={"host": "watchtower.example"},
                follow_redirects=False,
            )
            assert response.status_code == 307
            location = response.headers["location"]
            assert location.startswith("https://wt.example.test/api/v1/incidents")
            # The `Host` header the client sent must not become the redirect target.
            assert "watchtower.example" not in location

    def test_a_write_over_plain_http_is_refused_rather_than_redirected(self, make_cloud_app,
                                                                        cloud_settings):
        client = make_cloud_app(cloud_settings, require_https=True)
        other = type(client)(client.app, base_url="http://10.1.1.8:8080")
        with other:
            response = other.post("/api/v1/auth/login", json={"username": "a", "password": "b"})
            assert response.status_code == 403
            assert response.json()["error"]["code"] == "https_required"


class TestCors:
    def test_a_listed_origin_is_allowed_without_credentials(self, cloud_app):
        response = cloud_app.options(
            "/api/v1/auth/login",
            headers={
                "origin": "http://localhost:5173",
                "access-control-request-method": "POST",
                "access-control-request-headers": "authorization",
            },
        )
        assert response.status_code == 200
        assert response.headers["access-control-allow-origin"] == "http://localhost:5173"
        assert "access-control-allow-credentials" not in response.headers

    def test_an_unlisted_origin_gets_no_cors_header(self, cloud_app):
        response = cloud_app.get(
            "/healthz", headers={"origin": "http://somewhere-else.example"}
        )
        assert "access-control-allow-origin" not in response.headers


class TestOperationalRoutes:
    def test_health_reports_configuration_states_without_secrets(self, cloud_app, cloud_settings):
        response = cloud_app.get("/healthz")
        assert response.status_code == 200
        body = response.json()
        assert body["database"] == "ok"
        assert body["push"] == "disabled"
        assert body["ingest"] == "enabled"
        assert body["live_channel"] == "enabled"
        assert response.headers["cache-control"] == "no-store"
        text = response.text
        assert cloud_settings.database_url not in text
        assert cloud_settings.jwt_secret not in text

    def test_a_broken_database_is_503_not_a_lie(self, make_cloud_app, cloud_settings, tmp_path):
        from sqlalchemy import create_engine

        from watchtower.db import build_sessionmaker

        # A file inside a directory that does not exist: the driver can build no connection at all.
        unreachable = (tmp_path / "no-such-directory" / "watchtower.db").as_posix()
        broken_engine = create_engine(f"sqlite:///{unreachable}")
        client = make_cloud_app(
            cloud_settings, session_factory=build_sessionmaker(broken_engine)
        )
        response = client.get("/healthz")
        assert response.status_code == 503
        body = response.json()
        assert body["database"] == "unavailable"
        assert body["status"] == "degraded"
        assert body["database_detail"] == "connection failed"
        # A connection error names the file, and on other drivers the user and host of the
        # database. The fixed phrase is the only thing allowed out.
        assert unreachable not in response.text
        assert "sqlite" not in response.text

    def test_root_names_the_api_without_dumping_the_route_table(self, cloud_app):
        body = cloud_app.get("/").json()
        assert body["api"].endswith("/api/v1")
        assert set(body) == {
            "service", "api", "protocol_version", "docs", "authentication"
        }

    def test_every_path_exempted_from_the_https_rule_is_a_route_it_serves(self, cloud_app):
        """The exemption list is a hole in the TLS rule; naming a route that is not there keeps
        the hole open for a response that is only ever a 404, and a hosting health check aimed at
        that path reads as a service that will not come up.
        """
        from watchtower.cloud.app import _PROBE_PATHS

        declared = {getattr(route, "path", None) for route in cloud_app.app.routes}
        unexplained = sorted(_PROBE_PATHS - declared)
        assert not unexplained, f"{unexplained} are exempted from TLS but not served"
        assert "/readyz" not in declared, "readiness is /healthz here; the name is the console's"

    def test_a_path_that_is_not_a_probe_is_not_served_as_one(self, make_cloud_app, cloud_settings):
        """`/readyz` must be an ordinary authenticated-missing route, not a silently blessed one."""
        client = make_cloud_app(
            cloud_settings, require_https=True, public_base_url="https://wt.example.test"
        )
        other = type(client)(client.app, base_url="http://10.1.1.8:8080")
        with other:
            assert other.get("/healthz", follow_redirects=False).status_code == 200
            redirect = other.get("/readyz", follow_redirects=False)
            assert redirect.status_code == 307, "not a probe: the HTTPS rule applies to it"


class TestDeepLinkPage:
    def test_the_page_carries_the_number_and_nothing_else(self, cloud_app, factory):
        incident = factory.incident(title="Fence line disturbed")
        response = cloud_app.get(f"/open/incidents/{incident.id}")
        assert response.status_code == 200
        assert response.headers["x-frame-options"] == "DENY"
        assert response.headers["referrer-policy"] == "no-referrer"
        assert "script" not in response.text.lower()
        assert str(incident.id) in response.text
        assert "watchtower://incidents" in response.text
        # The page must not answer "may this person see it" before the API does.
        assert incident.title not in response.text
        assert incident.reference not in response.text

    def test_a_non_numeric_incident_id_never_reaches_the_page(self, cloud_app):
        # The path parameter is typed, so an injection attempt fails at the edge as a validation
        # refusal in the standard envelope; it is never concatenated into a query.
        for attempt in ("abc", "1%20or%201%3D1", "1.5", "0x10"):
            response = cloud_app.get(f"/open/incidents/{attempt}")
            assert response.status_code == 422, attempt
            assert _envelope(response)["code"] == "validation_failed"
            assert "incident" in response.text.lower()


@pytest.mark.parametrize("path", ["/docs", "/openapi.json"])
def test_documentation_is_available_outside_production(make_cloud_app, cloud_settings, path):
    assert make_cloud_app(cloud_settings).get(path).status_code == 200


def test_documentation_is_withdrawn_in_production(make_cloud_app, cloud_settings):
    from watchtower.security.secrets import KeyRing

    # A production process refuses to invent its own key ring, which is the right fail-closed
    # behaviour - so the deploy step that provisions one has to happen before the app starts.
    KeyRing(cloud_settings.secret_key_path, create_if_missing=True)
    client = make_cloud_app(cloud_settings, environment="production")
    assert client.get("/docs").status_code == 404
    assert client.get("/openapi.json").status_code == 404
    assert client.get("/").json()["docs"] is None
