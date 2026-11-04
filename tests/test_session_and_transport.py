"""Session, CSRF, transport-security and audit-completeness guarantees (proposal section 16).

Each of these claims can only be checked against the running application: the signed cookie and
its flags, the derived key that signs it, the middleware that refuses a cross-site write, the
lockout that has to survive the rollback of the request that triggered it, and the audit row that
has to exist *after* a refused login. No camera and no network are involved, so nothing here is
stubbed: the real app, the real middleware and the real database are driven over HTTP.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import time

import jwt
import pytest
from sqlalchemy import select
from starlette.testclient import TestClient

from watchtower import __version__
from watchtower.api.deps import TOKEN_COOKIE, _LOCKOUT_AFTER
from watchtower.models import AuditLog, User
from watchtower.security.passwords import verify_password
from watchtower.security.secrets import derive_media_key

GOOD_PASSWORD = "correct-horse-battery-st"
NEW_PASSWORD = "a-replaced-tower-passphrase"


def bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def raw(client) -> object:
    """The underlying TestClient, so a request can be sent without the dashboard header."""
    return client.client if hasattr(client, "client") else client


def user_row(db, username: str) -> User:
    db.commit()
    db.expire_all()
    return db.scalar(select(User).where(User.username == username))


def audit_for(db, action: str) -> list[AuditLog]:
    db.commit()
    return [
        row
        for row in db.scalars(select(AuditLog).order_by(AuditLog.id)).all()
        if row.action == action
    ]


def as_utc(value: dt.datetime) -> dt.datetime:
    return value if value.tzinfo else value.replace(tzinfo=dt.UTC)


def update_as_application(session_factory, user_id: int, **changes) -> None:
    """Apply a change through a second session, the way an HTTP request would."""
    session = session_factory()
    try:
        row = session.get(User, user_id)
        for key, value in changes.items():
            setattr(row, key, value)
        session.commit()
    finally:
        session.close()


@pytest.fixture
def supervisor_user(factory):
    user = factory.user(
        username="session.supervisor", roles=("security_supervisor",), password=GOOD_PASSWORD
    )
    factory.session.commit()
    return user


@pytest.fixture
def session_of(launched):
    return launched.app.state.session_factory


@pytest.fixture
def container_of(launched):
    return launched.app.state.container


# --------------------------------------------------------------------------- #
# Session handling: HS256 on a purpose-derived key, revoked on logout
# --------------------------------------------------------------------------- #


class TestSessionTokens:
    def test_the_session_token_is_hs256_on_a_purpose_derived_key(
        self, launched, dashboard, settings, container_of, supervisor_user
    ):
        assert dashboard.login(supervisor_user.username, GOOD_PASSWORD).status_code == 200

        token = dashboard.client.cookies.get(TOKEN_COOKIE)
        assert jwt.get_unverified_header(token)["alg"] == "HS256"
        assert container_of.token_key == derive_media_key(settings.jwt_secret, "auth-token")
        assert container_of.token_key != settings.jwt_secret.encode()

        claims = jwt.decode(token, container_of.token_key, algorithms=["HS256"], audience=None)
        assert claims["sub"] == str(supervisor_user.id)
        assert claims["scope"] == "watchtower.session"
        assert claims["exp"] - claims["iat"] == settings.jwt_ttl_minutes * 60

    @pytest.mark.filterwarnings("ignore:The HMAC key is 29 bytes long.*")
    def test_the_master_secret_never_signs_an_acceptable_session(
        self, launched, settings, supervisor_user
    ):
        now = int(time.time())
        # A cookie-free client, because the session cookie outranks a bearer header: the forged
        # token has to be the only thing the application is offered.
        api_client = TestClient(launched.app, base_url="http://testserver")

        forged = jwt.encode(
            {
                "sub": str(supervisor_user.id),
                "jti": "forged-jti",
                "iat": now,
                "exp": now + 3600,
                "scope": "watchtower.session",
            },
            settings.jwt_secret,
            algorithm="HS256",
        )

        assert api_client.get("/api/auth/me", headers=bearer(forged)).status_code == 401

    def test_the_session_cookie_is_httponly_same_site_strict_and_ttl_bounded(
        self, dashboard, settings, supervisor_user
    ):
        response = dashboard.login(supervisor_user.username, GOOD_PASSWORD)

        assert response.status_code == 200
        set_cookie = response.headers["set-cookie"].lower()
        assert TOKEN_COOKIE.lower() in set_cookie
        assert "httponly" in set_cookie
        assert "samesite=strict" in set_cookie
        assert f"max-age={settings.jwt_ttl_minutes * 60}" in set_cookie
        assert "path=/" in set_cookie

    def test_logout_revokes_the_token_for_the_cookie_and_the_bearer_transport(
        self, dashboard, supervisor_user
    ):
        assert dashboard.login(supervisor_user.username, GOOD_PASSWORD).status_code == 200
        token = dashboard.client.cookies.get(TOKEN_COOKIE)
        assert dashboard.client.get("/api/auth/me", headers=bearer(token)).status_code == 200

        assert dashboard.post("/api/auth/logout").status_code == 200

        refused = dashboard.client.get("/api/auth/me", headers=bearer(token))
        assert refused.status_code == 401
        assert refused.json()["detail"] == "session_expired"

    def test_an_expired_token_is_refused(self, dashboard, container_of, supervisor_user):
        past = int(time.time()) - 3600

        stale = jwt.encode(
            {
                "sub": str(supervisor_user.id),
                "jti": "stale-jti",
                "iat": past - 3600,
                "exp": past,
                "scope": "watchtower.session",
            },
            container_of.token_key,
            algorithm="HS256",
        )

        response = dashboard.client.get("/api/auth/me", headers=bearer(stale))

        assert response.status_code == 401
        assert response.json()["detail"] == "session_expired"

    def test_a_deactivated_account_loses_its_live_session(
        self, dashboard, session_of, supervisor_user
    ):
        assert dashboard.login(supervisor_user.username, GOOD_PASSWORD).status_code == 200
        token = dashboard.client.cookies.get(TOKEN_COOKIE)

        update_as_application(session_of, supervisor_user.id, is_active=False)

        assert dashboard.client.get("/api/auth/me", headers=bearer(token)).status_code == 401

    def test_an_unknown_account_and_a_disabled_account_answer_identically(
        self, dashboard, factory
    ):
        factory.user(username="ghost.account", roles=("security_supervisor",), is_active=False)
        factory.session.commit()

        unknown = dashboard.client.post(
            "/api/auth/login", json={"username": "no.such.account", "password": GOOD_PASSWORD}
        )
        disabled = dashboard.client.post(
            "/api/auth/login", json={"username": "ghost.account", "password": GOOD_PASSWORD}
        )

        assert unknown.status_code == disabled.status_code == 401
        assert unknown.json() == disabled.json()


# --------------------------------------------------------------------------- #
# Lockout after repeated failures
# --------------------------------------------------------------------------- #


class TestLoginLockout:
    def test_repeated_failures_lock_the_account(self, dashboard, db, supervisor_user):
        for attempt in range(_LOCKOUT_AFTER):
            refused = raw(dashboard.client).post(
                "/api/auth/login",
                json={"username": supervisor_user.username, "password": "wrong-password"},
            )
            assert refused.status_code == 401, attempt

        row = user_row(db, supervisor_user.username)
        assert row.locked_until is not None
        assert as_utc(row.locked_until) > dt.datetime.now(dt.UTC)
        assert row.failed_login_count == 0

        locked = raw(dashboard.client).post(
            "/api/auth/login",
            json={"username": supervisor_user.username, "password": GOOD_PASSWORD},
        )
        assert locked.status_code == 423
        assert locked.json()["detail"]["code"] == "account_locked"

    def test_a_failure_count_survives_the_rollback_of_the_refused_request(
        self, dashboard, db, supervisor_user
    ):
        raw(dashboard.client).post(
            "/api/auth/login",
            json={"username": supervisor_user.username, "password": "wrong-password"},
        )

        assert user_row(db, supervisor_user.username).failed_login_count == 1

    def test_a_successful_login_clears_the_counter(self, dashboard, db, supervisor_user):
        for _ in range(_LOCKOUT_AFTER - 1):
            raw(dashboard.client).post(
                "/api/auth/login",
                json={"username": supervisor_user.username, "password": "wrong-password"},
            )

        assert dashboard.login(supervisor_user.username, GOOD_PASSWORD).status_code == 200
        assert user_row(db, supervisor_user.username).failed_login_count == 0

        # The next burst needs the whole threshold again, not one further attempt.
        for _ in range(_LOCKOUT_AFTER - 1):
            raw(dashboard.client).post(
                "/api/auth/login",
                json={"username": supervisor_user.username, "password": "wrong-password"},
            )
        assert user_row(db, supervisor_user.username).locked_until is None

    def test_the_lock_expires_and_the_account_can_sign_in_again(
        self, dashboard, db, session_of, supervisor_user
    ):
        for _ in range(_LOCKOUT_AFTER):
            raw(dashboard.client).post(
                "/api/auth/login",
                json={"username": supervisor_user.username, "password": "wrong-password"},
            )

        update_as_application(
            session_of, supervisor_user.id,
            locked_until=dt.datetime.now(dt.UTC) - dt.timedelta(seconds=1),
        )

        assert dashboard.login(supervisor_user.username, GOOD_PASSWORD).status_code == 200
        assert user_row(db, supervisor_user.username).locked_until is None


# --------------------------------------------------------------------------- #
# Audit completeness: a refused attempt is still a recorded attempt
# --------------------------------------------------------------------------- #


class TestAuditCompleteness:
    def test_a_refused_login_is_recorded_before_the_401_leaves_the_process(
        self, dashboard, db, supervisor_user
    ):
        raw(dashboard.client).post(
            "/api/auth/login",
            json={"username": supervisor_user.username, "password": "wrong-password"},
        )

        rows = audit_for(db, "auth.login_failed")
        assert [row.outcome for row in rows] == ["failure"]
        assert rows[0].object_id == supervisor_user.username
        assert rows[0].details["reason"] == "invalid_credentials"

    def test_a_refused_login_does_not_record_a_successful_one(self, dashboard, db, supervisor_user):
        raw(dashboard.client).post(
            "/api/auth/login",
            json={"username": supervisor_user.username, "password": "wrong-password"},
        )

        assert audit_for(db, "auth.login") == []

    def test_a_successful_login_is_recorded(self, dashboard, db, supervisor_user):
        assert dashboard.login(supervisor_user.username, GOOD_PASSWORD).status_code == 200

        assert [row.outcome for row in audit_for(db, "auth.login")] == ["success"]

    def test_the_trail_never_stores_the_password_it_was_given(
        self, dashboard, db, supervisor_user
    ):
        raw(dashboard.client).post(
            "/api/auth/login",
            json={"username": supervisor_user.username, "password": "a-guessed-password"},
        )

        rows = audit_for(db, "auth.login_failed")
        assert len(rows) == 1
        assert "a-guessed-password" not in str(rows[0].details)
    def test_a_purge_is_a_post_and_never_a_get(self, admin):
        assert admin.client.get("/api/admin/audit/purge").status_code == 405
        assert admin.client.get("/api/admin/retention/purge").status_code == 405

    def test_an_unauthenticated_purge_is_refused(self, client):
        assert client.post("/api/admin/audit/purge").status_code in (401, 403)


# --------------------------------------------------------------------------- #
# Self-service password change
# --------------------------------------------------------------------------- #


class TestPasswordChange:
    def test_an_operator_can_change_their_own_password_and_stays_signed_in(
        self, dashboard, db, supervisor_user, client
    ):
        assert dashboard.login(supervisor_user.username, GOOD_PASSWORD).status_code == 200
        before = user_row(db, supervisor_user.username).password_hash

        changed = dashboard.post(
            "/api/auth/password",
            json={"current_password": GOOD_PASSWORD, "new_password": NEW_PASSWORD},
        )
        assert changed.status_code == 200, changed.text

        assert user_row(db, supervisor_user.username).password_hash != before
        assert verify_password(NEW_PASSWORD, user_row(db, supervisor_user.username).password_hash)
        # The cookie in the jar was replaced by the response above, so the tab is not logged out
        # by its own successful change.
        assert client.get("/api/auth/me").status_code == 200

    def test_the_old_password_stops_working_and_the_new_one_opens_a_session(
        self, dashboard, client, supervisor_user
    ):
        assert dashboard.login(supervisor_user.username, GOOD_PASSWORD).status_code == 200
        assert dashboard.post(
            "/api/auth/password",
            json={"current_password": GOOD_PASSWORD, "new_password": NEW_PASSWORD},
        ).status_code == 200

        stale = TestClient(client.app, base_url=str(client.base_url))
        assert stale.post(
            "/api/auth/login", json={"username": supervisor_user.username, "password": GOOD_PASSWORD}
        ).status_code == 401
        assert stale.post(
            "/api/auth/login", json={"username": supervisor_user.username, "password": NEW_PASSWORD}
        ).status_code == 200

    def test_a_wrong_current_password_leaves_the_account_untouched(
        self, dashboard, db, supervisor_user
    ):
        assert dashboard.login(supervisor_user.username, GOOD_PASSWORD).status_code == 200
        before = user_row(db, supervisor_user.username).password_hash

        refused = dashboard.post(
            "/api/auth/password",
            json={"current_password": "not-my-password", "new_password": NEW_PASSWORD},
        )
        assert refused.status_code == 403, refused.text
        assert refused.json()["detail"]["code"] == "current_password_incorrect"
        assert user_row(db, supervisor_user.username).password_hash == before

        rows = audit_for(db, "auth.password_change")
        assert [row.outcome for row in rows] == ["failure"]
        assert rows[0].details == {"reason": "current_password_incorrect"}

    def test_the_trail_records_the_change_and_neither_password(
        self, dashboard, db, supervisor_user
    ):
        assert dashboard.login(supervisor_user.username, GOOD_PASSWORD).status_code == 200
        assert dashboard.post(
            "/api/auth/password",
            json={"current_password": GOOD_PASSWORD, "new_password": NEW_PASSWORD},
        ).status_code == 200

        rows = audit_for(db, "auth.password_change")
        assert [row.outcome for row in rows] == ["success"]
        assert str(rows[0].object_id) == str(supervisor_user.id)
        assert GOOD_PASSWORD not in str(rows[0].details)
        assert NEW_PASSWORD not in str(rows[0].details)

    def test_the_token_that_made_the_change_is_retired_but_the_fresh_one_works(
        self, dashboard, supervisor_user, client, container_of, launched
    ):
        assert dashboard.login(supervisor_user.username, GOOD_PASSWORD).status_code == 200
        presented = client.cookies.get(TOKEN_COOKIE)
        claims = jwt.decode(presented, container_of.token_key, algorithms=["HS256"], options={"verify_exp": False})

        assert dashboard.post(
            "/api/auth/password",
            json={"current_password": GOOD_PASSWORD, "new_password": NEW_PASSWORD},
        ).status_code == 200

        assert container_of.revocations.is_revoked(claims["jti"]) is True
        # A bearer request on a clean client is the only way to prove the retired token is the one
        # being refused: the shared jar now carries the re-issued cookie, which wins over a header.
        stranger = TestClient(launched.app, base_url=str(client.base_url))
        assert stranger.get("/api/auth/me", headers=bearer(presented)).status_code == 401
        assert client.get("/api/auth/me").status_code == 200

    def test_a_new_password_below_the_minimum_is_refused_before_it_is_hashed(
        self, dashboard, db, supervisor_user
    ):
        assert dashboard.login(supervisor_user.username, GOOD_PASSWORD).status_code == 200
        before = user_row(db, supervisor_user.username).password_hash

        refused = dashboard.post(
            "/api/auth/password",
            json={"current_password": GOOD_PASSWORD, "new_password": "short-one"},
        )
        assert refused.status_code == 422, refused.text
        assert user_row(db, supervisor_user.username).password_hash == before

    def test_repeating_the_current_password_is_refused(self, dashboard, db, supervisor_user):
        assert dashboard.login(supervisor_user.username, GOOD_PASSWORD).status_code == 200
        before = user_row(db, supervisor_user.username).password_hash

        refused = dashboard.post(
            "/api/auth/password",
            json={"current_password": GOOD_PASSWORD, "new_password": GOOD_PASSWORD},
        )
        assert refused.status_code == 422, refused.text
        assert refused.json()["detail"]["code"] == "password_unchanged"
        assert user_row(db, supervisor_user.username).password_hash == before

    def test_a_self_service_change_clears_the_forced_change_flag(
        self, dashboard, db, supervisor_user, session_of
    ):
        update_as_application(session_of, supervisor_user.id, must_change_password=True)
        assert dashboard.login(supervisor_user.username, GOOD_PASSWORD).status_code == 200

        assert dashboard.post(
            "/api/auth/password",
            json={"current_password": GOOD_PASSWORD, "new_password": NEW_PASSWORD},
        ).status_code == 200
        assert user_row(db, supervisor_user.username).must_change_password is False

    def test_a_cross_site_password_change_without_the_header_is_refused(
        self, dashboard, db, supervisor_user, client
    ):
        assert dashboard.login(supervisor_user.username, GOOD_PASSWORD).status_code == 200
        before = user_row(db, supervisor_user.username).password_hash

        refused = raw(client).post(
            "/api/auth/password",
            json={"current_password": GOOD_PASSWORD, "new_password": NEW_PASSWORD},
        )
        assert refused.status_code == 403, refused.text
        assert user_row(db, supervisor_user.username).password_hash == before

    def test_the_identity_answer_reports_the_version_the_server_runs(
        self, dashboard, supervisor_user, client
    ):
        assert dashboard.login(supervisor_user.username, GOOD_PASSWORD).status_code == 200
        assert client.get("/api/auth/me").json()["version"] == __version__


# --------------------------------------------------------------------------- #
# CSRF: SameSite=Strict cookie plus a header a cross-site form cannot set
# --------------------------------------------------------------------------- #


class TestCsrfDefence:
    def test_a_cookie_authenticated_write_without_the_header_is_refused(
        self, dashboard, supervisor_user
    ):
        assert dashboard.login(supervisor_user.username, GOOD_PASSWORD).status_code == 200

        refused = raw(dashboard.client).post(
            "/api/admin/groups", json={"code": "GRP-CSRF", "name": "Cross-site"}
        )

        assert refused.status_code == 403
        assert refused.json()["detail"]["code"] == "csrf_check_failed"

    def test_the_same_write_with_the_header_is_accepted(self, admin):
        created = admin.client.post("/api/admin/groups", json={"code": "GRP-OK", "name": "Same site"})

        assert created.status_code in (200, 201)

    def test_a_bearer_client_is_not_required_to_send_the_dashboard_header(
        self, launched, dashboard, supervisor_user
    ):
        token = dashboard.token(supervisor_user.username, GOOD_PASSWORD)
        api_client = TestClient(launched.app, base_url="http://testserver")

        served = api_client.post(
            "/api/incidents",
            json={"title": "Man at the west fence", "category": "intrusion"},
            headers=bearer(token),
        )

        assert served.status_code in (200, 201), served.text
        assert served.json().get("detail", {}).get("code") != "csrf_check_failed"

    def test_login_is_reachable_without_the_header(self, client, supervisor_user):
        response = client.post(
            "/api/auth/login", json={"username": supervisor_user.username, "password": GOOD_PASSWORD}
        )

        assert response.status_code == 200

    def test_reads_need_no_header(self, dashboard, supervisor_user):
        assert dashboard.login(supervisor_user.username, GOOD_PASSWORD).status_code == 200

        assert raw(dashboard.client).get("/api/auth/me").status_code == 200


# --------------------------------------------------------------------------- #
# Transport security
# --------------------------------------------------------------------------- #


class TestTransportSecurity:
    def test_every_response_carries_the_hardening_headers(self, client):
        response = client.get("/healthz")

        assert response.status_code == 200
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["x-frame-options"] == "DENY"
        assert response.headers["referrer-policy"] == "no-referrer"
        assert "max-age=31536000" in response.headers["strict-transport-security"]

    def test_the_content_policy_forbids_inline_scripts(self, client):
        policy = client.get("/dashboard").headers["content-security-policy"]
        directives = {
            part.split()[0]: part.split()[1:]
            for part in policy.split(";")
            if part.strip()
        }

        assert directives["default-src"] == ["'self'"]
        assert directives["script-src"] == ["'self'"]
        assert directives["frame-ancestors"] == ["'none'"]

    def test_plain_http_reads_are_redirected_to_https_when_required(
        self, make_app, settings, supervisor
    ):
        stack = make_app(dataclasses.replace(settings, require_https=True), supervisor_obj=supervisor)

        # The harness client follows redirects; the redirect itself is the enforcement being tested.
        page = stack.client.get("/dashboard", follow_redirects=False)

        assert page.status_code == 307
        assert page.headers["location"].startswith("https://")

    def test_plain_http_writes_are_refused_rather_than_redirected(
        self, make_app, settings, supervisor
    ):
        stack = make_app(dataclasses.replace(settings, require_https=True), supervisor_obj=supervisor)

        refused = stack.client.post("/api/auth/login", json={"username": "x", "password": "y"})

        assert refused.status_code == 403
        assert refused.json()["detail"]["code"] == "https_required"

    def test_the_forwarded_protocol_from_a_tls_terminating_proxy_is_honoured(
        self, make_app, settings, supervisor
    ):
        stack = make_app(dataclasses.replace(settings, require_https=True), supervisor_obj=supervisor)

        served = stack.client.get("/healthz", headers={"X-Forwarded-Proto": "https"})

        assert served.status_code == 200
        assert served.json()["status"] == "ok"

    def test_a_hardened_deployment_marks_the_session_cookie_secure(
        self, make_app, settings, supervisor, supervisor_user
    ):
        plain = make_app(settings, supervisor_obj=supervisor)
        insecure = plain.client.post(
            "/api/auth/login",
            json={"username": supervisor_user.username, "password": GOOD_PASSWORD},
        )
        assert insecure.status_code == 200
        assert "Secure" not in insecure.headers["set-cookie"]

        hardened = make_app(
            dataclasses.replace(settings, require_https=True), supervisor_obj=supervisor
        )
        issued = hardened.client.post(
            "/api/auth/login",
            json={"username": supervisor_user.username, "password": GOOD_PASSWORD},
            headers={"X-Forwarded-Proto": "https"},
        )

        assert issued.status_code == 200
        assert "Secure" in issued.headers["set-cookie"]

    def test_an_unhandled_fault_never_echoes_a_credential_bearing_url(self, launched):
        secret_url = "rtsp://admin:do-not-leak-this@10.20.0.5:554/cam/realmonitor"
        # The harness client re-raises server faults; this route must answer with its own 500.
        silent = TestClient(launched.app, base_url="http://testserver", raise_server_exceptions=False)

        @launched.app.get("/boom")
        def boom():
            raise RuntimeError(f"ffmpeg failed for {secret_url}")

        response = silent.get("/boom")

        assert response.status_code == 500
        assert response.json()["detail"]["code"] == "internal_error"
        assert "do-not-leak-this" not in response.text
        assert secret_url not in response.text
