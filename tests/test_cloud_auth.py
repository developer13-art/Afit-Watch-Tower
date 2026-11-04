"""Personnel sign-in, session rotation and password change (contract sections 2 and 3).

The load-bearing promises tested here are the ones the security argument rests on: the access
token identifies a person but grants nothing, a refresh token can only be spent once, a console
token is worthless against this API, and a push token is never stored or returned as plaintext.
"""

from __future__ import annotations

import datetime as dt
import time
import uuid

import jwt
import pytest
from sqlalchemy import select

from watchtower.mobile.models import MobileDevice, RefreshToken
from watchtower.models import AuditLog
from watchtower.security.secrets import derive_media_key

from conftest import INSTALLATION_ID, TEST_PASSWORD, Personnel

PUSH_TOKEN = "fcm-device-token-AAAA-bbbb-CCCC"


def _reload(session):
    """Discard the harness session's snapshot so rows written by a request session are visible."""
    session.commit()
    session.expire_all()


class TestLogin:
    def test_a_valid_login_returns_a_bearer_pair_and_the_effective_permissions(self, signed_in):
        session = signed_in("security_supervisor")
        body = session.response.json()
        assert body["token_type"] == "Bearer"
        assert body["expires_in"] == 900
        assert body["refresh_expires_in"] == 2_592_000
        assert body["access_token"] and body["refresh_token"]
        user = body["user"]
        assert user["username"] == session.user.username
        assert user["roles"] == ["security_supervisor"]
        assert "incident.view" in user["permissions"]
        assert user["must_change_password"] is False
        # The tokens are the only credentials in the response, and never the account's own.
        assert TEST_PASSWORD not in str(body)

    def test_the_access_token_carries_identity_and_no_permissions(self, signed_in, cloud_settings):
        access = signed_in("security_operator").response.json()["access_token"]
        claims = jwt.decode(
            access,
            derive_media_key(cloud_settings.jwt_secret, "personnel-access-token"),
            algorithms=["HS256"],
            issuer="watchtower-cloud",
        )
        assert set(claims) == {"sub", "sid", "jti", "iat", "exp", "iss", "scope"}
        assert claims["scope"] == "watchtower.personnel"
        # Nothing in the token says what the holder may do, so revoking a grant cannot be
        # deferred until the token happens to expire.
        for forbidden in ("permissions", "roles", "camera_group_ids", "scope_id"):
            assert forbidden not in claims

    def test_a_token_signed_with_another_secret_is_worthless(self, cloud_app, cloud_settings):
        key = derive_media_key("a-completely-different-secret-value-0123456789", "personnel-access-token")
        forged = jwt.encode(
            {"sub": "1", "sid": "x", "jti": "y", "exp": int(time.time()) + 60,
             "iss": "watchtower-cloud", "scope": "watchtower.personnel"},
            key,
            algorithm="HS256",
        )
        response = cloud_app.get("/api/v1/auth/me", headers={"authorization": f"Bearer {forged}"})
        assert response.status_code == 401
        assert response.json()["error"]["code"] == "invalid_token"

    def test_a_console_scope_or_issuer_is_refused_even_with_the_right_key(self, cloud_app, cloud_settings):
        key = derive_media_key(cloud_settings.jwt_secret, "personnel-access-token")
        base = {"sub": "1", "sid": "x", "jti": "y", "exp": int(time.time()) + 60,
                "iss": "watchtower-cloud"}
        wrong_scope = jwt.encode({**base, "scope": "watchtower.console"}, key, algorithm="HS256")
        response = cloud_app.get(
            "/api/v1/auth/me", headers={"authorization": f"Bearer {wrong_scope}"}
        )
        assert response.status_code == 401
        assert response.json()["error"]["code"] == "invalid_scope"

        wrong_issuer = jwt.encode({**base, "iss": "someone-else",
                                   "scope": "watchtower.personnel"}, key, algorithm="HS256")
        response = cloud_app.get(
            "/api/v1/auth/me", headers={"authorization": f"Bearer {wrong_issuer}"}
        )
        assert response.json()["error"]["code"] == "invalid_token"

    def test_an_expired_access_token_says_so_distinctly(self, cloud_app, cloud_settings, factory):
        user = factory.user(username="expired.session", roles=("security_operator",))
        factory.session.commit()
        key = derive_media_key(cloud_settings.jwt_secret, "personnel-access-token")
        stale = jwt.encode(
            {"sub": str(user.id), "sid": "x", "jti": "y", "exp": int(time.time()) - 60,
             "iss": "watchtower-cloud", "scope": "watchtower.personnel"},
            key,
            algorithm="HS256",
        )
        response = cloud_app.get("/api/v1/auth/me", headers={"authorization": f"Bearer {stale}"})
        assert response.status_code == 401
        # The app refreshes on exactly this code and on nothing else.
        assert response.json()["error"]["code"] == "access_expired"

    def test_an_unknown_account_and_a_wrong_password_are_the_same_answer(self, cloud_app, factory):
        user = factory.user(username="real.account", roles=("security_operator",))
        factory.session.commit()
        actor = Personnel(cloud_app)
        first = actor.login("no.such.person", "wrong-password-here-1234")
        second = actor.login(user.username, "wrong-password-here-1234")
        assert first.status_code == second.status_code == 401
        assert first.json()["error"]["code"] == second.json()["error"]["code"]
        assert first.json()["error"]["message"] == second.json()["error"]["message"]

    def test_a_disabled_account_is_not_distinguishable(self, cloud_app, factory):
        user = factory.user(username="off.duty", roles=("security_operator",), is_active=False)
        factory.session.commit()
        response = Personnel(cloud_app).login(user.username, TEST_PASSWORD)
        assert response.status_code == 401
        assert response.json()["error"]["code"] == "invalid_credentials"

    def test_eight_failures_lock_the_account_even_for_the_right_password(self, cloud_app, factory):
        user = factory.user(username="locked.person", roles=("security_operator",))
        factory.session.commit()
        actor = Personnel(cloud_app)
        for _ in range(8):
            assert actor.login(user.username, "not-the-password-12345").status_code == 401
        response = actor.login(user.username, TEST_PASSWORD)
        assert response.status_code == 401
        assert response.json()["error"]["code"] == "account_locked"
        assert response.headers["retry-after"] == "300"

    def test_a_failure_is_audited_with_a_reason_and_never_a_password(self, cloud_app, factory):
        user = factory.user(username="audited.person", roles=("security_operator",))
        factory.session.commit()
        Personnel(cloud_app).login(user.username, "not-the-password-12345")
        _reload(factory.session)
        rows = factory.session.scalars(
            select(AuditLog).where(AuditLog.action == "auth.login_failed")
        ).all()
        assert len(rows) == 1
        assert rows[0].outcome == "failure"
        assert rows[0].details == {"reason": "invalid_credentials"}
        assert "not-the-password-12345" not in str(rows[0].details)
        assert "not-the-password-12345" not in str(rows[0].object_id)

    def test_login_without_a_device_registers_nothing(self, make_cloud_app, cloud_settings, factory):
        """The web console signs in the same way, without ever claiming a handset."""
        client = make_cloud_app(cloud_settings)
        user = factory.user(username="no.device", roles=("security_operator",))
        factory.session.commit()
        response = client.post(
            "/api/v1/auth/login", json={"username": user.username, "password": TEST_PASSWORD}
        )
        assert response.status_code == 200
        _reload(factory.session)
        assert factory.session.scalars(select(MobileDevice)).all() == []

    def test_the_push_token_is_sealed_and_never_stored_or_echoed_as_plaintext(
        self, signed_in, cloud_app, factory
    ):
        session = signed_in("security_operator", push_token=PUSH_TOKEN)
        assert PUSH_TOKEN not in str(session.response.json())
        _reload(factory.session)
        device = factory.session.scalar(select(MobileDevice))
        assert device.installation_id == INSTALLATION_ID
        assert device.push_state == "active"
        assert device.push_token_ciphertext is not None
        assert PUSH_TOKEN.encode() not in device.push_token_ciphertext
        assert device.push_token_fingerprint and PUSH_TOKEN not in device.push_token_fingerprint
        # Only the cloud's own key ring can read it back.
        container = cloud_app.app.state.container
        assert container.unseal_push_token(device.push_token_ciphertext, device.push_token_key_id) == (
            PUSH_TOKEN
        )

    def test_a_second_login_on_the_same_handset_refreshes_one_device_row(
        self, make_cloud_app, cloud_settings, factory
    ):
        client = make_cloud_app(cloud_settings)
        user = factory.user(username="same.handset", roles=("security_operator",))
        factory.session.commit()
        for token in ("fcm-token-first-value-aaaa", "fcm-token-second-value-bbbb"):
            assert Personnel(client).login(
                user.username, TEST_PASSWORD, push_token=token
            ).status_code == 200
        _reload(factory.session)
        devices = factory.session.scalars(select(MobileDevice)).all()
        assert len(devices) == 1
        assert devices[0].push_state == "active"


class TestLoginRateLimits:
    def test_the_budget_is_per_username_and_a_refusal_is_a_429(
        self, make_cloud_app, cloud_settings, factory
    ):
        client = make_cloud_app(cloud_settings, login_attempts_per_5_minutes=3)
        user = factory.user(username="spammed.account", roles=("security_operator",))
        other = factory.user(username="spammed.other", roles=("security_operator",))
        factory.session.commit()
        actor = Personnel(client)
        for _ in range(3):
            assert actor.login(user.username, "wrong-password-here-1234").status_code == 401
        response = actor.login(user.username, TEST_PASSWORD)
        assert response.status_code == 429
        assert response.json()["error"]["code"] == "too_many_login_attempts"
        assert int(response.headers["retry-after"]) >= 1
        # A different account is a different budget: one locked username must not become an
        # outage for the whole shift.
        assert Personnel(client, installation_id=str(uuid.uuid4())).login(
            other.username, TEST_PASSWORD
        ).status_code == 200


class TestRefresh:
    def test_a_refresh_rotates_and_the_old_value_cannot_be_spent_twice(
        self, signed_in, cloud_app, factory
    ):
        session = signed_in("security_operator")
        first_refresh = session.actor.refresh_token
        response = cloud_app.post("/api/v1/auth/refresh", json={"refresh_token": first_refresh})
        assert response.status_code == 200
        rotated = response.json()
        assert rotated["refresh_token"] != first_refresh

        _reload(factory.session)
        rows = factory.session.scalars(select(RefreshToken)).all()
        assert len(rows) == 2
        by_value = {row.token_hash: row for row in rows}
        from watchtower.cloud.tokens import token_digest

        old_row = by_value[token_digest(first_refresh)]
        assert old_row.rotated_at is not None
        assert old_row.replaced_by_id is not None
        assert old_row.generation == 1 and by_value[token_digest(rotated["refresh_token"])].generation == 2

        # Presenting the spent value means two parties hold it, so the login is over.
        response = cloud_app.post("/api/v1/auth/refresh", json={"refresh_token": first_refresh})
        assert response.status_code == 401
        assert response.json()["error"]["code"] == "refresh_reused"

        _reload(factory.session)
        family = factory.session.scalars(
            select(RefreshToken).where(RefreshToken.reuse_detected.is_(True))
        ).all()
        assert len(family) >= 1
        # The replacement went with it, which is the point of revoking the family.
        after_reuse = cloud_app.post(
            "/api/v1/auth/refresh", json={"refresh_token": rotated["refresh_token"]}
        )
        assert after_reuse.status_code == 401
        assert after_reuse.json()["error"]["code"] == "refresh_reused"

    def test_the_rotated_access_token_actually_works(self, signed_in, cloud_app):
        signed_in("security_supervisor")
        refresh = cloud_app.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": _login(cloud_app, "handset.security_supervisor").refresh_token},
        ).json()
        response = cloud_app.get(
            "/api/v1/auth/me", headers={"authorization": f"Bearer {refresh['access_token']}"}
        )
        assert response.status_code == 200

    def test_an_unrecognised_refresh_token_is_refused(self, cloud_app):
        response = cloud_app.post(
            "/api/v1/auth/refresh", json={"refresh_token": "not-a-token-anyone-was-issued"}
        )
        assert response.status_code == 401
        assert response.json()["error"]["code"] == "invalid_refresh"

    def test_an_expired_refresh_token_is_refused(self, signed_in, cloud_app, factory):
        session = signed_in("security_operator")
        _reload(factory.session)
        row = factory.session.scalar(select(RefreshToken))
        row.expires_at = dt.datetime.now(dt.UTC) - dt.timedelta(minutes=1)
        factory.session.commit()
        response = cloud_app.post(
            "/api/v1/auth/refresh", json={"refresh_token": session.actor.refresh_token}
        )
        assert response.status_code == 401
        assert response.json()["error"]["code"] == "refresh_expired"

    def test_a_disabled_account_cannot_refresh_into_a_session(
        self, signed_in, cloud_app, factory
    ):
        session = signed_in("security_operator")
        session.user.is_active = False
        factory.session.commit()
        response = cloud_app.post(
            "/api/v1/auth/refresh", json={"refresh_token": session.actor.refresh_token}
        )
        assert response.status_code == 401
        assert response.json()["error"]["code"] == "invalid_refresh"


def _login(client, username: str) -> Personnel:
    actor = Personnel(client)
    assert actor.login(username, TEST_PASSWORD).status_code == 200
    return actor


class TestLogout:
    def test_logging_out_retires_this_access_token_and_this_refresh_token(self, signed_in, cloud_app):
        session = signed_in("security_operator")
        actor = session.actor
        refresh_value = actor.refresh_token
        response = cloud_app.post(
            "/api/v1/auth/logout",
            json={"refresh_token": refresh_value},
            headers=actor.headers,
        )
        assert response.status_code == 200
        assert response.json()["signed_out"] is True

        still = cloud_app.get("/api/v1/auth/me", headers=actor.headers)
        assert still.status_code == 401
        assert still.json()["error"]["code"] == "session_revoked"

        after = cloud_app.post("/api/v1/auth/refresh", json={"refresh_token": refresh_value})
        assert after.status_code == 401
        assert after.json()["error"]["code"] == "refresh_reused"

    def test_forgotten_device_stops_being_targetable(self, signed_in, cloud_app, factory):
        session = signed_in("security_operator", push_token=PUSH_TOKEN)
        response = cloud_app.post(
            "/api/v1/auth/logout",
            json={"refresh_token": session.actor.refresh_token, "forget_device": True},
            headers=session.actor.headers,
        )
        assert response.json()["device_forgotten"] is True
        _reload(factory.session)
        device = factory.session.scalar(select(MobileDevice))
        assert device.push_state == "revoked"
        assert device.push_token_ciphertext is None
        assert device.deactivated_at is not None

    def test_an_unknown_refresh_token_is_not_an_error_when_leaving(self, signed_in, cloud_app):
        actor = signed_in("security_operator").actor
        response = cloud_app.post(
            "/api/v1/auth/logout",
            json={"refresh_token": "never-issued-refresh-token-value"},
            headers=actor.headers,
        )
        assert response.status_code == 200
        assert response.json()["signed_out"] is True


class TestTemporaryPassword:
    def test_an_unchanged_temporary_password_opens_nothing_but_its_own_screen(
        self, signed_in, cloud_app, factory
    ):
        session = signed_in("security_operator", must_change_password=True)
        assert session.response.json()["user"]["must_change_password"] is True

        for path in ("/api/v1/auth/me", "/api/v1/incidents"):
            response = cloud_app.get(path, headers=session.actor.headers)
            assert response.status_code == 403, path
            assert response.json()["error"]["code"] == "password_change_required"

        response = cloud_app.post(
            "/api/v1/auth/password",
            json={"current_password": TEST_PASSWORD, "new_password": "a-new-passphrase-1234"},
            headers=session.actor.headers,
        )
        assert response.status_code == 200
        assert response.json()["changed"] is True

        _reload(factory.session)
        factory.session.refresh(session.user)
        assert session.user.must_change_password is False
        assert cloud_app.get("/api/v1/auth/me", headers=session.actor.headers).status_code == 200

    def test_the_wrong_current_password_leaves_the_account_untouched(self, signed_in, cloud_app):
        session = signed_in("security_operator")
        response = cloud_app.post(
            "/api/v1/auth/password",
            json={"current_password": "not-the-password-12345",
                  "new_password": "a-new-passphrase-1234"},
            headers=session.actor.headers,
        )
        assert response.status_code == 401
        assert response.json()["error"]["code"] == "current_password_incorrect"
        assert Personnel(cloud_app).login(
            session.user.username, TEST_PASSWORD
        ).status_code == 200

    def test_a_new_password_below_the_minimum_names_the_field(self, signed_in, cloud_app):
        response = cloud_app.post(
            "/api/v1/auth/password",
            json={"current_password": TEST_PASSWORD, "new_password": "short"},
            headers=signed_in("security_operator").actor.headers,
        )
        assert response.status_code == 422
        error = response.json()["error"]
        assert error["code"] == "validation_failed"
        assert "new_password" in error["message"]

    def test_changing_a_password_closes_the_other_handssets(self, cloud_app, factory):
        user = factory.user(username="two.handsets", roles=("security_operator",))
        factory.session.commit()
        first = _login(cloud_app, user.username)
        second = Personnel(cloud_app, installation_id=str(uuid.uuid4()))
        assert second.login(user.username, TEST_PASSWORD).status_code == 200

        response = cloud_app.post(
            "/api/v1/auth/password",
            json={"current_password": TEST_PASSWORD, "new_password": "a-new-passphrase-1234"},
            headers=first.headers,
        )
        assert response.status_code == 200
        assert response.json()["other_sessions_revoked"] >= 1

        after = cloud_app.post(
            "/api/v1/auth/refresh", json={"refresh_token": second.refresh_token}
        )
        assert after.status_code == 401
        assert after.json()["error"]["code"] == "refresh_reused"
        # The new password is the only way back in.
        assert Personnel(cloud_app, installation_id=str(uuid.uuid4())).login(
            user.username, "a-new-passphrase-1234"
        ).status_code == 200

    def test_keeping_other_sessions_is_honoured(self, cloud_app, factory):
        user = factory.user(username="stay.online", roles=("security_operator",))
        factory.session.commit()
        first = _login(cloud_app, user.username)
        second = Personnel(cloud_app, installation_id=str(uuid.uuid4()))
        assert second.login(user.username, TEST_PASSWORD).status_code == 200

        response = cloud_app.post(
            "/api/v1/auth/password",
            json={"current_password": TEST_PASSWORD, "new_password": "a-new-passphrase-1234",
                  "keep_other_sessions": True},
            headers=first.headers,
        )
        assert response.json()["other_sessions_revoked"] == 0
        assert cloud_app.post(
            "/api/v1/auth/refresh", json={"refresh_token": second.refresh_token}
        ).status_code == 200


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("get", "/api/v1/auth/me"),
        ("get", "/api/v1/incidents"),
        ("get", "/api/v1/notifications"),
    ],
)
def test_every_personnel_route_needs_a_bearer_token(personnel, method, path):
    client = personnel.client
    response = getattr(client, method)(path)
    assert response.status_code == 401, path
    assert response.json()["error"]["code"] == "authentication_required"


def test_a_malformed_authorization_header_is_not_treated_as_anonymous(cloud_app):
    for header in ({"authorization": ""}, {"authorization": "Basic dXNlcjpwYXNz"},
                   {"authorization": "Bearer "}):
        response = cloud_app.get("/api/v1/auth/me", headers=header)
        assert response.status_code == 401, header
        assert response.json()["error"]["code"] == "authentication_required"


def test_the_grant_is_read_from_the_database_on_every_request(signed_in, cloud_app, factory):
    """A revoked role takes effect on the next call, not when the 15-minute token expires."""
    session = signed_in("security_supervisor")
    before = cloud_app.get("/api/v1/auth/me", headers=session.actor.headers).json()
    assert "incident.resolve" in before["permissions"]

    from watchtower.models import Role, UserRole

    _reload(factory.session)
    assignment = factory.session.scalar(select(UserRole).where(UserRole.user_id == session.user.id))
    operator = factory.session.scalar(select(Role).where(Role.code == "security_operator"))
    assert assignment is not None and operator is not None
    assignment.role_id = operator.id
    factory.session.commit()

    after = cloud_app.get("/api/v1/auth/me", headers=session.actor.headers).json()
    assert after["roles"] == ["security_operator"]
    assert "incident.resolve" not in after["permissions"]
    # The same token now fails the way an account without the grant fails.
    incident = factory.incident()
    factory.session.commit()
    response = cloud_app.post(
        f"/api/v1/incidents/{incident.id}/resolve",
        json={"outcome": "false alarm", "resolution": "Nothing found at the fence line."},
        headers=session.actor.headers,
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "forbidden"
