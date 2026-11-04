"""The configuration guards that decide whether a deployment is allowed to boot at all.

Everything else in the suite builds a `Settings` object directly (see
`tests/conftest.py::make_settings`), which is the harness convenience that lets the tests run
without a database server. That also means nothing in the suite used to exercise
`load_settings()` - the single function that refuses a non-PostgreSQL database and, since this
file was written, refuses a guessable session-signing secret. Those refusals are the rules the
proposal states most loudly, so they are pinned here rather than trusted to a reading of
`config.py`.
"""

from __future__ import annotations

import pytest

from watchtower.config import ConfigError, load_settings

LONG_SECRET = "z" * 48  # what `secrets.token_urlsafe(48)` produces
NEON_URL = (
    "postgresql://watchtower:S3cret-pa%40ss@ep-cool-name-123456-pooler"
    ".us-east-2.aws.neon.tech/neondb?sslmode=require"
)


def env(**overrides) -> dict[str, str]:
    """An environment dict where a `None` override means "this variable is not set"."""
    values = {"WATCHTOWER_DATABASE_URL": "postgresql://watchtower:pw@127.0.0.1:5432/watchtower",
              "WATCHTOWER_JWT_SECRET": LONG_SECRET}
    values.update(overrides)
    return {key: value for key, value in values.items() if value}


# ------------------------------------------------------------------ database (section 8.1)


def test_a_missing_database_url_is_refused_rather_than_defaulted():
    with pytest.raises(ConfigError, match="WATCHTOWER_DATABASE_URL is required"):
        load_settings(env(WATCHTOWER_DATABASE_URL=None))


@pytest.mark.parametrize(
    "url",
    [
        "sqlite:///var/dev/watchtower.db",
        "sqlite+pysqlite:///:memory:",
        "postgresql+asyncpg://watchtower:pw@127.0.0.1:5432/watchtower",
        "postgres://watchtower:pw@127.0.0.1:5432/watchtower",  # the short form some hosts print
        "mysql://watchtower:pw@127.0.0.1:3306/watchtower",
    ],
)
def test_only_a_postgresql_url_is_accepted(url):
    with pytest.raises(ConfigError, match="must be a PostgreSQL URL") as caught:
        load_settings(env(WATCHTOWER_DATABASE_URL=url))
    # The message names the offending scheme so a typo is obvious in a service log.
    assert repr(url.split("://", 1)[0]) in str(caught.value)


@pytest.mark.parametrize(
    "url",
    [
        "postgresql://watchtower:pw@127.0.0.1:5432/watchtower",
        "postgresql+psycopg://watchtower:pw@127.0.0.1:5432/watchtower",
        NEON_URL,
    ],
)
def test_the_accepted_postgresql_forms_load(url):
    settings = load_settings(env(WATCHTOWER_DATABASE_URL=url))
    assert settings.database_url == url


def test_a_managed_database_keeps_the_options_its_host_requires():
    """Neon terminates unencrypted connections, so the query string must survive to the driver."""
    from sqlalchemy.engine import make_url

    settings = load_settings(env(WATCHTOWER_DATABASE_URL=NEON_URL))
    parsed = make_url(settings.database_url)
    assert parsed.query["sslmode"] == "require"
    assert parsed.host.endswith(".aws.neon.tech")
    # Percent-encoding is what lets a host-generated password contain "@" or "#".
    assert parsed.password == "S3cret-pa@ss"


# ------------------------------------------------------------------ session secret (section 16)


def test_an_absent_session_secret_is_refused():
    with pytest.raises(ConfigError, match="WATCHTOWER_JWT_SECRET is required"):
        load_settings(env(WATCHTOWER_JWT_SECRET=None))


@pytest.mark.parametrize("secret", ["", "changeme", "CHANGE_ME", "z" * 31])
def test_a_guessable_session_secret_is_refused(secret):
    """An HMAC key anyone can guess is a session token anyone can forge."""
    with pytest.raises(ConfigError, match="at least 32 characters"):
        load_settings(env(WATCHTOWER_JWT_SECRET=secret))


def test_the_documented_generator_produces_an_acceptable_secret():
    import secrets

    settings = load_settings(env(WATCHTOWER_JWT_SECRET=secrets.token_urlsafe(48)))
    assert len(settings.jwt_secret) >= 32


def test_a_secret_is_stripped_of_the_whitespace_an_editor_adds():
    settings = load_settings(env(WATCHTOWER_JWT_SECRET=f"  {LONG_SECRET}\n"))
    assert settings.jwt_secret == LONG_SECRET


# ------------------------------------------------------------------ environment posture


def test_development_defaults_to_no_https_enforcement():
    assert load_settings(env(WATCHTOWER_ENVIRONMENT="development")).require_https is False


@pytest.mark.parametrize("environment", ["pilot", "production", "prod"])
def test_anything_but_development_defaults_to_enforcing_https(environment):
    settings = load_settings(env(WATCHTOWER_ENVIRONMENT=environment))
    assert settings.require_https is True
    assert settings.is_production is True


def test_the_template_ships_https_on_even_for_development_and_that_is_not_a_mistake():
    """WATCHTOWER_REQUIRE_HTTPS=1 next to ENVIRONMENT=development is honoured, not overridden.

    This is the combination that makes a first local run look broken: every GET is redirected
    to https:// and the session cookie is marked Secure, so nothing is served over plain http.
    """
    settings = load_settings(env(WATCHTOWER_REQUIRE_HTTPS="1"))
    assert settings.environment == "development"
    assert settings.require_https is True


def test_https_can_be_switched_off_explicitly_for_a_loopback_run():
    assert load_settings(env(WATCHTOWER_REQUIRE_HTTPS="0")).require_https is False


def test_an_unrecognised_environment_is_not_treated_as_production():
    settings = load_settings(env(WATCHTOWER_ENVIRONMENT="statge"))
    assert settings.is_production is False
    # ... but the HTTPS default still turns on, because only "development" is trusted.
    assert settings.require_https is True


def test_environment_defaults_to_development_when_unset():
    assert load_settings(env(WATCHTOWER_ENVIRONMENT=None)).environment == "development"


# ------------------------------------------------------------------ alert channel


def test_no_webhook_configured_means_dashboard_only_alerts():
    assert load_settings(env()).webhook_url is None


@pytest.mark.parametrize("url", ["https://alerting.internal.example/hook", "http://10.20.0.9:9000/hook"])
def test_an_http_or_https_webhook_is_accepted(url):
    assert load_settings(env(WATCHTOWER_WEBHOOK_URL=url)).webhook_url == url


@pytest.mark.parametrize("url", ["file:///var/log/alerts", "ftp://host/hook", "gopher://host/x"])
def test_a_webhook_that_could_write_locally_is_refused(url):
    with pytest.raises(ConfigError, match="must be an http\\(s\\) endpoint"):
        load_settings(env(WATCHTOWER_WEBHOOK_URL=url))


# ------------------------------------------------------------------ tuning values


def test_backoff_sequence_is_parsed_as_integers_in_order():
    settings = load_settings(env(WATCHTOWER_STREAM_BACKOFF="1, 3,7, 20"))
    assert settings.stream_retry_backoff_seconds == (1, 3, 7, 20)


def test_backoff_falls_back_to_the_documented_sequence():
    assert load_settings(env(WATCHTOWER_STREAM_BACKOFF=None)).stream_retry_backoff_seconds == (
        2,
        5,
        15,
        30,
        60,
    )


def test_retention_and_paths_come_from_the_environment():
    settings = load_settings(
        env(
            WATCHTOWER_EVIDENCE_RETENTION_DAYS="30",
            WATCHTOWER_AUDIT_RETENTION_DAYS="730",
            WATCHTOWER_EVIDENCE_DIR="./var/evidence",
            WATCHTOWER_SECRET_KEY_PATH="./var/watchtower.key",
        )
    )
    assert settings.evidence_retention_days == 30
    assert settings.audit_retention_days == 730
    assert settings.evidence_dir.as_posix() == "var/evidence"
    assert settings.secret_key_path.as_posix() == "var/watchtower.key"


@pytest.mark.parametrize("name", ["WATCHTOWER_MAX_CONCURRENT_STREAMS", "WATCHTOWER_PROBE_TIMEOUT_SECONDS"])
def test_a_non_numeric_limit_fails_loudly(name):
    """A typo in a limit must not silently become zero, or the estate stops being monitored."""
    with pytest.raises(ValueError):
        load_settings(env(**{name: "eight"}))
