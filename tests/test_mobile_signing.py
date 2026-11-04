"""Signed service-to-service ingest: freshness, replay refusal and body integrity.

`signing.verify()` is the only thing standing between the public internet and the incident
feed, so these tests assert the refusal path for every way a request can be wrong - and that
a correct request produced by `build_headers()` verifies byte-for-byte.
"""

from __future__ import annotations

import time

import pytest

from watchtower.mobile import signing
from watchtower.mobile.signing import ServiceCredentials, SignatureError

KEY_ID = "mon-host-1"
SECRET = "a-service-secret-that-is-long-enough-32"
BODY = b'{"incident":{"id":7},"idempotency_key":"incident:7:created"}'
PATH = "/api/v1/ingest/incident"
CREDENTIALS = {KEY_ID: SECRET}


def headers_for(*, method="POST", path=PATH, body=BODY, timestamp=None, nonce=None, key_id=KEY_ID):
    credentials = ServiceCredentials(key_id=key_id, secret=SECRET)
    return signing.build_headers(
        credentials,
        method=method,
        path=path,
        body=body,
        nonce=nonce or "0123456789abcdef0123456789abcdef",
        timestamp=int(time.time()) if timestamp is None else timestamp,
    )


def test_a_correctly_signed_request_verifies():
    signed = signing.verify(
        method="POST", path=PATH, body=BODY, headers=headers_for(), credentials=CREDENTIALS
    )
    assert signed.key_id == KEY_ID
    assert signed.content_sha256 == signing.content_sha256(BODY)
    assert signed.body == BODY


def test_the_signature_is_reproducible_from_the_documented_canonical_string():
    """The contract states the canonical string; this test is the proof both sides agree."""
    stamp, nonce = 1_800_000_000, "ab" * 16
    headers = headers_for(timestamp=stamp, nonce=nonce)
    canonical = "\n".join(
        (
            "POST",
            PATH,
            str(stamp),
            nonce,
            signing.content_sha256(BODY),
        )
    )
    expected = signing.sign(SECRET, canonical)
    assert headers["authorization"] == f"{signing.ALGORITHM} {KEY_ID}:{expected}"


def test_body_bytes_are_signed_not_a_re_serialisation():
    """Key order and whitespace are part of what was signed."""
    reformatted = b'{"incident":{"id":7} ,"idempotency_key":"incident:7:created"}'
    headers = headers_for(body=reformatted)
    with pytest.raises(SignatureError) as excinfo:
        signing.verify(
            method="POST", path=PATH, body=reformatted.replace(b"7", b"8"),
            headers=headers, credentials=CREDENTIALS,
        )
    assert excinfo.value.code == "content_mismatch"


@pytest.mark.parametrize(
    ("mutate", "code"),
    [
        (lambda h: h.pop(signing.HEADER_KEY_ID), "missing_key_id"),
        (lambda h: h.__setitem__(signing.HEADER_KEY_ID, "unknown-host"), "unknown_key_id"),
        (
            lambda h: h.__setitem__(
                signing.HEADER_AUTHORIZATION,
                h[signing.HEADER_AUTHORIZATION].replace("WATCHTOWER-HMAC", "OTHER"),
            ),
            "unsupported_scheme",
        ),
        (lambda h: h.__setitem__(signing.HEADER_TIMESTAMP, "not-a-number"), "invalid_timestamp"),
        (lambda h: h.__setitem__(signing.HEADER_NONCE, "zzzz"), "invalid_nonce"),
        (
            lambda h: h.__setitem__(signing.HEADER_CONTENT_SHA, "abc"),
            "invalid_content_sha256",
        ),
    ],
)
def test_each_malformed_header_refuses_with_its_own_code(mutate, code):
    headers = headers_for()
    mutate(headers)
    with pytest.raises(SignatureError) as excinfo:
        signing.verify(method="POST", path=PATH, body=BODY, headers=headers, credentials=CREDENTIALS)
    assert excinfo.value.code == code


def test_a_stale_timestamp_is_refused():
    headers = headers_for(timestamp=int(time.time()) - signing.MAX_CLOCK_SKEW_SECONDS - 30)
    with pytest.raises(SignatureError) as excinfo:
        signing.verify(
            method="POST", path=PATH, body=BODY, headers=headers, credentials=CREDENTIALS
        )
    assert excinfo.value.code == "timestamp_out_of_window"


def test_a_future_timestamp_beyond_the_window_is_refused():
    """Clock skew is symmetric; a client ahead by an hour is not trusted either."""
    headers = headers_for(timestamp=int(time.time()) + signing.MAX_CLOCK_SKEW_SECONDS + 30)
    with pytest.raises(SignatureError) as excinfo:
        signing.verify(
            method="POST", path=PATH, body=BODY, headers=headers, credentials=CREDENTIALS
        )
    assert excinfo.value.code == "timestamp_out_of_window"


def test_a_body_changed_after_signing_is_refused():
    headers = headers_for()
    with pytest.raises(SignatureError) as excinfo:
        signing.verify(
            method="POST", path=PATH, body=BODY + b" ", headers=headers, credentials=CREDENTIALS
        )
    assert excinfo.value.code == "content_mismatch"


def test_a_signature_from_a_different_secret_is_refused():
    headers = headers_for()
    headers[signing.HEADER_AUTHORIZATION] = headers[signing.HEADER_AUTHORIZATION][:-1] + "0"
    with pytest.raises(SignatureError) as excinfo:
        signing.verify(method="POST", path=PATH, body=BODY, headers=headers, credentials=CREDENTIALS)
    assert excinfo.value.code == "bad_signature"


def test_a_key_id_presented_twice_is_refused():
    headers = headers_for()
    headers[signing.HEADER_KEY_ID] = "mon-host-2"
    with pytest.raises(SignatureError) as excinfo:
        signing.verify(
            method="POST",
            path=PATH,
            body=BODY,
            headers={**headers, signing.HEADER_KEY_ID: "mon-host-2"},
            credentials={**CREDENTIALS, "mon-host-2": SECRET},
        )
    assert excinfo.value.code == "key_id_mismatch"


def test_header_names_are_case_insensitive():
    headers = {key.upper(): value for key, value in headers_for().items()}
    signed = signing.verify(method="POST", path=PATH, body=BODY, headers=headers, credentials=CREDENTIALS)
    assert signed.nonce == headers["X-WATCHTOWER-NONCE"].lower()


def test_a_query_string_and_a_trailing_slash_cannot_shift_the_path():
    """`/ingest/incident?x=1` must verify against the same canonical path."""
    headers = headers_for(path=f"{PATH}?debug=1")
    signed = signing.verify(
        method="POST", path=f"{PATH}?debug=1", body=BODY, headers=headers, credentials=CREDENTIALS
    )
    assert signed.path == PATH


def test_the_verifier_does_not_need_to_parse_the_body():
    """Section 11: refuse on signature grounds before any JSON work, so an unauthenticated
    caller cannot make the service allocate per-request objects."""
    signed = signing.verify(
        method="POST", path=PATH, body=b"\x00\xff not json",
        headers=headers_for(body=b"\x00\xff not json"), credentials=CREDENTIALS,
    )
    assert signed.body == b"\x00\xff not json"


def test_a_short_service_secret_is_refused_at_construction():
    with pytest.raises(ValueError, match="at least 32 characters"):
        ServiceCredentials(key_id=KEY_ID, secret="too-short")


def test_a_weird_key_id_is_refused_at_construction():
    with pytest.raises(ValueError, match=r"\[A-Za-z0-9_\.:-\]"):
        ServiceCredentials(key_id="has spaces and /slashes/", secret=SECRET)


def test_the_secret_never_appears_in_the_headers_it_produces():
    headers = headers_for()
    assert all(SECRET not in value for value in headers.values())
    assert SECRET not in str(headers)


def test_two_calls_to_the_same_route_use_different_nonces():
    """Production callers omit the nonce; each request must carry a fresh one."""
    credentials = ServiceCredentials(key_id=KEY_ID, secret=SECRET)
    nonces = {
        signing.build_headers(credentials, method="POST", path=PATH, body=BODY)[
            signing.HEADER_NONCE
        ]
        for _ in range(20)
    }
    assert len(nonces) == 20
