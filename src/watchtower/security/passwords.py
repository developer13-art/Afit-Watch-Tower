"""Password hashing for local accounts.

Two formats are accepted, deliberately:

  * `argon2id` - what new hashes use whenever the `argon2-cffi` package is importable. It is
    the memory-hard choice the mobile proposal asks for.
  * `pbkdf2_sha256$iterations$salt$digest` - the original format, written before the cloud
    service existed. Those hashes still verify, and every successful login re-hashes the
    account to Argon2id (see `needs_rehash`), so a deployment migrates as its users sign in
    rather than by a bulk rewrite that would invalidate sessions.

The fallback is not optional in the other direction: if `argon2-cffi` is missing, new hashes
are still PBKDF2 with a recorded iteration count, so the product never becomes unable to run
because a compiled dependency is absent. Iteration count is recorded in the stored hash so it
can be raised later without stranding existing logins.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

_ALGORITHM = "pbkdf2_sha256"
_DEFAULT_ITERATIONS = 310_000
_ARGON2_PREFIX = "$argon2id$"
MIN_PASSWORD_LENGTH = 12


def _password_too_short() -> ValueError:
    return ValueError(
        f"Password must be at least {MIN_PASSWORD_LENGTH} characters (institutional admin credential)."
    )


try:  # pragma: no cover - the import either works or it does not
    from argon2 import PasswordHasher
    from argon2.exceptions import VerificationError

    _argon2 = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2, hash_len=32, salt_len=16)
except ImportError:  # pragma: no cover
    PasswordHasher = None  # type: ignore[assignment]
    VerificationError = Exception  # type: ignore[assignment]
    _argon2 = None


def argon2_available() -> bool:
    return _argon2 is not None


def hash_password(password: str, *, iterations: int = _DEFAULT_ITERATIONS) -> str:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise _password_too_short()
    if _argon2 is not None:
        return _argon2.hash(password)
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return f"{_ALGORITHM}${iterations}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    if not stored or not password:
        return False
    if stored.startswith(_ARGON2_PREFIX):
        if _argon2 is None:
            # An Argon2id hash cannot be checked without the library. Refusing the login is
            # the only safe answer; pretending to verify would be worse than an outage.
            return False
        try:
            return _argon2.verify(stored, password)
        except VerificationError:
            return False
        except Exception:  # noqa: BLE001 - a malformed hash is a failed login, not a 500
            return False
    try:
        algorithm, iterations, salt_hex, digest_hex = stored.split("$")
        if algorithm != _ALGORITHM:
            return False
        candidate = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), bytes.fromhex(salt_hex), int(iterations)
        )
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(candidate.hex(), digest_hex)


def needs_rehash(stored: str) -> bool:
    """True for every PBKDF2 hash - that is the documented upgrade path on login."""
    if not stored:
        return False
    if stored.startswith(_ARGON2_PREFIX):
        if _argon2 is None:
            return False
        try:
            return _argon2.check_needs_rehash(stored)
        except Exception:  # noqa: BLE001 - an unreadable hash is re-hashed from scratch
            return True
    try:
        return int(stored.split("$")[1]) < _DEFAULT_ITERATIONS
    except (IndexError, ValueError):
        return True


def hash_kind(stored: str) -> str:
    """Which format a stored hash uses. For reports and tests, never for a response body."""
    if stored.startswith(_ARGON2_PREFIX):
        return "argon2id"
    return stored.split("$", 1)[0] if "$" in stored else "unknown"
