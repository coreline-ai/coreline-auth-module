"""Security helpers using proven libraries and high-entropy opaque tokens."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from urllib.parse import urlparse

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, VerifyMismatchError

from .errors import AuthValidationError

_TOKEN_BYTES = 32
_password_hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4, hash_len=32, salt_len=16)
_DUMMY_PASSWORD_HASH = _password_hasher.hash("coreline-auth-dummy-password")


def generate_token() -> str:
    return secrets.token_urlsafe(_TOKEN_BYTES)


def hash_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def compare_hash(secret: str, expected_hash: str) -> bool:
    return hmac.compare_digest(hash_secret(secret), expected_hash)


def hash_optional_context(value: str | None) -> str | None:
    return hash_secret(value) if value else None


def hash_password(password: str) -> str:
    if len(password) < 8:
        raise AuthValidationError("password must be at least 8 characters")
    return _password_hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _password_hasher.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError):
        return False


def verify_dummy_password(password: str) -> None:
    """Run one Argon2 verification for login timing hardening.

    This is used when a user or password credential is missing so that public
    login failure paths do not skip the expensive password verifier entirely.
    """

    verify_password(_DUMMY_PASSWORD_HASH, password)


@dataclass(frozen=True, slots=True)
class SafeReturnToPolicy:
    """Allow only same-site relative redirects by default."""

    def validate(self, return_to: str | None) -> str:
        if not return_to:
            return "/"
        parsed = urlparse(return_to)
        if parsed.scheme or parsed.netloc:
            raise AuthValidationError("return_to must be a same-site relative path")
        if not return_to.startswith("/") or return_to.startswith("//"):
            raise AuthValidationError("return_to must start with a single '/'")
        return return_to
