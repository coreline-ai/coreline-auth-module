"""Security helpers using proven libraries and high-entropy opaque tokens."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from urllib.parse import urlparse

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, VerifyMismatchError
from email_validator import EmailNotValidError, validate_email

from .errors import AuthValidationError

_TOKEN_BYTES = 32
_MAX_RETURN_TO_BYTES = 2048
_UNSAFE_RETURN_TO_CHARS = frozenset({"<", ">", '"', "'", "`", "\\", "\r", "\n", "\t"})
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


def normalize_email_address(email: str) -> str:
    """Validate and canonicalize user email input before storage or SMTP use."""

    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in email):
        raise AuthValidationError("invalid email")
    try:
        validated = validate_email(email.strip(), check_deliverability=False)
    except EmailNotValidError as exc:
        raise AuthValidationError("invalid email") from exc
    normalized = validated.normalized.lower()
    if len(normalized) > 320:
        raise AuthValidationError("invalid email")
    return normalized


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
        if len(return_to.encode("utf-8")) > _MAX_RETURN_TO_BYTES:
            raise AuthValidationError("return_to is too long")
        if any(char in _UNSAFE_RETURN_TO_CHARS or ord(char) < 0x20 or ord(char) == 0x7F for char in return_to):
            raise AuthValidationError("return_to contains unsafe characters")
        parsed = urlparse(return_to)
        if parsed.scheme or parsed.netloc:
            raise AuthValidationError("return_to must be a same-site relative path")
        if not return_to.startswith("/") or return_to.startswith("//"):
            raise AuthValidationError("return_to must start with a single '/'")
        return return_to
