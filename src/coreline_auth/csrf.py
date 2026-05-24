"""Double-submit CSRF helper for cookie-based host apps."""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass

from .errors import AuthConfigurationError, AuthValidationError
from .security import generate_token

_MIN_SECRET_UNIQUE_CHARS = 8
_WEAK_SECRET_MARKERS = ("demo", "test", "changeme", "password")


@dataclass(frozen=True, slots=True)
class CsrfToken:
    nonce: str
    signature: str

    @property
    def value(self) -> str:
        return f"{self.nonce}.{self.signature}"


@dataclass(frozen=True, slots=True)
class CsrfProtector:
    secret_key: str
    allow_weak_dev_secret: bool = False

    def __post_init__(self) -> None:
        if len(self.secret_key) < 32:
            raise AuthConfigurationError("csrf secret_key must be at least 32 characters")
        if not self.allow_weak_dev_secret and _looks_weak_secret(self.secret_key):
            raise AuthConfigurationError("csrf secret_key must be high-entropy; use allow_weak_dev_secret=True only for local demos/tests")

    def issue(self, *, session_token_hash: str) -> CsrfToken:
        return self.issue_for_context(context_key=session_token_hash)

    def verify(self, token: str, *, session_token_hash: str) -> None:
        self.verify_for_context(token, context_key=session_token_hash)

    def issue_global(self) -> CsrfToken:
        return self.issue_for_context(context_key="anonymous")

    def verify_global(self, token: str) -> None:
        self.verify_for_context(token, context_key="anonymous")

    def issue_for_context(self, *, context_key: str) -> CsrfToken:
        nonce = generate_token()
        return CsrfToken(nonce=nonce, signature=self._sign(nonce, context_key))

    def verify_for_context(self, token: str, *, context_key: str) -> None:
        nonce, sep, signature = token.partition(".")
        if not sep or not nonce or not signature:
            raise AuthValidationError("invalid csrf token")
        if not hmac.compare_digest(signature, self._sign(nonce, context_key)):
            raise AuthValidationError("invalid csrf token")

    def _sign(self, nonce: str, context_key: str) -> str:
        message = f"{context_key}:{nonce}".encode("utf-8")
        return hmac.new(self.secret_key.encode("utf-8"), message, hashlib.sha256).hexdigest()


def _looks_weak_secret(secret_key: str) -> bool:
    lowered = secret_key.lower()
    if len(set(secret_key)) < _MIN_SECRET_UNIQUE_CHARS:
        return True
    return any(marker in lowered for marker in _WEAK_SECRET_MARKERS)
