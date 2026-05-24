"""TOTP and recovery-code primitives for Coreline Auth."""

from __future__ import annotations

import base64
import hmac
import os
import struct
import time
from hashlib import sha1
from typing import Protocol

from .security import generate_token


class MfaSecretVault(Protocol):
    def store_totp_secret(self, *, factor_id: str, secret: str) -> None: ...
    def load_totp_secret(self, *, factor_id: str) -> str | None: ...


class InMemoryMfaSecretVault:
    """Development vault. Production apps should provide an encrypted vault."""

    def __init__(self) -> None:
        self._secrets: dict[str, str] = {}

    def store_totp_secret(self, *, factor_id: str, secret: str) -> None:
        self._secrets[factor_id] = secret

    def load_totp_secret(self, *, factor_id: str) -> str | None:
        return self._secrets.get(factor_id)


def generate_totp_secret() -> str:
    return base64.b32encode(os.urandom(20)).decode("ascii").rstrip("=")


def generate_recovery_code() -> str:
    return generate_token()[:20]


def totp_code(secret: str, *, timestamp: int | None = None, period_seconds: int = 30, digits: int = 6) -> str:
    current = int(time.time()) if timestamp is None else timestamp
    counter = current // period_seconds
    key = base64.b32decode(_pad_base32(secret), casefold=True)
    digest = hmac.new(key, struct.pack(">Q", counter), sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % (10 ** digits)).zfill(digits)


def verify_totp_code(secret: str, code: str, *, timestamp: int | None = None, window: int = 1, period_seconds: int = 30, digits: int = 6) -> bool:
    return totp_counter_for_code(secret, code, timestamp=timestamp, window=window, period_seconds=period_seconds, digits=digits) is not None


def totp_counter_for_code(secret: str, code: str, *, timestamp: int | None = None, window: int = 1, period_seconds: int = 30, digits: int = 6) -> int | None:
    normalized = "".join(ch for ch in code.strip() if ch.isdigit())
    if len(normalized) != digits:
        return None
    current = int(time.time()) if timestamp is None else timestamp
    current_counter = current // period_seconds
    for step in range(-window, window + 1):
        counter = current_counter + step
        candidate_time = counter * period_seconds
        if hmac.compare_digest(totp_code(secret, timestamp=candidate_time, period_seconds=period_seconds, digits=digits), normalized):
            return counter
    return None


def _pad_base32(value: str) -> str:
    return value + "=" * ((8 - len(value) % 8) % 8)
