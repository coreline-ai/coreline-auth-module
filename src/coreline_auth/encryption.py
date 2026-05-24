"""Authenticated encryption helpers for host-managed secrets."""

from __future__ import annotations

import base64
import binascii
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .errors import AuthConfigurationError, AuthValidationError


class SecretEnvelopeProtector:
    """AES-256-GCM envelope protector for sensitive extension secrets.

    The protector is intentionally small and stateless. Host applications own
    master-key generation, storage, and rotation policy; Coreline Auth only
    validates the key shape and performs authenticated encryption/decryption.
    """

    prefix = "v1.aes256gcm."

    def __init__(self, master_key_b64: str) -> None:
        try:
            key = base64.b64decode(master_key_b64.encode("ascii"), validate=True)
        except Exception as exc:  # noqa: BLE001 - normalize unsafe config errors
            raise AuthConfigurationError("envelope master key must be base64") from exc
        if len(key) != 32:
            raise AuthConfigurationError("envelope master key must decode to 32 bytes")
        self._aesgcm = AESGCM(key)

    @staticmethod
    def generate_master_key() -> str:
        """Return a base64 encoded 256-bit key suitable for this protector."""

        return base64.b64encode(os.urandom(32)).decode("ascii")

    def encrypt(self, plaintext: str, *, aad: bytes | None = None) -> str:
        nonce = os.urandom(12)
        ciphertext = self._aesgcm.encrypt(nonce, plaintext.encode("utf-8"), aad)
        return self.prefix + base64.b64encode(nonce + ciphertext).decode("ascii")

    def decrypt(self, token: str, *, aad: bytes | None = None) -> str:
        try:
            if not token.startswith(self.prefix):
                raise ValueError("unsupported format")
            encoded = token[len(self.prefix):]
            data = base64.b64decode(encoded.encode("ascii"), validate=True)
            if len(data) < 13:
                raise ValueError("payload too short")
            nonce, ciphertext = data[:12], data[12:]
            return self._aesgcm.decrypt(nonce, ciphertext, aad).decode("utf-8")
        except (InvalidTag, UnicodeDecodeError, ValueError, UnicodeEncodeError, binascii.Error) as exc:
            raise AuthValidationError("invalid encrypted secret") from exc
