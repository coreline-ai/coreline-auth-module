"""Minimal WebAuthn/passkey ceremony helpers.

This module implements the security-critical local verification pieces without
owning browser UX or attestation trust stores. Host applications store the
returned public key and sign counter in `AuthMfaFactor` or their own table.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from dataclasses import dataclass
from urllib.parse import urlparse

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from .errors import AuthenticationFailed, AuthValidationError
from .security import compare_hash, hash_secret

_LOCAL_ORIGIN_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


@dataclass(frozen=True, slots=True)
class VerifiedPasskeyRegistration:
    credential_id: str
    public_key_pem: str
    sign_count: int


@dataclass(frozen=True, slots=True)
class VerifiedPasskeyAssertion:
    credential_id: str
    sign_count: int
    user_present: bool
    user_verified: bool


def generate_webauthn_challenge() -> tuple[str, str]:
    """Return `(challenge, challenge_hash)` for storage."""

    from .security import generate_token

    challenge = generate_token()
    return challenge, hash_secret(challenge)


def verify_passkey_registration_response(
    *,
    challenge: str,
    expected_challenge_hash: str,
    origin: str,
    rp_id: str,
    credential_id: str,
    public_key_pem: str,
    sign_count: int = 0,
) -> VerifiedPasskeyRegistration:
    """Validate server-side registration inputs after browser attestation parsing.

    Full attestation object parsing is intentionally delegated to the host or a
    specialist library. Coreline Auth verifies the challenge binding, origin/RP
    shape, credential id, and public-key parsability before persistence.
    """

    _verify_challenge(challenge, expected_challenge_hash)
    _validate_origin_and_rp(origin=origin, rp_id=rp_id)
    if not credential_id:
        raise AuthValidationError("credential_id is required")
    _load_public_key(public_key_pem)
    if sign_count < 0:
        raise AuthValidationError("sign_count must be non-negative")
    return VerifiedPasskeyRegistration(credential_id=credential_id, public_key_pem=public_key_pem, sign_count=sign_count)


def verify_passkey_assertion_response(
    *,
    challenge: str,
    expected_challenge_hash: str,
    origin: str,
    rp_id: str,
    credential_id: str,
    public_key_pem: str,
    authenticator_data_b64url: str,
    client_data_json_b64url: str,
    signature_b64url: str,
    previous_sign_count: int,
    require_user_verification: bool = False,
) -> VerifiedPasskeyAssertion:
    """Verify a WebAuthn assertion signature and replay counter."""

    _verify_challenge(challenge, expected_challenge_hash)
    _validate_origin_and_rp(origin=origin, rp_id=rp_id)
    if not credential_id:
        raise AuthValidationError("credential_id is required")
    authenticator_data = _b64url_decode(authenticator_data_b64url)
    client_data_json = _b64url_decode(client_data_json_b64url)
    signature = _b64url_decode(signature_b64url)
    client_data = _json_object(client_data_json, context="clientDataJSON")
    if client_data.get("type") != "webauthn.get":
        raise AuthenticationFailed("invalid WebAuthn client data type")
    if client_data.get("origin") != origin:
        raise AuthenticationFailed("invalid WebAuthn origin")
    if client_data.get("challenge") != challenge:
        raise AuthenticationFailed("invalid WebAuthn challenge")
    if len(authenticator_data) < 37:
        raise AuthenticationFailed("invalid authenticator data")
    expected_rp_id_hash = hashlib.sha256(rp_id.encode("utf-8")).digest()
    if not hmac.compare_digest(authenticator_data[:32], expected_rp_id_hash):
        raise AuthenticationFailed("invalid WebAuthn RP ID hash")
    flags = authenticator_data[32]
    user_present = bool(flags & 0x01)
    user_verified = bool(flags & 0x04)
    if not user_present:
        raise AuthenticationFailed("user presence required")
    if require_user_verification and not user_verified:
        raise AuthenticationFailed("user verification required")
    sign_count = int.from_bytes(authenticator_data[33:37], "big")
    if previous_sign_count > 0 and sign_count <= previous_sign_count:
        raise AuthenticationFailed("WebAuthn sign counter replay detected")
    public_key = _load_public_key(public_key_pem)
    client_hash = _sha256(client_data_json)
    _verify_signature(public_key, authenticator_data + client_hash, signature)
    return VerifiedPasskeyAssertion(credential_id=credential_id, sign_count=sign_count, user_present=user_present, user_verified=user_verified)


def _verify_challenge(challenge: str, expected_challenge_hash: str) -> None:
    if not compare_hash(challenge, expected_challenge_hash):
        raise AuthenticationFailed("invalid WebAuthn challenge")


def _validate_origin_and_rp(*, origin: str, rp_id: str) -> None:
    parsed = urlparse(origin)
    origin_host = (parsed.hostname or "").lower().rstrip(".")
    origin_scheme = parsed.scheme.lower()
    if not origin_scheme or not origin_host or parsed.username or parsed.password:
        raise AuthValidationError("invalid WebAuthn origin")
    if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise AuthValidationError("WebAuthn origin must not include a path, query, or fragment")

    is_local_http = origin_scheme == "http" and origin_host in _LOCAL_ORIGIN_HOSTS
    if origin_scheme != "https" and not is_local_http:
        raise AuthValidationError("WebAuthn origin must be HTTPS outside localhost")
    rp_host = rp_id.lower().rstrip(".")
    if not rp_host or "://" in rp_id or "/" in rp_id or "\\" in rp_id or any(char.isspace() or ord(char) < 0x20 or ord(char) == 0x7F for char in rp_id):
        raise AuthValidationError("rp_id must be a host name")
    if ":" in rp_host and rp_host not in _LOCAL_ORIGIN_HOSTS:
        raise AuthValidationError("rp_id must not include a port")

    if is_local_http:
        if rp_host != origin_host:
            raise AuthValidationError("WebAuthn RP ID does not match localhost origin")
        return

    if origin_host != rp_host and not origin_host.endswith(f".{rp_host}"):
        raise AuthValidationError("WebAuthn RP ID does not match origin")


def _load_public_key(public_key_pem: str):
    try:
        return serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise AuthValidationError("invalid passkey public key") from exc


def _verify_signature(public_key, signed: bytes, signature: bytes) -> None:
    try:
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(signature, signed, ec.ECDSA(hashes.SHA256()))
        elif isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(signature, signed, padding.PKCS1v15(), hashes.SHA256())
        else:
            raise AuthValidationError("unsupported passkey public key type")
    except InvalidSignature as exc:
        raise AuthenticationFailed("invalid WebAuthn signature") from exc


def _json_object(data: bytes, *, context: str) -> dict[str, object]:
    try:
        parsed = json.loads(data)
    except json.JSONDecodeError as exc:
        raise AuthenticationFailed(f"invalid {context}") from exc
    if not isinstance(parsed, dict):
        raise AuthenticationFailed(f"invalid {context}")
    return parsed


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode((value + "=" * ((4 - len(value) % 4) % 4)).encode("ascii"))


def _sha256(data: bytes) -> bytes:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize()
