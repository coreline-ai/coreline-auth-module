"""OIDC ID token verification helpers."""

from __future__ import annotations

import base64
import json
import time
from collections.abc import Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from coreline_auth.errors import AuthenticationFailed

from ._utils import _email_verified_from_claim, _json_object, _optional_string
from .models import IdTokenClaims, SocialProfile

def verify_google_id_token(
    id_token: str,
    *,
    audience: str,
    jwks: Mapping[str, object],
    expected_nonce: str | None = None,
    expected_azp: str | None = None,
    now: int | None = None,
    leeway_seconds: int = 60,
    max_age_seconds: int | None = None,
) -> SocialProfile:
    claims = verify_oidc_id_token(
        id_token,
        audience=audience,
        issuer={"https://accounts.google.com", "accounts.google.com"},
        jwks=jwks,
        expected_nonce=expected_nonce,
        expected_azp=expected_azp,
        now=now,
        leeway_seconds=leeway_seconds,
        max_age_seconds=max_age_seconds,
    )
    return SocialProfile(
        provider="google",
        provider_subject=claims.subject,
        email=claims.email,
        email_verified=claims.email_verified,
        display_name=claims.name,
        avatar_url=claims.picture,
    )


def verify_oidc_id_token(
    id_token: str,
    *,
    audience: str,
    issuer: str | set[str],
    jwks: Mapping[str, object],
    expected_nonce: str | None = None,
    expected_azp: str | None = None,
    now: int | None = None,
    leeway_seconds: int = 60,
    max_age_seconds: int | None = None,
) -> IdTokenClaims:
    header, payload, signing_input, signature = _decode_jwt(id_token)
    if header.get("alg") != "RS256":
        raise AuthenticationFailed("ID token must use RS256")
    kid = _optional_string(header.get("kid"))
    if kid is None:
        raise AuthenticationFailed("ID token missing kid")
    key = _jwk_for_kid(jwks, kid)
    _verify_rs256_signature(key, signing_input, signature)

    token_issuer = _optional_string(payload.get("iss"))
    expected_issuers = {issuer} if isinstance(issuer, str) else issuer
    if token_issuer not in expected_issuers:
        raise AuthenticationFailed("ID token issuer mismatch")

    subject = _optional_string(payload.get("sub"))
    if subject is None:
        raise AuthenticationFailed("ID token missing subject")

    token_audience = payload.get("aud")
    if isinstance(token_audience, str):
        audience_ok = token_audience == audience
        normalized_audience: str | tuple[str, ...] = token_audience
    elif isinstance(token_audience, list) and all(isinstance(item, str) for item in token_audience):
        audience_ok = audience in token_audience
        normalized_audience = tuple(token_audience)
    else:
        raise AuthenticationFailed("ID token missing audience")
    if not audience_ok:
        raise AuthenticationFailed("ID token audience mismatch")
    azp = _optional_string(payload.get("azp"))
    if isinstance(normalized_audience, tuple) and len(normalized_audience) > 1:
        expected_party = expected_azp or audience
        if azp != expected_party:
            raise AuthenticationFailed("ID token azp mismatch")
    elif expected_azp is not None and azp != expected_azp:
        raise AuthenticationFailed("ID token azp mismatch")

    current = int(time.time()) if now is None else now
    exp = payload.get("exp")
    if not isinstance(exp, int):
        raise AuthenticationFailed("ID token missing exp")
    if exp + leeway_seconds < current:
        raise AuthenticationFailed("ID token expired")
    iat = payload.get("iat")
    if iat is not None and not isinstance(iat, int):
        raise AuthenticationFailed("ID token invalid iat")
    if iat is not None and iat - leeway_seconds > current:
        raise AuthenticationFailed("ID token issued in the future")
    nbf = payload.get("nbf")
    if nbf is not None and not isinstance(nbf, int):
        raise AuthenticationFailed("ID token invalid nbf")
    if nbf is not None and nbf - leeway_seconds > current:
        raise AuthenticationFailed("ID token not yet valid")
    if max_age_seconds is not None:
        if iat is None:
            raise AuthenticationFailed("ID token missing iat")
        if current - iat > max_age_seconds + leeway_seconds:
            raise AuthenticationFailed("ID token max age exceeded")

    token_nonce = _optional_string(payload.get("nonce"))
    if expected_nonce is not None and token_nonce != expected_nonce:
        raise AuthenticationFailed("ID token nonce mismatch")
    if expected_nonce is None and token_nonce is not None:
        raise AuthenticationFailed("ID token nonce was not expected")

    return IdTokenClaims(
        issuer=token_issuer,
        subject=subject,
        audience=normalized_audience,
        expires_at=exp,
        issued_at=iat,
        email=_optional_string(payload.get("email")),
        email_verified=_email_verified_from_claim(payload.get("email_verified"), email=_optional_string(payload.get("email"))),
        name=_optional_string(payload.get("name")),
        picture=_optional_string(payload.get("picture")),
        nonce=token_nonce,
        authorized_party=azp,
    )


def _decode_jwt(token: str) -> tuple[Mapping[str, object], Mapping[str, object], bytes, bytes]:
    parts = token.split(".")
    if len(parts) != 3:
        raise AuthenticationFailed("ID token must be a compact JWT")
    try:
        header = _json_object(json.loads(_b64url_decode(parts[0])), context="ID token header")
        payload = _json_object(json.loads(_b64url_decode(parts[1])), context="ID token payload")
        signature = _b64url_decode(parts[2])
    except (ValueError, json.JSONDecodeError) as exc:
        raise AuthenticationFailed("ID token is not valid base64url JSON") from exc
    return header, payload, f"{parts[0]}.{parts[1]}".encode("ascii"), signature


def _b64url_decode(value: str) -> bytes:
    padding_len = (-len(value)) % 4
    return base64.urlsafe_b64decode((value + "=" * padding_len).encode("ascii"))


def _jwk_for_kid(jwks: Mapping[str, object], kid: str) -> rsa.RSAPublicKey:
    keys = jwks.get("keys")
    if not isinstance(keys, list):
        raise AuthenticationFailed("JWKS keys must be a list")
    for raw_key in keys:
        if not isinstance(raw_key, Mapping):
            continue
        if raw_key.get("kid") != kid:
            continue
        if raw_key.get("kty") != "RSA":
            raise AuthenticationFailed("ID token key must be RSA")
        n = _optional_string(raw_key.get("n"))
        e = _optional_string(raw_key.get("e"))
        if n is None or e is None:
            raise AuthenticationFailed("RSA JWK missing modulus or exponent")
        numbers = rsa.RSAPublicNumbers(e=_b64url_int(e), n=_b64url_int(n))
        return numbers.public_key()
    raise AuthenticationFailed("ID token kid not found in JWKS")


def _b64url_int(value: str) -> int:
    return int.from_bytes(_b64url_decode(value), "big")


def _verify_rs256_signature(public_key: rsa.RSAPublicKey, signing_input: bytes, signature: bytes) -> None:
    try:
        public_key.verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature as exc:
        raise AuthenticationFailed("ID token signature verification failed") from exc
