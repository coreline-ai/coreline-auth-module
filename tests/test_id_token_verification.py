from __future__ import annotations

import base64
import json

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from coreline_auth import verify_google_id_token, verify_oidc_id_token
from coreline_auth.errors import AuthenticationFailed


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _jwk_for_private_key(private_key, *, kid: str) -> dict[str, object]:
    public_numbers = private_key.public_key().public_numbers()
    return {
        "kty": "RSA",
        "kid": kid,
        "alg": "RS256",
        "use": "sig",
        "n": _b64url(public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, "big")),
        "e": _b64url(public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, "big")),
    }


def _jwt(private_key, *, kid: str, payload: dict[str, object]) -> str:
    header = {"alg": "RS256", "typ": "JWT", "kid": kid}
    encoded_header = _b64url(json.dumps(header, separators=(",", ":")).encode())
    encoded_payload = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{encoded_header}.{encoded_payload}".encode("ascii")
    signature = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return f"{encoded_header}.{encoded_payload}.{_b64url(signature)}"


def test_google_id_token_verifies_rs256_jwks_audience_issuer_and_nonce() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwks = {"keys": [_jwk_for_private_key(private_key, kid="kid-1")]}
    token = _jwt(
        private_key,
        kid="kid-1",
        payload={
            "iss": "https://accounts.google.com",
            "sub": "google-subject",
            "aud": "client-id",
            "exp": 2_000,
            "iat": 1_000,
            "email": "user@example.com",
            "email_verified": True,
            "name": "User",
            "picture": "https://example.com/p.png",
            "nonce": "nonce-1",
        },
    )

    profile = verify_google_id_token(token, audience="client-id", jwks=jwks, expected_nonce="nonce-1", now=1_200)

    assert profile.provider == "google"
    assert profile.provider_subject == "google-subject"
    assert profile.email == "user@example.com"
    assert profile.email_verified is True
    assert profile.display_name == "User"


def test_oidc_id_token_rejects_bad_audience_expired_and_bad_signature() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwks = {"keys": [_jwk_for_private_key(private_key, kid="kid-1")]}
    payload = {"iss": "https://issuer.example.com", "sub": "sub", "aud": "client-id", "exp": 2_000, "iat": 1_000}
    token = _jwt(private_key, kid="kid-1", payload=payload)

    assert verify_oidc_id_token(token, audience="client-id", issuer="https://issuer.example.com", jwks=jwks, now=1_200).subject == "sub"
    with pytest.raises(AuthenticationFailed, match="audience"):
        verify_oidc_id_token(token, audience="other-client", issuer="https://issuer.example.com", jwks=jwks, now=1_200)
    with pytest.raises(AuthenticationFailed, match="expired"):
        verify_oidc_id_token(token, audience="client-id", issuer="https://issuer.example.com", jwks=jwks, now=3_000)

    bad_token = _jwt(other_key, kid="kid-1", payload=payload)
    with pytest.raises(AuthenticationFailed, match="signature"):
        verify_oidc_id_token(bad_token, audience="client-id", issuer="https://issuer.example.com", jwks=jwks, now=1_200)


def test_oidc_id_token_validates_azp_nbf_and_max_age() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwks = {"keys": [_jwk_for_private_key(private_key, kid="kid-1")]}
    base_payload = {
        "iss": "https://issuer.example.com",
        "sub": "sub",
        "aud": ["client-id", "other-client"],
        "azp": "client-id",
        "exp": 2_000,
        "iat": 1_000,
        "nbf": 900,
    }
    token = _jwt(private_key, kid="kid-1", payload=base_payload)

    claims = verify_oidc_id_token(
        token,
        audience="client-id",
        issuer="https://issuer.example.com",
        jwks=jwks,
        now=1_200,
        max_age_seconds=500,
    )
    assert claims.authorized_party == "client-id"

    missing_azp = _jwt(private_key, kid="kid-1", payload={**base_payload, "azp": None})
    with pytest.raises(AuthenticationFailed, match="azp"):
        verify_oidc_id_token(missing_azp, audience="client-id", issuer="https://issuer.example.com", jwks=jwks, now=1_200)

    future_nbf = _jwt(private_key, kid="kid-1", payload={**base_payload, "nbf": 1_500})
    with pytest.raises(AuthenticationFailed, match="not yet valid"):
        verify_oidc_id_token(future_nbf, audience="client-id", issuer="https://issuer.example.com", jwks=jwks, now=1_200, leeway_seconds=0)

    with pytest.raises(AuthenticationFailed, match="max age"):
        verify_oidc_id_token(token, audience="client-id", issuer="https://issuer.example.com", jwks=jwks, now=1_800, max_age_seconds=100)


def test_oidc_id_token_rejects_unexpected_nonce_claim() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwks = {"keys": [_jwk_for_private_key(private_key, kid="kid-1")]}
    token = _jwt(
        private_key,
        kid="kid-1",
        payload={"iss": "https://issuer.example.com", "sub": "sub", "aud": "client-id", "exp": 2_000, "iat": 1_000, "nonce": "unexpected"},
    )

    with pytest.raises(AuthenticationFailed, match="nonce was not expected"):
        verify_oidc_id_token(token, audience="client-id", issuer="https://issuer.example.com", jwks=jwks, now=1_200)


def test_oidc_id_token_rejects_alg_none_and_hs256() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwks = {"keys": [_jwk_for_private_key(private_key, kid="kid-1")]}
    payload = {"iss": "https://issuer.example.com", "sub": "sub", "aud": "client-id", "exp": 2_000, "iat": 1_000}

    none_header = _b64url(json.dumps({"alg": "none", "typ": "JWT", "kid": "kid-1"}, separators=(",", ":")).encode())
    encoded_payload = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    none_token = f"{none_header}.{encoded_payload}."
    with pytest.raises(AuthenticationFailed, match="RS256"):
        verify_oidc_id_token(none_token, audience="client-id", issuer="https://issuer.example.com", jwks=jwks, now=1_200)

    hs_header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT", "kid": "kid-1"}, separators=(",", ":")).encode())
    hs_token = f"{hs_header}.{encoded_payload}.{_b64url(b'forged-hmac')}"
    with pytest.raises(AuthenticationFailed, match="RS256"):
        verify_oidc_id_token(hs_token, audience="client-id", issuer="https://issuer.example.com", jwks=jwks, now=1_200)
