from __future__ import annotations

import base64
import json

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from coreline_auth import AuthenticationFailed, AuthValidationError, generate_webauthn_challenge, verify_passkey_assertion_response, verify_passkey_registration_response


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def test_passkey_registration_and_assertion_verification() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    challenge, challenge_hash = generate_webauthn_challenge()

    registered = verify_passkey_registration_response(
        challenge=challenge,
        expected_challenge_hash=challenge_hash,
        origin="https://app.example.com",
        rp_id="app.example.com",
        credential_id="cred-1",
        public_key_pem=public_pem,
        sign_count=1,
    )

    assert verify_passkey_registration_response(
        challenge=challenge,
        expected_challenge_hash=challenge_hash,
        origin="http://localhost",
        rp_id="localhost",
        credential_id="cred-local",
        public_key_pem=public_pem,
        sign_count=0,
    ).credential_id == "cred-local"

    with pytest.raises(AuthValidationError):
        verify_passkey_registration_response(
            challenge=challenge,
            expected_challenge_hash=challenge_hash,
            origin="http://localhost.evil.example",
            rp_id="localhost.evil.example",
            credential_id="cred-evil",
            public_key_pem=public_pem,
            sign_count=0,
        )

    with pytest.raises(AuthValidationError):
        verify_passkey_registration_response(
            challenge=challenge,
            expected_challenge_hash=challenge_hash,
            origin="https://app.example.com.evil.example",
            rp_id="app.example.com",
            credential_id="cred-evil",
            public_key_pem=public_pem,
            sign_count=0,
        )

    with pytest.raises(AuthValidationError):
        verify_passkey_registration_response(
            challenge=challenge,
            expected_challenge_hash=challenge_hash,
            origin="https://app.example.com",
            rp_id="app.example.com:443",
            credential_id="cred-port",
            public_key_pem=public_pem,
            sign_count=0,
        )

    client_data = json.dumps({"type": "webauthn.get", "challenge": challenge, "origin": "https://app.example.com"}, separators=(",", ":")).encode("utf-8")
    digest = hashes.Hash(hashes.SHA256())
    digest.update(b"app.example.com")
    rp_hash = digest.finalize()
    auth_data = rp_hash + bytes([0x05]) + (2).to_bytes(4, "big")
    digest = hashes.Hash(hashes.SHA256())
    digest.update(client_data)
    client_hash = digest.finalize()
    signature = private_key.sign(auth_data + client_hash, ec.ECDSA(hashes.SHA256()))

    assertion = verify_passkey_assertion_response(
        challenge=challenge,
        expected_challenge_hash=challenge_hash,
        origin="https://app.example.com",
        rp_id="app.example.com",
        credential_id=registered.credential_id,
        public_key_pem=registered.public_key_pem,
        authenticator_data_b64url=_b64url(auth_data),
        client_data_json_b64url=_b64url(client_data),
        signature_b64url=_b64url(signature),
        previous_sign_count=1,
        require_user_verification=True,
    )

    assert assertion.sign_count == 2
    assert assertion.user_present is True
    assert assertion.user_verified is True

    with pytest.raises(AuthenticationFailed):
        verify_passkey_assertion_response(
            challenge=challenge,
            expected_challenge_hash=challenge_hash,
            origin="https://app.example.com",
            rp_id="app.example.com",
            credential_id=registered.credential_id,
            public_key_pem=registered.public_key_pem,
            authenticator_data_b64url=_b64url(auth_data),
            client_data_json_b64url=_b64url(client_data),
            signature_b64url=_b64url(signature),
            previous_sign_count=2,
        )
