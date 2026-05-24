"""Social/OAuth/OIDC value objects and public protocols."""

from __future__ import annotations

import base64
import hashlib
import secrets
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol

from coreline_auth.errors import AuthConfigurationError

from ._utils import _normalize_provider_url, _optional_string, _required_string, _validate_code_verifier

class ProviderTokenVault(Protocol):
    """Optional external vault interface for provider tokens.

    Coreline Auth does not implement or call token persistence by default. Apps
    that need provider API access can implement this protocol with encrypted
    storage and call it outside the connector after successful profile linking.
    """

    def store_provider_token(self, *, provider: str, provider_subject: str, token_response: Mapping[str, object]) -> None:
        """Persist a provider token response in an application-owned encrypted vault."""


@dataclass(frozen=True, slots=True)
class OAuthProviderConfig:
    provider: str
    client_id: str
    client_secret: str
    redirect_uri: str
    scope: str
    auth_url: str
    token_url: str
    userinfo_url: str
    issuer: str | None = None


@dataclass(frozen=True, slots=True)
class OIDCProviderMetadata:
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    userinfo_endpoint: str
    jwks_uri: str | None = None

    @classmethod
    def from_document(cls, data: Mapping[str, object], *, expected_issuer: str | None = None) -> "OIDCProviderMetadata":
        issuer = _required_string(data, "issuer", context="OIDC metadata")
        normalized_issuer = _normalize_provider_url("issuer", issuer, allow_path=True).rstrip("/")
        if expected_issuer is not None and normalized_issuer != _normalize_provider_url("issuer", expected_issuer, allow_path=True).rstrip("/"):
            raise AuthConfigurationError("OIDC metadata issuer does not match configured issuer")

        authorization_endpoint = _normalize_provider_url(
            "authorization_endpoint",
            _required_string(data, "authorization_endpoint", context="OIDC metadata"),
            allow_path=True,
        )
        token_endpoint = _normalize_provider_url(
            "token_endpoint",
            _required_string(data, "token_endpoint", context="OIDC metadata"),
            allow_path=True,
        )
        userinfo_endpoint = _normalize_provider_url(
            "userinfo_endpoint",
            _required_string(data, "userinfo_endpoint", context="OIDC metadata"),
            allow_path=True,
        )
        jwks_uri = _optional_string(data.get("jwks_uri"))
        if jwks_uri is not None:
            jwks_uri = _normalize_provider_url("jwks_uri", jwks_uri, allow_path=True)

        return cls(
            issuer=normalized_issuer,
            authorization_endpoint=authorization_endpoint,
            token_endpoint=token_endpoint,
            userinfo_endpoint=userinfo_endpoint,
            jwks_uri=jwks_uri,
        )


@dataclass(frozen=True, slots=True)
class OAuthPKCE:
    code_verifier: str
    code_challenge: str
    code_challenge_method: str = "S256"

    @classmethod
    def create(cls, *, verifier_bytes: int = 64) -> "OAuthPKCE":
        if verifier_bytes < 32:
            raise ValueError("PKCE verifier must have at least 32 random bytes")
        return cls.from_verifier(secrets.token_urlsafe(verifier_bytes))

    @classmethod
    def from_verifier(cls, code_verifier: str) -> "OAuthPKCE":
        _validate_code_verifier(code_verifier)
        digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
        code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
        return cls(code_verifier=code_verifier, code_challenge=code_challenge)


@dataclass(frozen=True, slots=True)
class SocialProfile:
    provider: str
    provider_subject: str
    email: str | None
    email_verified: bool
    display_name: str | None = None
    avatar_url: str | None = None


@dataclass(frozen=True, slots=True)
class OAuthStart:
    authorization_url: str
    state: str
    nonce: str | None = None
    code_verifier: str | None = None


@dataclass(frozen=True, slots=True)
class IdTokenClaims:
    issuer: str
    subject: str
    audience: str | tuple[str, ...]
    expires_at: int
    issued_at: int | None = None
    email: str | None = None
    email_verified: bool = False
    name: str | None = None
    picture: str | None = None
    nonce: str | None = None
    authorized_party: str | None = None
