"""OAuth provider connector implementations."""

from __future__ import annotations

import secrets
from collections.abc import Mapping
from dataclasses import replace

import httpx

from coreline_auth.errors import AuthConfigurationError, AuthenticationFailed

from ._utils import (
    _RESERVED_AUTH_PARAMS,
    _append_query,
    _email_verified_from_claim,
    _extract_access_token,
    _normalize_provider_url,
    _optional_string,
    _require_openid_scope,
    _response_json_object,
)
from .discovery import OIDCMetadataFetcher, discover_oidc_metadata
from .models import OAuthPKCE, OAuthProviderConfig, OAuthStart, OIDCProviderMetadata, SocialProfile
from .verification import verify_google_id_token, verify_oidc_id_token

class OAuthConnector:
    def __init__(self, config: OAuthProviderConfig) -> None:
        if not config.client_id or not config.client_secret or not config.redirect_uri:
            raise AuthConfigurationError(f"{config.provider} OAuth connector requires client_id, client_secret and redirect_uri")
        auth_url = _normalize_provider_url("auth_url", config.auth_url, allow_path=True)
        token_url = _normalize_provider_url("token_url", config.token_url, allow_path=True)
        userinfo_url = _normalize_provider_url("userinfo_url", config.userinfo_url, allow_path=True)
        redirect_uri = _normalize_provider_url("redirect_uri", config.redirect_uri, allow_path=True)
        issuer = _normalize_provider_url("issuer", config.issuer, allow_path=True).rstrip("/") if config.issuer is not None else None
        self.config = replace(
            config,
            auth_url=auth_url,
            token_url=token_url,
            userinfo_url=userinfo_url,
            redirect_uri=redirect_uri,
            issuer=issuer,
        )

    def authorization_url(
        self,
        *,
        state: str,
        nonce: str | None = None,
        code_challenge: str | None = None,
        code_challenge_method: str = "S256",
        prompt: str | None = None,
        extra_params: Mapping[str, object | None] | None = None,
    ) -> str:
        query: dict[str, str] = {
            "client_id": self.config.client_id,
            "redirect_uri": self.config.redirect_uri,
            "response_type": "code",
            "scope": self.config.scope,
            "state": state,
        }
        if nonce is not None:
            query["nonce"] = nonce
        if code_challenge is not None:
            query["code_challenge"] = code_challenge
            query["code_challenge_method"] = code_challenge_method or "S256"
        if prompt is not None:
            query["prompt"] = prompt
        if extra_params:
            for key, value in extra_params.items():
                if key in _RESERVED_AUTH_PARAMS:
                    raise AuthConfigurationError(f"authorization_url extra_params cannot override reserved OAuth parameter: {key}")
                if value is not None:
                    query[key] = str(value)
        return _append_query(self.config.auth_url, query)

    def start_authorization(
        self,
        *,
        state: str,
        nonce: str | None = None,
        pkce: OAuthPKCE | None = None,
        prompt: str | None = None,
        extra_params: Mapping[str, object | None] | None = None,
    ) -> OAuthStart:
        return OAuthStart(
            authorization_url=self.authorization_url(
                state=state,
                nonce=nonce,
                code_challenge=pkce.code_challenge if pkce else None,
                code_challenge_method=pkce.code_challenge_method if pkce else "S256",
                prompt=prompt,
                extra_params=extra_params,
            ),
            state=state,
            nonce=nonce,
            code_verifier=pkce.code_verifier if pkce else None,
        )

    def exchange_code(
        self,
        *,
        code: str,
        code_verifier: str | None = None,
        expected_nonce: str | None = None,
        id_token_jwks: Mapping[str, object] | None = None,
        id_token_audience: str | None = None,
        id_token_issuer: str | set[str] | None = None,
        expected_azp: str | None = None,
        max_age_seconds: int | None = None,
        timeout_seconds: float = 10.0,
        max_response_bytes: int = 64 * 1024,
    ) -> SocialProfile:
        token_request: dict[str, str] = {
            "client_id": self.config.client_id,
            "client_secret": self.config.client_secret,
            "redirect_uri": self.config.redirect_uri,
            "grant_type": "authorization_code",
            "code": code,
        }
        if code_verifier is not None:
            token_request["code_verifier"] = code_verifier
        token_response = httpx.post(
            self.config.token_url,
            data=token_request,
            timeout=timeout_seconds,
        )
        token_response.raise_for_status()
        token_data = _response_json_object(token_response, context="provider token response", max_bytes=max_response_bytes)

        if expected_nonce is not None or id_token_jwks is not None:
            if id_token_jwks is None:
                raise AuthConfigurationError("ID token JWKS is required for nonce/ID token verification")
            id_token = _optional_string(token_data.get("id_token"))
            if id_token is None:
                raise AuthenticationFailed("provider did not return an ID token")
            audience = id_token_audience or self.config.client_id
            if self.config.provider == "google":
                return verify_google_id_token(
                    id_token,
                    audience=audience,
                    jwks=id_token_jwks,
                    expected_nonce=expected_nonce,
                    expected_azp=expected_azp,
                    max_age_seconds=max_age_seconds,
                )
            issuer = id_token_issuer or self.config.issuer
            if issuer is None:
                raise AuthConfigurationError("OIDC issuer is required for ID token verification")
            claims = verify_oidc_id_token(
                id_token,
                audience=audience,
                issuer=issuer,
                jwks=id_token_jwks,
                expected_nonce=expected_nonce,
                expected_azp=expected_azp,
                max_age_seconds=max_age_seconds,
            )
            return SocialProfile(
                provider=self.config.provider,
                provider_subject=claims.subject,
                email=claims.email,
                email_verified=claims.email_verified,
                display_name=claims.name,
                avatar_url=claims.picture,
            )

        access_token = _extract_access_token(token_data)

        userinfo_response = httpx.get(
            self.config.userinfo_url,
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=timeout_seconds,
        )
        userinfo_response.raise_for_status()
        userinfo_data = _response_json_object(userinfo_response, context="provider userinfo response", max_bytes=max_response_bytes)
        return self.profile_from_userinfo(userinfo_data)

    def profile_from_userinfo(self, data: Mapping[str, object]) -> SocialProfile:
        subject = _optional_string(data.get("sub")) or _optional_string(data.get("id"))
        if subject is None:
            raise AuthenticationFailed("provider userinfo missing subject")
        email = _optional_string(data.get("email"))
        name = _optional_string(data.get("name"))
        avatar = _optional_string(data.get("picture"))
        email_verified = _email_verified_from_claim(data.get("email_verified"), email=email)
        return SocialProfile(
            provider=self.config.provider,
            provider_subject=subject,
            email=email,
            email_verified=email_verified,
            display_name=name,
            avatar_url=avatar,
        )


class GenericOIDCConnector(OAuthConnector):
    @classmethod
    def from_endpoints(
        cls,
        *,
        provider: str,
        issuer: str,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        auth_url: str,
        token_url: str,
        userinfo_url: str,
        scope: str = "openid email profile",
    ) -> "GenericOIDCConnector":
        _require_openid_scope(scope)
        metadata = OIDCProviderMetadata(
            issuer=_normalize_provider_url("issuer", issuer, allow_path=True).rstrip("/"),
            authorization_endpoint=_normalize_provider_url("authorization_endpoint", auth_url, allow_path=True),
            token_endpoint=_normalize_provider_url("token_endpoint", token_url, allow_path=True),
            userinfo_endpoint=_normalize_provider_url("userinfo_endpoint", userinfo_url, allow_path=True),
        )
        return cls.from_metadata(
            provider=provider,
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=redirect_uri,
            metadata=metadata,
            scope=scope,
        )

    @classmethod
    def from_metadata(
        cls,
        *,
        provider: str,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        metadata: OIDCProviderMetadata | Mapping[str, object],
        scope: str = "openid email profile",
        expected_issuer: str | None = None,
    ) -> "GenericOIDCConnector":
        _require_openid_scope(scope)
        metadata_obj = (
            metadata
            if isinstance(metadata, OIDCProviderMetadata)
            else OIDCProviderMetadata.from_document(metadata, expected_issuer=expected_issuer)
        )
        if expected_issuer is not None and metadata_obj.issuer != _normalize_provider_url("issuer", expected_issuer, allow_path=True).rstrip("/"):
            raise AuthConfigurationError("OIDC metadata issuer does not match configured issuer")
        return cls(
            OAuthProviderConfig(
                provider=provider,
                client_id=client_id,
                client_secret=client_secret,
                redirect_uri=redirect_uri,
                scope=scope,
                auth_url=metadata_obj.authorization_endpoint,
                token_url=metadata_obj.token_endpoint,
                userinfo_url=metadata_obj.userinfo_endpoint,
                issuer=metadata_obj.issuer,
            )
        )

    @classmethod
    def from_issuer(
        cls,
        *,
        provider: str,
        issuer: str,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        scope: str = "openid email profile",
        metadata_fetcher: OIDCMetadataFetcher | None = None,
        timeout_seconds: float = 10.0,
    ) -> "GenericOIDCConnector":
        metadata = discover_oidc_metadata(issuer=issuer, fetcher=metadata_fetcher, timeout_seconds=timeout_seconds)
        return cls.from_metadata(
            provider=provider,
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=redirect_uri,
            metadata=metadata,
            scope=scope,
            expected_issuer=issuer,
        )

    def profile_from_userinfo(self, data: Mapping[str, object]) -> SocialProfile:
        subject = _optional_string(data.get("sub"))
        if subject is None:
            raise AuthenticationFailed("OIDC userinfo missing sub")
        email = _optional_string(data.get("email"))
        name = _optional_string(data.get("name"))
        avatar = _optional_string(data.get("picture"))
        email_verified = _email_verified_from_claim(data.get("email_verified"), email=email)
        return SocialProfile(
            provider=self.config.provider,
            provider_subject=subject,
            email=email,
            email_verified=email_verified,
            display_name=name,
            avatar_url=avatar,
        )


class GoogleOAuthConnector(OAuthConnector):
    @classmethod
    def from_credentials(cls, *, client_id: str, client_secret: str, redirect_uri: str) -> "GoogleOAuthConnector":
        return cls(
            OAuthProviderConfig(
                provider="google",
                client_id=client_id,
                client_secret=client_secret,
                redirect_uri=redirect_uri,
                scope="openid email profile",
                auth_url="https://accounts.google.com/o/oauth2/v2/auth",
                token_url="https://oauth2.googleapis.com/token",
                userinfo_url="https://openidconnect.googleapis.com/v1/userinfo",
                issuer="https://accounts.google.com",
            )
        )


class FacebookOAuthConnector(OAuthConnector):
    @classmethod
    def from_credentials(cls, *, client_id: str, client_secret: str, redirect_uri: str) -> "FacebookOAuthConnector":
        return cls(
            OAuthProviderConfig(
                provider="facebook",
                client_id=client_id,
                client_secret=client_secret,
                redirect_uri=redirect_uri,
                scope="email public_profile",
                auth_url="https://www.facebook.com/v19.0/dialog/oauth",
                token_url="https://graph.facebook.com/v19.0/oauth/access_token",
                userinfo_url="https://graph.facebook.com/me?fields=id,name,email,picture",
            )
        )

    def profile_from_userinfo(self, data: Mapping[str, object]) -> SocialProfile:
        subject = _optional_string(data.get("id"))
        if subject is None:
            raise AuthenticationFailed("facebook userinfo missing id")
        email = _optional_string(data.get("email"))
        name = _optional_string(data.get("name"))
        picture_url = None
        picture = data.get("picture")
        if isinstance(picture, Mapping):
            nested = picture.get("data")
            if isinstance(nested, Mapping):
                picture_url = _optional_string(nested.get("url"))
        if "email_verified" in data:
            email_verified = _email_verified_from_claim(data.get("email_verified"), email=email)
        else:
            # Facebook Graph does not return an email_verified claim in the
            # default profile response; keep existing connector behavior.
            email_verified = bool(email)
        return SocialProfile(
            provider="facebook",
            provider_subject=subject,
            email=email,
            email_verified=email_verified,
            display_name=name,
            avatar_url=picture_url,
        )


class DevSocialConnector:
    """Deterministic local connector for self-test webapps."""

    def __init__(self, provider: str) -> None:
        self.provider = provider

    def fake_profile(self, *, email: str | None = None, display_name: str | None = None) -> SocialProfile:
        safe_email = email or f"{self.provider}-user-{secrets.token_hex(3)}@example.com"
        return SocialProfile(
            provider=self.provider,
            provider_subject=f"dev:{safe_email.lower()}",
            email=safe_email.lower(),
            email_verified=True,
            display_name=display_name or f"Demo {self.provider.title()} User",
        )
