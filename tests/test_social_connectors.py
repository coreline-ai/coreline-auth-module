from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import pytest

from coreline_auth import FacebookOAuthConnector, GenericOIDCConnector, GoogleOAuthConnector, JWKSCache, OIDCMetadataClient, OAuthPKCE, discover_oidc_metadata, redact_token_response
from coreline_auth.errors import AuthConfigurationError, AuthenticationFailed


def _query(url: str) -> dict[str, list[str]]:
    return parse_qs(urlparse(url).query)


def _oidc_connector() -> GenericOIDCConnector:
    return GenericOIDCConnector.from_endpoints(
        provider="example-oidc",
        issuer="https://id.example.com",
        client_id="client-id",
        client_secret="client-secret",
        redirect_uri="https://app.example.com/callback",
        auth_url="https://id.example.com/oauth2/auth",
        token_url="https://id.example.com/oauth2/token",
        userinfo_url="https://id.example.com/oauth2/userinfo",
    )


def test_authorization_url_preserves_google_defaults_and_supports_oidc_pkce_params() -> None:
    connector = GoogleOAuthConnector.from_credentials(
        client_id="google-client",
        client_secret="google-secret",
        redirect_uri="https://app.example.com/social/google/callback",
    )

    default_query = _query(connector.authorization_url(state="state-1"))
    assert default_query["client_id"] == ["google-client"]
    assert default_query["redirect_uri"] == ["https://app.example.com/social/google/callback"]
    assert default_query["response_type"] == ["code"]
    assert default_query["scope"] == ["openid email profile"]
    assert default_query["state"] == ["state-1"]
    assert "nonce" not in default_query
    assert "code_challenge" not in default_query

    pkce = OAuthPKCE.from_verifier("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
    assert pkce.code_challenge == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    assert pkce.code_challenge_method == "S256"

    hardened_query = _query(
        connector.authorization_url(
            state="state-2",
            nonce="nonce-123",
            code_challenge=pkce.code_challenge,
            prompt="consent",
            extra_params={"login_hint": "user@example.com"},
        )
    )
    assert hardened_query["state"] == ["state-2"]
    assert hardened_query["nonce"] == ["nonce-123"]
    assert hardened_query["code_challenge"] == [pkce.code_challenge]
    assert hardened_query["code_challenge_method"] == ["S256"]
    assert hardened_query["prompt"] == ["consent"]
    assert hardened_query["login_hint"] == ["user@example.com"]


def test_authorization_url_rejects_reserved_extra_param_override() -> None:
    connector = _oidc_connector()
    with pytest.raises(AuthConfigurationError):
        connector.authorization_url(state="state", extra_params={"state": "attacker-state"})


def test_start_authorization_returns_url_state_nonce_and_pkce_verifier() -> None:
    connector = _oidc_connector()
    pkce = OAuthPKCE.create()

    start = connector.start_authorization(state="state", nonce="nonce", pkce=pkce, prompt="login")

    query = _query(start.authorization_url)
    assert start.state == "state"
    assert start.nonce == "nonce"
    assert start.code_verifier == pkce.code_verifier
    assert query["code_challenge"] == [pkce.code_challenge]
    assert query["code_challenge_method"] == ["S256"]
    assert query["prompt"] == ["login"]


def test_generic_oidc_connector_uses_mockable_metadata_discovery() -> None:
    calls: list[str] = []

    def fetcher(url: str) -> dict[str, object]:
        calls.append(url)
        return {
            "issuer": "https://issuer.example.com",
            "authorization_endpoint": "https://issuer.example.com/oauth2/v1/authorize",
            "token_endpoint": "https://issuer.example.com/oauth2/v1/token",
            "userinfo_endpoint": "https://issuer.example.com/oauth2/v1/userinfo",
            "jwks_uri": "https://issuer.example.com/oauth2/v1/keys",
        }

    connector = GenericOIDCConnector.from_issuer(
        provider="generic",
        issuer="https://issuer.example.com/",
        client_id="client-id",
        client_secret="client-secret",
        redirect_uri="https://app.example.com/callback",
        metadata_fetcher=fetcher,
    )

    assert calls == ["https://issuer.example.com/.well-known/openid-configuration"]
    assert connector.config.provider == "generic"
    assert connector.config.issuer == "https://issuer.example.com"
    assert connector.config.auth_url == "https://issuer.example.com/oauth2/v1/authorize"
    assert connector.config.token_url == "https://issuer.example.com/oauth2/v1/token"
    assert connector.config.userinfo_url == "https://issuer.example.com/oauth2/v1/userinfo"


def test_oidc_metadata_rejects_issuer_mismatch_and_missing_endpoints() -> None:
    with pytest.raises(AuthConfigurationError):
        discover_oidc_metadata(
            issuer="https://issuer.example.com",
            fetcher=lambda _url: {
                "issuer": "https://other.example.com",
                "authorization_endpoint": "https://issuer.example.com/auth",
                "token_endpoint": "https://issuer.example.com/token",
                "userinfo_endpoint": "https://issuer.example.com/userinfo",
            },
        )


def test_oidc_metadata_client_rejects_insecure_public_hosts_and_oversize(monkeypatch: pytest.MonkeyPatch) -> None:
    client = OIDCMetadataClient(allowed_hosts={"issuer.example.com"}, max_response_bytes=8)

    with pytest.raises(AuthConfigurationError, match="https"):
        client("http://issuer.example.com/.well-known/openid-configuration")
    with pytest.raises(AuthConfigurationError, match="not allowed"):
        client("https://other.example.com/.well-known/openid-configuration")

    class FakeResponse:
        headers = {"content-type": "application/json; charset=utf-8"}
        content = b'{"issuer":"https://issuer.example.com"}'

        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, object]:
            return {"issuer": "https://issuer.example.com"}

    monkeypatch.setattr("coreline_auth.social.httpx.get", lambda *_, **__: FakeResponse())

    with pytest.raises(AuthConfigurationError, match="exceeds"):
        client("https://issuer.example.com/.well-known/openid-configuration")


def test_jwks_cache_hits_and_refreshes_on_kid_miss() -> None:
    calls: list[str] = []
    documents = [
        {"keys": [{"kid": "kid-1"}]},
        {"keys": [{"kid": "kid-2"}]},
    ]

    def fetcher(url: str) -> dict[str, object]:
        calls.append(url)
        return documents[min(len(calls) - 1, 1)]

    cache = JWKSCache(fetcher, ttl_seconds=60)

    assert cache.get_jwks("https://issuer.example.com/keys", kid="kid-1", now=1) == {"keys": [{"kid": "kid-1"}]}
    assert cache.get_jwks("https://issuer.example.com/keys", kid="kid-1", now=2) == {"keys": [{"kid": "kid-1"}]}
    assert cache.get_jwks("https://issuer.example.com/keys", kid="kid-2", now=3) == {"keys": [{"kid": "kid-2"}]}
    assert calls == ["https://issuer.example.com/keys", "https://issuer.example.com/keys"]

    with pytest.raises(AuthConfigurationError):
        discover_oidc_metadata(
            issuer="https://issuer.example.com",
            fetcher=lambda _url: {
                "issuer": "https://issuer.example.com",
                "authorization_endpoint": "https://issuer.example.com/auth",
                "token_endpoint": "https://issuer.example.com/token",
            },
        )


def test_jwks_cache_negative_caches_repeated_unknown_kid_miss() -> None:
    calls: list[str] = []

    def fetcher(url: str) -> dict[str, object]:
        calls.append(url)
        return {"keys": [{"kid": "kid-1"}]}

    cache = JWKSCache(fetcher, ttl_seconds=60, kid_miss_refetch_cooldown_seconds=30)

    assert cache.get_jwks("https://issuer.example.com/keys", kid="kid-1", now=1) == {"keys": [{"kid": "kid-1"}]}
    assert cache.get_jwks("https://issuer.example.com/keys", kid="random-kid", now=2) == {"keys": [{"kid": "kid-1"}]}
    assert cache.get_jwks("https://issuer.example.com/keys", kid="random-kid", now=3) == {"keys": [{"kid": "kid-1"}]}
    assert calls == ["https://issuer.example.com/keys", "https://issuer.example.com/keys"]

    cache.get_jwks("https://issuer.example.com/keys", kid="random-kid", now=40)
    assert calls == ["https://issuer.example.com/keys", "https://issuer.example.com/keys", "https://issuer.example.com/keys"]


def test_oidc_userinfo_requires_sub_and_defaults_missing_email_verified_to_false() -> None:
    connector = _oidc_connector()

    with pytest.raises(AuthenticationFailed):
        connector.profile_from_userinfo({"id": "oauth-id", "email": "user@example.com", "email_verified": True})

    missing_verified = connector.profile_from_userinfo({"sub": "sub-123", "email": "user@example.com"})
    assert missing_verified.provider_subject == "sub-123"
    assert missing_verified.email == "user@example.com"
    assert missing_verified.email_verified is False

    string_true = connector.profile_from_userinfo({"sub": "sub-123", "email": "user@example.com", "email_verified": "true"})
    assert string_true.email_verified is True

    no_email = connector.profile_from_userinfo({"sub": "sub-123", "email_verified": True})
    assert no_email.email is None
    assert no_email.email_verified is False


def test_google_userinfo_missing_email_verified_is_not_trusted_by_default() -> None:
    connector = GoogleOAuthConnector.from_credentials(
        client_id="google-client",
        client_secret="google-secret",
        redirect_uri="https://app.example.com/social/google/callback",
    )

    profile = connector.profile_from_userinfo({"sub": "google-sub", "email": "user@example.com", "name": "User"})

    assert profile.provider == "google"
    assert profile.provider_subject == "google-sub"
    assert profile.email_verified is False


def test_facebook_profile_shape_remains_compatible() -> None:
    connector = FacebookOAuthConnector.from_credentials(
        client_id="facebook-client",
        client_secret="facebook-secret",
        redirect_uri="https://app.example.com/social/facebook/callback",
    )

    profile = connector.profile_from_userinfo(
        {
            "id": "facebook-id",
            "email": "fb-user@example.com",
            "name": "Facebook User",
            "picture": {"data": {"url": "https://cdn.example.com/avatar.jpg"}},
        }
    )

    assert profile.provider == "facebook"
    assert profile.provider_subject == "facebook-id"
    assert profile.email_verified is True
    assert profile.avatar_url == "https://cdn.example.com/avatar.jpg"


def test_exchange_code_uses_pkce_but_returns_profile_without_raw_provider_tokens(monkeypatch: pytest.MonkeyPatch) -> None:
    connector = _oidc_connector()
    seen: dict[str, object] = {}

    class FakeResponse:
        def __init__(self, payload: dict[str, object]) -> None:
            self.payload = payload

        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, object]:
            return self.payload

    def fake_post(url: str, *, data: dict[str, str], timeout: float) -> FakeResponse:
        seen["token_url"] = url
        seen["token_request"] = dict(data)
        seen["token_timeout"] = timeout
        return FakeResponse(
            {
                "access_token": "raw-access-token",
                "refresh_token": "raw-refresh-token",
                "id_token": "raw-id-token",
                "token_type": "Bearer",
            }
        )

    def fake_get(url: str, *, headers: dict[str, str], timeout: float) -> FakeResponse:
        seen["userinfo_url"] = url
        seen["userinfo_headers"] = dict(headers)
        seen["userinfo_timeout"] = timeout
        return FakeResponse({"sub": "oidc-sub", "email": "user@example.com", "email_verified": True})

    monkeypatch.setattr("coreline_auth.social.httpx.post", fake_post)
    monkeypatch.setattr("coreline_auth.social.httpx.get", fake_get)

    profile = connector.exchange_code(code="auth-code", code_verifier="pkce-verifier", timeout_seconds=3.0)

    assert seen["token_url"] == "https://id.example.com/oauth2/token"
    assert seen["token_request"] == {
        "client_id": "client-id",
        "client_secret": "client-secret",
        "redirect_uri": "https://app.example.com/callback",
        "grant_type": "authorization_code",
        "code": "auth-code",
        "code_verifier": "pkce-verifier",
    }
    assert seen["userinfo_headers"] == {"Authorization": "Bearer raw-access-token"}
    assert profile.provider_subject == "oidc-sub"
    assert not hasattr(profile, "access_token")
    assert "raw-access-token" not in repr(profile)
    assert "raw-refresh-token" not in repr(profile)
    assert "raw-id-token" not in repr(profile)


def test_exchange_code_rejects_oversize_response_and_redacts_token_data(monkeypatch: pytest.MonkeyPatch) -> None:
    connector = _oidc_connector()

    class OversizeResponse:
        headers = {"content-type": "application/json"}
        content = b"x" * 20

        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, object]:
            return {"access_token": "raw-token"}

    monkeypatch.setattr("coreline_auth.social.httpx.post", lambda *_, **__: OversizeResponse())

    with pytest.raises(AuthenticationFailed, match="exceeds"):
        connector.exchange_code(code="auth-code", max_response_bytes=8)

    assert redact_token_response({"access_token": "raw", "refresh_token": "raw2", "scope": "openid"}) == {
        "access_token": "[REDACTED]",
        "refresh_token": "[REDACTED]",
        "scope": "openid",
    }
