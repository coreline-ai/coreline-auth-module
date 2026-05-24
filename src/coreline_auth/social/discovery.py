"""OIDC metadata discovery and JWKS cache helpers."""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from urllib.parse import urlparse

import httpx

from coreline_auth.errors import AuthConfigurationError

from ._utils import _LOCAL_HTTP_HOSTS, _jwks_contains_kid, _normalize_provider_url, _response_json_object
from .models import OIDCProviderMetadata

OIDCMetadataFetcher = Callable[[str], Mapping[str, object]]

class OIDCMetadataClient:
    """Small hardened OIDC discovery/JWKS fetcher.

    It keeps networking policy explicit for reusable auth modules: HTTPS is
    required except localhost development, responses must be JSON, and oversized
    payloads are rejected before JSON parsing.
    """

    def __init__(
        self,
        *,
        timeout_seconds: float = 10.0,
        max_response_bytes: int = 64 * 1024,
        allowed_hosts: set[str] | None = None,
        allow_localhost_http: bool = True,
    ) -> None:
        self.timeout_seconds = timeout_seconds
        self.max_response_bytes = max_response_bytes
        self.allowed_hosts = {host.lower() for host in allowed_hosts} if allowed_hosts else None
        self.allow_localhost_http = allow_localhost_http

    def __call__(self, url: str) -> Mapping[str, object]:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        if parsed.scheme != "https" and not (self.allow_localhost_http and parsed.scheme == "http" and host in _LOCAL_HTTP_HOSTS):
            raise AuthConfigurationError("OIDC metadata fetch must use https outside localhost")
        if self.allowed_hosts is not None and host not in self.allowed_hosts:
            raise AuthConfigurationError("OIDC metadata host is not allowed")
        response = httpx.get(url, timeout=self.timeout_seconds)
        response.raise_for_status()
        return _response_json_object(response, context="OIDC metadata response", max_bytes=self.max_response_bytes, configuration_error=True)


class JWKSCache:
    """TTL cache for OIDC JWKS documents with kid-miss refresh cooldown."""

    def __init__(self, fetcher: Callable[[str], Mapping[str, object]], *, ttl_seconds: int = 3600, kid_miss_refetch_cooldown_seconds: int = 60) -> None:
        self.fetcher = fetcher
        self.ttl_seconds = ttl_seconds
        self.kid_miss_refetch_cooldown_seconds = kid_miss_refetch_cooldown_seconds
        self._cache: dict[str, tuple[float, Mapping[str, object]]] = {}
        self._kid_miss_refetch_after: dict[tuple[str, str], float] = {}

    def get_jwks(self, jwks_uri: str, *, kid: str | None = None, now: float | None = None) -> Mapping[str, object]:
        current = time.time() if now is None else now
        cached = self._cache.get(jwks_uri)
        if cached is None or cached[0] <= current:
            jwks = self.fetcher(jwks_uri)
            self._cache[jwks_uri] = (current + self.ttl_seconds, jwks)
            return jwks
        jwks = cached[1]
        if kid is not None and not _jwks_contains_kid(jwks, kid):
            miss_key = (jwks_uri, kid)
            if self._kid_miss_refetch_after.get(miss_key, 0.0) > current:
                return jwks
            jwks = self.fetcher(jwks_uri)
            self._cache[jwks_uri] = (current + self.ttl_seconds, jwks)
            if _jwks_contains_kid(jwks, kid):
                self._kid_miss_refetch_after.pop(miss_key, None)
            else:
                self._kid_miss_refetch_after[miss_key] = current + self.kid_miss_refetch_cooldown_seconds
        return jwks


def discover_oidc_metadata(*, issuer: str, fetcher: OIDCMetadataFetcher | None = None, timeout_seconds: float = 10.0) -> OIDCProviderMetadata:
    """Load and validate OIDC discovery metadata.

    The ``fetcher`` argument keeps this helper unit-testable and allows apps to
    inject a cached/SSRF-guarded HTTP client. When omitted, a plain ``httpx.get``
    is used for simple integrations.
    """

    normalized_issuer = _normalize_provider_url("issuer", issuer, allow_path=True).rstrip("/")
    metadata_url = f"{normalized_issuer}/.well-known/openid-configuration"

    if fetcher is None:
        response = httpx.get(metadata_url, timeout=timeout_seconds)
        response.raise_for_status()
        document = response.json()
    else:
        document = fetcher(metadata_url)

    if not isinstance(document, Mapping):
        raise AuthConfigurationError("OIDC metadata response must be a JSON object")
    return OIDCProviderMetadata.from_document(document, expected_issuer=normalized_issuer)
