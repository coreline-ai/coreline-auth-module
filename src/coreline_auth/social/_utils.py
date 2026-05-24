"""Internal helpers for OAuth/OIDC connectors."""

from __future__ import annotations

from collections.abc import Mapping
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from coreline_auth.errors import AuthConfigurationError, AuthenticationFailed

_LOCAL_HTTP_HOSTS = {"localhost", "127.0.0.1", "::1"}
_RESERVED_AUTH_PARAMS = {
    "client_id",
    "redirect_uri",
    "response_type",
    "scope",
    "state",
    "nonce",
    "code_challenge",
    "code_challenge_method",
}

def _append_query(url: str, params: Mapping[str, str]) -> str:
    parts = urlsplit(url)
    query_items = parse_qsl(parts.query, keep_blank_values=True)
    query_items.extend(params.items())
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query_items), parts.fragment))


def _json_object(value: object, *, context: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise AuthenticationFailed(f"{context} must be a JSON object")
    return value


def _response_json_object(response: object, *, context: str, max_bytes: int, configuration_error: bool = False) -> Mapping[str, object]:
    content = getattr(response, "content", b"")
    if isinstance(content, bytes) and len(content) > max_bytes:
        if configuration_error:
            raise AuthConfigurationError(f"{context} exceeds {max_bytes} bytes")
        raise AuthenticationFailed(f"{context} exceeds {max_bytes} bytes")
    headers = getattr(response, "headers", {})
    content_type = ""
    if isinstance(headers, Mapping):
        content_type = str(headers.get("content-type", "")).lower()
    if content_type and content_type.split(";", 1)[0].strip() not in {"application/json", "application/jwk-set+json"}:
        if configuration_error:
            raise AuthConfigurationError(f"{context} must be JSON")
        raise AuthenticationFailed(f"{context} must be JSON")
    try:
        data = response.json()  # type: ignore[attr-defined]
    except Exception as exc:
        if configuration_error:
            raise AuthConfigurationError(f"{context} must be valid JSON") from exc
        raise AuthenticationFailed(f"{context} must be valid JSON") from exc
    if configuration_error:
        if not isinstance(data, Mapping):
            raise AuthConfigurationError(f"{context} must be a JSON object")
        return data
    return _json_object(data, context=context)


def redact_token_response(token_data: Mapping[str, object]) -> dict[str, object]:
    sensitive_keys = {"access_token", "refresh_token", "id_token", "token", "client_secret"}
    return {key: ("[REDACTED]" if key.lower() in sensitive_keys else value) for key, value in token_data.items()}


def _extract_access_token(token_data: Mapping[str, object]) -> str:
    access_token = _optional_string(token_data.get("access_token"))
    if access_token is None:
        raise AuthenticationFailed("provider did not return an access token")
    return access_token


def _required_string(data: Mapping[str, object], key: str, *, context: str) -> str:
    value = _optional_string(data.get(key))
    if value is None:
        raise AuthConfigurationError(f"{context} missing required string field: {key}")
    return value


def _optional_string(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    return stripped or None


def _email_verified_from_claim(value: object, *, email: str | None) -> bool:
    if email is None:
        return False
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"true", "1"}
    return False


def _require_openid_scope(scope: str) -> None:
    if "openid" not in scope.split():
        raise AuthConfigurationError("OIDC connector scope must include openid")


def _normalize_provider_url(name: str, value: str, *, allow_path: bool) -> str:
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise AuthConfigurationError(f"{name} must be an absolute http(s) URL")
    if parsed.username or parsed.password:
        raise AuthConfigurationError(f"{name} must not include credentials")
    if parsed.fragment:
        raise AuthConfigurationError(f"{name} must not include a URL fragment")
    if parsed.scheme == "http" and parsed.hostname not in _LOCAL_HTTP_HOSTS:
        raise AuthConfigurationError(f"{name} must use https outside localhost")
    if not allow_path and parsed.path not in {"", "/"}:
        raise AuthConfigurationError(f"{name} must not include a path")
    return value.rstrip("/") if parsed.path in {"", "/"} and not parsed.query else value


def _validate_code_verifier(code_verifier: str) -> None:
    try:
        code_verifier.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError("PKCE code_verifier must be ASCII") from exc
    if not 43 <= len(code_verifier) <= 128:
        raise ValueError("PKCE code_verifier must be between 43 and 128 characters")
    allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
    if any(ch not in allowed for ch in code_verifier):
        raise ValueError("PKCE code_verifier contains characters outside RFC 7636 unreserved set")


def _jwks_contains_kid(jwks: Mapping[str, object], kid: str) -> bool:
    keys = jwks.get("keys")
    if not isinstance(keys, list):
        return False
    return any(isinstance(raw_key, Mapping) and raw_key.get("kid") == kid for raw_key in keys)
