"""Small CSRF helpers for board HTML forms."""

from __future__ import annotations

import hmac
import html
import secrets

from fastapi import Request
from fastapi.responses import Response

from .errors import BoardAuthorizationError
from typing import Any


def csrf_token_for_request(request: Request, settings: Any) -> str:
    return request.cookies.get(settings.csrf_cookie_name) or secrets.token_urlsafe(32)


def issue_csrf_cookie(response: Response, token: str, settings: Any) -> None:
    response.set_cookie(
        settings.csrf_cookie_name,
        token,
        httponly=False,
        secure=settings.secure_cookies,
        samesite=settings.cookie_samesite,
        path=settings.normalized_prefix,
    )


def csrf_field(token: str) -> str:
    return f"<input type='hidden' name='csrf_token' value='{html.escape(token, quote=True)}'>"


def require_csrf(request: Request, form_token: str, settings: Any) -> None:
    cookie_token = request.cookies.get(settings.csrf_cookie_name)
    if not form_token or not cookie_token or not hmac.compare_digest(form_token, cookie_token):
        raise BoardAuthorizationError("missing or invalid csrf token")
