"""CSRF helpers for the form-based demo webapp."""

from __future__ import annotations

import hmac
from contextvars import ContextVar
from urllib.parse import parse_qs

from fastapi import Request
from fastapi.responses import Response

from coreline_auth import AuthValidationError, CsrfProtector
from coreline_auth.fastapi_adapter import CSRF_COOKIE_NAME

_request_csrf_cookie: ContextVar[str | None] = ContextVar("coreline_auth_demo_csrf_cookie", default=None)


def csrf_token_for_page(csrf: CsrfProtector) -> str:
    """Return the current valid CSRF cookie, or issue one when absent/invalid."""

    existing = _request_csrf_cookie.get()
    if existing:
        try:
            csrf.verify_global(existing)
            return existing
        except AuthValidationError:
            pass
    return csrf.issue_global().value


def demo_csrf_middleware(csrf: CsrfProtector):
    """Build a middleware function that verifies form CSRF tokens."""

    async def middleware(request: Request, call_next):
        context_token = _request_csrf_cookie.set(request.cookies.get(CSRF_COOKIE_NAME))
        try:
            if request.method in {"POST", "PUT", "PATCH", "DELETE"} and not request.url.path.startswith("/auth/"):
                body = await request.body()
                form = parse_qs(body.decode("utf-8"), keep_blank_values=True)
                token = form.get("csrf_token", [None])[-1]
                cookie_token = request.cookies.get(CSRF_COOKIE_NAME)
                if not isinstance(token, str) or not cookie_token or not hmac.compare_digest(token, cookie_token):
                    return Response("Invalid CSRF token", status_code=403)
                try:
                    csrf.verify_global(token)
                except AuthValidationError:
                    return Response("Invalid CSRF token", status_code=403)

                async def receive():
                    return {"type": "http.request", "body": body, "more_body": False}

                request = Request(request.scope, receive)
            return await call_next(request)
        finally:
            _request_csrf_cookie.reset(context_token)

    return middleware
