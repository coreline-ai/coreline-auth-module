"""Async FastAPI JSON adapter for AsyncCorelineAuthService."""

from __future__ import annotations

import hmac
from typing import Annotated

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, EmailStr, Field

from .async_service import AsyncCorelineAuthService
from .csrf import CsrfProtector
from .errors import AuthenticationFailed, AuthorizationDenied, AuthValidationError
from .fastapi_adapter import CSRF_COOKIE_NAME, CSRF_HEADER_NAME, SESSION_COOKIE_NAME, request_context, token_from_request
from .security import hash_secret

_bearer = HTTPBearer(auto_error=False)


class AsyncLoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=1024)


class AsyncMagicLinkRequest(BaseModel):
    email: EmailStr
    return_to: str = "/"


class AsyncMagicLinkConsumeRequest(BaseModel):
    token: str = Field(min_length=16, max_length=512)


def mount_async_auth_routes(
    app: FastAPI,
    auth: AsyncCorelineAuthService,
    *,
    prefix: str = "/auth",
    cookie_name: str = SESSION_COOKIE_NAME,
    secure_cookies: bool = True,
    expose_magic_link_token: bool = False,
    csrf_protector: CsrfProtector | None = None,
    csrf_cookie_name: str = CSRF_COOKIE_NAME,
    csrf_header_name: str = CSRF_HEADER_NAME,
    csrf_cookie_samesite: str = "strict",
) -> APIRouter:
    router = APIRouter(prefix=prefix, tags=["coreline-auth-async"])

    def set_session_cookie(response: Response, token: str) -> None:
        response.set_cookie(cookie_name, token, httponly=True, secure=secure_cookies, samesite="lax", path="/")

    async def csrf_context_key(request: Request) -> str | None:
        session_token = request.cookies.get(cookie_name)
        if not session_token:
            return None
        try:
            await auth.verify_session(session_token)
        except AuthenticationFailed:
            return None
        return hash_secret(session_token)

    async def require_csrf(request: Request, *, cookie_auth_required: bool = False) -> None:
        authorization = request.headers.get("authorization", "")
        if authorization.lower().startswith("bearer "):
            return
        if csrf_protector is None:
            if cookie_auth_required and request.cookies.get(cookie_name):
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="csrf protection is required for cookie-authenticated requests")
            return
        header_token = request.headers.get(csrf_header_name)
        cookie_token = request.cookies.get(csrf_cookie_name)
        if not header_token or not cookie_token or not hmac.compare_digest(header_token, cookie_token):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="missing or invalid csrf token")
        try:
            context_key = await csrf_context_key(request)
            if context_key is not None:
                csrf_protector.verify_for_context(header_token, context_key=context_key)
            else:
                csrf_protector.verify_global(header_token)
        except AuthValidationError as exc:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc

    @router.get("/csrf")
    async def csrf(request: Request, response: Response) -> dict[str, str]:
        if csrf_protector is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="csrf is not enabled")
        context_key = await csrf_context_key(request)
        token = csrf_protector.issue_for_context(context_key=context_key) if context_key is not None else csrf_protector.issue_global()
        response.set_cookie(csrf_cookie_name, token.value, httponly=False, secure=secure_cookies, samesite=csrf_cookie_samesite, path="/")
        return {"csrf_token": token.value, "header": csrf_header_name, "cookie": csrf_cookie_name, "binding": "session" if context_key is not None else "anonymous"}

    @router.post("/login")
    async def login(payload: AsyncLoginRequest, request: Request, response: Response) -> dict[str, object]:
        await require_csrf(request)
        try:
            issued = await auth.login_password(email=str(payload.email), password=payload.password, context=request_context(request))
        except (AuthenticationFailed, AuthorizationDenied, AuthValidationError) as exc:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc
        set_session_cookie(response, issued.token)
        return {"ok": True, "user_id": issued.session.user_id, "expires_at": issued.session.expires_at.isoformat()}

    @router.post("/magic-link/request")
    async def magic_link_request(payload: AsyncMagicLinkRequest, request: Request) -> dict[str, object]:
        await require_csrf(request)
        try:
            challenge = await auth.request_magic_link(email=str(payload.email), return_to=payload.return_to)
        except (AuthorizationDenied, AuthValidationError, AuthenticationFailed) as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        body: dict[str, object] = {"ok": True, "expires_at": challenge.flow.expires_at.isoformat()}
        if expose_magic_link_token:
            body["debug_token"] = challenge.token
        return body

    @router.post("/magic-link/consume")
    async def magic_link_consume(payload: AsyncMagicLinkConsumeRequest, request: Request, response: Response) -> dict[str, object]:
        await require_csrf(request)
        try:
            issued = await auth.consume_magic_link(token=payload.token, context=request_context(request))
        except AuthenticationFailed as exc:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc
        set_session_cookie(response, issued.token)
        return {"ok": True, "user_id": issued.session.user_id, "expires_at": issued.session.expires_at.isoformat()}

    @router.post("/logout")
    async def logout(request: Request, response: Response, credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)] = None) -> dict[str, bool]:
        await require_csrf(request, cookie_auth_required=True)
        token = token_from_request(request, credentials, cookie_name)
        if token:
            await auth.logout(token)
        response.delete_cookie(cookie_name, path="/")
        return {"ok": True}

    @router.get("/me")
    async def me(request: Request, credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)] = None) -> dict[str, object]:
        token = token_from_request(request, credentials, cookie_name)
        if not token:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="missing session")
        try:
            principal = await auth.verify_session(token)
        except AuthenticationFailed as exc:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc
        return {"id": principal.user.id, "email": principal.user.primary_email, "role": principal.session.role.value, "permissions": list(principal.session.permissions)}

    app.include_router(router)
    return router
