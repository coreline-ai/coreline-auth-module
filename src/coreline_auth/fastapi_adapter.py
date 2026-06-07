"""FastAPI JSON adapter for Coreline Auth."""

from __future__ import annotations

import hmac
from datetime import datetime

from typing import Annotated, Callable

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query, Request, Response, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, EmailStr, Field

from .csrf import CsrfProtector
from .errors import AuthenticationFailed, AuthorizationDenied, AuthValidationError
from .models import RequestContext
from .security import hash_secret
from .service import CorelineAuthService

SESSION_COOKIE_NAME = "coreline_auth_session"
CSRF_COOKIE_NAME = "coreline_auth_csrf"
CSRF_HEADER_NAME = "x-csrf-token"
_bearer = HTTPBearer(auto_error=False)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=1024)


class MagicLinkRequest(BaseModel):
    email: EmailStr
    return_to: str = "/"


class MagicLinkConsumeRequest(BaseModel):
    token: str = Field(min_length=16, max_length=512)


class EmailVerificationRequest(BaseModel):
    email: EmailStr


class EmailVerificationConsumeRequest(BaseModel):
    token: str = Field(min_length=16, max_length=512)


class PasswordResetRequest(BaseModel):
    email: EmailStr


class PasswordResetConsumeRequest(BaseModel):
    token: str = Field(min_length=16, max_length=512)
    password: str = Field(min_length=8, max_length=1024)


def request_context(request: Request) -> RequestContext:
    return RequestContext(ip=request.client.host if request.client else None, user_agent=request.headers.get("user-agent"))


def token_from_request(request: Request, credentials: HTTPAuthorizationCredentials | None, cookie_name: str = SESSION_COOKIE_NAME) -> str | None:
    if credentials and credentials.scheme.lower() == "bearer":
        return credentials.credentials
    return request.cookies.get(cookie_name)


def mount_auth_routes(
    app: FastAPI,
    auth: CorelineAuthService,
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
    router = APIRouter(prefix=prefix, tags=["coreline-auth"])

    def set_session_cookie(response: Response, token: str) -> None:
        response.set_cookie(cookie_name, token, httponly=True, secure=secure_cookies, samesite="lax", path="/")

    def csrf_context_key(request: Request) -> str | None:
        session_token = request.cookies.get(cookie_name)
        if not session_token:
            return None
        try:
            auth.verify_session(session_token)
        except AuthenticationFailed:
            return None
        return hash_secret(session_token)

    def require_csrf(request: Request, *, cookie_auth_required: bool = False) -> None:
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
            context_key = csrf_context_key(request)
            if context_key is not None:
                csrf_protector.verify_for_context(header_token, context_key=context_key)
            else:
                csrf_protector.verify_global(header_token)
        except AuthValidationError as exc:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc

    @router.get("/csrf")
    def csrf(request: Request, response: Response) -> dict[str, str]:
        if csrf_protector is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="csrf is not enabled")
        context_key = csrf_context_key(request)
        token = csrf_protector.issue_for_context(context_key=context_key) if context_key is not None else csrf_protector.issue_global()
        response.set_cookie(csrf_cookie_name, token.value, httponly=False, secure=secure_cookies, samesite=csrf_cookie_samesite, path="/")
        return {"csrf_token": token.value, "header": csrf_header_name, "cookie": csrf_cookie_name, "binding": "session" if context_key is not None else "anonymous"}

    @router.post("/login")
    def login(payload: LoginRequest, request: Request, response: Response) -> dict[str, object]:
        require_csrf(request)
        try:
            issued = auth.login_password(email=str(payload.email), password=payload.password, context=request_context(request))
        except (AuthenticationFailed, AuthorizationDenied, AuthValidationError) as exc:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc
        set_session_cookie(response, issued.token)
        return {"ok": True, "user_id": issued.session.user_id, "expires_at": issued.session.expires_at.isoformat()}

    @router.post("/magic-link/request")
    def magic_link_request(payload: MagicLinkRequest, request: Request) -> dict[str, object]:
        require_csrf(request)
        try:
            challenge = auth.request_magic_link(email=str(payload.email), return_to=payload.return_to)
        except (AuthorizationDenied, AuthValidationError, AuthenticationFailed) as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        body: dict[str, object] = {"ok": True, "expires_at": challenge.flow.expires_at.isoformat()}
        if expose_magic_link_token:
            body["debug_token"] = challenge.token
        return body

    @router.post("/magic-link/consume")
    def magic_link_consume(payload: MagicLinkConsumeRequest, request: Request, response: Response) -> dict[str, object]:
        require_csrf(request)
        try:
            issued = auth.consume_magic_link(token=payload.token, context=request_context(request))
        except (AuthenticationFailed, AuthorizationDenied) as exc:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc
        set_session_cookie(response, issued.token)
        return {"ok": True, "user_id": issued.session.user_id, "expires_at": issued.session.expires_at.isoformat()}

    @router.post("/email-verification/request")
    def email_verification_request(payload: EmailVerificationRequest, request: Request) -> dict[str, object]:
        require_csrf(request)
        try:
            challenge = auth.request_email_verification(email=str(payload.email))
        except AuthenticationFailed:
            # Avoid account enumeration on the HTTP boundary. Service-level tests
            # still expose strict errors for trusted internal callers.
            return {"ok": True}
        except (AuthorizationDenied, AuthValidationError) as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        body: dict[str, object] = {"ok": True, "expires_at": challenge.flow.expires_at.isoformat()}
        if expose_magic_link_token:
            body["debug_token"] = challenge.token
        return body

    @router.post("/email-verification/consume")
    def email_verification_consume(payload: EmailVerificationConsumeRequest, request: Request) -> dict[str, object]:
        require_csrf(request)
        try:
            user = auth.consume_email_verification(payload.token)
        except AuthenticationFailed as exc:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc
        return {"ok": True, "user_id": user.id, "email_verified": user.primary_email_verified}

    @router.post("/password-reset/request")
    def password_reset_request(payload: PasswordResetRequest, request: Request) -> dict[str, object]:
        require_csrf(request)
        challenge = auth.request_password_reset(str(payload.email))
        body: dict[str, object] = {"ok": True}
        if expose_magic_link_token and auth.storage.get_login_flow_by_state_hash(challenge.flow.state_hash or "") is not None:
            body["debug_token"] = challenge.token
            body["expires_at"] = challenge.flow.expires_at.isoformat()
        return body

    @router.post("/password-reset/consume")
    def password_reset_consume(payload: PasswordResetConsumeRequest, request: Request) -> dict[str, bool]:
        require_csrf(request)
        try:
            auth.consume_password_reset(payload.token, payload.password)
        except AuthenticationFailed as exc:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc
        return {"ok": True}

    @router.post("/logout")
    def logout(request: Request, response: Response, credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)] = None) -> dict[str, bool]:
        require_csrf(request, cookie_auth_required=True)
        token = token_from_request(request, credentials, cookie_name)
        if token:
            auth.logout(token)
        response.delete_cookie(cookie_name, path="/")
        return {"ok": True}

    @router.get("/me")
    def me(request: Request, credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)] = None) -> dict[str, object]:
        token = token_from_request(request, credentials, cookie_name)
        if not token:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="missing session")
        try:
            principal = auth.verify_session(token)
        except AuthenticationFailed as exc:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc
        return {"id": principal.user.id, "email": principal.user.primary_email, "role": principal.session.role.value, "permissions": list(principal.session.permissions)}

    app.include_router(router)
    return router


def require_session(auth: CorelineAuthService, *, cookie_name: str = SESSION_COOKIE_NAME) -> Callable[..., object]:
    def dependency(request: Request, credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)] = None) -> object:
        token = token_from_request(request, credentials, cookie_name)
        if not token:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="missing session")
        try:
            return auth.verify_session(token)
        except AuthenticationFailed as exc:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc
    return dependency


def require_permission(auth: CorelineAuthService, permission: str, *, cookie_name: str = SESSION_COOKIE_NAME) -> Callable[..., object]:
    def dependency(request: Request, credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)] = None) -> object:
        token = token_from_request(request, credentials, cookie_name)
        if not token:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="missing session")
        try:
            return auth.verify_session(token, required_permission=permission)
        except AuthenticationFailed as exc:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc
        except AuthorizationDenied as exc:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    return dependency


class AdminRoleRequest(BaseModel):
    role: str = Field(pattern="^(owner|admin|viewer|user)$")


class AdminPasswordRequest(BaseModel):
    password: str = Field(min_length=8, max_length=1024)


class AdminReasonRequest(BaseModel):
    reason: str | None = Field(default=None, max_length=512)


def mount_admin_routes(
    app: FastAPI,
    auth: CorelineAuthService,
    *,
    prefix: str = "/auth/admin",
    cookie_name: str = SESSION_COOKIE_NAME,
    csrf_protector: CsrfProtector | None = None,
    csrf_cookie_name: str = CSRF_COOKIE_NAME,
    csrf_header_name: str = CSRF_HEADER_NAME,
    csrf_cookie_samesite: str = "strict",
) -> APIRouter:
    """Mount minimal multi-user admin routes."""

    from .admin import CorelineAdminService
    from .models import Role, to_iso

    router = APIRouter(prefix=prefix, tags=["coreline-auth-admin"])
    admin = CorelineAdminService(auth)

    def require_token(request: Request, credentials: HTTPAuthorizationCredentials | None) -> str:
        token = token_from_request(request, credentials, cookie_name)
        if not token:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="missing session")
        return token

    def csrf_context_key(request: Request) -> str | None:
        session_token = request.cookies.get(cookie_name)
        if not session_token:
            return None
        try:
            auth.verify_session(session_token)
        except AuthenticationFailed:
            return None
        return hash_secret(session_token)

    def require_csrf(request: Request, *, cookie_auth_required: bool = False) -> None:
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
            context_key = csrf_context_key(request)
            if context_key is not None:
                csrf_protector.verify_for_context(header_token, context_key=context_key)
            else:
                csrf_protector.verify_global(header_token)
        except AuthValidationError as exc:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc

    @router.get("/users")
    def list_users(
        request: Request,
        query: str | None = None,
        user_status: str | None = Query(default=None, alias="status"),
        role: str | None = None,
        credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)] = None,
    ) -> dict[str, object]:
        token = require_token(request, credentials)
        try:
            users = admin.list_users(actor_session_token=token, query=query, status=user_status, role=role)
        except (AuthenticationFailed, AuthorizationDenied) as exc:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
        except AuthValidationError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        return {
            "users": [
                {"id": user.id, "email": user.primary_email, "role": user.role.value, "status": user.status.value, "display_name": user.display_name}
                for user in users
            ]
        }

    @router.get("/audit")
    def list_audit(
        request: Request,
        action: str | None = None,
        actor_user_id: str | None = None,
        target_user_id: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = Query(default=100, ge=1, le=500),
        offset: int = Query(default=0, ge=0),
        credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)] = None,
    ) -> dict[str, object]:
        token = require_token(request, credentials)
        try:
            auth.verify_session(token, required_permission="audit:read")
        except AuthenticationFailed as exc:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc
        except AuthorizationDenied as exc:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
        events = auth.list_audit_events(action=action, actor_user_id=actor_user_id, target_user_id=target_user_id, since=since, until=until, limit=limit, offset=offset)
        return {
            "events": [
                {
                    "action": event.action,
                    "actor_user_id": event.actor_user_id,
                    "target_user_id": event.target_user_id,
                    "metadata": event.metadata,
                    "created_at": to_iso(event.created_at),
                }
                for event in events
            ]
        }

    @router.post("/users/{user_id}/role")
    def update_role(user_id: str, payload: AdminRoleRequest, request: Request, credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)] = None) -> dict[str, object]:
        require_csrf(request, cookie_auth_required=True)
        token = require_token(request, credentials)
        try:
            user = admin.update_user_role(actor_session_token=token, user_id=user_id, role=Role(payload.role))
        except (AuthenticationFailed, AuthorizationDenied) as exc:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
        return {"ok": True, "user": {"id": user.id, "email": user.primary_email, "role": user.role.value, "status": user.status.value}}

    @router.post("/users/{user_id}/ban")
    def ban_user(user_id: str, request: Request, payload: AdminReasonRequest | None = None, credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)] = None) -> dict[str, object]:
        require_csrf(request, cookie_auth_required=True)
        token = require_token(request, credentials)
        try:
            user = admin.ban_user(actor_session_token=token, user_id=user_id, reason=payload.reason if payload else None)
        except (AuthenticationFailed, AuthorizationDenied) as exc:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
        return {"ok": True, "user": {"id": user.id, "status": user.status.value}}

    @router.post("/users/{user_id}/unban")
    def unban_user(user_id: str, request: Request, payload: AdminReasonRequest | None = None, credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)] = None) -> dict[str, object]:
        require_csrf(request, cookie_auth_required=True)
        token = require_token(request, credentials)
        try:
            user = admin.unban_user(actor_session_token=token, user_id=user_id, reason=payload.reason if payload else None)
        except (AuthenticationFailed, AuthorizationDenied) as exc:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
        return {"ok": True, "user": {"id": user.id, "status": user.status.value}}

    @router.post("/users/{user_id}/password")
    def set_password(user_id: str, payload: AdminPasswordRequest, request: Request, credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)] = None) -> dict[str, bool]:
        require_csrf(request, cookie_auth_required=True)
        token = require_token(request, credentials)
        try:
            admin.set_user_password(actor_session_token=token, user_id=user_id, password=payload.password)
        except (AuthenticationFailed, AuthorizationDenied) as exc:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
        return {"ok": True}

    @router.get("/users/{user_id}/sessions")
    def list_user_sessions(user_id: str, request: Request, credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)] = None) -> dict[str, object]:
        token = require_token(request, credentials)
        try:
            sessions = admin.list_sessions_for_user(actor_session_token=token, user_id=user_id)
        except (AuthenticationFailed, AuthorizationDenied) as exc:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
        return {
            "sessions": [
                {
                    "id": session.id,
                    "user_id": session.user_id,
                    "email": session.email,
                    "role": session.role.value,
                    "created_at": to_iso(session.created_at),
                    "expires_at": to_iso(session.expires_at),
                    "revoked_at": to_iso(session.revoked_at) if session.revoked_at else None,
                    "last_seen_at": to_iso(session.last_seen_at) if session.last_seen_at else None,
                }
                for session in sessions
            ]
        }

    @router.post("/sessions/{session_id}/revoke")
    def revoke_session(session_id: str, request: Request, credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)] = None) -> dict[str, bool]:
        require_csrf(request, cookie_auth_required=True)
        token = require_token(request, credentials)
        try:
            admin.revoke_session(actor_session_token=token, session_id=session_id)
        except (AuthenticationFailed, AuthorizationDenied) as exc:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
        return {"ok": True}

    app.include_router(router)
    return router
