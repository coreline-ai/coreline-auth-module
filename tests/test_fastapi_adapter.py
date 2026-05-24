from __future__ import annotations

from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from coreline_auth import AuthProfile, CorelineAuthConfig, CorelineAuthService, CsrfProtector
from coreline_auth.fastapi_adapter import mount_auth_routes, require_permission
from coreline_auth.storage import MemoryAuthStorage


def make_app() -> FastAPI:
    app = FastAPI()
    auth = CorelineAuthService(storage=MemoryAuthStorage(), config=CorelineAuthConfig(profile=AuthProfile.SINGLE_OWNER, owner_email="owner@example.com"))
    auth.bootstrap_owner(email="owner@example.com", password="correct horse battery")
    mount_auth_routes(app, auth, expose_magic_link_token=True, secure_cookies=False)

    @app.get("/protected")
    def protected(_principal=Depends(require_permission(auth, "services:write"))):
        return {"ok": True}

    return app


def test_password_login_cookie_bearer_and_me() -> None:
    client = TestClient(make_app())
    response = client.post("/auth/login", json={"email": "owner@example.com", "password": "correct horse battery"})
    assert response.status_code == 200
    token = response.cookies["coreline_auth_session"]
    assert client.get("/auth/me").json()["email"] == "owner@example.com"
    assert client.get("/protected").status_code == 200
    assert client.get("/protected", headers={"Authorization": f"Bearer {token}"}).status_code == 200


def test_csrf_protector_blocks_cookie_post_but_allows_bearer_opt_out() -> None:
    app = FastAPI()
    auth = CorelineAuthService(storage=MemoryAuthStorage(), config=CorelineAuthConfig(profile=AuthProfile.SINGLE_OWNER, owner_email="owner@example.com"))
    auth.bootstrap_owner(email="owner@example.com", password="correct horse battery")
    mount_auth_routes(app, auth, expose_magic_link_token=True, secure_cookies=False, csrf_protector=CsrfProtector(secret_key="R4ndomLookingCsrfKey_20260524_Value!"))
    client = TestClient(app)

    blocked = client.post("/auth/login", json={"email": "owner@example.com", "password": "correct horse battery"})
    assert blocked.status_code == 403

    csrf = client.get("/auth/csrf").json()["csrf_token"]
    login = client.post("/auth/login", json={"email": "owner@example.com", "password": "correct horse battery"}, headers={"x-csrf-token": csrf})
    assert login.status_code == 200
    token = login.cookies["coreline_auth_session"]

    # API clients using bearer authorization do not need double-submit CSRF.
    assert client.post("/auth/logout", headers={"Authorization": f"Bearer {token}"}).status_code == 200


def test_magic_link_route_consumes_once() -> None:
    client = TestClient(make_app())
    request = client.post("/auth/magic-link/request", json={"email": "owner@example.com", "return_to": "/"})
    token = request.json()["debug_token"]
    assert client.post("/auth/magic-link/consume", json={"token": token}).status_code == 200
    assert client.post("/auth/magic-link/consume", json={"token": token}).status_code == 401


def test_email_verification_and_password_reset_routes_are_hash_only() -> None:
    app = FastAPI()
    auth = CorelineAuthService(storage=MemoryAuthStorage(), config=CorelineAuthConfig(profile=AuthProfile.RBAC, require_email_verified=False))
    auth.create_user(email="user@example.com", password="old correct horse", email_verified=False)
    mount_auth_routes(app, auth, expose_magic_link_token=True, secure_cookies=False)
    client = TestClient(app)

    verification_request = client.post("/auth/email-verification/request", json={"email": "user@example.com"})
    assert verification_request.status_code == 200
    verification_token = verification_request.json()["debug_token"]
    assert auth.storage.get_login_flow_by_state_hash(verification_token) is None
    assert client.post("/auth/email-verification/consume", json={"token": verification_token}).json()["email_verified"] is True
    assert client.post("/auth/email-verification/consume", json={"token": verification_token}).status_code == 401

    reset_request = client.post("/auth/password-reset/request", json={"email": "user@example.com"})
    assert reset_request.status_code == 200
    reset_token = reset_request.json()["debug_token"]
    assert auth.storage.get_login_flow_by_state_hash(reset_token) is None
    assert client.post("/auth/password-reset/consume", json={"token": reset_token, "password": "new correct horse"}).status_code == 200
    assert client.post("/auth/login", json={"email": "user@example.com", "password": "new correct horse"}).status_code == 200


def test_password_reset_request_does_not_enumerate_unknown_users() -> None:
    app = FastAPI()
    auth = CorelineAuthService(storage=MemoryAuthStorage(), config=CorelineAuthConfig(profile=AuthProfile.RBAC, require_email_verified=False))
    mount_auth_routes(app, auth, expose_magic_link_token=True, secure_cookies=False)
    client = TestClient(app)

    response = client.post("/auth/password-reset/request", json={"email": "missing@example.com"})

    assert response.status_code == 200
    assert response.json() == {"ok": True}


def test_csrf_token_is_session_bound_after_login() -> None:
    app = FastAPI()
    auth = CorelineAuthService(storage=MemoryAuthStorage(), config=CorelineAuthConfig(profile=AuthProfile.SINGLE_OWNER, owner_email="owner@example.com"))
    auth.bootstrap_owner(email="owner@example.com", password="correct horse battery")
    mount_auth_routes(app, auth, expose_magic_link_token=True, secure_cookies=False, csrf_protector=CsrfProtector(secret_key="R4ndomLookingCsrfKey_20260524_Value!"))
    client = TestClient(app)

    anonymous_csrf = client.get("/auth/csrf").json()["csrf_token"]
    login = client.post(
        "/auth/login",
        json={"email": "owner@example.com", "password": "correct horse battery"},
        headers={"x-csrf-token": anonymous_csrf},
    )
    assert login.status_code == 200

    # Once a cookie session exists, anonymous CSRF tokens are no longer enough.
    stale = client.post("/auth/logout", headers={"x-csrf-token": anonymous_csrf})
    assert stale.status_code == 403

    bound = client.get("/auth/csrf").json()
    assert bound["binding"] == "session"
    assert client.post("/auth/logout", headers={"x-csrf-token": bound["csrf_token"]}).status_code == 200


def test_auth_cookie_defaults_to_secure_when_not_overridden() -> None:
    app = FastAPI()
    auth = CorelineAuthService(storage=MemoryAuthStorage(), config=CorelineAuthConfig(profile=AuthProfile.SINGLE_OWNER, owner_email="owner@example.com"))
    auth.bootstrap_owner(email="owner@example.com", password="correct horse battery")
    mount_auth_routes(app, auth)
    client = TestClient(app)

    response = client.post("/auth/login", json={"email": "owner@example.com", "password": "correct horse battery"})

    assert response.status_code == 200
    assert "Secure" in response.headers["set-cookie"]
