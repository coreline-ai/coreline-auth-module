from __future__ import annotations

import asyncio

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from coreline_auth import AsyncCorelineAuthService, AuthProfile, CorelineAuthConfig, CsrfProtector, AuthenticationFailed, mount_async_auth_routes
from coreline_auth.storage import AsyncMemoryAuthStorage


class CountingAsyncMemoryAuthStorage(AsyncMemoryAuthStorage):
    def __init__(self) -> None:
        super().__init__()
        self.session_updates = 0

    async def update_session(self, session):
        self.session_updates += 1
        return await super().update_session(session)


def run(coro):
    return asyncio.run(coro)


def make_async_service(storage=None, *, owner_email: str = "owner@example.com") -> AsyncCorelineAuthService:
    return AsyncCorelineAuthService(storage=storage or AsyncMemoryAuthStorage(), config=CorelineAuthConfig(profile=AuthProfile.SINGLE_OWNER, owner_email=owner_email))


def test_async_password_login_verify_and_logout() -> None:
    async def scenario() -> None:
        service = make_async_service()
        await service.bootstrap_owner(email="owner@example.com", password="correct horse battery")
        issued = await service.login_password(email="OWNER@example.com", password="correct horse battery")
        principal = await service.verify_session(issued.token, required_permission="services:write")
        assert principal.email == "owner@example.com"

        await service.logout(issued.token)
        with pytest.raises(AuthenticationFailed):
            await service.verify_session(issued.token)

    run(scenario())


def test_async_magic_link_is_one_time() -> None:
    async def scenario() -> None:
        service = make_async_service()
        challenge = await service.request_magic_link(email="owner@example.com")
        issued = await service.consume_magic_link(token=challenge.token)
        assert (await service.verify_session(issued.token)).email == "owner@example.com"
        with pytest.raises(AuthenticationFailed):
            await service.consume_magic_link(token=challenge.token)

    run(scenario())


def test_async_magic_link_consume_is_atomic_for_memory_storage() -> None:
    async def scenario() -> None:
        service = make_async_service()
        challenge = await service.request_magic_link(email="owner@example.com")
        results = await asyncio.gather(
            service.consume_magic_link(token=challenge.token),
            service.consume_magic_link(token=challenge.token),
            return_exceptions=True,
        )
        assert sum(1 for result in results if not isinstance(result, Exception)) == 1
        assert sum(1 for result in results if isinstance(result, AuthenticationFailed)) == 1

    run(scenario())


def test_async_session_touch_interval_throttles_update_session() -> None:
    async def scenario() -> None:
        storage = CountingAsyncMemoryAuthStorage()
        service = AsyncCorelineAuthService(
            storage=storage,
            config=CorelineAuthConfig(profile=AuthProfile.RBAC, require_email_verified=False, session_touch_interval_seconds=60),
        )
        await service.create_user(email="user@example.com", password="correct horse battery", email_verified=True)
        issued = await service.login_password(email="user@example.com", password="correct horse battery")
        await service.verify_session(issued.token)
        assert storage.session_updates == 0

    run(scenario())


def test_async_session_touch_interval_zero_updates_session() -> None:
    async def scenario() -> None:
        storage = CountingAsyncMemoryAuthStorage()
        service = AsyncCorelineAuthService(
            storage=storage,
            config=CorelineAuthConfig(profile=AuthProfile.RBAC, require_email_verified=False, session_touch_interval_seconds=0),
        )
        await service.create_user(email="user@example.com", password="correct horse battery", email_verified=True)
        issued = await service.login_password(email="user@example.com", password="correct horse battery")
        await service.verify_session(issued.token)
        assert storage.session_updates == 1

    run(scenario())


def test_async_fastapi_adapter_login_me_logout_smoke() -> None:
    app = FastAPI()
    service = make_async_service()
    run(service.bootstrap_owner(email="owner@example.com", password="correct horse battery"))
    mount_async_auth_routes(app, service, secure_cookies=False, csrf_protector=CsrfProtector(secret_key="AsyncCsrfSecret_20260524_RandomValue!"))

    client = TestClient(app)
    csrf = client.get("/auth/csrf").json()["csrf_token"]
    login = client.post("/auth/login", json={"email": "owner@example.com", "password": "correct horse battery"}, headers={"x-csrf-token": csrf})
    assert login.status_code == 200

    me = client.get("/auth/me")
    assert me.status_code == 200
    assert me.json()["email"] == "owner@example.com"

    csrf2 = client.get("/auth/csrf").json()["csrf_token"]
    logout = client.post("/auth/logout", headers={"x-csrf-token": csrf2})
    assert logout.status_code == 200
    assert client.get("/auth/me").status_code == 401
