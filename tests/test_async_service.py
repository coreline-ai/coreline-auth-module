from __future__ import annotations

import asyncio

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from coreline_auth import AsyncCorelineAuthService, AuthProfile, CorelineAuthConfig, CsrfProtector, InMemoryMetricSink, AuthenticationFailed, mount_async_auth_routes
from coreline_auth.storage import AsyncMemoryAuthStorage


class CountingAsyncMemoryAuthStorage(AsyncMemoryAuthStorage):
    def __init__(self) -> None:
        super().__init__()
        self.session_updates = 0

    async def touch_session(self, session_id, *, last_seen_at, idle_expires_at):
        self.session_updates += 1
        return await super().touch_session(session_id, last_seen_at=last_seen_at, idle_expires_at=idle_expires_at)


class FailingAuditAsyncMemoryAuthStorage(AsyncMemoryAuthStorage):
    async def record_audit_event(self, event):
        raise RuntimeError("audit sink down")


class FailingEmailSender:
    def send_magic_link(self, *, email: str, token: str, return_to: str) -> None:
        raise RuntimeError("smtp down")

    def send_email_verification(self, *, email: str, token: str) -> None:
        raise RuntimeError("smtp down")

    def send_password_reset(self, *, email: str, token: str) -> None:
        raise RuntimeError("smtp down")


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


def test_async_session_touch_interval_throttles_touch_session() -> None:
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


def test_async_session_touch_interval_zero_touches_session() -> None:
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


def test_async_audit_write_failure_does_not_break_auth_flow() -> None:
    async def scenario() -> None:
        service = AsyncCorelineAuthService(
            storage=FailingAuditAsyncMemoryAuthStorage(),
            config=CorelineAuthConfig(profile=AuthProfile.RBAC, require_email_verified=False),
        )
        user = await service.create_user(email="user@example.com", password="correct horse battery", email_verified=True)
        assert user.primary_email == "user@example.com"
        issued = await service.login_password(email="user@example.com", password="correct horse battery")
        assert (await service.verify_session(issued.token)).email == "user@example.com"

    run(scenario())


def test_async_magic_link_email_failure_is_best_effort() -> None:
    async def scenario() -> None:
        metrics = InMemoryMetricSink()
        service = AsyncCorelineAuthService(
            storage=AsyncMemoryAuthStorage(),
            config=CorelineAuthConfig(profile=AuthProfile.SINGLE_OWNER, owner_email="owner@example.com"),
            email_sender=FailingEmailSender(),
            metric_sink=metrics,
        )
        challenge = await service.request_magic_link(email="owner@example.com")
        assert challenge.token
        assert metrics.count("auth.email_send_failed") == 1

    run(scenario())


def test_async_password_reset_is_one_time_and_rotates_password() -> None:
    async def scenario() -> None:
        service = AsyncCorelineAuthService(
            storage=AsyncMemoryAuthStorage(),
            config=CorelineAuthConfig(profile=AuthProfile.RBAC, require_email_verified=False),
        )
        await service.create_user(email="user@example.com", password="old password value", email_verified=True)
        challenge = await service.request_password_reset(email="user@example.com")

        await service.consume_password_reset(challenge.token, "new password value")

        with pytest.raises(AuthenticationFailed):
            await service.login_password(email="user@example.com", password="old password value")
        issued = await service.login_password(email="user@example.com", password="new password value")
        assert (await service.verify_session(issued.token)).email == "user@example.com"

        with pytest.raises(AuthenticationFailed):
            await service.consume_password_reset(challenge.token, "another password value")

    run(scenario())


def test_async_password_reset_consume_is_atomic_for_memory_storage() -> None:
    async def scenario() -> None:
        service = AsyncCorelineAuthService(
            storage=AsyncMemoryAuthStorage(),
            config=CorelineAuthConfig(profile=AuthProfile.RBAC, require_email_verified=False),
        )
        await service.create_user(email="user@example.com", password="old password value", email_verified=True)
        challenge = await service.request_password_reset(email="user@example.com")
        results = await asyncio.gather(
            service.consume_password_reset(challenge.token, "new password one!"),
            service.consume_password_reset(challenge.token, "new password two!"),
            return_exceptions=True,
        )
        assert sum(1 for result in results if not isinstance(result, Exception)) == 1
        assert sum(1 for result in results if isinstance(result, AuthenticationFailed)) == 1

    run(scenario())


def test_async_email_verification_marks_user_verified_and_is_one_time() -> None:
    async def scenario() -> None:
        service = AsyncCorelineAuthService(
            storage=AsyncMemoryAuthStorage(),
            config=CorelineAuthConfig(profile=AuthProfile.RBAC, require_email_verified=False),
        )
        user = await service.create_user(email="user@example.com", password="correct horse battery", email_verified=False)
        assert user.primary_email_verified is False

        challenge = await service.request_email_verification(user_id=user.id)
        verified = await service.consume_email_verification(challenge.token)
        assert verified.primary_email_verified is True

        with pytest.raises(AuthenticationFailed):
            await service.consume_email_verification(challenge.token)

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
