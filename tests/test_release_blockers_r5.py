from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier

import pytest

from coreline_auth import (
    AuthAssuranceLevel,
    AuthProfile,
    AuthenticationFailed,
    CorelineAuthConfig,
    CorelineAuthService,
    InMemoryEmailSender,
    Role,
    totp_code,
)
from coreline_auth.models import AuditEvent
from coreline_auth.security import hash_secret
from coreline_auth.storage import MemoryAuthStorage, SQLiteAuthStorage


class FailingAuditStorage(MemoryAuthStorage):
    def record_audit_event(self, event: AuditEvent) -> AuditEvent:
        raise RuntimeError("audit sink unavailable")


class FailingEmailSender(InMemoryEmailSender):
    def send_magic_link(self, *, email: str, token: str, return_to: str) -> None:
        raise RuntimeError("smtp unavailable")


def _rbac_service(storage) -> CorelineAuthService:
    return CorelineAuthService(storage=storage, config=CorelineAuthConfig(profile=AuthProfile.RBAC, require_email_verified=False))


def test_sqlite_aal2_survives_db_roundtrip(tmp_path: Path) -> None:
    storage = SQLiteAuthStorage(tmp_path / "auth.sqlite3")
    try:
        service = _rbac_service(storage)
        user = service.create_user(email="user@example.com", role=Role.USER, password="correct horse battery", email_verified=True)
        issued = service.login_password(email="user@example.com", password="correct horse battery")
        factor, secret = service.begin_totp_enrollment(user.id)
        service.verify_totp_enrollment(user_id=user.id, factor_id=factor.id, code=totp_code(secret))

        stepped = service.step_up_totp(issued.token, code=totp_code(secret))

        assert stepped.session.assurance_level == AuthAssuranceLevel.AAL2
        persisted = storage.get_session_by_token_hash(hash_secret(issued.token))
        assert persisted is not None
        assert persisted.assurance_level == AuthAssuranceLevel.AAL2
        assert service.require_aal2(issued.token).session.assurance_level == AuthAssuranceLevel.AAL2
    finally:
        storage.close()


def test_sqlite_magic_link_concurrent_consume_allows_exactly_one_session(tmp_path: Path) -> None:
    storage = SQLiteAuthStorage(tmp_path / "auth.sqlite3")
    try:
        service = _rbac_service(storage)
        service.create_user(email="user@example.com", role=Role.USER, password="correct horse battery", email_verified=True)
        challenge = service.request_magic_link(email="user@example.com")
        barrier = Barrier(2)

        def consume() -> bool:
            barrier.wait()
            try:
                service.consume_magic_link(token=challenge.token)
                return True
            except AuthenticationFailed:
                return False

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: consume(), range(2)))

        assert sorted(results) == [False, True]
    finally:
        storage.close()


def test_sqlite_password_reset_concurrent_consume_allows_exactly_one_success(tmp_path: Path) -> None:
    storage = SQLiteAuthStorage(tmp_path / "auth.sqlite3")
    try:
        service = _rbac_service(storage)
        service.create_user(email="user@example.com", role=Role.USER, password="old correct horse", email_verified=True)
        challenge = service.request_password_reset("user@example.com")
        barrier = Barrier(2)

        def consume(index: int) -> bool:
            barrier.wait()
            try:
                service.consume_password_reset(challenge.token, f"new correct horse {index}")
                return True
            except AuthenticationFailed:
                return False

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(consume, range(2)))

        assert sorted(results) == [False, True]
    finally:
        storage.close()


def test_sqlite_recovery_code_concurrent_step_up_allows_exactly_one_success(tmp_path: Path) -> None:
    storage = SQLiteAuthStorage(tmp_path / "auth.sqlite3")
    try:
        service = _rbac_service(storage)
        service.create_user(email="user@example.com", role=Role.USER, password="correct horse battery", email_verified=True)
        issued = service.login_password(email="user@example.com", password="correct horse battery")
        code = service.generate_recovery_codes(issued.session.user_id, count=1)[0]
        barrier = Barrier(2)

        def step_up() -> bool:
            barrier.wait()
            try:
                service.step_up_recovery_code(issued.token, code=code)
                return True
            except AuthenticationFailed:
                return False

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: step_up(), range(2)))

        assert sorted(results) == [False, True]
    finally:
        storage.close()


def test_totp_code_replay_in_same_window_is_rejected() -> None:
    service = _rbac_service(MemoryAuthStorage())
    user = service.create_user(email="user@example.com", role=Role.USER, password="correct horse battery", email_verified=True)
    issued = service.login_password(email="user@example.com", password="correct horse battery")
    factor, secret = service.begin_totp_enrollment(user.id)
    service.verify_totp_enrollment(user_id=user.id, factor_id=factor.id, code=totp_code(secret))
    code = totp_code(secret)

    service.step_up_totp(issued.token, code=code)

    with pytest.raises(AuthenticationFailed):
        service.step_up_totp(issued.token, code=code)


def test_audit_write_failure_is_best_effort() -> None:
    service = CorelineAuthService(storage=FailingAuditStorage(), config=CorelineAuthConfig(profile=AuthProfile.RBAC, require_email_verified=False))

    user = service.create_user(email="user@example.com", role=Role.USER, password="correct horse battery", email_verified=True)

    assert user.primary_email == "user@example.com"


def test_email_sender_failure_does_not_break_magic_link_request() -> None:
    service = CorelineAuthService(
        storage=MemoryAuthStorage(),
        config=CorelineAuthConfig(profile=AuthProfile.RBAC, require_email_verified=False),
        email_sender=FailingEmailSender(),
    )
    service.create_user(email="user@example.com", role=Role.USER, password="correct horse battery", email_verified=True)

    challenge = service.request_magic_link(email="user@example.com")

    assert challenge.token


def test_storage_health_check() -> None:
    memory = MemoryAuthStorage()
    memory.health_check()
    sqlite = SQLiteAuthStorage(":memory:")
    try:
        sqlite.health_check()
    finally:
        sqlite.close()
