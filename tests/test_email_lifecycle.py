from __future__ import annotations

import sqlite3
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import pytest

from coreline_auth import AuthProfile, AuthenticationFailed, CorelineAuthConfig, CorelineAuthService, InMemoryEmailSender
from coreline_auth.models import FlowType, now_utc
from coreline_auth.security import hash_secret
from coreline_auth.storage import MemoryAuthStorage, SQLiteAuthStorage
from coreline_auth.storage.base import AuthStorage


def make_service(storage: AuthStorage, *, email_sender: InMemoryEmailSender | None = None) -> CorelineAuthService:
    return CorelineAuthService(storage=storage, config=CorelineAuthConfig(profile=AuthProfile.RBAC), email_sender=email_sender)


@pytest.fixture(params=["memory", "sqlite"])
def storage(request: pytest.FixtureRequest, tmp_path: Path) -> AuthStorage:
    if request.param == "memory":
        return MemoryAuthStorage()
    sqlite_storage = SQLiteAuthStorage(tmp_path / "auth.sqlite3")
    request.addfinalizer(sqlite_storage.close)
    return sqlite_storage


def test_email_verification_marks_user_and_identity_verified_once(storage: AuthStorage) -> None:
    sender = InMemoryEmailSender()
    service = make_service(storage, email_sender=sender)
    user = service.create_user(email="User@example.com", password="correct horse battery", email_verified=False)

    user_id_challenge = service.request_email_verification(user_id=user.id)
    assert sender.sent_email_verifications[-1].email == "user@example.com"

    challenge = service.request_email_verification(email="USER@example.com")
    sent = sender.sent_email_verifications[-1]
    assert sent.email == "user@example.com"
    assert sent.token == challenge.token

    flow = storage.get_login_flow_by_state_hash(hash_secret(challenge.token))
    assert flow is not None
    assert flow.flow_type == FlowType.EMAIL_VERIFICATION
    assert flow.state_hash == hash_secret(challenge.token)
    assert flow.state_hash != challenge.token
    assert storage.get_login_flow_by_state_hash(hash_secret(user_id_challenge.token)) is not None

    verified = service.consume_email_verification(challenge.token)
    assert verified.primary_email_verified is True
    stored_user = storage.get_user(user.id)
    assert stored_user is not None
    assert stored_user.primary_email_verified is True
    identity = storage.get_identity("email", "user@example.com")
    assert identity is not None
    assert identity.email_verified is True

    with pytest.raises(AuthenticationFailed):
        service.consume_email_verification(challenge.token)


def test_email_verification_expired_token_is_rejected(storage: AuthStorage) -> None:
    service = make_service(storage)
    user = service.create_user(email="user@example.com", email_verified=False)
    challenge = service.request_email_verification(user_id=user.id)
    flow = storage.get_login_flow_by_state_hash(hash_secret(challenge.token))
    assert flow is not None
    storage.update_login_flow(replace(flow, expires_at=now_utc() - timedelta(seconds=1)))

    with pytest.raises(AuthenticationFailed, match="expired"):
        service.consume_email_verification(challenge.token)


def test_password_reset_sets_new_password_once(storage: AuthStorage) -> None:
    sender = InMemoryEmailSender()
    service = make_service(storage, email_sender=sender)
    service.create_user(email="User@example.com", password="old correct horse", email_verified=True)

    challenge = service.request_password_reset("USER@example.com")
    sent = sender.sent_password_resets[-1]
    assert sent.email == "user@example.com"
    assert sent.token == challenge.token

    flow = storage.get_login_flow_by_state_hash(hash_secret(challenge.token))
    assert flow is not None
    assert flow.flow_type == FlowType.PASSWORD_RESET
    assert flow.state_hash == hash_secret(challenge.token)
    assert flow.state_hash != challenge.token

    service.consume_password_reset(challenge.token, "new correct horse")
    issued = service.login_password(email="user@example.com", password="new correct horse")
    assert service.verify_session(issued.token).email == "user@example.com"

    with pytest.raises(AuthenticationFailed):
        service.login_password(email="user@example.com", password="old correct horse")
    with pytest.raises(AuthenticationFailed):
        service.consume_password_reset(challenge.token, "another password")


def test_password_reset_expired_token_is_rejected(storage: AuthStorage) -> None:
    service = make_service(storage)
    service.create_user(email="user@example.com", password="old correct horse", email_verified=True)
    challenge = service.request_password_reset("user@example.com")
    flow = storage.get_login_flow_by_state_hash(hash_secret(challenge.token))
    assert flow is not None
    storage.update_login_flow(replace(flow, expires_at=now_utc() - timedelta(seconds=1)))

    with pytest.raises(AuthenticationFailed, match="expired"):
        service.consume_password_reset(challenge.token, "new correct horse")


def test_password_reset_unknown_user_does_not_store_flow_or_send_email(storage: AuthStorage) -> None:
    sender = InMemoryEmailSender()
    service = make_service(storage, email_sender=sender)

    challenge = service.request_password_reset("missing@example.com")

    assert sender.sent_password_resets == []
    assert storage.get_login_flow_by_state_hash(hash_secret(challenge.token)) is None
    with pytest.raises(AuthenticationFailed):
        service.consume_password_reset(challenge.token, "new correct horse")


def test_sqlite_email_lifecycle_tokens_are_hash_only(tmp_path: Path) -> None:
    db_path = tmp_path / "auth.sqlite3"
    storage = SQLiteAuthStorage(db_path)
    try:
        service = make_service(storage)
        user = service.create_user(email="user@example.com", password="old correct horse", email_verified=False)
        verification = service.request_email_verification(user_id=user.id)
        reset = service.request_password_reset("user@example.com")
    finally:
        storage.close()

    raw = db_path.read_bytes()
    assert verification.token.encode() not in raw
    assert reset.token.encode() not in raw

    db = sqlite3.connect(db_path)
    try:
        rows = db.execute("SELECT flow_type, state_hash FROM auth_login_flows ORDER BY created_at ASC").fetchall()
        assert rows == [
            (FlowType.EMAIL_VERIFICATION.value, hash_secret(verification.token)),
            (FlowType.PASSWORD_RESET.value, hash_secret(reset.token)),
        ]
    finally:
        db.close()


def test_password_reset_unknown_user_runs_dummy_password_work(monkeypatch, storage: AuthStorage) -> None:
    sender = InMemoryEmailSender()
    service = make_service(storage, email_sender=sender)
    calls: list[str] = []

    def fake_dummy(password: str) -> None:
        calls.append(password)

    monkeypatch.setattr("coreline_auth.service.verify_dummy_password", fake_dummy)

    service.request_password_reset("missing@example.com")

    assert len(calls) == 1
    assert sender.sent_password_resets == []
