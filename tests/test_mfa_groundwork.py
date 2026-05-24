from __future__ import annotations

import sqlite3
from datetime import timedelta

import pytest

from coreline_auth import AuthAssuranceLevel, AuthMfaFactor, AuthPasskeyChallenge, AuthProfile, CorelineAuthConfig, CorelineAuthService, MfaFactorType, Role, totp_code
from coreline_auth.errors import AuthenticationFailed, AuthorizationDenied
from coreline_auth.models import now_utc
from coreline_auth.storage import MemoryAuthStorage, SQLiteAuthStorage


def test_session_defaults_to_aal1_and_mfa_models_are_serializable() -> None:
    service = CorelineAuthService(storage=MemoryAuthStorage(), config=CorelineAuthConfig(profile=AuthProfile.RBAC, require_email_verified=False))
    user = service.create_user(email="user@example.com", role=Role.USER, password="correct horse battery", email_verified=True)
    issued = service.issue_session(user, provider="pytest")

    assert issued.session.assurance_level == AuthAssuranceLevel.AAL1
    factor = AuthMfaFactor(id="mfa_1", user_id=user.id, factor_type=MfaFactorType.TOTP, name="Authenticator", secret_hash="sha256:secret")
    challenge = AuthPasskeyChallenge(id="chal_1", user_id=user.id, challenge_hash="sha256:challenge", purpose="passkey_login", expires_at=now_utc() + timedelta(minutes=5))
    assert factor.enabled is True
    assert challenge.consumed_at is None


def test_sqlite_sessions_store_assurance_level_and_upgrade_legacy_table(tmp_path) -> None:
    db_path = tmp_path / "auth.sqlite3"
    legacy = sqlite3.connect(db_path)
    legacy.executescript(
        """
        CREATE TABLE auth_users (
          id TEXT PRIMARY KEY, primary_email TEXT NOT NULL UNIQUE, primary_email_verified INTEGER NOT NULL DEFAULT 0,
          role TEXT NOT NULL DEFAULT 'user', display_name TEXT, avatar_url TEXT, status TEXT NOT NULL DEFAULT 'active',
          created_at TEXT NOT NULL, updated_at TEXT NOT NULL, last_login_at TEXT
        );
        CREATE TABLE auth_identities (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, provider TEXT NOT NULL, provider_subject TEXT, email TEXT, email_verified INTEGER NOT NULL DEFAULT 0, linked_at TEXT NOT NULL, last_seen_at TEXT, UNIQUE(provider, provider_subject));
        CREATE TABLE auth_credentials (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, credential_type TEXT NOT NULL, password_hash TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, revoked_at TEXT);
        CREATE TABLE auth_login_flows (id TEXT PRIMARY KEY, flow_type TEXT NOT NULL, provider TEXT, state_hash TEXT UNIQUE, nonce_hash TEXT, email TEXT, return_to TEXT NOT NULL DEFAULT '/', created_at TEXT NOT NULL, expires_at TEXT NOT NULL, consumed_at TEXT, metadata_json TEXT NOT NULL DEFAULT '{}');
        CREATE TABLE auth_sessions (id TEXT PRIMARY KEY, session_token_hash TEXT NOT NULL UNIQUE, user_id TEXT NOT NULL, subject TEXT, email TEXT, provider TEXT, role TEXT NOT NULL, permissions_json TEXT NOT NULL, created_at TEXT NOT NULL, expires_at TEXT NOT NULL, idle_expires_at TEXT, revoked_at TEXT, last_seen_at TEXT, user_agent_hash TEXT, ip_hash TEXT);
        """
    )
    legacy.close()

    storage = SQLiteAuthStorage(db_path)
    try:
        columns = {row[1] for row in storage.db.execute("PRAGMA table_info(auth_sessions)").fetchall()}
        assert "assurance_level" in columns
        service = CorelineAuthService(storage=storage, config=CorelineAuthConfig(profile=AuthProfile.RBAC, require_email_verified=False))
        user = service.create_user(email="user@example.com", role=Role.USER, password="correct horse battery", email_verified=True)
        issued = service.issue_session(user, provider="pytest")
        stored = storage.get_session_by_token_hash(issued.session.session_token_hash)
        assert stored is not None
        assert stored.assurance_level == AuthAssuranceLevel.AAL1
    finally:
        storage.close()


def test_totp_enrollment_step_up_and_aal2_guard() -> None:
    service = CorelineAuthService(storage=MemoryAuthStorage(), config=CorelineAuthConfig(profile=AuthProfile.RBAC, require_email_verified=False))
    user = service.create_user(email="user@example.com", role=Role.USER, password="correct horse battery", email_verified=True)
    issued = service.login_password(email="user@example.com", password="correct horse battery")
    factor, secret = service.begin_totp_enrollment(user.id)

    with pytest.raises(AuthenticationFailed):
        service.verify_totp_enrollment(user_id=user.id, factor_id=factor.id, code="000000")

    enabled = service.verify_totp_enrollment(user_id=user.id, factor_id=factor.id, code=totp_code(secret))
    assert enabled.enabled is True
    with pytest.raises(AuthorizationDenied):
        service.require_aal2(issued.token)

    stepped_up = service.step_up_totp(issued.token, code=totp_code(secret))

    assert stepped_up.session.assurance_level == AuthAssuranceLevel.AAL2
    assert service.require_aal2(issued.token).session.assurance_level == AuthAssuranceLevel.AAL2


def test_recovery_code_is_one_time_and_steps_up_session() -> None:
    service = CorelineAuthService(storage=MemoryAuthStorage(), config=CorelineAuthConfig(profile=AuthProfile.RBAC, require_email_verified=False))
    service.create_user(email="user@example.com", role=Role.USER, password="correct horse battery", email_verified=True)
    issued = service.login_password(email="user@example.com", password="correct horse battery")
    codes = service.generate_recovery_codes(issued.session.user_id, count=2)

    principal = service.step_up_recovery_code(issued.token, code=codes[0])

    assert principal.session.assurance_level == AuthAssuranceLevel.AAL2
    with pytest.raises(AuthenticationFailed):
        service.step_up_recovery_code(issued.token, code=codes[0])
