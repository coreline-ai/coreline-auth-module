from __future__ import annotations

import sqlite3
import warnings
from datetime import timedelta

import pytest

from coreline_auth import AuthAssuranceLevel, AuthMfaFactor, AuthPasskeyChallenge, AuthProfile, CorelineAuthConfig, CorelineAuthService, InMemoryMfaSecretVault, InsecureMfaVaultWarning, MfaFactorType, Role, totp_code
from coreline_auth.errors import AuthConfigurationError, AuthenticationFailed, AuthorizationDenied
from coreline_auth.models import now_utc
from coreline_auth.storage import MemoryAuthStorage, SQLiteAuthStorage


def make_test_mfa_service(*, mfa_verify_limit_per_minute: int = 5) -> CorelineAuthService:
    return CorelineAuthService(
        storage=MemoryAuthStorage(),
        config=CorelineAuthConfig(
            profile=AuthProfile.RBAC,
            require_email_verified=False,
            mfa_verify_limit_per_minute=mfa_verify_limit_per_minute,
            allow_insecure_mfa_vault=True,
        ),
        mfa_secret_vault=InMemoryMfaSecretVault(),
    )


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
    service = make_test_mfa_service()
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


def test_mfa_step_up_is_rate_limited_across_totp_and_recovery() -> None:
    # RLIM-02: MFA step-up verification must be brute-force throttled, and TOTP
    # and recovery-code attempts must share one per-user budget.
    service = make_test_mfa_service(mfa_verify_limit_per_minute=3)
    user = service.create_user(email="user@example.com", role=Role.USER, password="correct horse battery", email_verified=True)
    issued = service.login_password(email="user@example.com", password="correct horse battery")
    factor, secret = service.begin_totp_enrollment(user.id)
    service.verify_totp_enrollment(user_id=user.id, factor_id=factor.id, code=totp_code(secret))
    codes = service.generate_recovery_codes(user.id, count=2)

    # Exhaust the per-user step-up budget with wrong TOTP codes.
    for _ in range(3):
        with pytest.raises(AuthenticationFailed, match="invalid mfa code"):
            service.step_up_totp(issued.token, code="000000")

    # A valid TOTP code is now blocked by rate limiting...
    with pytest.raises(AuthenticationFailed, match="rate limited"):
        service.step_up_totp(issued.token, code=totp_code(secret))
    # ...and so is a valid recovery code, proving the shared bucket. The code is
    # not consumed because the limiter rejects before the lookup.
    with pytest.raises(AuthenticationFailed, match="rate limited"):
        service.step_up_recovery_code(issued.token, code=codes[0])


def test_default_mfa_vault_requires_explicit_insecure_opt_in() -> None:
    # VAULT-01/CRED-04: enrolling TOTP against the implicit plaintext vault must
    # fail closed by default, so it is not silently shipped.
    service = CorelineAuthService(storage=MemoryAuthStorage(), config=CorelineAuthConfig(profile=AuthProfile.RBAC, require_email_verified=False))
    user = service.create_user(email="user@example.com", role=Role.USER, password="correct horse battery", email_verified=True)
    with pytest.raises(AuthConfigurationError, match="encrypted mfa_secret_vault"):
        service.begin_totp_enrollment(user.id)

    # Tests/local demos can opt in to the implicit plaintext vault, but still
    # receive a visible warning.
    opt_in = CorelineAuthService(
        storage=MemoryAuthStorage(),
        config=CorelineAuthConfig(profile=AuthProfile.RBAC, require_email_verified=False, allow_insecure_mfa_vault=True),
    )
    user_opt_in = opt_in.create_user(email="optin@example.com", role=Role.USER, password="correct horse battery", email_verified=True)
    with pytest.warns(InsecureMfaVaultWarning):
        opt_in.begin_totp_enrollment(user_opt_in.id)

    # An explicitly provided insecure vault must also opt in, then stays silent
    # because the developer made an intentional local/test choice.
    explicit = CorelineAuthService(
        storage=MemoryAuthStorage(),
        config=CorelineAuthConfig(profile=AuthProfile.RBAC, require_email_verified=False, allow_insecure_mfa_vault=True),
        mfa_secret_vault=InMemoryMfaSecretVault(),
    )
    user2 = explicit.create_user(email="user2@example.com", role=Role.USER, password="correct horse battery", email_verified=True)
    with warnings.catch_warnings():
        warnings.simplefilter("error", InsecureMfaVaultWarning)
        explicit.begin_totp_enrollment(user2.id)


def test_recovery_code_meets_entropy_floor() -> None:
    # REC-01: recovery codes must carry >=160 bits. base64url is 6 bits/char,
    # so codes must be at least 27 characters long.
    from coreline_auth.mfa import generate_recovery_code

    codes = {generate_recovery_code() for _ in range(50)}
    assert len(codes) == 50  # high-entropy: no collisions across samples
    for code in codes:
        assert len(code) * 6 >= 160


def test_recovery_code_is_one_time_and_steps_up_session() -> None:
    service = CorelineAuthService(storage=MemoryAuthStorage(), config=CorelineAuthConfig(profile=AuthProfile.RBAC, require_email_verified=False))
    service.create_user(email="user@example.com", role=Role.USER, password="correct horse battery", email_verified=True)
    issued = service.login_password(email="user@example.com", password="correct horse battery")
    codes = service.generate_recovery_codes(issued.session.user_id, count=2)

    principal = service.step_up_recovery_code(issued.token, code=codes[0])

    assert principal.session.assurance_level == AuthAssuranceLevel.AAL2
    with pytest.raises(AuthenticationFailed):
        service.step_up_recovery_code(issued.token, code=codes[0])
